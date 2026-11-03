//! OpenSSH protocol extensions (see OpenSSH's PROTOCOL file).
//!
//! These are what real clients negotiate on top of SFTP v3. Each is
//! advertised in the VERSION reply and reached through SSH_FXP_EXTENDED.

use std::ffi::CString;
use std::fs::{self, File};
use std::io::ErrorKind;
use std::mem::MaybeUninit;
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};

use crate::attrs::FileAttrs;
use crate::handles::Handle;
use crate::protocol::*;
use crate::server::{
    OpResult, Server, Status, cstring, last_os_error, ok, path_from, realpath, single_name,
    status_text,
};
use crate::sys;
use crate::wire::{DecodeError, DecodeResult, Reader, Writer};

/// (name, version) pairs sent in SSH_FXP_VERSION.
pub const ADVERTISED: &[(&str, &str)] = &[
    ("posix-rename@openssh.com", "1"),
    ("statvfs@openssh.com", "2"),
    ("fstatvfs@openssh.com", "2"),
    ("hardlink@openssh.com", "1"),
    ("fsync@openssh.com", "1"),
    ("lsetstat@openssh.com", "1"),
    ("limits@openssh.com", "1"),
    ("expand-path@openssh.com", "1"),
    ("copy-data", "1"),
    ("home-directory", "1"),
    ("users-groups-by-id@openssh.com", "1"),
];

/// Chunk size for server-side copies.
const COPY_CHUNK: usize = 64 * 1024;

// statvfs flag bits as defined by the extension.
const SSH_FXE_STATVFS_ST_RDONLY: u64 = 0x1;
const SSH_FXE_STATVFS_ST_NOSUID: u64 = 0x2;

fn unsupported() -> Status {
    Status::new(SSH_FX_OP_UNSUPPORTED, status_text(SSH_FX_OP_UNSUPPORTED))
}

impl Server {
    pub(crate) fn extended(
        &mut self,
        id: u32,
        request: &[u8],
        r: &mut Reader<'_>,
    ) -> DecodeResult<OpResult> {
        Ok(match request {
            b"posix-rename@openssh.com" => {
                let from = r.string()?;
                let to = r.string()?;
                fs::rename(path_from(from), path_from(to))
                    .map_err(Status::from)
                    .and_then(|()| ok(id))
            }
            b"hardlink@openssh.com" => {
                let existing = r.string()?;
                let link = r.string()?;
                fs::hard_link(path_from(existing), path_from(link))
                    .map_err(Status::from)
                    .and_then(|()| ok(id))
            }
            b"statvfs@openssh.com" => {
                let path = r.string()?;
                statvfs(id, path_from(path))
            }
            b"fstatvfs@openssh.com" => {
                let handle = r.string()?;
                match self.handles.get_mut(handle) {
                    Some(Handle::File { file }) => fstatvfs(id, file),
                    _ => Err(Status::bad_handle()),
                }
            }
            b"fsync@openssh.com" => {
                let handle = r.string()?;
                match self.handles.get_mut(handle) {
                    Some(Handle::File { file }) => {
                        file.sync_all().map_err(Status::from).and_then(|()| ok(id))
                    }
                    _ => Err(Status::bad_handle()),
                }
            }
            b"lsetstat@openssh.com" => {
                let path = r.string()?;
                let attrs = FileAttrs::decode(r)?;
                lsetstat(path_from(path), &attrs).and_then(|()| ok(id))
            }
            b"limits@openssh.com" => {
                let mut w = Writer::new(SSH_FXP_EXTENDED_REPLY);
                w.u32(id)
                    .u64(MAX_PACKET_LEN.into())
                    .u64(MAX_READ_LEN.into())
                    .u64(MAX_READ_LEN.into())
                    .u64(MAX_HANDLES as u64);
                Ok(w.finish())
            }
            b"expand-path@openssh.com" => {
                let path = r.string()?;
                expand_path(path)
                    .and_then(|p| realpath(&p))
                    .map(|p| single_name(id, p.as_os_str().as_bytes()))
            }
            b"home-directory" => {
                let user = r.string()?;
                let home = if user.is_empty() {
                    sys::current_home()
                } else {
                    sys::passwd_by_name(user).map(|p| p.home)
                };
                match home {
                    Some(h) => Ok(single_name(id, h.as_os_str().as_bytes())),
                    None => Err(Status::new(SSH_FX_NO_SUCH_FILE, "No such user")),
                }
            }
            b"copy-data" => {
                let read_handle = r.string()?;
                let read_offset = r.u64()?;
                let read_len = r.u64()?;
                let write_handle = r.string()?;
                let write_offset = r.u64()?;
                self.copy_data(
                    read_handle,
                    read_offset,
                    read_len,
                    write_handle,
                    write_offset,
                )
                .and_then(|()| ok(id))
            }
            b"users-groups-by-id@openssh.com" => {
                let uids = r.string()?;
                let gids = r.string()?;
                let mut w = Writer::new(SSH_FXP_EXTENDED_REPLY);
                w.u32(id);
                let users = self.packed_names(uids, |c, id| c.user(id).map(str::to_owned))?;
                let groups = self.packed_names(gids, |c, id| c.group(id).map(str::to_owned))?;
                w.string(&users).string(&groups);
                Ok(w.finish())
            }
            _ => Err(unsupported()),
        })
    }

    /// Resolve a packed list of u32 ids into a packed list of name strings,
    /// using an empty string for ids without a name.
    fn packed_names(
        &mut self,
        ids: &[u8],
        lookup: impl Fn(&mut sys::NameCache, u32) -> Option<String>,
    ) -> DecodeResult<Vec<u8>> {
        if ids.len() % 4 != 0 {
            return Err(DecodeError);
        }
        let mut r = Reader::new(ids);
        let mut out = Vec::new();
        while r.remaining() > 0 {
            let name = lookup(&mut self.names, r.u32()?).unwrap_or_default();
            out.extend_from_slice(&(name.len() as u32).to_be_bytes());
            out.extend_from_slice(name.as_bytes());
        }
        Ok(out)
    }

    fn copy_data(
        &mut self,
        read_handle: &[u8],
        read_offset: u64,
        read_len: u64,
        write_handle: &[u8],
        write_offset: u64,
    ) -> Result<(), Status> {
        // A zero length means "until end of file".
        let read_end = if read_len == 0 {
            u64::MAX
        } else {
            read_offset.saturating_add(read_len)
        };
        if read_handle == write_handle {
            // Copying within one file is allowed only between ranges that
            // cannot overlap.
            let write_end = write_offset.saturating_add(read_end - read_offset);
            if read_len == 0 || (write_offset < read_end && read_offset < write_end) {
                return Err(Status::new(SSH_FX_FAILURE, "Overlapping copy"));
            }
        }

        let src = match self.handles.get_mut(read_handle) {
            Some(Handle::File { file }) => file.try_clone()?,
            _ => return Err(Status::bad_handle()),
        };
        let Some(Handle::File { file: dst }) = self.handles.get_mut(write_handle) else {
            return Err(Status::bad_handle());
        };

        let mut buf = vec![0u8; COPY_CHUNK];
        let (mut src_pos, mut dst_pos) = (read_offset, write_offset);
        while src_pos < read_end {
            let want = (read_end - src_pos).min(COPY_CHUNK as u64) as usize;
            let n = match src.read_at(&mut buf[..want], src_pos) {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(e) => return Err(e.into()),
            };
            dst.write_all_at(&buf[..n], dst_pos)?;
            src_pos += n as u64;
            dst_pos += n as u64;
        }
        Ok(())
    }
}

fn expand_path(path: &[u8]) -> Result<PathBuf, Status> {
    sys::expand_tilde(path).ok_or_else(|| Status::new(SSH_FX_NO_SUCH_FILE, "No such user"))
}

#[allow(clippy::unnecessary_cast)] // field types vary between libc targets
fn statvfs_reply(id: u32, st: &libc::statvfs) -> Vec<u8> {
    let mut flag = 0;
    if st.f_flag & libc::ST_RDONLY != 0 {
        flag |= SSH_FXE_STATVFS_ST_RDONLY;
    }
    if st.f_flag & libc::ST_NOSUID != 0 {
        flag |= SSH_FXE_STATVFS_ST_NOSUID;
    }
    let mut w = Writer::new(SSH_FXP_EXTENDED_REPLY);
    w.u32(id)
        .u64(st.f_bsize as u64)
        .u64(st.f_frsize as u64)
        .u64(st.f_blocks as u64)
        .u64(st.f_bfree as u64)
        .u64(st.f_bavail as u64)
        .u64(st.f_files as u64)
        .u64(st.f_ffree as u64)
        .u64(st.f_favail as u64)
        .u64(st.f_fsid as u64)
        .u64(flag)
        .u64(st.f_namemax as u64);
    w.finish()
}

fn statvfs(id: u32, path: &Path) -> OpResult {
    let cpath = cstring(path)?;
    let mut st = MaybeUninit::<libc::statvfs>::uninit();
    // SAFETY: cpath is valid; st is written by statvfs on success.
    if unsafe { libc::statvfs(cpath.as_ptr(), st.as_mut_ptr()) } != 0 {
        return last_os_error();
    }
    // SAFETY: statvfs returned 0, so st is initialized.
    Ok(statvfs_reply(id, &unsafe { st.assume_init() }))
}

fn fstatvfs(id: u32, file: &File) -> OpResult {
    let mut st = MaybeUninit::<libc::statvfs>::uninit();
    // SAFETY: the fd is open for the lifetime of `file`.
    if unsafe { libc::fstatvfs(file.as_raw_fd(), st.as_mut_ptr()) } != 0 {
        return last_os_error();
    }
    // SAFETY: fstatvfs returned 0, so st is initialized.
    Ok(statvfs_reply(id, &unsafe { st.assume_init() }))
}

/// Like SETSTAT but applies to a symlink itself rather than its target.
fn lsetstat(path: &Path, attrs: &FileAttrs) -> Result<(), Status> {
    if attrs.size.is_some() {
        // There is no way to truncate a symlink.
        return Err(unsupported());
    }
    let cpath: CString = cstring(path)?;
    if let Some(perm) = attrs.permissions {
        // SAFETY: cpath is a valid NUL-terminated string. Linux refuses to
        // chmod symlinks themselves; that error is passed to the client.
        let rc = unsafe {
            libc::fchmodat(
                libc::AT_FDCWD,
                cpath.as_ptr(),
                (perm & 0o7777) as libc::mode_t,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if rc != 0 {
            return last_os_error();
        }
    }
    if let Some((atime, mtime)) = attrs.times {
        let ts = [
            libc::timespec {
                tv_sec: atime as libc::time_t,
                tv_nsec: 0,
            },
            libc::timespec {
                tv_sec: mtime as libc::time_t,
                tv_nsec: 0,
            },
        ];
        // SAFETY: cpath is valid and ts holds exactly two timespecs.
        let rc = unsafe {
            libc::utimensat(
                libc::AT_FDCWD,
                cpath.as_ptr(),
                ts.as_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if rc != 0 {
            return last_os_error();
        }
    }
    if let Some((uid, gid)) = attrs.uid_gid {
        std::os::unix::fs::lchown(path, Some(uid), Some(gid))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tilde_expansion() {
        let home = sys::current_home().unwrap();
        assert_eq!(expand_path(b"~").unwrap(), home);
        assert_eq!(expand_path(b"~/a/b").unwrap(), home.join("a/b"));
        let root = sys::passwd_by_name(b"root").unwrap().home;
        assert_eq!(expand_path(b"~root/x").unwrap(), root.join("x"));
        assert_eq!(expand_path(b"/abs").unwrap(), PathBuf::from("/abs"));
        assert_eq!(expand_path(b"rel/~x").unwrap(), PathBuf::from("rel/~x"));
        assert_eq!(
            expand_path(b"~no-such-user-ferrisftp").unwrap_err().code,
            SSH_FX_NO_SUCH_FILE
        );
    }
}
