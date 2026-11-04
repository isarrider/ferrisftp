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
use crate::checkfile::{self, Algorithm};
use crate::handles::Handle;
use crate::log::Quoted;
use crate::protocol::*;
use crate::server::{
    OpResult, Server, Status, cstring, last_os_error, log_setstat, ok, path_from, realpath,
    single_name, status_text,
};
use crate::sys;
use crate::wire::{DecodeError, DecodeResult, Reader, Writer};

/// Request extensions and their versions, as advertised in SSH_FXP_VERSION.
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

/// Append every extension pair for the SSH_FXP_VERSION reply: the request
/// extensions above plus informational ones.
pub fn write_version_extensions(w: &mut Writer) {
    for (name, version) in ADVERTISED {
        w.string(name.as_bytes()).string(version.as_bytes());
    }

    // vendor-id (draft-ietf-secsh-filexfer-13, section 4.4): vendor name,
    // product name, product version, build number.
    let mut vendor = Writer::new(0);
    vendor
        .string(b"isarrider")
        .string(b"ferrisftp")
        .string(env!("CARGO_PKG_VERSION").as_bytes())
        .u64(0);
    let vendor = vendor.finish();
    // Skip the 4-byte length and 1-byte type that Writer frames packets with.
    w.string(b"vendor-id").string(&vendor[5..]);

    // Tells clients which SSH_FXP_SYMLINK argument order we use, see
    // https://www.greenend.org.uk/rjk/sftp/symlink-order@rjk.greenend.org.uk.html
    w.string(b"symlink-order@rjk.greenend.org.uk")
        .string(b"targetpath-linkpath");

    // Server-side hashing. The draft defines no extension data for SFTP v3;
    // we list the supported algorithms. WinSCP detects the extension by
    // this name.
    w.string(b"check-file")
        .string(checkfile::ALGORITHMS.as_bytes());
}

/// Which wire format a check-file request uses.
#[derive(Clone, Copy, PartialEq, Eq)]
enum CheckFileVariant {
    /// check-file-name / check-file-handle
    /// (draft-ietf-secsh-filexfer-extensions-00): the reply is the
    /// algorithm name followed by the hashes. WinSCP uses this.
    Current,
    /// check-file with a handle, from the older filexfer drafts: the reply
    /// starts with the string "check-file". Paramiko uses this.
    Legacy,
}

/// Bytes of a check-file reply other than the hashes: header, request
/// id, "check-file" for the legacy variant and the algorithm name.
const CHECK_FILE_OVERHEAD: usize = 64;

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
                crate::log_info!("posix-rename old {} new {}", Quoted(from), Quoted(to));
                fs::rename(path_from(from), path_from(to))
                    .map_err(Status::from)
                    .and_then(|()| ok(id))
            }
            b"hardlink@openssh.com" => {
                let existing = r.string()?;
                let link = r.string()?;
                crate::log_info!("hardlink old {} new {}", Quoted(existing), Quoted(link));
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
                    Some(Handle::File { file, .. }) => fstatvfs(id, file),
                    _ => Err(Status::bad_handle()),
                }
            }
            b"fsync@openssh.com" => {
                let handle = r.string()?;
                match self.handles.get_mut(handle) {
                    Some(Handle::File { file, .. }) => {
                        file.sync_all().map_err(Status::from).and_then(|()| ok(id))
                    }
                    _ => Err(Status::bad_handle()),
                }
            }
            b"lsetstat@openssh.com" => {
                let path = r.string()?;
                let attrs = FileAttrs::decode(r)?;
                log_setstat(path, &attrs);
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
            b"check-file-name" => {
                let path = r.string()?;
                let algorithms = r.string()?;
                let (start, length, block_size) = (r.u64()?, r.u64()?, r.u32()?);
                // Follows symlinks, as the draft specifies.
                match File::open(path_from(path)) {
                    Ok(file) => check_file(
                        id,
                        &file,
                        path,
                        CheckFileVariant::Current,
                        algorithms,
                        (start, length, block_size),
                    ),
                    Err(e) => Err(e.into()),
                }
            }
            b"check-file-handle" | b"check-file" => {
                let handle = r.string()?;
                let algorithms = r.string()?;
                let (start, length, block_size) = (r.u64()?, r.u64()?, r.u32()?);
                let variant = if request == b"check-file" {
                    CheckFileVariant::Legacy
                } else {
                    CheckFileVariant::Current
                };
                match self.handles.get_mut(handle) {
                    Some(Handle::File { file, path, .. }) => check_file(
                        id,
                        file,
                        path.as_os_str().as_bytes(),
                        variant,
                        algorithms,
                        (start, length, block_size),
                    ),
                    _ => Err(Status::bad_handle()),
                }
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

        let (src, src_path) = match self.handles.get_mut(read_handle) {
            Some(Handle::File { file, path, .. }) => (file.try_clone()?, path.clone()),
            _ => return Err(Status::bad_handle()),
        };
        let Some(Handle::File {
            file: dst,
            path: dst_path,
            ..
        }) = self.handles.get_mut(write_handle)
        else {
            return Err(Status::bad_handle());
        };
        crate::log_info!(
            "copy-data from {} offset {read_offset} length {read_len} to {} offset {write_offset}",
            Quoted(src_path.as_os_str().as_bytes()),
            Quoted(dst_path.as_os_str().as_bytes())
        );

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

/// Hash a file for check-file-name, check-file-handle or check-file.
fn check_file(
    id: u32,
    file: &File,
    path: &[u8],
    variant: CheckFileVariant,
    algorithms: &[u8],
    (start, length, block_size): (u64, u64, u32),
) -> OpResult {
    let Some(algorithm) = Algorithm::select(algorithms) else {
        return Err(Status::new(
            SSH_FX_OP_UNSUPPORTED,
            "No supported hash algorithm",
        ));
    };
    crate::log_info!(
        "check-file {} algorithm {} offset {start} length {length} block-size {block_size}",
        Quoted(path),
        algorithm.name()
    );
    let max_output = MAX_PACKET_LEN as usize - CHECK_FILE_OVERHEAD;
    let hashes = checkfile::hash_file(file, algorithm, start, length, block_size, max_output)
        .map_err(|e| match e {
            checkfile::Error::BlockSizeTooSmall => {
                Status::new(SSH_FX_FAILURE, "Block size must be 0 or at least 256")
            }
            checkfile::Error::TooManyBlocks => {
                Status::new(SSH_FX_FAILURE, "Too many blocks for one reply")
            }
            checkfile::Error::NotRegularFile => Status::new(SSH_FX_FAILURE, "Not a regular file"),
            // A handle opened without read access.
            checkfile::Error::Io(e) if e.raw_os_error() == Some(libc::EBADF) => {
                Status::new(SSH_FX_PERMISSION_DENIED, "Handle not open for reading")
            }
            checkfile::Error::Io(e) => e.into(),
        })?;
    let mut w = Writer::with_capacity(SSH_FXP_EXTENDED_REPLY, hashes.len() + 32);
    w.u32(id);
    if variant == CheckFileVariant::Legacy {
        w.string(b"check-file");
    }
    w.string(algorithm.name().as_bytes()).bytes(&hashes);
    Ok(w.finish())
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
