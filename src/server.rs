//! Request dispatch and the SFTP v3 operations.

use std::ffi::{CStr, CString, OsStr};
use std::fs::{self, DirBuilder, File, FileTimes};
use std::io::{self, BufReader, ErrorKind, Read, Write};
use std::os::fd::FromRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, FileExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, UNIX_EPOCH};

use crate::attrs::FileAttrs;
use crate::handles::{Handle, HandleTable};
use crate::longname::longname;
use crate::protocol::*;
use crate::sys::NameCache;
use crate::wire::{DecodeError, DecodeResult, Reader, Writer};

/// The client broke the protocol badly enough that the session must end.
#[derive(Debug)]
pub struct Fatal(pub &'static str);

impl std::fmt::Display for Fatal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for Fatal {}

/// Outcome of one operation: a reply packet, or a status code to send.
pub(crate) type OpResult = Result<Vec<u8>, Status>;

/// An SFTP status reply that is not `SSH_FX_OK`.
#[derive(Debug)]
pub(crate) struct Status {
    pub(crate) code: u32,
    pub(crate) message: String,
}

impl Status {
    pub(crate) fn new(code: u32, message: impl Into<String>) -> Self {
        Status {
            code,
            message: message.into(),
        }
    }

    pub(crate) fn bad_handle() -> Self {
        Status::new(SSH_FX_FAILURE, "Invalid handle")
    }
}

impl From<io::Error> for Status {
    fn from(e: io::Error) -> Self {
        let code = match e.kind() {
            ErrorKind::NotFound => SSH_FX_NO_SUCH_FILE,
            ErrorKind::PermissionDenied => SSH_FX_PERMISSION_DENIED,
            _ => SSH_FX_FAILURE,
        };
        Status::new(code, error_message(&e))
    }
}

/// Human-readable error text without Rust's " (os error N)" suffix.
fn error_message(e: &io::Error) -> String {
    match e.raw_os_error() {
        Some(errno) => {
            // SAFETY: strerror returns a valid NUL-terminated string. We are
            // single-threaded here, so its static buffer is not shared.
            let s = unsafe { CStr::from_ptr(libc::strerror(errno)) };
            s.to_string_lossy().into_owned()
        }
        None => e.to_string(),
    }
}

pub(crate) fn status_text(code: u32) -> &'static str {
    match code {
        SSH_FX_OK => "Success",
        SSH_FX_EOF => "End of file",
        SSH_FX_NO_SUCH_FILE => "No such file",
        SSH_FX_PERMISSION_DENIED => "Permission denied",
        SSH_FX_BAD_MESSAGE => "Bad message",
        SSH_FX_OP_UNSUPPORTED => "Operation unsupported",
        _ => "Failure",
    }
}

fn status_packet(id: u32, code: u32, message: &str) -> Vec<u8> {
    let mut w = Writer::new(SSH_FXP_STATUS);
    w.u32(id).u32(code).string(message.as_bytes()).string(b"");
    w.finish()
}

pub(crate) fn ok(id: u32) -> OpResult {
    Ok(status_packet(id, SSH_FX_OK, status_text(SSH_FX_OK)))
}

pub(crate) fn path_from(bytes: &[u8]) -> &Path {
    Path::new(OsStr::from_bytes(bytes))
}

pub(crate) fn cstring(path: &Path) -> Result<CString, Status> {
    CString::new(path.as_os_str().as_bytes())
        .map_err(|_| Status::new(SSH_FX_FAILURE, "Path contains NUL byte"))
}

pub(crate) fn last_os_error<T>() -> Result<T, Status> {
    Err(io::Error::last_os_error().into())
}

pub struct Server {
    initialized: bool,
    pub(crate) handles: HandleTable,
    pub(crate) names: NameCache,
    read_buf: Vec<u8>,
}

impl Default for Server {
    fn default() -> Self {
        Self::new()
    }
}

impl Server {
    pub fn new() -> Self {
        Server {
            initialized: false,
            handles: HandleTable::default(),
            names: NameCache::default(),
            read_buf: Vec::new(),
        }
    }

    /// Serve one session until the client closes the stream.
    pub fn run<R: Read, W: Write>(&mut self, input: R, output: W) -> io::Result<()> {
        let mut input = BufReader::with_capacity(64 * 1024, input);
        let mut output = io::BufWriter::with_capacity(64 * 1024, output);
        let mut packet = Vec::new();
        let mut reply = Vec::new();
        loop {
            let mut len = [0u8; 4];
            match input.read_exact(&mut len) {
                Ok(()) => {}
                Err(e) if e.kind() == ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(e),
            }
            let len = u32::from_be_bytes(len);
            if len == 0 || len > MAX_PACKET_LEN {
                return Err(io::Error::new(
                    ErrorKind::InvalidData,
                    Fatal("invalid packet length"),
                ));
            }
            packet.resize(len as usize, 0);
            input.read_exact(&mut packet)?;

            reply.clear();
            self.process(&packet, &mut reply)
                .map_err(|f| io::Error::new(ErrorKind::InvalidData, f))?;
            output.write_all(&reply)?;
            // Let pipelined requests batch their replies into one write; flush
            // once we would otherwise block waiting for more input.
            if input.buffer().is_empty() {
                output.flush()?;
            }
        }
        output.flush()
    }

    /// Handle one packet (type byte plus body, without the length prefix)
    /// and append any reply to `out`.
    pub fn process(&mut self, packet: &[u8], out: &mut Vec<u8>) -> Result<(), Fatal> {
        let Some((&kind, body)) = packet.split_first() else {
            return Err(Fatal("empty packet"));
        };
        let mut r = Reader::new(body);

        if kind == SSH_FXP_INIT {
            if self.initialized {
                return Err(Fatal("duplicate SSH_FXP_INIT"));
            }
            let client_version = r.u32().map_err(|_| Fatal("malformed SSH_FXP_INIT"))?;
            self.initialized = true;
            let mut w = Writer::new(SSH_FXP_VERSION);
            w.u32(client_version.min(SFTP_VERSION));
            for (name, version) in crate::extensions::ADVERTISED {
                w.string(name.as_bytes()).string(version.as_bytes());
            }
            out.extend_from_slice(&w.finish());
            return Ok(());
        }
        if !self.initialized {
            return Err(Fatal("request before SSH_FXP_INIT"));
        }

        // Every other request starts with a request id. Without one we
        // cannot even address an error reply.
        let id = r.u32().map_err(|_| Fatal("request without id"))?;
        let reply = match self.dispatch(kind, id, &mut r) {
            Ok(Ok(packet)) => packet,
            Ok(Err(status)) => status_packet(id, status.code, &status.message),
            Err(DecodeError) => {
                status_packet(id, SSH_FX_BAD_MESSAGE, status_text(SSH_FX_BAD_MESSAGE))
            }
        };
        out.extend_from_slice(&reply);
        Ok(())
    }

    fn dispatch(&mut self, kind: u8, id: u32, r: &mut Reader<'_>) -> DecodeResult<OpResult> {
        Ok(match kind {
            SSH_FXP_OPEN => {
                let path = r.string()?;
                let pflags = r.u32()?;
                let attrs = FileAttrs::decode(r)?;
                self.open(id, path_from(path), pflags, &attrs)
            }
            SSH_FXP_CLOSE => {
                let handle = r.string()?;
                self.close(id, handle)
            }
            SSH_FXP_READ => {
                let handle = r.string()?;
                let offset = r.u64()?;
                let len = r.u32()?;
                self.read(id, handle, offset, len)
            }
            SSH_FXP_WRITE => {
                let handle = r.string()?;
                let offset = r.u64()?;
                let data = r.string()?;
                self.write(id, handle, offset, data)
            }
            SSH_FXP_LSTAT => {
                let path = r.string()?;
                attrs_reply(id, fs::symlink_metadata(path_from(path)))
            }
            SSH_FXP_STAT => {
                let path = r.string()?;
                attrs_reply(id, fs::metadata(path_from(path)))
            }
            SSH_FXP_FSTAT => {
                let handle = r.string()?;
                match self.handles.get_mut(handle) {
                    Some(Handle::File { file }) => attrs_reply(id, file.metadata()),
                    _ => Err(Status::bad_handle()),
                }
            }
            SSH_FXP_SETSTAT => {
                let path = r.string()?;
                let attrs = FileAttrs::decode(r)?;
                setstat(path_from(path), &attrs).and_then(|()| ok(id))
            }
            SSH_FXP_FSETSTAT => {
                let handle = r.string()?;
                let attrs = FileAttrs::decode(r)?;
                match self.handles.get_mut(handle) {
                    Some(Handle::File { file }) => fsetstat(file, &attrs).and_then(|()| ok(id)),
                    _ => Err(Status::bad_handle()),
                }
            }
            SSH_FXP_OPENDIR => {
                let path = r.string()?;
                self.opendir(id, path_from(path))
            }
            SSH_FXP_READDIR => {
                let handle = r.string()?;
                self.readdir(id, handle)
            }
            SSH_FXP_REMOVE => {
                let path = r.string()?;
                fs::remove_file(path_from(path))
                    .map_err(Status::from)
                    .and_then(|()| ok(id))
            }
            SSH_FXP_MKDIR => {
                let path = r.string()?;
                let attrs = FileAttrs::decode(r)?;
                let mode = attrs.permissions.map_or(0o777, |p| p & 0o7777);
                DirBuilder::new()
                    .mode(mode)
                    .create(path_from(path))
                    .map_err(Status::from)
                    .and_then(|()| ok(id))
            }
            SSH_FXP_RMDIR => {
                let path = r.string()?;
                fs::remove_dir(path_from(path))
                    .map_err(Status::from)
                    .and_then(|()| ok(id))
            }
            SSH_FXP_REALPATH => {
                let path = r.string()?;
                realpath(path_from(path)).map(|p| single_name(id, p.as_os_str().as_bytes()))
            }
            SSH_FXP_RENAME => {
                let from = r.string()?;
                let to = r.string()?;
                rename_noreplace(path_from(from), path_from(to)).and_then(|()| ok(id))
            }
            SSH_FXP_READLINK => {
                let path = r.string()?;
                fs::read_link(path_from(path))
                    .map_err(Status::from)
                    .map(|target| single_name(id, target.as_os_str().as_bytes()))
            }
            SSH_FXP_SYMLINK => {
                // OpenSSH sends these in the opposite order to the draft:
                // link target first, then the path of the new link. Every
                // client in practice follows OpenSSH, so we do too.
                let target = r.string()?;
                let link = r.string()?;
                std::os::unix::fs::symlink(path_from(target), path_from(link))
                    .map_err(Status::from)
                    .and_then(|()| ok(id))
            }
            SSH_FXP_EXTENDED => {
                let request = r.string()?;
                return self.extended(id, request, r);
            }
            _ => Err(Status::new(
                SSH_FX_OP_UNSUPPORTED,
                status_text(SSH_FX_OP_UNSUPPORTED),
            )),
        })
    }

    fn open(&mut self, id: u32, path: &Path, pflags: u32, attrs: &FileAttrs) -> OpResult {
        let read = pflags & SSH_FXF_READ != 0;
        let write = pflags & SSH_FXF_WRITE != 0;
        let mut flags = match (read, write) {
            (true, true) => libc::O_RDWR,
            (false, true) => libc::O_WRONLY,
            _ => libc::O_RDONLY,
        };
        if pflags & SSH_FXF_APPEND != 0 {
            flags |= libc::O_APPEND;
        }
        if pflags & SSH_FXF_CREAT != 0 {
            flags |= libc::O_CREAT;
        }
        if pflags & SSH_FXF_TRUNC != 0 {
            flags |= libc::O_TRUNC;
        }
        if pflags & SSH_FXF_EXCL != 0 {
            flags |= libc::O_EXCL;
        }
        flags |= libc::O_CLOEXEC;
        let mode = attrs.permissions.map_or(0o666, |p| p & 0o7777);

        // std's OpenOptions rejects some combinations SFTP allows (e.g.
        // create without write), so call open(2) directly. The umask still
        // applies, as with any other program the user runs.
        let cpath = cstring(path)?;
        // SAFETY: cpath is a valid NUL-terminated string.
        let fd = unsafe { libc::open(cpath.as_ptr(), flags, mode as libc::c_uint) };
        if fd < 0 {
            return last_os_error();
        }
        // SAFETY: fd is a freshly opened descriptor we exclusively own.
        let file = unsafe { File::from_raw_fd(fd) };
        self.new_handle(id, Handle::File { file })
    }

    fn new_handle(&mut self, id: u32, handle: Handle) -> OpResult {
        let raw = self
            .handles
            .insert(handle)
            .map_err(|_| Status::new(SSH_FX_FAILURE, "Too many open handles"))?;
        let mut w = Writer::new(SSH_FXP_HANDLE);
        w.u32(id).string(&raw);
        Ok(w.finish())
    }

    fn close(&mut self, id: u32, handle: &[u8]) -> OpResult {
        match self.handles.remove(handle) {
            // Dropping the File closes it; close(2) errors on regular files
            // are not reported by std, matching common sftp-server behaviour.
            Some(_) => ok(id),
            None => Err(Status::bad_handle()),
        }
    }

    fn read(&mut self, id: u32, handle: &[u8], offset: u64, len: u32) -> OpResult {
        let Some(Handle::File { file }) = self.handles.get_mut(handle) else {
            return Err(Status::bad_handle());
        };
        let len = len.min(MAX_READ_LEN) as usize;
        self.read_buf.resize(len, 0);
        let n = loop {
            match file.read_at(&mut self.read_buf, offset) {
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                other => break other?,
            }
        };
        if n == 0 && len > 0 {
            return Err(Status::new(SSH_FX_EOF, status_text(SSH_FX_EOF)));
        }
        let mut w = Writer::with_capacity(SSH_FXP_DATA, 8 + n);
        w.u32(id).string(&self.read_buf[..n]);
        Ok(w.finish())
    }

    fn write(&mut self, id: u32, handle: &[u8], offset: u64, data: &[u8]) -> OpResult {
        let Some(Handle::File { file }) = self.handles.get_mut(handle) else {
            return Err(Status::bad_handle());
        };
        // With O_APPEND, Linux ignores the offset and appends, which is the
        // semantics SSH_FXF_APPEND asks for.
        file.write_all_at(data, offset)?;
        ok(id)
    }

    fn opendir(&mut self, id: u32, path: &Path) -> OpResult {
        let entries = fs::read_dir(path)?;
        self.new_handle(
            id,
            Handle::Dir {
                path: path.to_path_buf(),
                entries,
                dots_sent: false,
            },
        )
    }

    fn readdir(&mut self, id: u32, handle: &[u8]) -> OpResult {
        let Some(Handle::Dir {
            path,
            entries,
            dots_sent,
        }) = self.handles.get_mut(handle)
        else {
            return Err(Status::bad_handle());
        };

        let mut batch: Vec<(Vec<u8>, fs::Metadata)> = Vec::with_capacity(READDIR_BATCH);
        if !*dots_sent {
            *dots_sent = true;
            for dot in [".", ".."] {
                if let Ok(m) = fs::symlink_metadata(path.join(dot)) {
                    batch.push((dot.as_bytes().to_vec(), m));
                }
            }
        }
        while batch.len() < READDIR_BATCH {
            let Some(entry) = entries.next() else { break };
            let entry = entry?;
            // Entries can vanish between readdir and lstat; skip those.
            let Ok(meta) = entry.metadata() else { continue };
            batch.push((entry.file_name().as_bytes().to_vec(), meta));
        }

        if batch.is_empty() {
            return Err(Status::new(SSH_FX_EOF, status_text(SSH_FX_EOF)));
        }
        let mut w = Writer::with_capacity(SSH_FXP_NAME, batch.len() * 128);
        w.u32(id).u32(batch.len() as u32);
        for (name, meta) in &batch {
            w.string(name);
            w.string(&longname(name, meta, &mut self.names));
            FileAttrs::from_metadata(meta).encode(&mut w);
        }
        Ok(w.finish())
    }
}

fn attrs_reply(id: u32, meta: io::Result<fs::Metadata>) -> OpResult {
    let meta = meta?;
    let mut w = Writer::new(SSH_FXP_ATTRS);
    w.u32(id);
    FileAttrs::from_metadata(&meta).encode(&mut w);
    Ok(w.finish())
}

/// A NAME reply with one entry and empty attributes, as used by REALPATH
/// and READLINK.
pub(crate) fn single_name(id: u32, name: &[u8]) -> Vec<u8> {
    let mut w = Writer::new(SSH_FXP_NAME);
    w.u32(id).u32(1).string(name).string(name);
    FileAttrs::default().encode(&mut w);
    w.finish()
}

fn file_times(atime: u32, mtime: u32) -> FileTimes {
    FileTimes::new()
        .set_accessed(UNIX_EPOCH + Duration::from_secs(atime.into()))
        .set_modified(UNIX_EPOCH + Duration::from_secs(mtime.into()))
}

fn setstat(path: &Path, attrs: &FileAttrs) -> Result<(), Status> {
    if let Some(size) = attrs.size {
        let cpath = cstring(path)?;
        let size = libc::off_t::try_from(size)
            .map_err(|_| Status::new(SSH_FX_FAILURE, "Size out of range"))?;
        // SAFETY: cpath is a valid NUL-terminated string.
        if unsafe { libc::truncate(cpath.as_ptr(), size) } != 0 {
            return last_os_error();
        }
    }
    if let Some(perm) = attrs.permissions {
        fs::set_permissions(path, fs::Permissions::from_mode(perm & 0o7777))?;
    }
    if let Some((atime, mtime)) = attrs.times {
        let cpath = cstring(path)?;
        let tv = [
            libc::timeval {
                tv_sec: atime as libc::time_t,
                tv_usec: 0,
            },
            libc::timeval {
                tv_sec: mtime as libc::time_t,
                tv_usec: 0,
            },
        ];
        // SAFETY: cpath is valid and tv holds exactly two timevals.
        if unsafe { libc::utimes(cpath.as_ptr(), tv.as_ptr()) } != 0 {
            return last_os_error();
        }
    }
    if let Some((uid, gid)) = attrs.uid_gid {
        std::os::unix::fs::chown(path, Some(uid), Some(gid))?;
    }
    Ok(())
}

fn fsetstat(file: &File, attrs: &FileAttrs) -> Result<(), Status> {
    if let Some(size) = attrs.size {
        file.set_len(size)?;
    }
    if let Some(perm) = attrs.permissions {
        file.set_permissions(fs::Permissions::from_mode(perm & 0o7777))?;
    }
    if let Some((atime, mtime)) = attrs.times {
        file.set_times(file_times(atime, mtime))?;
    }
    if let Some((uid, gid)) = attrs.uid_gid {
        std::os::unix::fs::fchown(file, Some(uid), Some(gid))?;
    }
    Ok(())
}

/// Canonicalize a path. An empty path means the current directory. If the
/// final component does not exist yet, resolve its parent instead, since
/// clients use REALPATH on upload targets before creating them.
pub(crate) fn realpath(path: &Path) -> Result<PathBuf, Status> {
    let path = if path.as_os_str().is_empty() {
        Path::new(".")
    } else {
        path
    };
    match fs::canonicalize(path) {
        Ok(p) => Ok(p),
        Err(e) if e.kind() == ErrorKind::NotFound => {
            let (Some(parent), Some(name)) = (path.parent(), path.file_name()) else {
                return Err(e.into());
            };
            let parent = if parent.as_os_str().is_empty() {
                Path::new(".")
            } else {
                parent
            };
            Ok(fs::canonicalize(parent)?.join(name))
        }
        Err(e) => Err(e.into()),
    }
}

/// SFTP v3 RENAME must fail if the target exists. For regular files,
/// link + unlink gives that atomically; for other types, or filesystems
/// without hard links, fall back to an existence check plus rename(2).
fn rename_noreplace(from: &Path, to: &Path) -> Result<(), Status> {
    let meta = fs::symlink_metadata(from)?;
    if meta.file_type().is_file() {
        match fs::hard_link(from, to) {
            Ok(()) => {
                if let Err(e) = fs::remove_file(from) {
                    // Undo the link so we don't leave two names behind.
                    let _ = fs::remove_file(to);
                    return Err(e.into());
                }
                return Ok(());
            }
            Err(e) if e.kind() == ErrorKind::AlreadyExists => {
                return Err(Status::new(SSH_FX_FAILURE, "Target exists"));
            }
            Err(e) => match e.raw_os_error() {
                Some(libc::EPERM | libc::EOPNOTSUPP | libc::EMLINK | libc::ENOSYS) => {}
                _ => return Err(e.into()),
            },
        }
    }
    if fs::symlink_metadata(to).is_ok() {
        return Err(Status::new(SSH_FX_FAILURE, "Target exists"));
    }
    fs::rename(from, to)?;
    Ok(())
}
