//! Which requests a session may use: read-only mode plus the allow and
//! deny lists from `-p` / `-P`, using the request names of OpenSSH's
//! sftp-server so existing configurations carry over.

use std::collections::HashSet;
use std::fmt;

use crate::protocol::*;

/// A request kind and whether it can modify the filesystem.
struct RequestKind {
    name: &'static str,
    packet: u8,
    /// Extension name for SSH_FXP_EXTENDED requests.
    extension: Option<&'static str>,
    writes: bool,
}

const fn req(name: &'static str, packet: u8, writes: bool) -> RequestKind {
    RequestKind {
        name,
        packet,
        extension: None,
        writes,
    }
}

const fn ext(name: &'static str, extension: &'static str, writes: bool) -> RequestKind {
    RequestKind {
        name,
        packet: SSH_FXP_EXTENDED,
        extension: Some(extension),
        writes,
    }
}

const REQUESTS: &[RequestKind] = &[
    // OPEN only writes with certain flags; Server::open checks those.
    req("open", SSH_FXP_OPEN, false),
    req("close", SSH_FXP_CLOSE, false),
    req("read", SSH_FXP_READ, false),
    req("write", SSH_FXP_WRITE, true),
    req("lstat", SSH_FXP_LSTAT, false),
    req("fstat", SSH_FXP_FSTAT, false),
    req("setstat", SSH_FXP_SETSTAT, true),
    req("fsetstat", SSH_FXP_FSETSTAT, true),
    req("opendir", SSH_FXP_OPENDIR, false),
    req("readdir", SSH_FXP_READDIR, false),
    req("remove", SSH_FXP_REMOVE, true),
    req("mkdir", SSH_FXP_MKDIR, true),
    req("rmdir", SSH_FXP_RMDIR, true),
    req("realpath", SSH_FXP_REALPATH, false),
    req("stat", SSH_FXP_STAT, false),
    req("rename", SSH_FXP_RENAME, true),
    req("readlink", SSH_FXP_READLINK, false),
    req("symlink", SSH_FXP_SYMLINK, true),
    ext("posix-rename", "posix-rename@openssh.com", true),
    ext("statvfs", "statvfs@openssh.com", false),
    ext("fstatvfs", "fstatvfs@openssh.com", false),
    ext("hardlink", "hardlink@openssh.com", true),
    ext("fsync", "fsync@openssh.com", true),
    ext("lsetstat", "lsetstat@openssh.com", true),
    ext("limits", "limits@openssh.com", false),
    ext("expand-path", "expand-path@openssh.com", false),
    ext("copy-data", "copy-data", true),
    ext("home-directory", "home-directory", false),
    ext(
        "users-groups-by-id",
        "users-groups-by-id@openssh.com",
        false,
    ),
    ext("check-file-name", "check-file-name", false),
    ext("check-file-handle", "check-file-handle", false),
    // The older draft's name for check-file-handle, used by Paramiko.
    ext("check-file", "check-file", false),
];

/// Names accepted by `-p` / `-P`, in protocol order (for `-Q requests`).
pub fn request_names() -> impl Iterator<Item = &'static str> {
    REQUESTS.iter().map(|r| r.name)
}

fn lookup(packet: u8, extension: Option<&[u8]>) -> Option<&'static RequestKind> {
    REQUESTS.iter().find(|r| {
        r.packet == packet
            && match (r.extension, extension) {
                (Some(want), Some(got)) => want.as_bytes() == got,
                (None, _) => true,
                (Some(_), None) => false,
            }
    })
}

/// The `-p` / `-P` name of a request, if it is one we know.
pub fn request_name(packet: u8, extension: Option<&[u8]>) -> Option<&'static str> {
    lookup(packet, extension).map(|r| r.name)
}

/// `-p` / `-P` named a request that does not exist.
#[derive(Debug, PartialEq, Eq)]
pub struct UnknownRequest(pub String);

impl fmt::Display for UnknownRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unknown request \"{}\"", self.0)
    }
}

impl std::error::Error for UnknownRequest {}

fn parse_list(list: &str) -> Result<HashSet<&'static str>, UnknownRequest> {
    list.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|name| {
            request_names()
                .find(|n| *n == name)
                .ok_or_else(|| UnknownRequest(name.to_owned()))
        })
        .collect()
}

#[derive(Debug, Default, Clone)]
pub struct Policy {
    pub read_only: bool,
    /// If set, only these requests are allowed.
    allow: Option<HashSet<&'static str>>,
    deny: HashSet<&'static str>,
}

impl Policy {
    /// Set the allow list from a comma-separated `-p` argument.
    pub fn set_allowed(&mut self, list: &str) -> Result<(), UnknownRequest> {
        self.allow = Some(parse_list(list)?);
        Ok(())
    }

    /// Set the deny list from a comma-separated `-P` argument.
    pub fn set_denied(&mut self, list: &str) -> Result<(), UnknownRequest> {
        self.deny = parse_list(list)?;
        Ok(())
    }

    /// Whether a request may run. Unknown requests are permitted here;
    /// the dispatcher answers them with SSH_FX_OP_UNSUPPORTED anyway.
    pub fn permits(&self, packet: u8, extension: Option<&[u8]>) -> bool {
        let Some(kind) = lookup(packet, extension) else {
            return true;
        };
        if let Some(allow) = &self.allow
            && !allow.contains(kind.name)
        {
            return false;
        }
        !(self.deny.contains(kind.name) || (self.read_only && kind.writes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_request_has_a_unique_name() {
        let names: HashSet<_> = request_names().collect();
        assert_eq!(names.len(), REQUESTS.len());
    }

    #[test]
    fn read_only_blocks_writes() {
        let p = Policy {
            read_only: true,
            ..Default::default()
        };
        assert!(p.permits(SSH_FXP_READ, None));
        assert!(p.permits(SSH_FXP_OPEN, None));
        assert!(!p.permits(SSH_FXP_WRITE, None));
        assert!(!p.permits(SSH_FXP_REMOVE, None));
        assert!(!p.permits(SSH_FXP_EXTENDED, Some(b"posix-rename@openssh.com")));
        assert!(p.permits(SSH_FXP_EXTENDED, Some(b"statvfs@openssh.com")));
        // Hashing only reads.
        assert!(p.permits(SSH_FXP_EXTENDED, Some(b"check-file-name")));
        assert!(p.permits(SSH_FXP_EXTENDED, Some(b"check-file")));
        // Unknown extensions fall through to OP_UNSUPPORTED.
        assert!(p.permits(SSH_FXP_EXTENDED, Some(b"bogus@example.com")));
    }

    #[test]
    fn allow_and_deny_lists() {
        let mut p = Policy::default();
        p.set_allowed("open, read,close,opendir,readdir,realpath,stat,statvfs")
            .unwrap();
        assert!(p.permits(SSH_FXP_READ, None));
        assert!(!p.permits(SSH_FXP_WRITE, None));
        assert!(p.permits(SSH_FXP_EXTENDED, Some(b"statvfs@openssh.com")));
        assert!(!p.permits(SSH_FXP_EXTENDED, Some(b"fstatvfs@openssh.com")));

        let mut p = Policy::default();
        p.set_denied("remove,rmdir").unwrap();
        assert!(!p.permits(SSH_FXP_REMOVE, None));
        assert!(p.permits(SSH_FXP_MKDIR, None));

        assert_eq!(
            Policy::default().set_denied("remove,nope"),
            Err(UnknownRequest("nope".into()))
        );
    }
}
