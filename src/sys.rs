//! User and group database lookups.

use std::collections::HashMap;
use std::ffi::{CStr, CString, OsStr};
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;

/// Size of the scratch buffer for the reentrant passwd/group calls.
const BUF_LEN: usize = 16 * 1024;

/// The passwd fields we use.
pub struct PasswdEntry {
    pub name: String,
    pub home: PathBuf,
}

/// SAFETY: `pwd` must have been filled in by a successful getpw*_r call.
unsafe fn passwd_entry(pwd: &libc::passwd) -> Option<PasswdEntry> {
    if pwd.pw_name.is_null() || pwd.pw_dir.is_null() {
        return None;
    }
    // SAFETY: both pointers point into the caller's buffer and are
    // NUL-terminated, as guaranteed by getpw*_r.
    let (name, dir) = unsafe { (CStr::from_ptr(pwd.pw_name), CStr::from_ptr(pwd.pw_dir)) };
    Some(PasswdEntry {
        name: name.to_string_lossy().into_owned(),
        home: PathBuf::from(OsStr::from_bytes(dir.to_bytes())),
    })
}

pub fn passwd_by_uid(uid: u32) -> Option<PasswdEntry> {
    let mut buf = vec![0 as libc::c_char; BUF_LEN];
    // SAFETY: an all-zero passwd is a valid value to pass for filling in.
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: all pointers refer to live, correctly sized buffers.
    let rc = unsafe { libc::getpwuid_r(uid, &mut pwd, buf.as_mut_ptr(), buf.len(), &mut result) };
    if rc != 0 || result.is_null() {
        return None;
    }
    // SAFETY: the call succeeded and `buf` is still alive.
    unsafe { passwd_entry(&pwd) }
}

pub fn passwd_by_name(name: &[u8]) -> Option<PasswdEntry> {
    let cname = CString::new(name).ok()?;
    let mut buf = vec![0 as libc::c_char; BUF_LEN];
    // SAFETY: an all-zero passwd is a valid value to pass for filling in.
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: all pointers refer to live, correctly sized buffers.
    let rc = unsafe {
        libc::getpwnam_r(
            cname.as_ptr(),
            &mut pwd,
            buf.as_mut_ptr(),
            buf.len(),
            &mut result,
        )
    };
    if rc != 0 || result.is_null() {
        return None;
    }
    // SAFETY: the call succeeded and `buf` is still alive.
    unsafe { passwd_entry(&pwd) }
}

pub fn group_name(gid: u32) -> Option<String> {
    let mut buf = vec![0 as libc::c_char; BUF_LEN];
    // SAFETY: an all-zero group is a valid value to pass for filling in.
    let mut grp: libc::group = unsafe { std::mem::zeroed() };
    let mut result: *mut libc::group = std::ptr::null_mut();
    // SAFETY: all pointers refer to live, correctly sized buffers.
    let rc = unsafe { libc::getgrgid_r(gid, &mut grp, buf.as_mut_ptr(), buf.len(), &mut result) };
    if rc != 0 || result.is_null() || grp.gr_name.is_null() {
        return None;
    }
    // SAFETY: getgrgid_r succeeded, so gr_name points into `buf`.
    let name = unsafe { CStr::from_ptr(grp.gr_name) };
    Some(name.to_string_lossy().into_owned())
}

/// Home directory of the user this process runs as. Prefers the passwd
/// entry, falling back to `$HOME`.
pub fn current_home() -> Option<PathBuf> {
    // SAFETY: getuid has no failure modes.
    let uid = unsafe { libc::getuid() };
    passwd_by_uid(uid)
        .map(|p| p.home)
        .or_else(|| std::env::var_os("HOME").map(PathBuf::from))
}

/// Caches uid/gid → name lookups for the lifetime of the session.
#[derive(Default)]
pub struct NameCache {
    users: HashMap<u32, Option<String>>,
    groups: HashMap<u32, Option<String>>,
}

impl NameCache {
    pub fn user(&mut self, uid: u32) -> Option<&str> {
        self.users
            .entry(uid)
            .or_insert_with(|| passwd_by_uid(uid).map(|p| p.name))
            .as_deref()
    }

    pub fn group(&mut self, gid: u32) -> Option<&str> {
        self.groups
            .entry(gid)
            .or_insert_with(|| group_name(gid))
            .as_deref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_lookups() {
        let root = passwd_by_uid(0).unwrap();
        assert_eq!(root.name, "root");
        assert_eq!(passwd_by_name(b"root").unwrap().home, root.home);
        assert!(passwd_by_name(b"no-such-user-ferrisftp").is_none());
        assert_eq!(group_name(0).as_deref(), Some("root"));

        let mut c = NameCache::default();
        assert_eq!(c.user(0), Some("root"));
        assert_eq!(c.user(4_000_000_000), None);
    }
}
