//! `ls -l`-style "longname" strings for READDIR responses.
//!
//! SFTP v3 clients display this field verbatim, and some parse it, so the
//! layout follows what OpenSSH's sftp-server produces.

use std::collections::HashMap;
use std::ffi::CStr;
use std::fs::Metadata;
use std::os::unix::fs::MetadataExt;
use std::time::{SystemTime, UNIX_EPOCH};

/// Caches uid/gid → name lookups for the lifetime of the session.
#[derive(Default)]
pub struct NameCache {
    users: HashMap<u32, String>,
    groups: HashMap<u32, String>,
}

impl NameCache {
    pub fn user(&mut self, uid: u32) -> &str {
        self.users
            .entry(uid)
            .or_insert_with(|| lookup_user(uid).unwrap_or_else(|| uid.to_string()))
    }

    pub fn group(&mut self, gid: u32) -> &str {
        self.groups
            .entry(gid)
            .or_insert_with(|| lookup_group(gid).unwrap_or_else(|| gid.to_string()))
    }
}

fn lookup_user(uid: u32) -> Option<String> {
    let mut buf = vec![0 as libc::c_char; 4096];
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: all pointers refer to live, correctly sized buffers.
    let rc = unsafe { libc::getpwuid_r(uid, &mut pwd, buf.as_mut_ptr(), buf.len(), &mut result) };
    if rc != 0 || result.is_null() || pwd.pw_name.is_null() {
        return None;
    }
    // SAFETY: getpwuid_r succeeded, so pw_name points into `buf`.
    let name = unsafe { CStr::from_ptr(pwd.pw_name) };
    Some(name.to_string_lossy().into_owned())
}

fn lookup_group(gid: u32) -> Option<String> {
    let mut buf = vec![0 as libc::c_char; 4096];
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

/// Ten-character mode string, e.g. `drwxr-xr-x`.
pub fn mode_string(mode: u32) -> String {
    // POSIX file-type bits, which SFTP v3 permissions carry verbatim.
    let kind = match mode & 0o170000 {
        0o040000 => 'd',
        0o120000 => 'l',
        0o020000 => 'c',
        0o060000 => 'b',
        0o010000 => 'p',
        0o140000 => 's',
        _ => '-',
    };
    let bit = |mask: u32, c: char| if mode & mask != 0 { c } else { '-' };
    let exec =
        |x: u32, special: u32, set: char, unset: char| match (mode & x != 0, mode & special != 0) {
            (true, true) => set,
            (false, true) => unset,
            (true, false) => 'x',
            (false, false) => '-',
        };
    let mut s = String::with_capacity(10);
    s.push(kind);
    s.push(bit(0o400, 'r'));
    s.push(bit(0o200, 'w'));
    s.push(exec(0o100, 0o4000, 's', 'S'));
    s.push(bit(0o040, 'r'));
    s.push(bit(0o020, 'w'));
    s.push(exec(0o010, 0o2000, 's', 'S'));
    s.push(bit(0o004, 'r'));
    s.push(bit(0o002, 'w'));
    s.push(exec(0o001, 0o1000, 't', 'T'));
    s
}

/// `ls`-style date: time of day for recent files, year for older ones.
fn date_string(mtime: i64) -> String {
    const SIX_MONTHS: i64 = 182 * 24 * 60 * 60;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let fmt: &CStr = if mtime + SIX_MONTHS > now && mtime <= now {
        c"%b %e %H:%M"
    } else {
        c"%b %e  %Y"
    };
    let t: libc::time_t = mtime as libc::time_t;
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    let mut buf = [0u8; 64];
    // SAFETY: localtime_r writes into `tm`; strftime writes at most
    // `buf.len()` bytes into `buf` and returns how many it wrote.
    let n = unsafe {
        if libc::localtime_r(&t, &mut tm).is_null() {
            return "?".into();
        }
        libc::strftime(buf.as_mut_ptr().cast(), buf.len(), fmt.as_ptr(), &tm)
    };
    String::from_utf8_lossy(&buf[..n]).into_owned()
}

/// Build the longname for one directory entry.
pub fn longname(name: &[u8], m: &Metadata, names: &mut NameCache) -> Vec<u8> {
    let user = names.user(m.uid()).to_owned();
    let group = names.group(m.gid());
    let head = format!(
        "{} {:>4} {:<8} {:<8} {:>8} {} ",
        mode_string(m.mode()),
        m.nlink(),
        user,
        group,
        m.size(),
        date_string(m.mtime()),
    );
    let mut out = head.into_bytes();
    out.extend_from_slice(name);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modes() {
        assert_eq!(mode_string(0o040755), "drwxr-xr-x");
        assert_eq!(mode_string(0o100644), "-rw-r--r--");
        assert_eq!(mode_string(0o104755), "-rwsr-xr-x");
        assert_eq!(mode_string(0o041777), "drwxrwxrwt");
        assert_eq!(mode_string(0o120777), "lrwxrwxrwx");
        assert_eq!(mode_string(0o102644), "-rw-r-Sr--");
    }

    #[test]
    fn root_names_resolve() {
        let mut c = NameCache::default();
        assert_eq!(c.user(0), "root");
        // Unknown ids fall back to the number.
        assert_eq!(c.user(4_000_000_000), "4000000000");
    }
}
