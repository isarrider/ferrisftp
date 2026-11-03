//! The SFTP v3 ATTRS structure.

use std::fs::Metadata;
use std::os::unix::fs::MetadataExt;

use crate::protocol::*;
use crate::wire::{DecodeResult, Reader, Writer};

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct FileAttrs {
    pub size: Option<u64>,
    pub uid_gid: Option<(u32, u32)>,
    /// Full `st_mode`, including the file-type bits, as OpenSSH sends it.
    pub permissions: Option<u32>,
    /// (atime, mtime) in seconds since the epoch.
    pub times: Option<(u32, u32)>,
}

impl FileAttrs {
    pub fn decode(r: &mut Reader<'_>) -> DecodeResult<Self> {
        let flags = r.u32()?;
        let mut a = FileAttrs::default();
        if flags & SSH_FILEXFER_ATTR_SIZE != 0 {
            a.size = Some(r.u64()?);
        }
        if flags & SSH_FILEXFER_ATTR_UIDGID != 0 {
            a.uid_gid = Some((r.u32()?, r.u32()?));
        }
        if flags & SSH_FILEXFER_ATTR_PERMISSIONS != 0 {
            a.permissions = Some(r.u32()?);
        }
        if flags & SSH_FILEXFER_ATTR_ACMODTIME != 0 {
            a.times = Some((r.u32()?, r.u32()?));
        }
        if flags & SSH_FILEXFER_ATTR_EXTENDED != 0 {
            // Vendor extensions: parsed for framing, otherwise ignored.
            let count = r.u32()?;
            for _ in 0..count {
                r.string()?;
                r.string()?;
            }
        }
        Ok(a)
    }

    pub fn encode(&self, w: &mut Writer) {
        let mut flags = 0;
        if self.size.is_some() {
            flags |= SSH_FILEXFER_ATTR_SIZE;
        }
        if self.uid_gid.is_some() {
            flags |= SSH_FILEXFER_ATTR_UIDGID;
        }
        if self.permissions.is_some() {
            flags |= SSH_FILEXFER_ATTR_PERMISSIONS;
        }
        if self.times.is_some() {
            flags |= SSH_FILEXFER_ATTR_ACMODTIME;
        }
        w.u32(flags);
        if let Some(size) = self.size {
            w.u64(size);
        }
        if let Some((uid, gid)) = self.uid_gid {
            w.u32(uid).u32(gid);
        }
        if let Some(perm) = self.permissions {
            w.u32(perm);
        }
        if let Some((atime, mtime)) = self.times {
            w.u32(atime).u32(mtime);
        }
    }

    pub fn from_metadata(m: &Metadata) -> Self {
        FileAttrs {
            size: Some(m.size()),
            uid_gid: Some((m.uid(), m.gid())),
            permissions: Some(m.mode()),
            // v3 times are 32-bit; clamp rather than wrap for pre-1970 or
            // post-2106 timestamps.
            times: Some((clamp_time(m.atime()), clamp_time(m.mtime()))),
        }
    }
}

fn clamp_time(t: i64) -> u32 {
    t.clamp(0, u32::MAX as i64) as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_all_fields() {
        let a = FileAttrs {
            size: Some(12345),
            uid_gid: Some((1000, 100)),
            permissions: Some(0o100644),
            times: Some((1_700_000_000, 1_700_000_001)),
        };
        let mut w = Writer::new(0);
        a.encode(&mut w);
        let pkt = w.finish();
        let mut r = Reader::new(&pkt[5..]);
        assert_eq!(FileAttrs::decode(&mut r).unwrap(), a);
        assert_eq!(r.remaining(), 0);
    }

    #[test]
    fn skips_extended() {
        let mut w = Writer::new(0);
        w.u32(SSH_FILEXFER_ATTR_PERMISSIONS | SSH_FILEXFER_ATTR_EXTENDED)
            .u32(0o755)
            .u32(1)
            .string(b"vendor@example.com")
            .string(b"data");
        let pkt = w.finish();
        let mut r = Reader::new(&pkt[5..]);
        let a = FileAttrs::decode(&mut r).unwrap();
        assert_eq!(a.permissions, Some(0o755));
        assert_eq!(r.remaining(), 0);
    }
}
