//! SFTP wire encoding: big-endian integers and length-prefixed strings.

use std::fmt;

/// A packet body ended early or contained an impossible length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecodeError;

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("malformed packet")
    }
}

impl std::error::Error for DecodeError {}

pub type DecodeResult<T> = Result<T, DecodeError>;

/// Cursor over a received packet body.
pub struct Reader<'a> {
    buf: &'a [u8],
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Reader { buf }
    }

    pub fn remaining(&self) -> usize {
        self.buf.len()
    }

    fn take(&mut self, n: usize) -> DecodeResult<&'a [u8]> {
        if n > self.buf.len() {
            return Err(DecodeError);
        }
        let (head, tail) = self.buf.split_at(n);
        self.buf = tail;
        Ok(head)
    }

    pub fn u8(&mut self) -> DecodeResult<u8> {
        Ok(self.take(1)?[0])
    }

    pub fn u32(&mut self) -> DecodeResult<u32> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub fn u64(&mut self) -> DecodeResult<u64> {
        let b = self.take(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(b);
        Ok(u64::from_be_bytes(a))
    }

    /// A length-prefixed byte string. The length is checked against the
    /// remaining buffer before anything is sliced, so a hostile length can
    /// never cause an out-of-bounds access or a large allocation.
    pub fn string(&mut self) -> DecodeResult<&'a [u8]> {
        let len = self.u32()? as usize;
        self.take(len)
    }
}

/// Builder for an outgoing packet. The 4-byte length prefix is reserved up
/// front and filled in by [`Writer::finish`].
pub struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    pub fn new(packet_type: u8) -> Self {
        Self::with_capacity(packet_type, 64)
    }

    pub fn with_capacity(packet_type: u8, cap: usize) -> Self {
        let mut buf = Vec::with_capacity(cap + 5);
        buf.extend_from_slice(&[0, 0, 0, 0, packet_type]);
        Writer { buf }
    }

    pub fn u8(&mut self, v: u8) -> &mut Self {
        self.buf.push(v);
        self
    }

    pub fn u32(&mut self, v: u32) -> &mut Self {
        self.buf.extend_from_slice(&v.to_be_bytes());
        self
    }

    pub fn u64(&mut self, v: u64) -> &mut Self {
        self.buf.extend_from_slice(&v.to_be_bytes());
        self
    }

    pub fn string(&mut self, s: &[u8]) -> &mut Self {
        // Callers never build strings anywhere near 4 GiB; the packet size
        // limit caps everything we send far below that.
        self.u32(s.len() as u32);
        self.buf.extend_from_slice(s);
        self
    }

    /// Current size of the packet including the length prefix.
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn is_empty(&self) -> bool {
        false
    }

    /// Fill in the length prefix and return the complete framed packet.
    pub fn finish(mut self) -> Vec<u8> {
        let body_len = (self.buf.len() - 4) as u32;
        self.buf[..4].copy_from_slice(&body_len.to_be_bytes());
        self.buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let mut w = Writer::new(42);
        w.u8(7).u32(0xdead_beef).u64(1 << 40).string(b"hello");
        let pkt = w.finish();
        assert_eq!(&pkt[..4], &((pkt.len() - 4) as u32).to_be_bytes());
        assert_eq!(pkt[4], 42);
        let mut r = Reader::new(&pkt[5..]);
        assert_eq!(r.u8().unwrap(), 7);
        assert_eq!(r.u32().unwrap(), 0xdead_beef);
        assert_eq!(r.u64().unwrap(), 1 << 40);
        assert_eq!(r.string().unwrap(), b"hello");
        assert_eq!(r.remaining(), 0);
    }

    #[test]
    fn truncated_and_oversized() {
        assert_eq!(Reader::new(&[0, 0, 1]).u32(), Err(DecodeError));
        // claims 0xffffffff bytes, has 2
        assert_eq!(
            Reader::new(&[0xff, 0xff, 0xff, 0xff, 1, 2]).string(),
            Err(DecodeError)
        );
    }
}
