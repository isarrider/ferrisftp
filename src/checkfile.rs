//! Server-side file hashing: the `check-file` extension
//! (draft-ietf-secsh-filexfer-extensions-00, section 3).
//!
//! The client names a file, a range and a list of acceptable algorithms,
//! and gets back one hash for the whole range or one per block, without
//! the data crossing the network.
//!
//! Only SHA-256 is offered. The draft also lists md5, sha1 and crc32, but
//! those are unsuitable for detecting deliberate tampering, so a client
//! cannot fall back to them.

use std::fs::File;
use std::io::{self, ErrorKind};
use std::os::unix::fs::FileExt;

use sha2::{Digest, Sha256};

/// The algorithm name on the wire, and the advertised algorithm list.
pub const SHA256: &str = "sha256";

/// Bytes per hash.
pub const HASH_LEN: usize = 32;

/// The draft forbids block sizes below this (0 means "no blocks").
pub const MIN_BLOCK_SIZE: u32 = 256;

const CHUNK: usize = 64 * 1024;

/// Whether a comma-separated algorithm list from the client includes
/// SHA-256, the only algorithm we offer.
pub fn accepts_sha256(list: &[u8]) -> bool {
    list.split(|&b| b == b',')
        .any(|name| name.trim_ascii() == SHA256.as_bytes())
}

#[derive(Debug)]
pub enum Error {
    /// A non-zero block size below [`MIN_BLOCK_SIZE`].
    BlockSizeTooSmall,
    /// The hashes would not fit in one reply packet.
    TooManyBlocks,
    /// Not a regular file; hashing a device or FIFO could block forever.
    NotRegularFile,
    Io(io::Error),
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(e)
    }
}

/// SHA-256 of `length` bytes of `file` from `start` (0 = up to end of
/// file), either as one hash or one per `block_size` bytes. The range is
/// clipped to the end of the file. `max_output` caps the total hash bytes.
pub fn hash_file(
    file: &File,
    start: u64,
    length: u64,
    block_size: u32,
    max_output: usize,
) -> Result<Vec<u8>, Error> {
    if block_size != 0 && block_size < MIN_BLOCK_SIZE {
        return Err(Error::BlockSizeTooSmall);
    }
    let meta = file.metadata()?;
    if !meta.file_type().is_file() {
        return Err(Error::NotRegularFile);
    }
    let size = meta.len();
    let end = if length == 0 {
        size
    } else {
        start.saturating_add(length).min(size)
    };
    let range = end.saturating_sub(start);

    let block = u64::from(block_size);
    let hashes = if block == 0 { 1 } else { range.div_ceil(block) };
    let output = hashes.saturating_mul(HASH_LEN as u64);
    if output > max_output as u64 {
        return Err(Error::TooManyBlocks);
    }

    let mut out = Vec::with_capacity(output as usize);
    let mut buf = vec![0u8; CHUNK.min(range.max(1) as usize)];
    let mut hasher = Sha256::new();
    let mut in_block = 0u64;
    let mut pos = start;
    while pos < end {
        let mut want = (end - pos).min(buf.len() as u64);
        if block != 0 {
            want = want.min(block - in_block);
        }
        let n = match file.read_at(&mut buf[..want as usize], pos) {
            Ok(0) => break, // the file shrank while we were reading it
            Ok(n) => n,
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        };
        hasher.update(&buf[..n]);
        pos += n as u64;
        in_block += n as u64;
        if block != 0 && in_block == block {
            out.extend_from_slice(&std::mem::take(&mut hasher).finalize());
            in_block = 0;
        }
    }
    // One hash for the whole range (even an empty one), or the last,
    // partial block.
    if block == 0 || in_block > 0 {
        out.extend_from_slice(&hasher.finalize());
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_file(data: &[u8]) -> (File, std::path::PathBuf) {
        let p = std::env::temp_dir().join(format!(
            "ferrisftp-checkfile-{}-{}",
            std::process::id(),
            data.len()
        ));
        std::fs::write(&p, data).unwrap();
        (File::open(&p).unwrap(), p)
    }

    #[test]
    fn known_vector() {
        let (f, p) = temp_file(b"abc");
        let got = hash_file(&f, 0, 0, 0, 1024).unwrap();
        let hex: String = got.iter().map(|x| format!("{x:02x}")).collect();
        assert_eq!(
            hex,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        std::fs::remove_file(p).unwrap();
    }

    #[test]
    fn only_sha256_is_accepted() {
        assert!(accepts_sha256(b"sha256"));
        assert!(accepts_sha256(b"md5, sha256 ,sha1"));
        for weak in [
            "md5",
            "sha1",
            "crc32",
            "md5,sha1,crc32",
            "sha224",
            "sha512",
            "",
        ] {
            assert!(!accepts_sha256(weak.as_bytes()), "{weak}");
        }
    }

    #[test]
    fn ranges_and_blocks() {
        let data: Vec<u8> = (0..1000u32).map(|i| (i * 31) as u8).collect();
        let (f, p) = temp_file(&data);
        let sha = |d: &[u8]| Sha256::digest(d).to_vec();

        assert_eq!(hash_file(&f, 0, 0, 0, 1024).unwrap(), sha(&data));
        assert_eq!(
            hash_file(&f, 10, 100, 0, 1024).unwrap(),
            sha(&data[10..110])
        );
        // Ranges past the end are clipped; a start past the end hashes
        // nothing.
        assert_eq!(
            hash_file(&f, 900, 5000, 0, 1024).unwrap(),
            sha(&data[900..])
        );
        assert_eq!(hash_file(&f, 5000, 0, 0, 1024).unwrap(), sha(b""));

        let blocks = hash_file(&f, 0, 0, 256, 1024).unwrap();
        let want: Vec<u8> = data.chunks(256).flat_map(sha).collect();
        assert_eq!(blocks, want);
        assert_eq!(blocks.len(), 4 * HASH_LEN);
        assert!(hash_file(&f, 5000, 0, 256, 1024).unwrap().is_empty());

        assert!(matches!(
            hash_file(&f, 0, 0, 255, 1024),
            Err(Error::BlockSizeTooSmall)
        ));
        assert!(matches!(
            hash_file(&f, 0, 0, 256, 100),
            Err(Error::TooManyBlocks)
        ));
        std::fs::remove_file(p).unwrap();
    }

    #[test]
    fn refuses_non_regular_files() {
        let dev = File::open("/dev/zero").unwrap();
        assert!(matches!(
            hash_file(&dev, 0, 0, 0, 1024),
            Err(Error::NotRegularFile)
        ));
        let dir = File::open("/").unwrap();
        assert!(matches!(
            hash_file(&dir, 0, 0, 0, 1024),
            Err(Error::NotRegularFile)
        ));
    }
}
