//! Server-side file hashing: the `check-file` extension
//! (draft-ietf-secsh-filexfer-extensions-00, section 3).
//!
//! The client names a file, a range and a list of acceptable algorithms,
//! and gets back one hash for the whole range or one per block, without
//! the data crossing the network.

use std::fs::File;
use std::io::{self, ErrorKind};
use std::os::unix::fs::FileExt;

use sha2::Digest;

/// Every algorithm the draft defines, in the order advertised.
pub const ALGORITHMS: &str = "md5,sha1,sha224,sha256,sha384,sha512,crc32";

/// The draft forbids block sizes below this (0 means "no blocks").
pub const MIN_BLOCK_SIZE: u32 = 256;

const CHUNK: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    Md5,
    Sha1,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
    Crc32,
}

impl Algorithm {
    fn from_name(name: &[u8]) -> Option<Self> {
        Some(match name {
            b"md5" => Algorithm::Md5,
            b"sha1" => Algorithm::Sha1,
            b"sha224" => Algorithm::Sha224,
            b"sha256" => Algorithm::Sha256,
            b"sha384" => Algorithm::Sha384,
            b"sha512" => Algorithm::Sha512,
            b"crc32" => Algorithm::Crc32,
            _ => return None,
        })
    }

    /// The first algorithm in a comma-separated list that we support, as
    /// the draft requires.
    pub fn select(list: &[u8]) -> Option<Self> {
        list.split(|&b| b == b',')
            .map(|name| name.trim_ascii())
            .find_map(Self::from_name)
    }

    pub fn name(self) -> &'static str {
        match self {
            Algorithm::Md5 => "md5",
            Algorithm::Sha1 => "sha1",
            Algorithm::Sha224 => "sha224",
            Algorithm::Sha256 => "sha256",
            Algorithm::Sha384 => "sha384",
            Algorithm::Sha512 => "sha512",
            Algorithm::Crc32 => "crc32",
        }
    }

    /// Bytes per hash.
    pub fn output_len(self) -> usize {
        match self {
            Algorithm::Md5 => 16,
            Algorithm::Sha1 => 20,
            Algorithm::Sha224 => 28,
            Algorithm::Sha256 => 32,
            Algorithm::Sha384 => 48,
            Algorithm::Sha512 => 64,
            Algorithm::Crc32 => 4,
        }
    }

    fn hasher(self) -> Hasher {
        match self {
            Algorithm::Md5 => Hasher::Md5(md5::Md5::new()),
            Algorithm::Sha1 => Hasher::Sha1(sha1::Sha1::new()),
            Algorithm::Sha224 => Hasher::Sha224(sha2::Sha224::new()),
            Algorithm::Sha256 => Hasher::Sha256(sha2::Sha256::new()),
            Algorithm::Sha384 => Hasher::Sha384(sha2::Sha384::new()),
            Algorithm::Sha512 => Hasher::Sha512(sha2::Sha512::new()),
            Algorithm::Crc32 => Hasher::Crc32(crc32fast::Hasher::new()),
        }
    }
}

enum Hasher {
    Md5(md5::Md5),
    Sha1(sha1::Sha1),
    Sha224(sha2::Sha224),
    Sha256(sha2::Sha256),
    Sha384(sha2::Sha384),
    Sha512(sha2::Sha512),
    Crc32(crc32fast::Hasher),
}

impl Hasher {
    fn update(&mut self, data: &[u8]) {
        match self {
            Hasher::Md5(h) => h.update(data),
            Hasher::Sha1(h) => h.update(data),
            Hasher::Sha224(h) => h.update(data),
            Hasher::Sha256(h) => h.update(data),
            Hasher::Sha384(h) => h.update(data),
            Hasher::Sha512(h) => h.update(data),
            Hasher::Crc32(h) => h.update(data),
        }
    }

    fn finish_into(self, out: &mut Vec<u8>) {
        match self {
            Hasher::Md5(h) => out.extend_from_slice(&h.finalize()),
            Hasher::Sha1(h) => out.extend_from_slice(&h.finalize()),
            Hasher::Sha224(h) => out.extend_from_slice(&h.finalize()),
            Hasher::Sha256(h) => out.extend_from_slice(&h.finalize()),
            Hasher::Sha384(h) => out.extend_from_slice(&h.finalize()),
            Hasher::Sha512(h) => out.extend_from_slice(&h.finalize()),
            // Big-endian, like the CRC-32 that zlib and cksum tools print.
            Hasher::Crc32(h) => out.extend_from_slice(&h.finalize().to_be_bytes()),
        }
    }
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

/// Hash `length` bytes of `file` from `start` (0 = up to end of file),
/// either as one hash or one per `block_size` bytes. The range is clipped
/// to the end of the file. `max_output` caps the total hash bytes.
pub fn hash_file(
    file: &File,
    algorithm: Algorithm,
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
    let output = hashes.saturating_mul(algorithm.output_len() as u64);
    if output > max_output as u64 {
        return Err(Error::TooManyBlocks);
    }

    let mut out = Vec::with_capacity(output as usize);
    let mut buf = vec![0u8; CHUNK.min(range.max(1) as usize)];
    let mut hasher = algorithm.hasher();
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
            std::mem::replace(&mut hasher, algorithm.hasher()).finish_into(&mut out);
            in_block = 0;
        }
    }
    // One hash for the whole range (even an empty one), or the last,
    // partial block.
    if block == 0 || in_block > 0 {
        hasher.finish_into(&mut out);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

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
    fn known_vectors() {
        let (f, p) = temp_file(b"abc");
        let cases = [
            (Algorithm::Md5, "900150983cd24fb0d6963f7d28e17f72"),
            (Algorithm::Sha1, "a9993e364706816aba3e25717850c26c9cd0d89d"),
            (
                Algorithm::Sha224,
                "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7",
            ),
            (
                Algorithm::Sha256,
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            ),
            (
                Algorithm::Sha384,
                "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed\
                 8086072ba1e7cc2358baeca134c825a7",
            ),
            (
                Algorithm::Sha512,
                "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
                 2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
            ),
            (Algorithm::Crc32, "352441c2"),
        ];
        for (alg, want) in cases {
            let got = hash_file(&f, alg, 0, 0, 0, 1024).unwrap();
            assert_eq!(hex(&got), want, "{}", alg.name());
            assert_eq!(got.len(), alg.output_len());
        }
        std::fs::remove_file(p).unwrap();
    }

    #[test]
    fn selection() {
        assert_eq!(Algorithm::select(b"sha256"), Some(Algorithm::Sha256));
        assert_eq!(
            Algorithm::select(b"whirlpool, sha512 ,md5"),
            Some(Algorithm::Sha512)
        );
        assert_eq!(Algorithm::select(b"whirlpool,blake3"), None);
        assert_eq!(Algorithm::select(b""), None);
        for name in ALGORITHMS.split(',') {
            assert_eq!(Algorithm::select(name.as_bytes()).unwrap().name(), name);
        }
    }

    #[test]
    fn ranges_and_blocks() {
        let data: Vec<u8> = (0..1000u32).map(|i| (i * 31) as u8).collect();
        let (f, p) = temp_file(&data);
        let sha = |d: &[u8]| sha2::Sha256::digest(d).to_vec();

        assert_eq!(
            hash_file(&f, Algorithm::Sha256, 0, 0, 0, 1024).unwrap(),
            sha(&data)
        );
        assert_eq!(
            hash_file(&f, Algorithm::Sha256, 10, 100, 0, 1024).unwrap(),
            sha(&data[10..110])
        );
        // Ranges past the end are clipped; a start past the end hashes
        // nothing.
        assert_eq!(
            hash_file(&f, Algorithm::Sha256, 900, 5000, 0, 1024).unwrap(),
            sha(&data[900..])
        );
        assert_eq!(
            hash_file(&f, Algorithm::Sha256, 5000, 0, 0, 1024).unwrap(),
            sha(b"")
        );

        let blocks = hash_file(&f, Algorithm::Sha256, 0, 0, 256, 1024).unwrap();
        let want: Vec<u8> = data.chunks(256).flat_map(sha).collect();
        assert_eq!(blocks, want);
        assert_eq!(blocks.len(), 4 * 32);
        assert!(
            hash_file(&f, Algorithm::Sha256, 5000, 0, 256, 1024)
                .unwrap()
                .is_empty()
        );

        assert!(matches!(
            hash_file(&f, Algorithm::Sha256, 0, 0, 255, 1024),
            Err(Error::BlockSizeTooSmall)
        ));
        assert!(matches!(
            hash_file(&f, Algorithm::Sha256, 0, 0, 256, 100),
            Err(Error::TooManyBlocks)
        ));
        std::fs::remove_file(p).unwrap();
    }

    #[test]
    fn refuses_non_regular_files() {
        let dev = File::open("/dev/zero").unwrap();
        assert!(matches!(
            hash_file(&dev, Algorithm::Md5, 0, 0, 0, 1024),
            Err(Error::NotRegularFile)
        ));
        let dir = File::open("/").unwrap();
        assert!(matches!(
            hash_file(&dir, Algorithm::Md5, 0, 0, 0, 1024),
            Err(Error::NotRegularFile)
        ));
    }
}
