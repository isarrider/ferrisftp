//! Test client that drives the server with real SFTP packets.

#![allow(dead_code)]

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

pub use ferrisftp::Server;
use ferrisftp::attrs::FileAttrs;
use ferrisftp::protocol::*;
use ferrisftp::wire::{Reader, Writer};

pub struct TempDir(pub PathBuf);

impl TempDir {
    pub fn new() -> Self {
        static N: AtomicU32 = AtomicU32::new(0);
        let p = std::env::temp_dir().join(format!(
            "ferrisftp-test-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&p).unwrap();
        TempDir(p)
    }

    pub fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// One decoded reply: packet type and body (request id included).
pub struct Reply {
    pub kind: u8,
    pub body: Vec<u8>,
}

impl Reply {
    pub fn reader(&self) -> Reader<'_> {
        let mut r = Reader::new(&self.body);
        r.u32().unwrap(); // request id
        r
    }

    pub fn status(&self) -> u32 {
        assert_eq!(self.kind, SSH_FXP_STATUS, "expected STATUS");
        self.reader().u32().unwrap()
    }

    pub fn handle(&self) -> Vec<u8> {
        assert_eq!(
            self.kind,
            SSH_FXP_HANDLE,
            "expected HANDLE, got status {:?}",
            self.try_status()
        );
        self.reader().string().unwrap().to_vec()
    }

    pub fn data(&self) -> Vec<u8> {
        assert_eq!(self.kind, SSH_FXP_DATA, "expected DATA");
        self.reader().string().unwrap().to_vec()
    }

    pub fn attrs(&self) -> FileAttrs {
        assert_eq!(
            self.kind,
            SSH_FXP_ATTRS,
            "expected ATTRS, got status {:?}",
            self.try_status()
        );
        FileAttrs::decode(&mut self.reader()).unwrap()
    }

    pub fn names(&self) -> Vec<(Vec<u8>, Vec<u8>, FileAttrs)> {
        assert_eq!(
            self.kind,
            SSH_FXP_NAME,
            "expected NAME, got status {:?}",
            self.try_status()
        );
        let mut r = self.reader();
        let n = r.u32().unwrap();
        (0..n)
            .map(|_| {
                let name = r.string().unwrap().to_vec();
                let long = r.string().unwrap().to_vec();
                (name, long, FileAttrs::decode(&mut r).unwrap())
            })
            .collect()
    }

    pub fn try_status(&self) -> Option<u32> {
        (self.kind == SSH_FXP_STATUS).then(|| self.reader().u32().unwrap())
    }
}

pub struct Client {
    pub server: Server,
    pub next_id: u32,
}

impl Client {
    pub fn new() -> Self {
        let mut c = Client {
            server: Server::new(),
            next_id: 1,
        };
        let mut w = Writer::new(SSH_FXP_INIT);
        w.u32(3);
        let reply = c.raw(&w.finish()).unwrap();
        assert_eq!(reply.kind, SSH_FXP_VERSION);
        c
    }

    /// Send one framed packet, return the single reply.
    pub fn raw(&mut self, framed: &[u8]) -> Result<Reply, ferrisftp::server::Fatal> {
        let mut out = Vec::new();
        self.server.process(&framed[4..], &mut out)?;
        let len = u32::from_be_bytes(out[..4].try_into().unwrap()) as usize;
        assert_eq!(len + 4, out.len(), "exactly one reply");
        Ok(Reply {
            kind: out[4],
            body: out[5..].to_vec(),
        })
    }

    /// Build a request with a fresh id; `f` appends the body after the id.
    pub fn req(&mut self, kind: u8, f: impl FnOnce(&mut Writer)) -> Reply {
        let id = self.next_id;
        self.next_id += 1;
        let mut w = Writer::new(kind);
        w.u32(id);
        f(&mut w);
        let reply = self.raw(&w.finish()).unwrap();
        assert_eq!(
            reply.body[..4],
            id.to_be_bytes(),
            "reply carries request id"
        );
        reply
    }

    pub fn open(&mut self, path: &Path, pflags: u32, attrs: FileAttrs) -> Reply {
        self.req(SSH_FXP_OPEN, |w| {
            w.string(path.as_os_str().as_encoded_bytes()).u32(pflags);
            attrs.encode(w);
        })
    }

    pub fn path_op(&mut self, kind: u8, path: &Path) -> Reply {
        self.req(kind, |w| {
            w.string(path.as_os_str().as_encoded_bytes());
        })
    }

    pub fn handle_op(&mut self, kind: u8, handle: &[u8]) -> Reply {
        self.req(kind, |w| {
            w.string(handle);
        })
    }

    pub fn write(&mut self, handle: &[u8], offset: u64, data: &[u8]) -> Reply {
        self.req(SSH_FXP_WRITE, |w| {
            w.string(handle).u64(offset).string(data);
        })
    }

    pub fn read(&mut self, handle: &[u8], offset: u64, len: u32) -> Reply {
        self.req(SSH_FXP_READ, |w| {
            w.string(handle).u64(offset).u32(len);
        })
    }

    /// An SSH_FXP_EXTENDED request; `f` appends the request-specific data.
    pub fn ext(&mut self, name: &str, f: impl FnOnce(&mut Writer)) -> Reply {
        self.req(SSH_FXP_EXTENDED, |w| {
            w.string(name.as_bytes());
            f(w);
        })
    }

    pub fn two_paths(&mut self, kind: u8, a: &Path, b: &Path) -> Reply {
        self.req(kind, |w| {
            w.string(a.as_os_str().as_encoded_bytes())
                .string(b.as_os_str().as_encoded_bytes());
        })
    }
}

pub fn perms(mode: u32) -> FileAttrs {
    FileAttrs {
        permissions: Some(mode),
        ..Default::default()
    }
}

/// A `'static` output sink for `Server::run` whose contents the test can
/// read afterwards.
#[derive(Clone, Default)]
pub struct SharedBuf(pub Arc<Mutex<Vec<u8>>>);

impl SharedBuf {
    pub fn take(&self) -> Vec<u8> {
        std::mem::take(&mut self.0.lock().unwrap())
    }
}

impl Write for SharedBuf {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Split a byte stream of framed packets into (type, body) pairs.
pub fn split_packets(stream: &[u8]) -> Vec<(u8, Vec<u8>)> {
    let mut r = Reader::new(stream);
    let mut out = Vec::new();
    while r.remaining() > 0 {
        let p = r.string().unwrap();
        out.push((p[0], p[1..].to_vec()));
    }
    out
}

pub fn init_packet() -> Vec<u8> {
    let mut w = Writer::new(SSH_FXP_INIT);
    w.u32(3);
    w.finish()
}
