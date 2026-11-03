//! Three-stage I/O pipeline: one thread reads requests from stdin, the
//! calling thread executes them in order, and one thread writes replies to
//! stdout.
//!
//! Requests are still executed strictly one after another, so ordering
//! semantics are identical to a single-threaded server. What the threads
//! buy is overlap: while one request waits on the disk, the next requests
//! are already being read and earlier replies are being written.
//!
//! Both queues are bounded, so memory stays capped no matter how many
//! requests the client keeps in flight. When the work queue is full the
//! reader stops reading stdin, and backpressure flows to the client
//! through the SSH channel window.

use std::io::{self, BufReader, BufWriter, ErrorKind, Read, Write};
use std::sync::mpsc::{Receiver, SyncSender, TryRecvError, sync_channel};
use std::sync::{Arc, Mutex};
use std::thread;

use crate::protocol::MAX_PACKET_LEN;
use crate::server::{Fatal, Server};

/// Requests buffered between the reader and the executor, and replies
/// buffered between the executor and the writer. With packets of at most
/// 256 KiB each, the queues hold at most ~4 MiB in the worst case.
const QUEUE_DEPTH: usize = 8;

/// Packet buffers kept for reuse. Large buffers would otherwise be
/// allocated and freed (via mmap/munmap with musl) for every request.
const POOL_SIZE: usize = 2 * QUEUE_DEPTH + 4;

/// Stack size for the I/O threads; they do little beyond read/write calls.
const IO_STACK: usize = 64 * 1024;

#[derive(Default)]
struct BufferPool(Mutex<Vec<Vec<u8>>>);

impl BufferPool {
    fn get(&self) -> Vec<u8> {
        self.0
            .lock()
            .ok()
            .and_then(|mut v| v.pop())
            .unwrap_or_default()
    }

    fn put(&self, mut buf: Vec<u8>) {
        buf.clear();
        if let Ok(mut v) = self.0.lock()
            && v.len() < POOL_SIZE
        {
            v.push(buf);
        }
    }
}

fn invalid(f: Fatal) -> io::Error {
    io::Error::new(ErrorKind::InvalidData, f)
}

/// Read framed packets from `input` and queue their bodies. Returns when
/// the input ends, a read fails, or the executor has gone away.
fn read_loop<R: Read>(input: R, tx: SyncSender<Vec<u8>>, pool: &BufferPool) -> io::Result<()> {
    let mut input = BufReader::with_capacity(64 * 1024, input);
    loop {
        let mut len = [0u8; 4];
        match input.read_exact(&mut len) {
            Ok(()) => {}
            Err(e) if e.kind() == ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e),
        }
        let len = u32::from_be_bytes(len);
        if len == 0 || len > MAX_PACKET_LEN {
            return Err(invalid(Fatal("invalid packet length")));
        }
        let mut packet = pool.get();
        packet.resize(len as usize, 0);
        input.read_exact(&mut packet)?;
        if tx.send(packet).is_err() {
            return Ok(());
        }
    }
}

/// Write queued replies to `output`. Replies that are already queued are
/// batched into one write; the buffer is flushed whenever the queue runs
/// dry, so a reply never sits unsent while the client waits for it.
fn write_loop<W: Write>(output: W, rx: Receiver<Vec<u8>>, pool: &BufferPool) -> io::Result<()> {
    let mut output = BufWriter::with_capacity(64 * 1024, output);
    let mut next = rx.recv().ok();
    while let Some(reply) = next.take() {
        output.write_all(&reply)?;
        pool.put(reply);
        next = match rx.try_recv() {
            Ok(r) => Some(r),
            Err(TryRecvError::Empty) => {
                output.flush()?;
                rx.recv().ok()
            }
            Err(TryRecvError::Disconnected) => None,
        };
    }
    output.flush()
}

impl Server {
    /// Serve one session until the client closes the stream.
    ///
    /// The streams are moved to the I/O threads, hence the `'static`
    /// bounds; stdin/stdout and in-memory buffers both satisfy them.
    pub fn run<R, W>(&mut self, input: R, output: W) -> io::Result<()>
    where
        R: Read + Send + 'static,
        W: Write + Send + 'static,
    {
        let pool = Arc::new(BufferPool::default());
        let (req_tx, req_rx) = sync_channel::<Vec<u8>>(QUEUE_DEPTH);
        let (rep_tx, rep_rx) = sync_channel::<Vec<u8>>(QUEUE_DEPTH);

        let reader = {
            let pool = Arc::clone(&pool);
            thread::Builder::new()
                .name("reader".into())
                .stack_size(IO_STACK)
                .spawn(move || read_loop(input, req_tx, &pool))?
        };
        let writer = {
            let pool = Arc::clone(&pool);
            thread::Builder::new()
                .name("writer".into())
                .stack_size(IO_STACK)
                .spawn(move || write_loop(output, rep_rx, &pool))?
        };

        let mut result = Ok(());
        for packet in req_rx.iter() {
            let mut reply = pool.get();
            if let Err(f) = self.process(&packet, &mut reply) {
                result = Err(invalid(f));
                break;
            }
            pool.put(packet);
            if rep_tx.send(reply).is_err() {
                break; // the writer failed; its error is reported below
            }
        }
        // Closing the reply queue lets the writer send what is queued and
        // exit. Closing the request queue stops the reader at its next
        // packet.
        drop(rep_tx);
        drop(req_rx);

        let written = joined(writer);
        if result.is_err() || written.is_err() {
            // The reader may be blocked in read(2) on stdin, which cannot
            // be interrupted. Leave it; the process exits right after.
            return result.and(written);
        }
        // The loop above only ends without error once the reader has
        // closed its side, so this join returns promptly.
        joined(reader).and(written)
    }
}

fn joined(handle: thread::JoinHandle<io::Result<()>>) -> io::Result<()> {
    handle
        .join()
        .unwrap_or_else(|_| Err(io::Error::other("I/O thread panicked")))
}
