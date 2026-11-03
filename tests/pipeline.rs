//! End-to-end tests of `Server::run`: framing, ordering and shutdown.

mod common;

use std::fs;
use std::io::{Cursor, Write};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use common::*;
use ferrisftp::attrs::FileAttrs;
use ferrisftp::protocol::*;
use ferrisftp::wire::{Reader, Writer};

fn run(input: Vec<u8>) -> (std::io::Result<()>, Vec<(u8, Vec<u8>)>) {
    let out = SharedBuf::default();
    let result = Server::new().run(Cursor::new(input), out.clone());
    (result, split_packets(&out.take()))
}

fn reply_id(body: &[u8]) -> u32 {
    Reader::new(body).u32().unwrap()
}

#[test]
fn replies_in_request_order() {
    let mut input = init_packet();
    for id in 1..=500 {
        let mut w = Writer::new(SSH_FXP_STAT);
        w.u32(id).string(b"/");
        input.extend(w.finish());
    }
    let (result, replies) = run(input);
    result.unwrap();
    assert_eq!(replies.len(), 501);
    assert_eq!(replies[0].0, SSH_FXP_VERSION);
    for (i, (kind, body)) in replies[1..].iter().enumerate() {
        assert_eq!(*kind, SSH_FXP_ATTRS);
        assert_eq!(reply_id(body), i as u32 + 1);
    }
}

#[test]
fn pipelined_write_then_read_back() {
    // A client that pipelines an entire upload and read-back without
    // waiting for any reply must still see its writes.
    let t = TempDir::new();
    let path = t.path("f");
    let data: Vec<u8> = (0..1_000_000u32).map(|i| (i * 7) as u8).collect();
    let chunk = 32 * 1024;
    // Handle ids are allocated from 0, so the first OPEN returns handle 0.
    let h = 0u32.to_be_bytes();

    let mut input = init_packet();
    let mut id = 1;
    let mut push = |w: &mut Writer| {
        input.extend(std::mem::replace(w, Writer::new(0)).finish());
    };
    let mut w = Writer::new(SSH_FXP_OPEN);
    w.u32(id).string(path.as_os_str().as_encoded_bytes());
    w.u32(SSH_FXF_READ | SSH_FXF_WRITE | SSH_FXF_CREAT);
    FileAttrs::default().encode(&mut w);
    push(&mut w);
    for (n, part) in data.chunks(chunk).enumerate() {
        id += 1;
        let mut w = Writer::new(SSH_FXP_WRITE);
        w.u32(id).string(&h).u64((n * chunk) as u64).string(part);
        push(&mut w);
    }
    for n in 0..data.len().div_ceil(chunk) {
        id += 1;
        let mut w = Writer::new(SSH_FXP_READ);
        w.u32(id)
            .string(&h)
            .u64((n * chunk) as u64)
            .u32(chunk as u32);
        push(&mut w);
    }

    let (result, replies) = run(input);
    result.unwrap();
    assert_eq!(replies[1].0, SSH_FXP_HANDLE);
    let mut back = Vec::new();
    for (kind, body) in &replies[2..] {
        match *kind {
            SSH_FXP_STATUS => {
                let mut r = Reader::new(body);
                r.u32().unwrap();
                assert_eq!(r.u32().unwrap(), SSH_FX_OK);
            }
            SSH_FXP_DATA => {
                let mut r = Reader::new(body);
                r.u32().unwrap();
                back.extend_from_slice(r.string().unwrap());
            }
            other => panic!("unexpected reply type {other}"),
        }
    }
    assert_eq!(back, data);
    assert_eq!(fs::read(&path).unwrap(), data);
}

#[test]
fn oversized_packet_ends_session() {
    let mut input = init_packet();
    input.extend((MAX_PACKET_LEN + 1).to_be_bytes());
    let (result, replies) = run(input);
    assert!(result.is_err());
    // The VERSION reply was still delivered.
    assert_eq!(replies.len(), 1);
}

#[test]
fn replies_before_a_fatal_error_are_delivered() {
    let mut input = init_packet();
    let mut w = Writer::new(SSH_FXP_STAT);
    w.u32(1).string(b"/");
    input.extend(w.finish());
    input.extend(init_packet()); // duplicate INIT is fatal
    let (result, replies) = run(input);
    assert!(result.is_err());
    let kinds: Vec<u8> = replies.iter().map(|r| r.0).collect();
    assert_eq!(kinds, [SSH_FXP_VERSION, SSH_FXP_ATTRS]);
}

#[test]
fn fatal_error_does_not_wait_for_open_input() {
    // The client keeps the stream open after sending a fatal request. The
    // server must end the session instead of blocking on the next read.
    let (reader, mut writer) = std::io::pipe().unwrap();
    writer.write_all(&init_packet()).unwrap();
    writer.write_all(&init_packet()).unwrap();

    let (done_tx, done_rx) = mpsc::channel();
    thread::spawn(move || {
        let result = Server::new().run(reader, SharedBuf::default());
        done_tx.send(result.is_err()).unwrap();
    });
    let failed = done_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("run() hung");
    assert!(failed);
    drop(writer);
}

#[test]
fn clean_eof() {
    let (result, replies) = run(init_packet());
    result.unwrap();
    assert_eq!(replies.len(), 1);
    let (result, replies) = run(Vec::new());
    result.unwrap();
    assert!(replies.is_empty());
}
