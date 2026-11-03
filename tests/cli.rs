//! Runs the ferrisftp binary with command-line options and checks their
//! effect on a real session.

mod common;

use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Output, Stdio};

use common::*;
use ferrisftp::attrs::FileAttrs;
use ferrisftp::protocol::*;
use ferrisftp::wire::{Reader, Writer};

const BIN: &str = env!("CARGO_BIN_EXE_ferrisftp");

/// Run the binary with `args`, feed it INIT plus `requests`, and return
/// the (type, body) replies after VERSION.
fn session(args: &[&str], requests: Vec<Vec<u8>>) -> Vec<(u8, Vec<u8>)> {
    let mut child = Command::new(BIN)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all(&init_packet()).unwrap();
    for r in requests {
        stdin.write_all(&r).unwrap();
    }
    drop(stdin);
    let out = child.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let mut replies = split_packets(&out.stdout);
    assert_eq!(replies.remove(0).0, SSH_FXP_VERSION);
    replies
}

fn run(args: &[&str]) -> Output {
    Command::new(BIN).args(args).output().unwrap()
}

fn status(reply: &(u8, Vec<u8>)) -> u32 {
    assert_eq!(reply.0, SSH_FXP_STATUS);
    let mut r = Reader::new(&reply.1);
    r.u32().unwrap();
    r.u32().unwrap()
}

fn path_req(kind: u8, id: u32, path: &Path) -> Vec<u8> {
    let mut w = Writer::new(kind);
    w.u32(id).string(path.as_os_str().as_encoded_bytes());
    w.finish()
}

fn open_req(id: u32, path: &Path, pflags: u32, mode: Option<u32>) -> Vec<u8> {
    let mut w = Writer::new(SSH_FXP_OPEN);
    w.u32(id)
        .string(path.as_os_str().as_encoded_bytes())
        .u32(pflags);
    FileAttrs {
        permissions: mode,
        ..Default::default()
    }
    .encode(&mut w);
    w.finish()
}

#[test]
fn help_version_and_requests() {
    let out = run(&["-h"]);
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("-R"));

    let out = run(&["-V"]);
    assert!(String::from_utf8_lossy(&out.stdout).starts_with("ferrisftp "));

    let out = run(&["-Q", "requests"]);
    let names = String::from_utf8(out.stdout).unwrap();
    assert!(names.lines().any(|l| l == "posix-rename"));
    assert!(names.lines().any(|l| l == "open"));
}

#[test]
fn bad_options_exit_with_usage() {
    for args in [
        &["-x"][..],
        &["-u", "888"],
        &["-P", "frobnicate"],
        &["stray"],
    ] {
        let out = run(args);
        assert_eq!(out.status.code(), Some(2), "{args:?}");
        assert!(String::from_utf8_lossy(&out.stderr).contains("usage:"));
    }
}

#[test]
fn read_only_mode() {
    let t = TempDir::new();
    fs::write(t.path("existing"), b"data").unwrap();
    let replies = session(
        &["-R"],
        vec![
            open_req(1, &t.path("new"), SSH_FXF_WRITE | SSH_FXF_CREAT, None),
            open_req(2, &t.path("existing"), SSH_FXF_READ | SSH_FXF_TRUNC, None),
            path_req(SSH_FXP_REMOVE, 3, &t.path("existing")),
            path_req(SSH_FXP_MKDIR, 4, &t.path("dir")),
            path_req(SSH_FXP_STAT, 5, &t.path("existing")),
            open_req(6, &t.path("existing"), SSH_FXF_READ, None),
        ],
    );
    for r in &replies[..4] {
        assert_eq!(status(r), SSH_FX_PERMISSION_DENIED);
    }
    assert_eq!(replies[4].0, SSH_FXP_ATTRS);
    assert_eq!(replies[5].0, SSH_FXP_HANDLE);
    assert!(!t.path("new").exists());
    assert_eq!(fs::read(t.path("existing")).unwrap(), b"data");
}

#[test]
fn deny_and_allow_lists() {
    let t = TempDir::new();
    fs::write(t.path("f"), b"").unwrap();
    let replies = session(
        &["-P", "remove,mkdir"],
        vec![
            path_req(SSH_FXP_REMOVE, 1, &t.path("f")),
            path_req(SSH_FXP_STAT, 2, &t.path("f")),
        ],
    );
    assert_eq!(status(&replies[0]), SSH_FX_PERMISSION_DENIED);
    assert_eq!(replies[1].0, SSH_FXP_ATTRS);

    let replies = session(
        &["-p", "stat"],
        vec![
            path_req(SSH_FXP_STAT, 1, &t.path("f")),
            path_req(SSH_FXP_LSTAT, 2, &t.path("f")),
        ],
    );
    assert_eq!(replies[0].0, SSH_FXP_ATTRS);
    assert_eq!(status(&replies[1]), SSH_FX_PERMISSION_DENIED);
}

#[test]
fn start_directory() {
    let t = TempDir::new();
    let replies = session(
        &["-d", t.0.to_str().unwrap()],
        vec![path_req(SSH_FXP_REALPATH, 1, Path::new("."))],
    );
    let mut r = Reader::new(&replies[0].1);
    r.u32().unwrap();
    assert_eq!(r.u32().unwrap(), 1);
    assert_eq!(
        Path::new(std::str::from_utf8(r.string().unwrap()).unwrap()),
        fs::canonicalize(&t.0).unwrap()
    );
}

#[test]
fn unusable_start_directory_is_not_fatal() {
    let replies = session(
        &["-d", "/nonexistent/ferrisftp"],
        vec![path_req(SSH_FXP_STAT, 1, Path::new("/"))],
    );
    assert_eq!(replies[0].0, SSH_FXP_ATTRS);
}

#[test]
fn explicit_umask() {
    let t = TempDir::new();
    let p = t.path("f");
    let mut close = Writer::new(SSH_FXP_CLOSE);
    close.u32(2).string(&0u32.to_be_bytes());
    let replies = session(
        &["-u", "077"],
        vec![
            open_req(1, &p, SSH_FXF_WRITE | SSH_FXF_CREAT, Some(0o666)),
            close.finish(),
        ],
    );
    assert_eq!(replies[0].0, SSH_FXP_HANDLE);
    assert_eq!(
        fs::metadata(&p).unwrap().permissions().mode() & 0o777,
        0o600
    );
}
