//! Drives the server with real SFTP packets against a scratch directory.

mod common;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use common::*;
use ferrisftp::attrs::FileAttrs;
use ferrisftp::protocol::*;
use ferrisftp::wire::Writer;

#[test]
fn version_negotiation() {
    let mut s = Server::new();
    let mut out = Vec::new();
    let mut w = Writer::new(SSH_FXP_INIT);
    w.u32(6).u32(0); // v6 client; trailing bytes as if extensions followed
    s.process(&w.finish()[4..], &mut out).unwrap();
    assert_eq!(out[4], SSH_FXP_VERSION);
    assert_eq!(&out[5..9], &3u32.to_be_bytes());
}

#[test]
fn request_before_init_is_fatal() {
    let mut s = Server::new();
    let mut w = Writer::new(SSH_FXP_STAT);
    w.u32(1).string(b"/");
    assert!(s.process(&w.finish()[4..], &mut Vec::new()).is_err());
}

#[test]
fn duplicate_init_is_fatal() {
    let mut c = Client::new();
    let mut w = Writer::new(SSH_FXP_INIT);
    w.u32(3);
    assert!(c.raw(&w.finish()).is_err());
}

#[test]
fn write_then_read() {
    let t = TempDir::new();
    let p = t.path("f");
    let mut c = Client::new();

    let h = c
        .open(
            &p,
            SSH_FXF_WRITE | SSH_FXF_CREAT | SSH_FXF_TRUNC,
            perms(0o600),
        )
        .handle();
    assert_eq!(c.write(&h, 0, b"hello ").status(), SSH_FX_OK);
    assert_eq!(c.write(&h, 6, b"world").status(), SSH_FX_OK);
    assert_eq!(c.handle_op(SSH_FXP_CLOSE, &h).status(), SSH_FX_OK);
    assert_eq!(fs::read(&p).unwrap(), b"hello world");
    // umask may only clear bits; 0600 has nothing a normal umask removes.
    assert_eq!(
        fs::metadata(&p).unwrap().permissions().mode() & 0o777,
        0o600
    );

    let h = c.open(&p, SSH_FXF_READ, FileAttrs::default()).handle();
    assert_eq!(c.read(&h, 0, 5).data(), b"hello");
    assert_eq!(c.read(&h, 6, 100).data(), b"world");
    assert_eq!(c.read(&h, 11, 100).status(), SSH_FX_EOF);
    assert_eq!(c.handle_op(SSH_FXP_CLOSE, &h).status(), SSH_FX_OK);
    // Closed handles are gone.
    assert_eq!(c.read(&h, 0, 1).status(), SSH_FX_FAILURE);
}

#[test]
fn large_read_is_capped() {
    let t = TempDir::new();
    let p = t.path("big");
    fs::write(&p, vec![7u8; 512 * 1024]).unwrap();
    let mut c = Client::new();
    let h = c.open(&p, SSH_FXF_READ, FileAttrs::default()).handle();
    let data = c.read(&h, 0, u32::MAX).data();
    assert_eq!(data.len(), MAX_READ_LEN as usize);
}

#[test]
fn append_mode() {
    let t = TempDir::new();
    let p = t.path("log");
    fs::write(&p, b"one\n").unwrap();
    let mut c = Client::new();
    let h = c
        .open(&p, SSH_FXF_WRITE | SSH_FXF_APPEND, FileAttrs::default())
        .handle();
    assert_eq!(c.write(&h, 0, b"two\n").status(), SSH_FX_OK);
    c.handle_op(SSH_FXP_CLOSE, &h);
    assert_eq!(fs::read(&p).unwrap(), b"one\ntwo\n");
}

#[test]
fn open_errors() {
    let t = TempDir::new();
    let mut c = Client::new();
    assert_eq!(
        c.open(&t.path("missing"), SSH_FXF_READ, FileAttrs::default())
            .status(),
        SSH_FX_NO_SUCH_FILE
    );
    fs::write(t.path("exists"), b"").unwrap();
    assert_eq!(
        c.open(
            &t.path("exists"),
            SSH_FXF_WRITE | SSH_FXF_CREAT | SSH_FXF_EXCL,
            FileAttrs::default()
        )
        .status(),
        SSH_FX_FAILURE
    );
    // Create without write access is legal in SFTP.
    let h = c
        .open(
            &t.path("created"),
            SSH_FXF_READ | SSH_FXF_CREAT,
            FileAttrs::default(),
        )
        .handle();
    c.handle_op(SSH_FXP_CLOSE, &h);
    assert!(t.path("created").exists());
}

#[test]
fn stat_family_and_setstat() {
    let t = TempDir::new();
    let p = t.path("f");
    fs::write(&p, b"12345").unwrap();
    std::os::unix::fs::symlink("f", t.path("link")).unwrap();
    let mut c = Client::new();

    let a = c.path_op(SSH_FXP_STAT, &p).attrs();
    assert_eq!(a.size, Some(5));
    assert_eq!(a.permissions.unwrap() & 0o170000, 0o100000);

    let l = c.path_op(SSH_FXP_LSTAT, &t.path("link")).attrs();
    assert_eq!(l.permissions.unwrap() & 0o170000, 0o120000);
    let s = c.path_op(SSH_FXP_STAT, &t.path("link")).attrs();
    assert_eq!(s.size, Some(5));

    let set = FileAttrs {
        size: Some(2),
        permissions: Some(0o640),
        times: Some((1_000_000_000, 1_234_567_890)),
        ..Default::default()
    };
    let r = c.req(SSH_FXP_SETSTAT, |w| {
        w.string(p.as_os_str().as_encoded_bytes());
        set.encode(w);
    });
    assert_eq!(r.status(), SSH_FX_OK);
    let a = c.path_op(SSH_FXP_STAT, &p).attrs();
    assert_eq!(a.size, Some(2));
    assert_eq!(a.permissions.unwrap() & 0o7777, 0o640);
    assert_eq!(a.times, Some((1_000_000_000, 1_234_567_890)));

    let h = c.open(&p, SSH_FXF_WRITE, FileAttrs::default()).handle();
    let set = FileAttrs {
        size: Some(0),
        permissions: Some(0o600),
        times: Some((5, 6)),
        ..Default::default()
    };
    let r = c.req(SSH_FXP_FSETSTAT, |w| {
        w.string(&h);
        set.encode(w);
    });
    assert_eq!(r.status(), SSH_FX_OK);
    let a = c.handle_op(SSH_FXP_FSTAT, &h).attrs();
    assert_eq!(a.size, Some(0));
    assert_eq!(a.permissions.unwrap() & 0o7777, 0o600);
    assert_eq!(a.times, Some((5, 6)));

    assert_eq!(
        c.path_op(SSH_FXP_STAT, &t.path("nope")).status(),
        SSH_FX_NO_SUCH_FILE
    );
}

#[test]
fn directories() {
    let t = TempDir::new();
    let d = t.path("dir");
    let mut c = Client::new();

    assert_eq!(
        c.req(SSH_FXP_MKDIR, |w| {
            w.string(d.as_os_str().as_encoded_bytes());
            perms(0o750).encode(w);
        })
        .status(),
        SSH_FX_OK
    );
    assert_eq!(
        fs::metadata(&d).unwrap().permissions().mode() & 0o777,
        0o750
    );

    for i in 0..250 {
        fs::write(d.join(format!("file{i:03}")), b"x").unwrap();
    }

    let h = c.path_op(SSH_FXP_OPENDIR, &d).handle();
    let mut seen = Vec::new();
    loop {
        let r = c.handle_op(SSH_FXP_READDIR, &h);
        if r.try_status() == Some(SSH_FX_EOF) {
            break;
        }
        let batch = r.names();
        assert!(batch.len() <= READDIR_BATCH);
        for (name, long, attrs) in batch {
            let long = String::from_utf8(long).unwrap();
            assert!(long.ends_with(std::str::from_utf8(&name).unwrap()));
            assert!(attrs.permissions.is_some());
            seen.push(String::from_utf8(name).unwrap());
        }
    }
    c.handle_op(SSH_FXP_CLOSE, &h);
    assert_eq!(seen.len(), 252);
    assert!(seen.contains(&".".into()) && seen.contains(&"..".into()));
    assert!(seen.contains(&"file249".into()));

    // READDIR on a file handle is rejected.
    fs::write(t.path("plain"), b"").unwrap();
    let fh = c
        .open(&t.path("plain"), SSH_FXF_READ, FileAttrs::default())
        .handle();
    assert_eq!(c.handle_op(SSH_FXP_READDIR, &fh).status(), SSH_FX_FAILURE);

    // Non-empty rmdir fails; after cleanup it works.
    assert_eq!(c.path_op(SSH_FXP_RMDIR, &d).status(), SSH_FX_FAILURE);
    for i in 0..250 {
        let f = d.join(format!("file{i:03}"));
        assert_eq!(c.path_op(SSH_FXP_REMOVE, &f).status(), SSH_FX_OK);
    }
    assert_eq!(c.path_op(SSH_FXP_RMDIR, &d).status(), SSH_FX_OK);
    assert!(!d.exists());

    assert_eq!(
        c.path_op(SSH_FXP_OPENDIR, &t.path("missing")).status(),
        SSH_FX_NO_SUCH_FILE
    );
}

#[test]
fn rename_does_not_overwrite() {
    let t = TempDir::new();
    let (a, b, c_) = (t.path("a"), t.path("b"), t.path("c"));
    fs::write(&a, b"A").unwrap();
    fs::write(&b, b"B").unwrap();
    let mut c = Client::new();

    assert_eq!(c.two_paths(SSH_FXP_RENAME, &a, &b).status(), SSH_FX_FAILURE);
    assert_eq!(fs::read(&b).unwrap(), b"B");
    assert_eq!(c.two_paths(SSH_FXP_RENAME, &a, &c_).status(), SSH_FX_OK);
    assert!(!a.exists());
    assert_eq!(fs::read(&c_).unwrap(), b"A");

    // Directories take the non-link path.
    fs::create_dir(t.path("d1")).unwrap();
    assert_eq!(
        c.two_paths(SSH_FXP_RENAME, &t.path("d1"), &t.path("d2"))
            .status(),
        SSH_FX_OK
    );
    assert!(t.path("d2").is_dir());
}

#[test]
fn symlink_uses_openssh_argument_order() {
    let t = TempDir::new();
    let mut c = Client::new();
    // target first, link path second
    let r = c.req(SSH_FXP_SYMLINK, |w| {
        w.string(b"some/target")
            .string(t.path("ln").as_os_str().as_encoded_bytes());
    });
    assert_eq!(r.status(), SSH_FX_OK);
    assert_eq!(
        fs::read_link(t.path("ln")).unwrap(),
        PathBuf::from("some/target")
    );
    let names = c.path_op(SSH_FXP_READLINK, &t.path("ln")).names();
    assert_eq!(names[0].0, b"some/target");
}

#[test]
fn realpath() {
    let t = TempDir::new();
    fs::create_dir(t.path("sub")).unwrap();
    let canon = fs::canonicalize(&t.0).unwrap();
    let mut c = Client::new();

    let dotted = t.0.join("sub/../sub");
    let names = c.path_op(SSH_FXP_REALPATH, &dotted).names();
    assert_eq!(names.len(), 1);
    assert_eq!(
        Path::new(std::str::from_utf8(&names[0].0).unwrap()),
        canon.join("sub")
    );

    // Non-existent final component resolves via its parent.
    let names = c.path_op(SSH_FXP_REALPATH, &t.path("sub/new.txt")).names();
    assert_eq!(
        Path::new(std::str::from_utf8(&names[0].0).unwrap()),
        canon.join("sub/new.txt")
    );

    // Empty path is the working directory.
    let names = c.path_op(SSH_FXP_REALPATH, Path::new("")).names();
    assert_eq!(
        Path::new(std::str::from_utf8(&names[0].0).unwrap()),
        std::env::current_dir().unwrap()
    );
}

#[test]
fn bad_requests() {
    let mut c = Client::new();
    // Truncated body after the id → BAD_MESSAGE, session continues.
    let r = c.req(SSH_FXP_OPEN, |w| {
        w.u32(1000); // string length with no bytes behind it
    });
    assert_eq!(r.status(), SSH_FX_BAD_MESSAGE);
    // Unknown handle.
    assert_eq!(c.handle_op(SSH_FXP_CLOSE, b"nope").status(), SSH_FX_FAILURE);
    // Unknown extension.
    let r = c.req(SSH_FXP_EXTENDED, |w| {
        w.string(b"nonexistent@example.com").string(b"/");
    });
    assert_eq!(r.status(), SSH_FX_OP_UNSUPPORTED);
    // Unknown packet type.
    assert_eq!(c.req(99, |_| {}).status(), SSH_FX_OP_UNSUPPORTED);
    // Still alive.
    assert_eq!(
        c.path_op(SSH_FXP_STAT, Path::new("/"))
            .attrs()
            .permissions
            .unwrap()
            & 0o170000,
        0o040000
    );
}
