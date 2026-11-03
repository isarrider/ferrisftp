//! Tests for the OpenSSH protocol extensions.

mod common;

use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use common::*;
use ferrisftp::attrs::FileAttrs;
use ferrisftp::protocol::*;
use ferrisftp::wire::{Reader, Writer};

fn bytes(p: &Path) -> &[u8] {
    p.as_os_str().as_encoded_bytes()
}

fn name_path(r: &Reply) -> PathBuf {
    let names = r.names();
    assert_eq!(names.len(), 1);
    PathBuf::from(String::from_utf8(names[0].0.clone()).unwrap())
}

/// Body of an EXTENDED_REPLY after the request id.
fn ext_reply(r: &Reply) -> Reader<'_> {
    assert_eq!(
        r.kind,
        SSH_FXP_EXTENDED_REPLY,
        "expected EXTENDED_REPLY, got status {:?}",
        r.try_status()
    );
    r.reader()
}

#[test]
fn version_advertises_extensions() {
    let mut s = Server::new();
    let mut out = Vec::new();
    let mut w = Writer::new(SSH_FXP_INIT);
    w.u32(3);
    s.process(&w.finish()[4..], &mut out).unwrap();
    let mut r = Reader::new(&out[5..]);
    assert_eq!(r.u32().unwrap(), 3);
    let mut names = Vec::new();
    while r.remaining() > 0 {
        names.push(String::from_utf8(r.string().unwrap().to_vec()).unwrap());
        r.string().unwrap();
    }
    for expected in [
        "posix-rename@openssh.com",
        "statvfs@openssh.com",
        "fstatvfs@openssh.com",
        "hardlink@openssh.com",
        "fsync@openssh.com",
        "lsetstat@openssh.com",
        "limits@openssh.com",
        "expand-path@openssh.com",
        "copy-data",
        "home-directory",
        "users-groups-by-id@openssh.com",
    ] {
        assert!(names.iter().any(|n| n == expected), "missing {expected}");
    }
}

/// Extension data advertised in VERSION, by name.
fn version_extension(name: &str) -> Vec<u8> {
    let mut s = Server::new();
    let mut out = Vec::new();
    s.process(&init_packet()[4..], &mut out).unwrap();
    let mut r = Reader::new(&out[5..]);
    r.u32().unwrap();
    while r.remaining() > 0 {
        let n = r.string().unwrap();
        let data = r.string().unwrap();
        if n == name.as_bytes() {
            return data.to_vec();
        }
    }
    panic!("{name} not advertised");
}

#[test]
fn vendor_id() {
    let data = version_extension("vendor-id");
    let mut r = Reader::new(&data);
    assert_eq!(r.string().unwrap(), b"isarrider");
    assert_eq!(r.string().unwrap(), b"ferrisftp");
    assert_eq!(r.string().unwrap(), env!("CARGO_PKG_VERSION").as_bytes());
    r.u64().unwrap();
    assert_eq!(r.remaining(), 0);
}

#[test]
fn symlink_order_matches_behaviour() {
    assert_eq!(
        version_extension("symlink-order@rjk.greenend.org.uk"),
        b"targetpath-linkpath"
    );
    // ...and SYMLINK really takes the target first.
    let t = TempDir::new();
    let mut c = Client::new();
    let r = c.req(SSH_FXP_SYMLINK, |w| {
        w.string(b"the-target").string(bytes(&t.path("the-link")));
    });
    assert_eq!(r.status(), SSH_FX_OK);
    assert_eq!(
        fs::read_link(t.path("the-link")).unwrap(),
        PathBuf::from("the-target")
    );
}

#[test]
fn posix_rename_overwrites() {
    let t = TempDir::new();
    fs::write(t.path("a"), b"A").unwrap();
    fs::write(t.path("b"), b"B").unwrap();
    let mut c = Client::new();
    let r = c.ext("posix-rename@openssh.com", |w| {
        w.string(bytes(&t.path("a"))).string(bytes(&t.path("b")));
    });
    assert_eq!(r.status(), SSH_FX_OK);
    assert!(!t.path("a").exists());
    assert_eq!(fs::read(t.path("b")).unwrap(), b"A");
}

#[test]
fn hardlink() {
    let t = TempDir::new();
    fs::write(t.path("orig"), b"x").unwrap();
    let mut c = Client::new();
    let r = c.ext("hardlink@openssh.com", |w| {
        w.string(bytes(&t.path("orig")))
            .string(bytes(&t.path("link")));
    });
    assert_eq!(r.status(), SSH_FX_OK);
    assert_eq!(fs::metadata(t.path("orig")).unwrap().nlink(), 2);
    // Existing target fails.
    let r = c.ext("hardlink@openssh.com", |w| {
        w.string(bytes(&t.path("orig")))
            .string(bytes(&t.path("link")));
    });
    assert_eq!(r.status(), SSH_FX_FAILURE);
}

#[test]
fn statvfs_and_fstatvfs() {
    let t = TempDir::new();
    fs::write(t.path("f"), b"x").unwrap();
    let mut c = Client::new();

    let check = |r: &Reply| {
        let mut rd = ext_reply(r);
        let v: Vec<u64> = (0..11).map(|_| rd.u64().unwrap()).collect();
        assert_eq!(rd.remaining(), 0);
        assert!(v[0] > 0, "bsize");
        assert!(v[2] > 0, "blocks");
        assert!(v[10] > 0, "namemax");
        v
    };
    let a = check(&c.ext("statvfs@openssh.com", |w| {
        w.string(bytes(&t.0));
    }));
    let h = c
        .open(&t.path("f"), SSH_FXF_READ, FileAttrs::default())
        .handle();
    let b = check(&c.ext("fstatvfs@openssh.com", |w| {
        w.string(&h);
    }));
    assert_eq!(a[2], b[2], "same filesystem");

    let r = c.ext("statvfs@openssh.com", |w| {
        w.string(bytes(&t.path("missing")));
    });
    assert_eq!(r.status(), SSH_FX_NO_SUCH_FILE);
}

#[test]
fn fsync() {
    let t = TempDir::new();
    let mut c = Client::new();
    let h = c
        .open(
            &t.path("f"),
            SSH_FXF_WRITE | SSH_FXF_CREAT,
            FileAttrs::default(),
        )
        .handle();
    c.write(&h, 0, b"data");
    assert_eq!(
        c.ext("fsync@openssh.com", |w| {
            w.string(&h);
        })
        .status(),
        SSH_FX_OK
    );
    assert_eq!(
        c.ext("fsync@openssh.com", |w| {
            w.string(b"bad!");
        })
        .status(),
        SSH_FX_FAILURE
    );
}

#[test]
fn lsetstat_touches_link_not_target() {
    let t = TempDir::new();
    fs::write(t.path("target"), b"x").unwrap();
    std::os::unix::fs::symlink("target", t.path("link")).unwrap();
    let target_mtime = fs::metadata(t.path("target")).unwrap().mtime();
    let mut c = Client::new();

    let times = FileAttrs {
        times: Some((100, 200)),
        ..Default::default()
    };
    let r = c.ext("lsetstat@openssh.com", |w| {
        w.string(bytes(&t.path("link")));
        times.encode(w);
    });
    assert_eq!(r.status(), SSH_FX_OK);
    assert_eq!(fs::symlink_metadata(t.path("link")).unwrap().mtime(), 200);
    assert_eq!(
        fs::metadata(t.path("target")).unwrap().mtime(),
        target_mtime
    );

    let size = FileAttrs {
        size: Some(0),
        ..Default::default()
    };
    let r = c.ext("lsetstat@openssh.com", |w| {
        w.string(bytes(&t.path("link")));
        size.encode(w);
    });
    assert_eq!(r.status(), SSH_FX_OP_UNSUPPORTED);
}

#[test]
fn limits() {
    let mut c = Client::new();
    let r = c.ext("limits@openssh.com", |_| {});
    let mut rd = ext_reply(&r);
    assert_eq!(rd.u64().unwrap(), MAX_PACKET_LEN as u64);
    assert_eq!(rd.u64().unwrap(), MAX_READ_LEN as u64);
    assert_eq!(rd.u64().unwrap(), MAX_READ_LEN as u64);
    assert_eq!(rd.u64().unwrap(), MAX_HANDLES as u64);
}

#[test]
fn expand_path_and_home_directory() {
    let home = fs::canonicalize(ferrisftp::sys::current_home().unwrap()).unwrap();
    let mut c = Client::new();

    let r = c.ext("expand-path@openssh.com", |w| {
        w.string(b"~");
    });
    assert_eq!(name_path(&r), home);
    let r = c.ext("expand-path@openssh.com", |w| {
        w.string(b"~/not-yet-there");
    });
    assert_eq!(name_path(&r), home.join("not-yet-there"));
    let r = c.ext("expand-path@openssh.com", |w| {
        w.string(b"~no-such-user-ferrisftp");
    });
    assert_eq!(r.status(), SSH_FX_NO_SUCH_FILE);

    let r = c.ext("home-directory", |w| {
        w.string(b"root");
    });
    assert_eq!(
        name_path(&r),
        ferrisftp::sys::passwd_by_name(b"root").unwrap().home
    );
    let r = c.ext("home-directory", |w| {
        w.string(b"");
    });
    assert_eq!(fs::canonicalize(name_path(&r)).unwrap(), home);
}

#[test]
fn copy_data() {
    let t = TempDir::new();
    let src: Vec<u8> = (0..200_000u32).map(|i| i as u8).collect();
    fs::write(t.path("src"), &src).unwrap();
    let mut c = Client::new();
    let rh = c
        .open(&t.path("src"), SSH_FXF_READ, FileAttrs::default())
        .handle();
    let wh = c
        .open(
            &t.path("dst"),
            SSH_FXF_WRITE | SSH_FXF_CREAT,
            FileAttrs::default(),
        )
        .handle();

    // Whole file (length 0 = until EOF).
    let r = c.ext("copy-data", |w| {
        w.string(&rh).u64(0).u64(0).string(&wh).u64(0);
    });
    assert_eq!(r.status(), SSH_FX_OK);
    assert_eq!(fs::read(t.path("dst")).unwrap(), src);

    // A range to an offset.
    let r = c.ext("copy-data", |w| {
        w.string(&rh).u64(10).u64(5).string(&wh).u64(300_000);
    });
    assert_eq!(r.status(), SSH_FX_OK);
    let dst = fs::read(t.path("dst")).unwrap();
    assert_eq!(&dst[300_000..], &src[10..15]);

    // Same handle: overlapping ranges are refused, disjoint ones work.
    let rw = c
        .open(
            &t.path("dst"),
            SSH_FXF_READ | SSH_FXF_WRITE,
            FileAttrs::default(),
        )
        .handle();
    let r = c.ext("copy-data", |w| {
        w.string(&rw).u64(0).u64(100).string(&rw).u64(50);
    });
    assert_eq!(r.status(), SSH_FX_FAILURE);
    let r = c.ext("copy-data", |w| {
        w.string(&rw).u64(0).u64(100).string(&rw).u64(1000);
    });
    assert_eq!(r.status(), SSH_FX_OK);

    let r = c.ext("copy-data", |w| {
        w.string(b"bad!").u64(0).u64(0).string(&wh).u64(0);
    });
    assert_eq!(r.status(), SSH_FX_FAILURE);
}

#[test]
fn users_groups_by_id() {
    let mut c = Client::new();
    let mut uids = Vec::new();
    uids.extend(0u32.to_be_bytes());
    uids.extend(4_000_000_000u32.to_be_bytes());
    let gids = 0u32.to_be_bytes();
    let r = c.ext("users-groups-by-id@openssh.com", |w| {
        w.string(&uids).string(&gids);
    });
    let mut rd = ext_reply(&r);
    let users = rd.string().unwrap();
    let groups = rd.string().unwrap();
    let mut u = Reader::new(users);
    assert_eq!(u.string().unwrap(), b"root");
    assert_eq!(u.string().unwrap(), b"");
    assert_eq!(u.remaining(), 0);
    let mut g = Reader::new(groups);
    assert_eq!(g.string().unwrap(), b"root");

    // A list that is not a multiple of 4 bytes is malformed.
    let r = c.ext("users-groups-by-id@openssh.com", |w| {
        w.string(&[0, 0, 0]).string(b"");
    });
    assert_eq!(r.status(), SSH_FX_BAD_MESSAGE);
}
