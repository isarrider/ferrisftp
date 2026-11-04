"""SFTP checks with Paramiko, an SFTP client independent of OpenSSH.

usage: python3 e2e_paramiko.py HOST PORT USER KEYFILE

Covers what the OpenSSH and rclone checks in dropbear-e2e.sh do not:
random-access I/O, append, truncate, timestamps, fstat, both rename
flavours and the mapping of SFTP errors to the right exceptions.
"""

import hashlib
import os
import stat
import sys

import paramiko


def main() -> None:
    host, port, user, key = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(host, port, user, key_filename=key, look_for_keys=False, allow_agent=False)
    s = ssh.open_sftp()

    def ok(msg: str) -> None:
        print("ok:", msg)

    home = s.normalize(".")
    ok(f"normalize . -> {home}")
    s.mkdir("pm", 0o750)
    assert stat.S_IMODE(s.stat("pm").st_mode) == 0o750
    ok("mkdir with mode")
    s.chdir("pm")

    data = os.urandom(5_000_000)
    with s.open("f.bin", "wb") as f:
        f.set_pipelined(True)
        f.write(data)
    with s.open("f.bin", "rb") as f:
        f.prefetch()
        assert f.read() == data
    ok("5 MB pipelined write and prefetched read")

    with s.open("f.bin", "r+b") as f:
        f.seek(1_000_000)
        f.write(b"PATCH")
        f.seek(999_998)
        assert f.read(9) == data[999_998:1_000_000] + b"PATCH" + data[1_000_005:1_000_007]
    ok("random-access write and read")

    with s.open("f.bin", "ab") as f:
        f.write(b"TAIL")
    assert s.stat("f.bin").st_size == 5_000_004
    ok("append")

    # Server-side hashing (the check-file extension).
    with s.open("f.bin", "rb") as f:
        content = f.read()
        assert f.check("sha256") == hashlib.sha256(content).digest()
        assert f.check("md5", 100, 4096) == hashlib.md5(content[100:4196]).digest()
        blocks = f.check("sha1", 0, 0, 1_000_000)
        want = b"".join(
            hashlib.sha1(content[i : i + 1_000_000]).digest()
            for i in range(0, len(content), 1_000_000)
        )
        assert blocks == want
    ok("check-file: whole file, range and blocks")

    s.truncate("f.bin", 1234)
    assert s.stat("f.bin").st_size == 1234
    ok("truncate")
    s.chmod("f.bin", 0o600)
    assert stat.S_IMODE(s.stat("f.bin").st_mode) == 0o600
    ok("chmod")
    s.utime("f.bin", (1_000_000_000, 1_234_567_890))
    st = s.stat("f.bin")
    assert (st.st_atime, st.st_mtime) == (1_000_000_000, 1_234_567_890)
    ok("utime")
    with s.open("f.bin") as f:
        assert f.stat().st_size == 1234
    ok("fstat")

    s.symlink("f.bin", "link")
    assert s.readlink("link") == "f.bin"
    assert stat.S_ISLNK(s.lstat("link").st_mode)
    assert stat.S_ISREG(s.stat("link").st_mode)
    ok("symlink, readlink, lstat vs stat")

    s.open("g.bin", "w").close()
    try:
        s.rename("f.bin", "g.bin")
        raise SystemExit("SFTP v3 rename overwrote an existing file")
    except OSError:
        ok("rename refuses to overwrite")
    s.posix_rename("f.bin", "g.bin")
    assert "f.bin" not in s.listdir()
    ok("posix-rename overwrites")

    names = sorted(a.filename for a in s.listdir_attr("."))
    assert names == ["g.bin", "link"], names
    ok("listdir_attr")

    for call, exc in [
        (lambda: s.stat("missing"), FileNotFoundError),
        (lambda: s.open("/root/x", "w"), PermissionError),
        (lambda: s.remove("/etc/hostname"), PermissionError),
        (lambda: s.rmdir(home + "/pm"), OSError),
    ]:
        try:
            call()
            raise SystemExit(f"expected {exc.__name__}")
        except exc:
            pass
    ok("errors map to FileNotFoundError, PermissionError, OSError")

    s.remove("link")
    s.remove("g.bin")
    s.chdir("..")
    s.rmdir("pm")
    assert "pm" not in s.listdir(".")
    ok("cleanup")
    s.close()
    ssh.close()


if __name__ == "__main__":
    main()
