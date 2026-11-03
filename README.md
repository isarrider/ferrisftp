# ferrisftp

Lightweight SFTP server in Rust — a drop-in `sftp-server` subsystem for
Dropbear and OpenSSH.

ferrisftp does not handle networking, authentication or encryption. The SSH
server authenticates the user, then runs ferrisftp as that user and talks to it
over stdin/stdout. That keeps the code small and the attack surface narrow.

## Goals

- SFTP protocol version 3 plus the OpenSSH extensions real clients use
- Small static binary for embedded and single-board systems (e.g. DietPi)
- Low memory use, bounded buffers, no async runtime
- Clean-room implementation from the protocol specifications

## Status

Early development — not yet ready for production use.

Implemented:

- All SFTP v3 requests (open/close/read/write, stat family, setstat,
  directories, remove, rename, realpath, readlink, symlink)
- OpenSSH extensions: `posix-rename`, `statvfs`, `fstatvfs`, `hardlink`,
  `fsync`, `lsetstat`, `limits`, `expand-path`, `copy-data`,
  `home-directory`, `users-groups-by-id`

Not yet: threaded request handling, read-only and chroot modes.

## Building

```sh
cargo build --release
```

## Usage

ferrisftp is started by the SSH server, not by hand.

**Dropbear** looks for the SFTP server at a fixed path (usually
`/usr/libexec/sftp-server`); point that at ferrisftp:

```sh
install -m 755 target/release/ferrisftp /usr/local/bin/ferrisftp
ln -sf /usr/local/bin/ferrisftp /usr/libexec/sftp-server
```

**OpenSSH** — in `sshd_config`:

```
Subsystem sftp /usr/local/bin/ferrisftp
```

For local testing without any SSH server, the OpenSSH client can run it
directly:

```sh
sftp -D ./target/release/ferrisftp
```

## License

MIT — see [LICENSE](LICENSE).
