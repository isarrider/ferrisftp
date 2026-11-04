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
- Command-line options compatible with OpenSSH's sftp-server: read-only
  mode, start directory, umask, request allow/deny lists
- Logging to syslog or stderr, with OpenSSH's levels and log lines
- Static binaries for armv6l, armv7l, aarch64, x86_64 and riscv64

## Footprint

On an x86_64 test machine, compared with Green End and OpenSSH's own
sftp-server:

| | ferrisftp | Green End | OpenSSH |
|---|---|---|---|
| Lines of code (server only) | 1,873 Rust | — | — |
| Binary | 381 KB | 84 KB | 88 KB |
| Peak RSS, 1 GiB download | 3.3 MB | 2.4 MB | 3.4 MB |
| Download / upload, no SSH | 1,396 / 1,715 MiB/s | 928 / 1,149 MiB/s | 1,454 / 1,708 MiB/s |

The binary is larger because Rust's standard library is compiled in.
The static release binaries are 410–500 KB and use 0.3 MB idle, 1.3 MB
while transferring.

**About RSS:** RSS (resident set size) is the memory a process actually
has in physical RAM, the RES column in `top`/`htop`. Memory a program
merely reserves but never touches is not counted. RSS does include
*shared* memory, though: a dynamically linked program counts the
system's C library pages, of which only one copy exists in RAM for all
programs using it. That is why the glibc build shows 2.4 MB idle and the
static build 0.3 MB. What each additional SFTP session really costs is
its private memory: about 0.2–0.3 MB for ferrisftp, Green End and
OpenSSH alike, so even a 512 MB Raspberry Pi Zero could serve hundreds
of sessions. "Peak RSS" is the highest RSS a session reached.

Details, methodology and the measuring script:
[docs/footprint.md](docs/footprint.md).

## Installing

Each [release](https://github.com/isarrider/ferrisftp/releases) has a
static binary per architecture, named after `uname -m`. They have no
dependencies, so they run on any Linux distribution:

```sh
arch=$(uname -m)   # armv6l, armv7l, aarch64, x86_64 or riscv64
curl -fLO "https://github.com/isarrider/ferrisftp/releases/latest/download/ferrisftp-$arch"
curl -fLO "https://github.com/isarrider/ferrisftp/releases/latest/download/SHA256SUMS"
sha256sum --check --ignore-missing SHA256SUMS
install -m 755 "ferrisftp-$arch" /usr/local/bin/ferrisftp
```

| Binary | Runs on |
|---|---|
| `armv6l` | Raspberry Pi 1 and Zero, and every newer 32-bit ARM board |
| `armv7l` | ARMv7 boards with a 32-bit kernel, e.g. Raspberry Pi 2 and 3 |
| `aarch64` | 64-bit ARM kernels (Raspberry Pi 3 and newer), even with 32-bit userland |
| `x86_64` | 64-bit PCs and VMs |
| `riscv64` | 64-bit RISC-V boards (RV64GC) |

Each binary is tested in CI under QEMU emulating the oldest CPU it
supports, with the full test suite and an OpenSSH client session.

## Building

```sh
cargo build --release
```

Static binaries for other architectures need only the Rust target, since
Rust ships musl and links with its own `rust-lld`:

```sh
rustup target add aarch64-unknown-linux-musl
cargo build --release --target aarch64-unknown-linux-musl
```

The targets for the other release binaries are
`arm-unknown-linux-musleabihf`, `armv7-unknown-linux-musleabihf`,
`x86_64-unknown-linux-musl` and `riscv64gc-unknown-linux-musl`.

### Releasing

Set the version in `Cargo.toml`, merge, then push a matching tag:

```sh
git tag v0.1.0 && git push origin v0.1.0
```

CI builds and tests all architectures and publishes them with
`SHA256SUMS` as a GitHub release.

## Usage

ferrisftp is started by the SSH server, not by hand.

**Dropbear** looks for the SFTP server at a fixed path (usually
`/usr/libexec/sftp-server`); point that at ferrisftp:

```sh
ln -sf /usr/local/bin/ferrisftp /usr/libexec/sftp-server
```

**OpenSSH** — in `sshd_config`:

```
Subsystem sftp /usr/local/bin/ferrisftp
```

### Options

The options match OpenSSH's sftp-server, so existing `Subsystem` lines
keep working.

| Option | Effect |
|---|---|
| `-R` | Read-only: refuse every request that modifies files |
| `-d dir` | Start in `dir` instead of the home directory. `%d` is the home directory, `%u` the user name, and `~` / `~user` expand too |
| `-u umask` | Explicit octal umask for new files and directories |
| `-P list` | Refuse the listed requests (comma-separated) |
| `-p list` | Allow only the listed requests |
| `-Q requests` | Print the request names usable with `-p` / `-P` |
| `-l level` | Log level: `QUIET`, `FATAL`, `ERROR` (default), `INFO`, `VERBOSE`, `DEBUG1`–`DEBUG3` |
| `-f facility` | Syslog facility: `AUTH` (default), `AUTHPRIV`, `DAEMON`, `USER`, `LOCAL0`–`LOCAL7` |
| `-e` | Log to stderr instead of syslog |
| `-h`, `-V` | Help, version |

Example — a read-only server that starts in a shared directory:

```
Subsystem sftp /usr/local/bin/ferrisftp -R -d /srv/share
```

Refused requests get a "Permission denied" status.

### Logging

By default only errors are logged, to syslog as `ferrisftp[pid]`. With
`-l INFO` every session and file operation is logged in the same format
as OpenSSH's sftp-server:

```
session opened for local user alex from [192.0.2.7]
open "/home/alex/notes.txt" flags WRITE,CREATE,TRUNCATE mode 0644
close "/home/alex/notes.txt" bytes read 0 written 1832
remove name "/home/alex/old.txt"
session closed for local user alex from [192.0.2.7]
```

`VERBOSE` adds directory listings and refused requests, `DEBUG` every
request. Control characters in file names are escaped (`\x0a`), so a
crafted name cannot forge log lines.

### Testing locally

For local testing without any SSH server, the OpenSSH client can run it
directly:

```sh
sftp -D ./target/release/ferrisftp
```

## Fuzzing

Two [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) targets live
in `fuzz/` (nightly toolchain required):

- `decode` — the wire primitives and ATTRS decoding, including an
  encode/decode round-trip check
- `session` — whole sessions on arbitrary input: framing, handshake,
  every request parser and the extension dispatcher. The server runs
  read-only, so random requests cannot change files on the fuzzing
  machine.

```sh
cd fuzz
cargo +nightly fuzz run session
```

CI runs both briefly on every pull request.

## License

MIT — see [LICENSE](LICENSE).
