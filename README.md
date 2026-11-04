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

**The release binaries** are static, so they need nothing else on the
system. Each one is tested in CI under QEMU emulating the oldest CPU it
supports:

| Binary | Size | Tested on |
|---|---|---|
| `ferrisftp-armv6l` | 446 KB | ARM1176 (Raspberry Pi 1, Zero) |
| `ferrisftp-armv7l` | 408 KB | Cortex-A7 (Raspberry Pi 2) |
| `ferrisftp-aarch64` | 442 KB | Cortex-A53 (Raspberry Pi 3) |
| `ferrisftp-x86_64` | 496 KB | x86_64 |
| `ferrisftp-riscv64` | 427 KB | RV64GC |

**Compared with Green End and OpenSSH's sftp-server**, all four measured
in the same CI run on x86_64 (AMD EPYC 7763, 4 CPUs). The OpenSSH `sftp`
client starts each server directly, without an SSH connection, so the
server itself is measured; transfers use a 1 GiB file, median of 5 runs.

| | ferrisftp release (static) | ferrisftp from source (glibc) | Green End | OpenSSH |
|---|---|---|---|---|
| Binary | 496 KB | 380 KB | 84 KB | 88 KB |
| **Memory per extra session** | **60 KiB** | 168 KiB | 124 KiB | 128 KiB |
| Peak RSS, idle | 0.4 MiB | 2.4 MiB | 2.2 MiB | 1.9 MiB |
| Peak RSS, download / upload | 1.3 / 0.8 MiB | 3.0 / 2.5 MiB | 2.2 / 4.4 MiB | 2.7 / 2.5 MiB |
| Download / upload | 1,106 / 2,054 MiB/s | 1,631 / 2,022 MiB/s | 826 / 1,579 MiB/s | 1,600 / 1,634 MiB/s |
| `ls -l` of 10,000 files | 0.13 s | 0.11 s | 0.30 s | 0.13 s |

The server is 1,873 lines of Rust (without comments, blanks and tests),
with `libc` as its only dependency.

What the numbers mean:

- **Memory per extra session** is what each additional SFTP client
  really costs: the memory the session allocates for itself (heap,
  stack, written data). Code and shared libraries are not counted,
  because all sessions share them. The static release binary needs the
  least of the four: a hundred simultaneous sessions take about 6 MiB.
- **RSS** (resident set size) is the memory a process has in physical
  RAM, the RES column in `top`/`htop`. It includes *shared* memory: a
  dynamically linked server counts the system's C library, of which one
  copy in RAM serves every program. That is why the glibc builds show
  around 2 MiB idle while the static binary, which carries only the
  parts of musl it uses, shows 0.4 MiB. Peak RSS is the highest value
  during the session.
- **Binary size**: the static binary includes its C library (musl) and
  Rust's standard library; the C servers use the system's shared C
  library instead.
- **Speed**: over SSH on a single-board computer, the SSH server's
  encryption limits a transfer to tens of MB/s, far below any of these
  figures, so the SFTP server makes no visible difference to transfer
  speed. musl's simpler `memcpy` and `malloc` are why the static
  binary's downloads are slower than the glibc build's.

Methodology, code size details and the measuring script:
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
