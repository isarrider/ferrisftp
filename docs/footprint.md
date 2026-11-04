# Footprint

Size and resource use of ferrisftp 0.1.0, compared with Green End SFTP
Server (Ubuntu's `gesftpserver` 2) and OpenSSH's `sftp-server` 9.6p1.

## Test setup

- All four servers measured in the same CI run (the "Footprint" step of
  the x86_64 job in `.github/workflows/release.yml`), on a GitHub Actions
  runner: Ubuntu 24.04, x86_64, AMD EPYC 7763, 4 CPUs. Files are in the
  page cache.
- The OpenSSH `sftp` client starts each server directly (`sftp -D`), so
  there is no SSH connection and no encryption. That isolates the server
  itself; in real use the SSH server's encryption is the bottleneck long
  before any of these servers is (see [Throughput](#throughput)).
- "ferrisftp release" is the static musl binary published in releases;
  "ferrisftp from source" is a plain `cargo build --release` (glibc,
  dynamically linked).

Every number can be reproduced with
[`scripts/footprint.sh`](../scripts/footprint.sh), which takes any number
of server binaries:

```sh
cargo build --release
scripts/footprint.sh target/release/ferrisftp /usr/libexec/gesftpserver /usr/lib/openssh/sftp-server
```

## Code size

| | Lines of code |
|---|---|
| ferrisftp server (no comments, blanks or tests) | **1,873** |
| Unit tests inside `src/` | 274 |
| Integration tests (`tests/`) | 1,217 |
| Fuzz targets (`fuzz/`) | 49 |

63 tests in total, plus two fuzz targets. The only runtime dependency is
the `libc` crate.

For comparison, Green End's repository has about 8,000 lines of C,
though that also includes its own SFTP client used for testing.

Largest modules: `server.rs` (624 lines, all v3 requests),
`extensions.rs` (315, the OpenSSH extensions), `cli.rs` (152) and
`log.rs` (130).

## Binary size

The release binaries are statically linked against musl:

| Release binary | Size |
|---|---|
| `ferrisftp-armv6l` | 446 KB |
| `ferrisftp-armv7l` | 408 KB |
| `ferrisftp-aarch64` | 442 KB |
| `ferrisftp-x86_64` | 496 KB |
| `ferrisftp-riscv64` | 427 KB |

On x86_64, compared with the dynamically linked servers:

| | Size | Links against |
|---|---|---|
| ferrisftp release (static) | 496 KB | nothing |
| ferrisftp from source (glibc) | 380 KB | libc, libgcc_s |
| Green End | 84 KB | libc |
| OpenSSH sftp-server | 88 KB | libc |

The static binary includes its C library (musl) and Rust's standard
library. The C servers use the system's shared C library instead.

## Memory

Two different measures matter:

- **Memory per extra session** is what each additional SFTP client
  really costs: the anonymous memory of an idle session (heap, stack,
  written data), read from `RssAnon` in `/proc/PID/status`. Code and
  shared libraries are not included, because all sessions share them.
- **RSS** (resident set size) is all memory a process has in physical
  RAM, the RES column in `top`/`htop`. It includes shared memory: a
  dynamically linked server counts the system's C library, of which one
  copy in RAM serves every program. Peak RSS is the highest value during
  the session, measured with GNU `time`.

| | ferrisftp release (static) | ferrisftp from source (glibc) | Green End | OpenSSH |
|---|---|---|---|---|
| **Memory per extra session** | **60 KiB** | 168 KiB | 124 KiB | 128 KiB |
| Peak RSS, idle | 396 KiB | 2,420 KiB | 2,244 KiB | 1,960 KiB |
| Peak RSS, `ls -l` of 10,000 files | 600 KiB | 2,448 KiB | 2,372 KiB | 1,960 KiB |
| Peak RSS, 1 GiB download | 1,328 KiB | 3,120 KiB | 2,244 KiB | 2,744 KiB |
| Peak RSS, 1 GiB upload | 856 KiB | 2,572 KiB | 4,456 KiB | 2,564 KiB |

The static binary's RSS is far lower because it maps only the parts of
musl it uses, rather than all of glibc. Its per-session cost is also the
lowest: a hundred simultaneous sessions take about 6 MiB.

Memory stays flat with transfer size: requests are handled one at a
time, packets are capped at 256 KiB, and there are no unbounded queues.

## Throughput

1 GiB file, median of 5 runs:

| | Download | Upload |
|---|---|---|
| ferrisftp release (static) | 1,106 MiB/s | 2,054 MiB/s |
| ferrisftp from source (glibc) | 1,631 MiB/s | 2,022 MiB/s |
| Green End | 826 MiB/s | 1,579 MiB/s |
| OpenSSH | 1,600 MiB/s | 1,634 MiB/s |

`ls -l` of a 10,000-entry directory took 0.13 s with the static
ferrisftp, 0.11 s built from source, 0.30 s with Green End and 0.13 s
with OpenSSH.

The static binary's downloads are about a third slower than the glibc
build's, because musl's `memcpy` and `malloc` are simpler than glibc's.

None of this is visible in practice: over SSH on a single-board
computer, the SSH server's encryption limits a session to roughly tens
of MB/s, far below any of these figures.

## Why it is single-threaded

A threaded version (reader, executor and writer threads) was built and
measured. It added about 10% to cold-cache downloads but made uploads
roughly 40% slower on two cores and almost tripled memory use, so it was
not merged. See the `feature/threaded-pipeline` branch for the prototype.
