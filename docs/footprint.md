# Footprint

Measured on ferrisftp 0.1.0 (commit `514aaa5`), alongside Green End SFTP
Server (Ubuntu's `gesftpserver` 2) and OpenSSH's `sftp-server` 9.6p1 on
the same machine in the same run.

The numbers can be reproduced with [`scripts/footprint.sh`](../scripts/footprint.sh):

```sh
cargo build --release
scripts/footprint.sh target/release/ferrisftp /usr/libexec/gesftpserver /usr/lib/openssh/sftp-server
```

## Test setup

- x86_64 VM with 2 vCPUs, Linux 6.18, fast virtual disk; files are in the
  page cache.
- The OpenSSH `sftp` client starts each server directly (`sftp -D`), so
  there is no SSH connection and no encryption. That isolates the server
  itself; in real use the SSH server's encryption is the bottleneck long
  before any of these servers is (see [Throughput](#throughput)).
- ferrisftp is the default `cargo build --release` (glibc, dynamically
  linked). The static release binaries are covered in
  [Static release binaries](#static-release-binaries).

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

| | Size | Links against |
|---|---|---|
| ferrisftp | 381 KB | libc, libgcc_s |
| Green End | 84 KB | libc |
| OpenSSH sftp-server | 88 KB | libc |

The difference is mostly Rust's standard library, which is compiled into
the binary while the C servers use the system's shared C library. On a
Raspberry Pi this is a slightly larger download, nothing more.

## Memory

| Peak RSS | ferrisftp | Green End | OpenSSH |
|---|---|---|---|
| Idle session | 2.5 MB | 2.1 MB | 1.9 MB |
| `ls -l` of 10,000 files | 2.7 MB | 2.3 MB | 2.2 MB |
| Downloading 1 GiB | 3.3 MB | 2.4 MB | 3.4 MB |
| Uploading 1 GiB | 2.8 MB | 4.3 MB | 3.0 MB |

Most of that RSS is the shared C library, which every process on the
system shares. What one idle session adds on its own:

| Per idle session | ferrisftp | Green End | OpenSSH |
|---|---|---|---|
| Private, written (heap, stack) | 184 KB | 136 KB | 156 KB |
| Private, read-only (code) | 388 KB | 104 KB | 84 KB |

The code pages are shared again between concurrent sessions of the same
binary, so each further session costs roughly 0.2 MB with all three
servers.

Memory stays flat with transfer size: requests are handled one at a
time, packets are capped at 256 KiB, and there are no unbounded queues.

## Throughput

1 GiB file, median of 5 runs:

| | Download | Upload |
|---|---|---|
| ferrisftp | 1,396 MiB/s | 1,715 MiB/s |
| Green End | 928 MiB/s | 1,149 MiB/s |
| OpenSSH | 1,454 MiB/s | 1,708 MiB/s |

ferrisftp is on par with OpenSSH's server. These figures are far beyond
what an SSH connection carries on a single-board computer: there the SSH
server's encryption limits a session to roughly tens of MB/s, so the
choice of SFTP server makes no visible difference to transfer speed.

`ls -l` of a 10,000-entry directory took 0.08 s with ferrisftp and
OpenSSH, and 0.16 s with Green End.

## Static release binaries

The release binaries are statically linked against musl, so they carry
their own C library instead of sharing the system's.

| Binary | Size |
|---|---|
| `ferrisftp-armv6l` | 446 KB |
| `ferrisftp-armv7l` | 408 KB |
| `ferrisftp-aarch64` | 442 KB |
| `ferrisftp-x86_64` | 496 KB |
| `ferrisftp-riscv64` | 427 KB |

Static x86_64 (musl) against the dynamically linked glibc build, both
built and measured on the same GitHub Actions runner (a different
machine from the tables above), 512 MiB file, median of 3:

| | musl, static | glibc, dynamic |
|---|---|---|
| Peak RSS, idle | 0.3 MB | 2.4 MB |
| Peak RSS, `ls -l` of 10,000 files | 0.5 MB | 2.6 MB |
| Peak RSS, download / upload | 1.3 / 0.9 MB | 3.1 / 2.5 MB |
| Download / upload | 1,088 / 1,985 MiB/s | 1,597 / 1,995 MiB/s |
| `ls -l` of 10,000 files | 0.13 s | 0.11 s |

The static binary's RSS is far lower because it maps only the parts of
musl it uses, rather than all of glibc. Unlike glibc's shared pages,
though, this memory is not shared with other programs; per session the
real cost is similar.

Downloads are about a third slower with musl, whose `memcpy` and
`malloc` are simpler than glibc's. At over 1 GB/s this is still far
beyond what an SSH connection on a single-board computer carries.

## Why it is single-threaded

A threaded version (reader, executor and writer threads) was built and
measured. It added about 10% to cold-cache downloads but made uploads
roughly 40% slower on two cores and almost tripled memory use, so it was
not merged. See the `feature/threaded-pipeline` branch for the prototype.
