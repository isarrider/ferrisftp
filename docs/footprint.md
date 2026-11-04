# Footprint

Size and resource use of ferrisftp [v0.1.0](https://github.com/isarrider/ferrisftp/releases/tag/v0.1.0), compared with Green End SFTP
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
| ferrisftp server (no comments, blanks or tests) | 1,873 |
| Unit tests inside `src/` | 274 |
| Integration tests (`tests/`) | 1,217 |
| Fuzz targets (`fuzz/`) | 49 |

63 tests in total, plus two fuzz targets. The only runtime dependency is
the `libc` crate. (Server-side hashing, added after v0.1.0, adds the
RustCrypto `sha2` crate.)

For comparison, Green End's repository has about 8,000 lines of C,
though that also includes its own SFTP client used for testing.

Largest modules: `server.rs` (624 lines, all v3 requests),
`extensions.rs` (315, the OpenSSH extensions), `cli.rs` (152) and
`log.rs` (130).

## Binary size

The release binaries are statically linked against musl. Sizes of the
files published in the [v0.1.0 release](https://github.com/isarrider/ferrisftp/releases/tag/v0.1.0):

| Release binary | Size |
|---|---|
| `ferrisftp-armv6l` | 446 KB (445,832 bytes) |
| `ferrisftp-armv7l` | 408 KB (407,884 bytes) |
| `ferrisftp-aarch64` | 442 KB (441,584 bytes) |
| `ferrisftp-x86_64` | 496 KB (496,360 bytes) |
| `ferrisftp-riscv64` | 427 KB (426,704 bytes) |

On x86_64, compared with the dynamically linked servers:

| | Size | Links against |
|---|---|---|
| ferrisftp v0.1.0 release (static) | 496 KB | nothing |
| ferrisftp v0.1.0 from source (glibc) | 380 KB | libc, libgcc_s |
| Green End | **<ins>84 KB</ins>** | libc |
| OpenSSH sftp-server | 88 KB | libc |

The smallest is in bold and underlined.

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

| | ferrisftp v0.1.0 release (static) | ferrisftp v0.1.0 from source (glibc) | Green End | OpenSSH |
|---|---|---|---|---|
| Memory per extra session | **<ins>60 KiB</ins>** | 168 KiB | 124 KiB | 128 KiB |
| Peak RSS, idle | **<ins>396 KiB</ins>** | 2,420 KiB | 2,244 KiB | 1,960 KiB |
| Peak RSS, `ls -l` of 10,000 files | **<ins>600 KiB</ins>** | 2,448 KiB | 2,372 KiB | 1,960 KiB |
| Peak RSS, 1 GiB download | **<ins>1,328 KiB</ins>** | 3,120 KiB | 2,244 KiB | 2,744 KiB |
| Peak RSS, 1 GiB upload | **<ins>856 KiB</ins>** | 2,572 KiB | 4,456 KiB | 2,564 KiB |

The best value in each row is in bold and underlined.

The static binary's RSS is far lower because it maps only the parts of
musl it uses, rather than all of glibc. Its per-session cost is also the
lowest: a hundred simultaneous sessions take about 6 MiB.

Memory stays flat with transfer size: requests are handled one at a
time, packets are capped at 256 KiB, and there are no unbounded queues.

## Throughput

1 GiB file, median of 5 runs:

| | Download | Upload |
|---|---|---|
| ferrisftp v0.1.0 release (static) | 1,106 MiB/s | **<ins>2,054 MiB/s</ins>** |
| ferrisftp v0.1.0 from source (glibc) | **<ins>1,631 MiB/s</ins>** | 2,022 MiB/s |
| Green End | 826 MiB/s | 1,579 MiB/s |
| OpenSSH | 1,600 MiB/s | 1,634 MiB/s |

The best value in each column is in bold and underlined.

`ls -l` of a 10,000-entry directory took 0.13 s with the static
ferrisftp, 0.11 s built from source, 0.30 s with Green End and 0.13 s
with OpenSSH.

The static binary's downloads are about a third slower than the glibc
build's, because musl's `memcpy` and `malloc` are simpler than glibc's.

None of this is visible in practice, because the SSH server's
encryption is the limit. Each server installed as Dropbear's `sftp`
subsystem, on a 2-core x86_64 VM (Intel Xeon, 2.1 GHz), cipher
chacha20-poly1305, 256 MiB file, median of 3:

| Behind Dropbear 2022.83 | Download | Upload |
|---|---|---|
| ferrisftp (glibc) | 162 MiB/s | 110 MiB/s |
| Green End | 158 MiB/s | **<ins>117 MiB/s</ins>** |
| OpenSSH | **<ins>173 MiB/s</ins>** | 111 MiB/s |

The differences are within measurement noise. On a single-board
computer the encryption limit is lower still, roughly tens of MB/s.

## Why it is single-threaded

A threaded version (reader, executor and writer threads) was built and
measured. It added about 10% to cold-cache downloads but made uploads
roughly 40% slower on two cores and almost tripled memory use, so it was
not merged. See the `feature/threaded-pipeline` branch for the prototype.
