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

Not yet: prebuilt static binaries.

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
