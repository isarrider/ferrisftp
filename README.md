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

Not yet: logging (`-e`, `-f`, `-l` are accepted but do nothing yet),
prebuilt static binaries.

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
| `-e`, `-f fac`, `-l level` | Logging options; accepted, not implemented yet |
| `-h`, `-V` | Help, version |

Example — a read-only server that starts in a shared directory:

```
Subsystem sftp /usr/local/bin/ferrisftp -R -d /srv/share
```

Refused requests get a "Permission denied" status.

### Testing locally

For local testing without any SSH server, the OpenSSH client can run it
directly:

```sh
sftp -D ./target/release/ferrisftp
```

## License

MIT — see [LICENSE](LICENSE).
