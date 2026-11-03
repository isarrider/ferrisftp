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

Early development — not yet ready for use.

## License

MIT — see [LICENSE](LICENSE).
