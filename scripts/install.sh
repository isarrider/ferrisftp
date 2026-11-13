#!/bin/sh
# Install ferrisftp as the SFTP server for Dropbear (e.g. on DietPi).
#
#   curl -fsSL https://raw.githubusercontent.com/isarrider/ferrisftp/main/scripts/install.sh | sh
#
# Options (after "sh -s --" when piping):
#   --version vX.Y.Z   install that release instead of the latest
#   --uninstall        remove ferrisftp and restore the previous state
#
# What it does:
#   1. downloads the static binary for this machine from the GitHub
#      release and verifies it against the release's SHA256SUMS
#   2. installs it as /usr/local/bin/ferrisftp
#   3. links the path Dropbear runs for SFTP (usually /usr/lib/sftp-server)
#      to it. If a package owns that path (e.g. openssh-sftp-server), the
#      package's file is moved aside with dpkg-divert, so package updates
#      cannot overwrite the link and --uninstall can restore it.
#
# Dropbear needs no restart: it looks up the SFTP server for each new
# connection. With OpenSSH, the script installs the binary and prints the
# sshd_config line to use instead of changing sshd's configuration.

set -eu

REPO="isarrider/ferrisftp"
BIN="/usr/local/bin/ferrisftp"
VERSION=""
ACTION="install"

die() {
    echo "error: $*" >&2
    exit 1
}

while [ $# -gt 0 ]; do
    case "$1" in
        --version) [ $# -ge 2 ] || die "--version needs a value"; VERSION=$2; shift 2 ;;
        --uninstall) ACTION="uninstall"; shift ;;
        -h | --help) sed -n '2,23p' "$0" 2> /dev/null || true; exit 0 ;;
        *) die "unknown option: $1" ;;
    esac
done

[ "$(id -u)" = 0 ] || die "please run as root"

# Where this Dropbear build runs the SFTP server from; it is compiled in.
# grep -a reads the binary directly, so binutils' strings is not needed.
sftp_path() {
    db=$(command -v dropbear 2> /dev/null || true)
    [ -n "$db" ] || return 0
    grep -ao '/[A-Za-z0-9/._-]*sftp-server' "$db" | head -n 1 || true
}

# The diverted (moved-aside) location of a package's file, if any.
diverted_to() {
    dpkg-divert --truename "$1" 2> /dev/null | grep -v "^$1\$" || true
}

uninstall() {
    path=$(sftp_path)
    if [ -n "$path" ] && [ "$(readlink "$path" 2> /dev/null || true)" = "$BIN" ]; then
        rm -f "$path"
        echo "removed link $path"
    fi
    if [ -n "$path" ] && command -v dpkg-divert > /dev/null &&
        dpkg-divert --list "$path" | grep -q "by ferrisftp"; then
        dpkg-divert --package ferrisftp --rename --remove "$path" > /dev/null
        if [ -e "$path" ] || [ -L "$path" ]; then
            echo "restored the packaged $path"
        else
            echo "removed the dpkg diversion of $path"
        fi
    fi
    if [ -e "$BIN" ]; then
        rm -f "$BIN"
        echo "removed $BIN"
    fi
    echo "ferrisftp is uninstalled"
}

if [ "$ACTION" = uninstall ]; then
    uninstall
    exit 0
fi

# The release files are named after uname -m. A static binary does not
# care about userland, so a 64-bit kernel with 32-bit userland simply
# gets the aarch64 build.
arch=$(uname -m)
case "$arch" in
    armv6l | armv7l | aarch64 | x86_64 | riscv64) ;;
    armv8l) arch=armv7l ;;
    arm64) arch=aarch64 ;;
    *) die "no ferrisftp build for architecture $arch" ;;
esac

if [ -n "$VERSION" ]; then
    base="https://github.com/$REPO/releases/download/$VERSION"
else
    base="https://github.com/$REPO/releases/latest/download"
fi

fetch() {
    if command -v curl > /dev/null; then
        curl -fsSL -o "$2" "$1"
    elif command -v wget > /dev/null; then
        wget -q -O "$2" "$1"
    else
        die "curl or wget is required"
    fi
}

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

echo "downloading ferrisftp-$arch (${VERSION:-latest release})"
fetch "$base/ferrisftp-$arch" "$tmp/ferrisftp-$arch" || die "download failed"
fetch "$base/SHA256SUMS" "$tmp/SHA256SUMS" || die "download of SHA256SUMS failed"
(cd "$tmp" && grep " ferrisftp-$arch\$" SHA256SUMS | sha256sum -c - > /dev/null) ||
    die "checksum verification failed, nothing was installed"
echo "checksum verified"

# install(1) replaces the file instead of writing into it, so this also
# works while a session is still running the old binary.
install -m 755 "$tmp/ferrisftp-$arch" "$BIN"
echo "installed $("$BIN" -V) as $BIN"

path=$(sftp_path)
if [ -n "$path" ]; then
    if [ "$(readlink "$path" 2> /dev/null || true)" != "$BIN" ]; then
        # Move a packaged file aside, and keep future package versions of
        # it aside too.
        if command -v dpkg-divert > /dev/null; then
            dpkg-divert --package ferrisftp --rename --add "$path" > /dev/null
            moved=$(diverted_to "$path")
            [ -n "$moved" ] && [ -e "$moved" ] && echo "moved the packaged $path to $moved"
        elif [ -e "$path" ] || [ -L "$path" ]; then
            mv "$path" "$path.orig"
            echo "moved the existing $path to $path.orig"
        fi
        mkdir -p "$(dirname "$path")"
        ln -sf "$BIN" "$path"
    fi
    echo "Dropbear now uses ferrisftp for SFTP ($path -> $BIN)"
    echo "New SFTP connections use it right away; no restart needed."
elif command -v sshd > /dev/null || [ -x /usr/sbin/sshd ]; then
    echo "OpenSSH found. To use ferrisftp, set this in /etc/ssh/sshd_config"
    echo "(replacing the existing Subsystem sftp line) and reload ssh:"
    echo "  Subsystem sftp $BIN"
else
    echo "warning: no Dropbear or OpenSSH server found; only the binary was installed" >&2
fi
