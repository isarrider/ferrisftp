#!/bin/bash
# End-to-end test: ferrisftp as Dropbear's sftp subsystem, over a real
# encrypted SSH connection, with three independent SFTP clients
# (OpenSSH sftp, rclone, Paramiko).
#
# usage: sudo scripts/dropbear-e2e.sh FERRISFTP_BINARY
#
# THIS CHANGES THE SYSTEM, so it is meant for CI and throwaway machines.
# Dropbear's SFTP server path is fixed at build time, so the script points
# it at ferrisftp (and restores it afterwards), creates a temporary user
# and runs Dropbear on 127.0.0.1:2222. It refuses to run unless CI is set
# or --yes is given.
#
# Needs: root, dropbear, dropbearkey, sftp/ssh (OpenSSH client), rclone,
# python3 with paramiko.

set -euo pipefail

[ "${2:-}" = --yes ] || [ -n "${CI:-}" ] || { sed -n '2,15p' "$0"; exit 2; }
[ "$(id -u)" = 0 ] || { echo "must run as root"; exit 2; }
BIN=$(readlink -f "$1")
HERE=$(dirname "$(readlink -f "$0")")

# Where this Dropbear build execs the sftp subsystem from.
# (sed reads all input; grep -m1 would SIGPIPE strings under pipefail)
SFTP_PATH=$(strings "$(command -v dropbear)" | grep -E '^/.*sftp-server$' | sed -n 1p)
USER_NAME=ferrisftp-e2e
PORT=2222
W=$(mktemp -d)
chmod 755 "$W"

cleanup() {
    [ -f "$W/dropbear.pid" ] && kill "$(cat "$W/dropbear.pid")" 2> /dev/null || true
    if [ -e "$W/sftp-server.orig" ] || [ -L "$W/sftp-server.orig" ]; then
        mv -f "$W/sftp-server.orig" "$SFTP_PATH"
    else
        rm -f "$SFTP_PATH"
    fi
    pkill -KILL -u "$USER_NAME" 2> /dev/null || true
    sleep 0.5
    userdel -r "$USER_NAME" 2> /dev/null || true
    rm -rf "$W"
}
trap cleanup EXIT

echo "== Dropbear $(dropbear -V 2>&1 | head -n1), sftp subsystem at $SFTP_PATH"
if [ -e "$SFTP_PATH" ] || [ -L "$SFTP_PATH" ]; then
    mv "$SFTP_PATH" "$W/sftp-server.orig"
fi
mkdir -p "$(dirname "$SFTP_PATH")"
install -m 755 "$BIN" "$W/ferrisftp"
ln -s "$W/ferrisftp" "$SFTP_PATH"

useradd -m -s /bin/sh "$USER_NAME"
HOME_DIR=$(getent passwd "$USER_NAME" | cut -d: -f6)
ssh-keygen -q -t ed25519 -N '' -f "$W/key"
install -d -m 700 -o "$USER_NAME" "$HOME_DIR/.ssh"
install -m 600 -o "$USER_NAME" "$W/key.pub" "$HOME_DIR/.ssh/authorized_keys"

# Both key types: some clients (e.g. older Go SSH libraries) ask for RSA.
dropbearkey -t ed25519 -f "$W/host_ed25519" > /dev/null 2>&1
dropbearkey -t rsa -s 3072 -f "$W/host_rsa" > /dev/null 2>&1
dropbear -F -E -s -p "127.0.0.1:$PORT" -r "$W/host_ed25519" -r "$W/host_rsa" \
    -P "$W/dropbear.pid" 2> "$W/dropbear.log" &
for _ in $(seq 50); do [ -f "$W/dropbear.pid" ] && break; sleep 0.1; done

cat > "$W/ssh_config" << EOF
Host e2e
  HostName 127.0.0.1
  Port $PORT
  User $USER_NAME
  IdentityFile $W/key
  IdentitiesOnly yes
  StrictHostKeyChecking no
  UserKnownHostsFile /dev/null
  LogLevel ERROR
EOF

echo "== Session runs ferrisftp as the user"
( (sleep 3; echo bye) | sftp -q -F "$W/ssh_config" e2e > /dev/null 2>&1 & )
sleep 1.5
# Dropbear starts the subsystem via the user's shell; match the server
# process by its name, not the shell wrapping it.
pid=$(pgrep -u "$USER_NAME" -x "$(basename "$SFTP_PATH")" | head -n1)
exe=$(readlink "/proc/$pid/exe")
echo "pid $pid, user $(ps -o user= -p "$pid"), exe $exe"
[ "$exe" = "$W/ferrisftp" ]
sleep 2

echo "== OpenSSH sftp"
head -c 32000000 /dev/urandom > "$W/big.bin"
echo hello > "$W/small.txt"
cat > "$W/batch" << EOF
mkdir up
cd up
put $W/big.bin big.bin
put $W/small.txt small.txt
put $W/small.txt other.txt
rename small.txt other.txt
chmod 640 other.txt
symlink big.bin link.bin
ln big.bin hard.bin
cp big.bin copy.bin
ls -l
df -h .
get copy.bin $W/copy-back.bin
get link.bin $W/link-back.bin
-put $W/small.txt /root/denied.txt
-mkdir /etc/denied
-rm /etc/passwd
-get /etc/shadow $W/shadow
rm *
cd ..
rmdir up
EOF
sftp -b "$W/batch" -F "$W/ssh_config" e2e
cmp "$W/big.bin" "$W/copy-back.bin"
cmp "$W/big.bin" "$W/link-back.bin"
[ ! -e "$W/shadow" ] && [ ! -e /root/denied.txt ] && [ ! -e /etc/denied ]
echo "ok: transfers identical, privileged paths refused"

echo "== rclone (Go SFTP client)"
mkdir -p "$W/tree/a/b"
for i in $(seq 1 100); do head -c $((RANDOM * 10)) /dev/urandom > "$W/tree/a/f$i.bin"; done
head -c 20000000 /dev/urandom > "$W/tree/a/b/large.bin"
echo "Grüße" > "$W/tree/a/b/Name mit Leerzeichen und Ümlaut.txt"
export RCLONE_CONFIG_E2E_TYPE=sftp RCLONE_CONFIG_E2E_HOST=127.0.0.1 \
    RCLONE_CONFIG_E2E_PORT=$PORT RCLONE_CONFIG_E2E_USER=$USER_NAME \
    RCLONE_CONFIG_E2E_KEY_FILE=$W/key RCLONE_CONFIG_E2E_DISABLE_HASHCHECK=true \
    RCLONE_CONFIG_E2E_SHELL_TYPE=none
rc() { rclone --config /dev/null -q "$@"; }
rc copy "$W/tree" e2e:rc
rc check --download "$W/tree" e2e:rc
rc moveto e2e:rc/a/f1.bin e2e:rc/a/moved.bin
rc about e2e:rc
rc copy e2e:rc "$W/back"
mv "$W/tree/a/f1.bin" "$W/tree/a/moved.bin"
diff -r "$W/tree" "$W/back"
rc purge e2e:rc
echo "ok: upload, byte compare, move, about, download, purge"

echo "== Paramiko (Python SFTP client)"
python3 -I "$HERE/e2e_paramiko.py" 127.0.0.1 "$PORT" "$USER_NAME" "$W/key"

if grep -qE "Exit before auth|Failed assertion" "$W/dropbear.log"; then
    echo "Dropbear reported errors:"
    cat "$W/dropbear.log"
    exit 1
fi
echo "== All end-to-end checks passed"
