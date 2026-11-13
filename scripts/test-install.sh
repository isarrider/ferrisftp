#!/bin/sh
# Test scripts/install.sh end to end on a Dropbear system: install, log in
# over SSH through Dropbear and transfer files, update, uninstall, and
# check that the original state is restored.
#
# usage: sudo scripts/test-install.sh
#
# Meant for CI containers and throwaway machines: it installs ferrisftp
# system-wide, creates a temporary user and runs Dropbear on port 2222.
# Needs: root, dropbear, dropbearkey, ssh/sftp/ssh-keygen (OpenSSH
# client), curl or wget, pgrep.

set -eu

HERE=$(dirname "$(readlink -f "$0")")
INSTALL="$HERE/install.sh"
BIN=/usr/local/bin/ferrisftp
USER_NAME=ferrisftp-inst
PORT=2222

[ "$(id -u)" = 0 ] || { echo "must run as root"; exit 2; }
fail() { echo "FAIL: $*" >&2; exit 1; }
# "absent", "file", or "link to TARGET".
state() {
    if [ -L "$1" ]; then
        echo "link to $(readlink "$1")"
    elif [ -e "$1" ]; then
        echo file
    else
        echo absent
    fi
}
ok() { echo "ok: $*"; }

W=$(mktemp -d)
chmod 755 "$W"
cleanup() {
    status=$?
    if [ "$status" != 0 ]; then
        echo "--- failed in step: ${STEP:-?}" >&2
        for log in "$W"/*.log; do
            [ -s "$log" ] && { echo "--- $log" >&2; cat "$log" >&2; }
        done
    fi
    if [ -f "$W/dropbear.pid" ]; then
        kill "$(cat "$W/dropbear.pid")" 2> /dev/null || true
    fi
    pkill -KILL -u "$USER_NAME" 2> /dev/null || true
    sleep 0.5
    userdel -r "$USER_NAME" 2> /dev/null || true
    rm -rf "$W"
}
trap cleanup EXIT

SFTP_PATH=$(grep -ao '/[A-Za-z0-9/._-]*sftp-server' "$(command -v dropbear)" | head -n 1)
echo "== $(dropbear -V 2>&1 | head -n 1), sftp path $SFTP_PATH, $(uname -m)"
[ -n "$SFTP_PATH" ] || fail "cannot find Dropbear's sftp path"

# Remember what was there before, to check that --uninstall restores it.
before=$(state "$SFTP_PATH")
echo "before: $SFTP_PATH is $before"

echo "== install"
sh "$INSTALL"
[ "$(readlink "$SFTP_PATH")" = "$BIN" ] || fail "$SFTP_PATH does not point to $BIN"
"$BIN" -V | grep -q '^ferrisftp ' || fail "$BIN -V"
ok "installed $("$BIN" -V), $SFTP_PATH -> $BIN"

echo "== log in through Dropbear"
STEP="create user"
useradd -m -s /bin/sh "$USER_NAME"
HOME_DIR=$(getent passwd "$USER_NAME" | cut -d: -f6)
STEP="client key"
ssh-keygen -q -t ed25519 -N '' -f "$W/key"
install -d -m 700 -o "$USER_NAME" "$HOME_DIR/.ssh"
install -m 600 -o "$USER_NAME" "$W/key.pub" "$HOME_DIR/.ssh/authorized_keys"
STEP="host keys"
dropbearkey -t ed25519 -f "$W/host_ed25519" > "$W/keygen.log" 2>&1
dropbearkey -t rsa -s 3072 -f "$W/host_rsa" >> "$W/keygen.log" 2>&1
STEP="start dropbear"
dropbear -F -E -s -p "127.0.0.1:$PORT" -r "$W/host_ed25519" -r "$W/host_rsa" \
    -P "$W/dropbear.pid" 2> "$W/dropbear.log" &
for _ in $(seq 50); do [ -f "$W/dropbear.pid" ] && break; sleep 0.1; done
[ -f "$W/dropbear.pid" ] || fail "Dropbear did not start"
STEP="first session"

cat > "$W/ssh_config" << EOF
Host t
  HostName 127.0.0.1
  Port $PORT
  User $USER_NAME
  IdentityFile $W/key
  IdentitiesOnly yes
  StrictHostKeyChecking no
  UserKnownHostsFile /dev/null
  LogLevel ERROR
EOF

transfer() {
    rm -f "$W/back.bin"
    head -c 10000000 /dev/urandom > "$W/src.bin"
    printf 'put %s up.bin\nget up.bin %s\nrm up.bin\n' "$W/src.bin" "$W/back.bin" > "$W/batch"
    sftp -q -b "$W/batch" -F "$W/ssh_config" t > /dev/null
    cmp -s "$W/src.bin" "$W/back.bin"
}

# While a session is open, the process behind the sftp path must be the
# installed ferrisftp, running as the user.
( (sleep 3; echo bye) | sftp -q -F "$W/ssh_config" t > /dev/null 2>&1 & )
sleep 1.5
pid=$(pgrep -u "$USER_NAME" -x "$(basename "$SFTP_PATH")" | head -n 1)
[ -n "$pid" ] || fail "no sftp server process for $USER_NAME"
exe=$(readlink "/proc/$pid/exe")
[ "$exe" = "$BIN" ] || fail "session runs $exe, not $BIN"
ok "Dropbear session runs $exe as $USER_NAME"
sleep 2

STEP="transfer"
transfer || fail "transfer through Dropbear"
ok "10 MB upload and download through Dropbear are identical"

echo "== update (run again)"
sh "$INSTALL" > /dev/null
[ "$(readlink "$SFTP_PATH")" = "$BIN" ] || fail "link changed on update"
transfer || fail "transfer after update"
ok "second run keeps everything working"

echo "== uninstall"
sh "$INSTALL" --uninstall
[ ! -e "$BIN" ] || fail "$BIN still exists"
if command -v dpkg-divert > /dev/null; then
    [ -z "$(dpkg-divert --list "$SFTP_PATH")" ] || fail "diversion left behind"
fi
after=$(state "$SFTP_PATH")
[ "$after" = "$before" ] || fail "$SFTP_PATH is '$after' after uninstall, was '$before'"
ok "uninstall restored $SFTP_PATH ($after), binary and diversion removed"

if grep -q "Failed assertion" "$W/dropbear.log"; then
    cat "$W/dropbear.log"
    fail "Dropbear reported errors"
fi
echo "== install.sh passed all checks"
