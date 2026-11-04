#!/bin/bash
# Measure binary size, memory use and throughput of one or more SFTP
# server binaries, driven by the OpenSSH sftp client in -D mode (no SSH,
# no encryption, so the server itself is what gets measured).
#
# usage: scripts/footprint.sh SERVER [SERVER...]
#   e.g. scripts/footprint.sh target/release/ferrisftp /usr/libexec/gesftpserver
#
# Environment:
#   SIZE_MIB  size of the transfer test file (default 1024)
#   RUNS      runs per transfer test; the median is reported (default 3)
#   FILES     entries in the directory-listing test (default 10000)
#   WORK      scratch directory (default: a new mktemp dir, removed at exit)
#
# Needs: sftp (OpenSSH client), GNU time at /usr/bin/time, bc.

set -euo pipefail

SIZE_MIB=${SIZE_MIB:-1024}
RUNS=${RUNS:-3}
FILES=${FILES:-10000}
if [ -z "${WORK:-}" ]; then
    WORK=$(mktemp -d)
    trap 'rm -rf "$WORK"' EXIT
fi
mkdir -p "$WORK"

[ $# -ge 1 ] || { sed -n '2,15p' "$0"; exit 2; }

# Test data, created once.
SRC="$WORK/src.bin"
[ -f "$SRC" ] || head -c $((SIZE_MIB * 1048576)) /dev/urandom > "$SRC"
LISTDIR="$WORK/listing"
if [ ! -d "$LISTDIR" ]; then
    mkdir -p "$LISTDIR"
    (cd "$LISTDIR" && seq -f 'file%05g' 1 "$FILES" | xargs touch)
fi

# Run one sftp batch against SERVER; print "seconds peak_rss_kib".
session() {
    local server=$1 batch=$2 rss="$WORK/rss.$$"
    rm -f "$rss"
    printf '#!/bin/sh\nexec /usr/bin/time -f %%M -o "%s" "%s"\n' "$rss" "$server" > "$WORK/wrap.sh"
    chmod +x "$WORK/wrap.sh"
    local start end
    start=$(date +%s.%N)
    sftp -q -b "$batch" -D "$WORK/wrap.sh" > /dev/null
    end=$(date +%s.%N)
    echo "$(echo "$end - $start" | bc -l) $(tail -1 "$rss")"
}

median() { sort -n | awk '{a[NR]=$1} END {print a[int((NR+1)/2)]}'; }

# Memory one more session really costs: start two idle servers and read
# the private memory of the second. Code pages are shared between the two
# and shared libraries with the whole system, so neither is counted.
session_cost() {
    local server=$1 first second private
    sleep 3 | "$server" > /dev/null 2>&1 &
    first=$!
    sleep 3 | "$server" > /dev/null 2>&1 &
    second=$!
    sleep 1
    private=$(awk '/^Private_(Clean|Dirty):/ {s += $2} END {print s}' "/proc/$second/smaps_rollup")
    wait "$first" "$second" 2> /dev/null || true
    echo "$private"
}

echo "machine: $(nproc) CPUs, $(sed -n 's/^model name[[:space:]]*: //p' /proc/cpuinfo | head -n1)"

for server in "$@"; do
    server=$(readlink -f "$server")
    echo "== $server"
    echo "binary size:        $(stat -c %s "$server") bytes"
    echo "linked libraries:   $(ldd "$server" 2>/dev/null | awk '/=>/ {print $1}' | tr '\n' ' ' || echo static)"

    echo "pwd" > "$WORK/b"
    read -r _ idle < <(session "$server" "$WORK/b")
    echo "peak RSS, idle:     $idle KiB"
    echo "per extra session:  $(session_cost "$server") KiB private"

    echo "ls -l $LISTDIR" > "$WORK/b"
    read -r secs rss < <(session "$server" "$WORK/b")
    printf 'ls -l %6d files: %.2f s, peak RSS %s KiB\n' "$FILES" "$secs" "$rss"

    for op in get put; do
        speeds=() peak=0
        for _ in $(seq "$RUNS"); do
            rm -f "$WORK/out.bin"
            if [ "$op" = get ]; then
                echo "get $SRC $WORK/out.bin" > "$WORK/b"
            else
                echo "put $SRC $WORK/out.bin" > "$WORK/b"
            fi
            read -r secs rss < <(session "$server" "$WORK/b")
            cmp -s "$SRC" "$WORK/out.bin" || { echo "$op: data mismatch!"; exit 1; }
            speeds+=("$(echo "$SIZE_MIB / $secs" | bc -l)")
            [ "$rss" -gt "$peak" ] && peak=$rss
        done
        printf '%s %d MiB:       %.0f MiB/s (median of %d), peak RSS %s KiB\n' \
            "$op" "$SIZE_MIB" "$(printf '%s\n' "${speeds[@]}" | median)" "$RUNS" "$peak"
    done
done
