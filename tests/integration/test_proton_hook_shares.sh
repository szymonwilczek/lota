#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Szymon Wilczek
#
# tests/integration/test_proton_hook_shares.sh
#
# What lota-proton-hook puts in PRESSURE_VESSEL_FILESYSTEMS_RW.
# Only listed paths are bound into the pressure-vessel container;
# without the hook's directory its status and token stay invisible to the host.
#
# Requires:
#   - bash, and a writable temp directory
#
# Runs unprivileged and loads nothing: the library is an empty file named
# through LOTA_HOOK_LIB_PATH, and the wrapped command prints its environment.

set -euo pipefail

# assertions grep the wrapper's own messages
export LC_ALL=C

REPO_DIR=$(cd "$(dirname "$0")/../.." && pwd)
WRAPPER="$REPO_DIR/scripts/lota-proton-hook"

if [[ ! -x "$WRAPPER" ]]; then
    echo "[proton-hook-shares] missing artifact: $WRAPPER" >&2
    exit 2
fi

WORK_DIR=$(mktemp -d)
trap 'rm -rf "$WORK_DIR"' EXIT

failures=0

check() {
    local msg="$1"
    shift
    if "$@"; then
	echo "PASS: $msg"
    else
	echo "FAIL: $msg"
	failures=$((failures + 1))
    fi
}

says() { grep -qi -- "$2" <<<"$1"; }
denies() { ! grep -qi -- "$2" <<<"$1"; }

# whole colon-separated element, not a prefix
shares() {
    local list="$1" want="$2" entry

    local IFS=:
    for entry in $list; do
	[[ "$entry" == "$want" ]] && return 0
    done
    return 1
}

shares_once() {
    local list="$1" want="$2" entry seen=0

    local IFS=:
    for entry in $list; do
	[[ "$entry" == "$want" ]] && seen=$((seen + 1))
    done
    test "$seen" -eq 1
}

LIB="$WORK_DIR/liblota_wine_hook.so"
: >"$LIB"

run_wrapper() {
    local out_file="$WORK_DIR/out"
    local err_file="$WORK_DIR/err"

    set +e
    env "$@" LOTA_HOOK_LIB_PATH="$LIB" \
	"$WRAPPER" /bin/sh -c \
	'printf "RW=[%s]\n" "${PRESSURE_VESSEL_FILESYSTEMS_RW:-}"' \
	>"$out_file" 2>"$err_file"
    rc=$?
    set -e
    out=$(cat "$out_file")
    err=$(cat "$err_file")
    rw=${out#RW=[}
    rw=${rw%]*}
    return $rc
}

echo "=== lota-proton-hook: what the game's container is given ==="

# session dir as under Steam: agent socket dir beside the hook's dir
RUNTIME="$WORK_DIR/run"
mkdir -p "$RUNTIME/lota"
: >"$RUNTIME/lota/lota.sock"

# 1. The wrapper alone shares both directories.
run_wrapper XDG_RUNTIME_DIR="$RUNTIME" \
	    LOTA_HOOK_SOCKET="$RUNTIME/lota/lota.sock"
check "the hook's own directory is shared" \
      shares "$rw" "$RUNTIME/lota-hook"
check "the socket's directory is shared" \
      shares "$rw" "$RUNTIME/lota"

# 2. Created on the host first, or there is nothing to bind.
check "the hook's directory is created on the host" \
      test -d "$RUNTIME/lota-hook"
check "and it is the player's alone" \
      test "$(stat -c %a "$RUNTIME/lota-hook")" = "700"

# 3. A player's own share is kept.
run_wrapper XDG_RUNTIME_DIR="$RUNTIME" \
	    LOTA_HOOK_SOCKET="$RUNTIME/lota/lota.sock" \
	    PRESSURE_VESSEL_FILESYSTEMS_RW="/opt/mymods"
check "an existing share survives" shares "$rw" "/opt/mymods"
check "and the hook's directory is added to it" \
      shares "$rw" "$RUNTIME/lota-hook"

# 4. The setup script's launch string already names both: no duplicates.
run_wrapper XDG_RUNTIME_DIR="$RUNTIME" \
	    LOTA_HOOK_SOCKET="$RUNTIME/lota/lota.sock" \
	    PRESSURE_VESSEL_FILESYSTEMS_RW="$RUNTIME/lota:$RUNTIME/lota-hook"
check "a directory already shared is shared once" \
      shares_once "$rw" "$RUNTIME/lota-hook"
check "and so is the socket's" shares_once "$rw" "$RUNTIME/lota"

# 5. LOTA_HOOK_TOKEN_DIR is followed.
OVERRIDE="$WORK_DIR/elsewhere"
run_wrapper XDG_RUNTIME_DIR="$RUNTIME" LOTA_HOOK_TOKEN_DIR="$OVERRIDE"
check "the overridden token directory is shared" shares "$rw" "$OVERRIDE"
check "the default is not shared instead" denies "$rw" "$RUNTIME/lota-hook"
check "the overridden directory is created" test -d "$OVERRIDE"

# 6. No session: the library's /tmp/lota-<uid> fallback is shared.
run_wrapper XDG_RUNTIME_DIR=
check "the fallback directory is shared when there is no session" \
      shares "$rw" "/tmp/lota-$(id -u)"

# 7. A missing socket dir is left out: a nonexistent path fails the
#    container build, and the agent owns that directory.
run_wrapper XDG_RUNTIME_DIR="$RUNTIME" \
	    LOTA_HOOK_SOCKET="$WORK_DIR/no-such-dir/lota.sock"
check "a missing socket directory is left out" \
      denies "$rw" "$WORK_DIR/no-such-dir"
check "and the hook's directory is still shared" \
      shares "$rw" "$RUNTIME/lota-hook"

# 8. LOTA_HOOK_DISABLE=1 leaves the container's mounts untouched.
run_wrapper XDG_RUNTIME_DIR="$RUNTIME" LOTA_HOOK_DISABLE=1 \
	    PRESSURE_VESSEL_FILESYSTEMS_RW="/opt/mymods"
check "DISABLE=1: nothing of LOTA's is shared" denies "$rw" "lota"
check "DISABLE=1: the player's own share is untouched" \
      says "$rw" "/opt/mymods"

# 9. Missing library: nothing to share, only the library warning.
MISSING_RUNTIME="$WORK_DIR/run-nolib"
mkdir -p "$MISSING_RUNTIME"
set +e
nolib_out=$(env XDG_RUNTIME_DIR="$MISSING_RUNTIME" \
	        LOTA_HOOK_LIB_PATH="$WORK_DIR/no-such-hook.so" \
	        "$WRAPPER" /bin/sh -c \
	        'printf "RW=[%s]\n" "${PRESSURE_VESSEL_FILESYSTEMS_RW:-}"' 2>/dev/null)
set -e
check "a missing library shares nothing" denies "$nolib_out" "lota-hook"
check "and creates nothing" test ! -d "$MISSING_RUNTIME/lota-hook"

echo ""
if [[ $failures -eq 0 ]]; then
    echo "[proton-hook-shares] OK"
    exit 0
fi
echo "[proton-hook-shares] $failures check(s) failed" >&2
exit 1
