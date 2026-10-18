#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Szymon Wilczek
#
# tests/integration/test_proton_hook_disable.sh
#
# What the Proton launch wrapper does with the two escape hatches it documents.
# Both end the same way -- the game is exec'd with LD_PRELOAD untouched and one
# warning on stderr -- and they are the only thing standing between a player
# and a launch the preload breaks, so they are driven through the script.
#
# The library honours LOTA_HOOK_DISABLE as well, but by the time it can it is
# already mapped into the game; the wrapper's answer is the one that keeps it out.
#
# Requires:
#   - bash, and a writable temp directory
#
# Runs unprivileged and loads nothing: the "library" the wrapper finds is a file
# in the temp directory, named through LOTA_HOOK_LIB_PATH, and the command it
# wraps only prints the environment it was handed.

set -euo pipefail

export LC_ALL=C

REPO_DIR=$(cd "$(dirname "$0")/../.." && pwd)
WRAPPER="$REPO_DIR/scripts/lota-proton-hook"

if [[ ! -x "$WRAPPER" ]]; then
    echo "[proton-hook-disable] missing artifact: $WRAPPER" >&2
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

# A library the wrapper can find, so every case below is decided by the switch.
# It is an empty file and not a loadable object: nothing here loads it,
# and the assertions read the LD_PRELOAD the game was handed.
LIB="$WORK_DIR/liblota_wine_hook.so"
: >"$LIB"

AMBIENT_PRELOAD=$(/bin/sh -c 'printf "%s" "${LD_PRELOAD:-}"')

own_preload() {
    local entry kept=""
    local -a entries ambient

    IFS=': ' read -ra ambient <<<"$AMBIENT_PRELOAD"
    IFS=': ' read -ra entries <<<"$1"
    for entry in "${entries[@]}"; do
        [[ " ${ambient[*]} " == *" $entry "* ]] && continue
        kept+="${kept:+:}$entry"
    done
    printf '%s' "$kept"
}

# The wrapped command reports the LD_PRELOAD it was exec'd with,
# which is the whole question. stdout and stderr are captured apart so a warning
# cannot be mistaken for the payload.
run_wrapper() {
    local out_file="$WORK_DIR/out"
    local err_file="$WORK_DIR/err"

    set +e
    env "$@" LOTA_HOOK_LIB_PATH="$LIB" \
        "$WRAPPER" /bin/sh -c 'printf "%s\n" "${LD_PRELOAD:-}"' \
        >"$out_file" 2>"$err_file"
    rc=$?
    set -e
    out="LD_PRELOAD=[$(own_preload "$(cat "$out_file")")]"
    err=$(cat "$err_file")
    return $rc
}

echo "=== lota-proton-hook: the switches that keep the hook out ==="

# the default: the library is found and preloaded
run_wrapper LOTA_HOOK_QUIET=
check "unset: the wrapper preloads the library" says "$out" "LD_PRELOAD=\[$LIB\]"
check "unset: no warning is printed" denies "$err" "LOTA_HOOK_DISABLE"

# the documented value
run_wrapper LOTA_HOOK_DISABLE=1
check "DISABLE=1: LD_PRELOAD reaches the game empty" says "$out" 'LD_PRELOAD=\[\]'
check "DISABLE=1: the library is not preloaded" denies "$out" "$LIB"
check "DISABLE=1: one warning names the switch" says "$err" "LOTA_HOOK_DISABLE"

# Count the wrapper's own lines, not every line on the channel:
# the stub library is not loadable, so when it does reach LD_PRELOAD the dynamic
# loader writes a line of its own, and counting those would score a wrapper that
# said nothing.
check "DISABLE=1: the wrapper writes one line" \
    test "$(grep -c "^lota-proton-hook:" <<<"$err")" -eq 1

# the value the library also accepts, so the two layers agre
run_wrapper LOTA_HOOK_DISABLE=true
check "DISABLE=true: LD_PRELOAD reaches the game empty" says "$out" 'LD_PRELOAD=\[\]'
check "DISABLE=true: one warning names the switch" says "$err" "LOTA_HOOK_DISABLE"

# anything else is not the switch:
#   an unset-shaped value must not disable the hook,
#   or a player who exports 0 loses attestation silently
run_wrapper LOTA_HOOK_DISABLE=0
check "DISABLE=0: the library is still preloaded" says "$out" "LD_PRELOAD=\[$LIB\]"
run_wrapper LOTA_HOOK_DISABLE=""
check "DISABLE=empty: the library is still preloaded" says "$out" "LD_PRELOAD=\[$LIB\]"

# player's own LD_PRELOAD survives the pass-through untouched:
#   the switch removes LOTA from the launch, not everything else
run_wrapper LOTA_HOOK_DISABLE=1 LD_PRELOAD=/lib64/libfoo.so
check "DISABLE=1: an existing LD_PRELOAD is passed through" \
    says "$out" 'LD_PRELOAD=\[/lib64/libfoo.so\]'

# the other documented fallback still behaves, and says something different:
#   the two paths must not be told apart by guesswork
set +e
missing_err=$(env LOTA_HOOK_LIB_PATH="$WORK_DIR/no-such-hook.so" \
    "$WRAPPER" /bin/true 2>&1 >/dev/null)
set -e
check "missing library: the wrapper still warns" says "$missing_err" "not found"
check "missing library: the warning is not the disable one" \
    denies "$missing_err" "LOTA_HOOK_DISABLE"

echo ""
if [[ $failures -eq 0 ]]; then
    echo "[proton-hook-disable] OK"
    exit 0
fi
echo "[proton-hook-disable] $failures check(s) failed" >&2
exit 1
