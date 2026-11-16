#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Szymon Wilczek
#
# tests/integration/test_examples_cli.sh
#
# The example programs refuse a bad value instead of reading a number off
# its front, and the example scripts name a missing tool before they start.
#
# Requires:
#   - bash, and the examples built ('make examples')
#
# Runs unprivileged; no agent or server is reached.

set -euo pipefail

export LC_ALL=C

REPO_DIR=$(cd "$(dirname "$0")/../.." && pwd)
BUILD_DIR="${BUILD_DIR:-${LOTA_BUILD_DIR:-$REPO_DIR/build}}"
EXAMPLES_DIR="$BUILD_DIR/examples"
DEMO_AC="$EXAMPLES_DIR/demo_anticheat"
CI_ATTEST="$EXAMPLES_DIR/lota-ci-attest"
REMEASURE="$EXAMPLES_DIR/runtime_remeasure"

for f in "$DEMO_AC" "$CI_ATTEST" "$REMEASURE"; do
    if [[ ! -x "$f" ]]; then
        echo "[examples-cli] missing artifact: $f" >&2
        exit 2
    fi
done

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

# exits_with CODE CMD...: CMD exits CODE
exits_with() {
    local want="$1" rc=0
    shift
    "$@" >/dev/null 2>&1 </dev/null || rc=$?
    [[ "$rc" -eq "$want" ]] || {
        echo "  $*: exit $rc, want $want"
        return 1
    }
}

check "demo_anticheat refuses --interval 5s" \
      exits_with 64 "$DEMO_AC" --interval 5s --once
check "demo_anticheat refuses LOTA_DEMO_INTERVAL_SEC=5s" \
      exits_with 64 env LOTA_DEMO_INTERVAL_SEC=5s "$DEMO_AC" --once
check "demo_anticheat refuses LOTA_DEMO_INTERVAL_SEC=abc" \
      exits_with 64 env LOTA_DEMO_INTERVAL_SEC=abc "$DEMO_AC" --once

for t in abc 0 -1 5s; do
    check "lota-ci-attest refuses --timeout $t" \
        exits_with 2 "$CI_ATTEST" --gate http://127.0.0.1:9 \
        --out "$WORK_DIR/secret" --timeout "$t"
done

# a manifest line as long as a path may be, and one character longer
long_path() { printf '/%*s' "$(($1 - 1))" '' | tr ' ' a; }
takes_line() {
    local len="$1" nl="$2" m="$WORK_DIR/manifest" out
    printf "%s$nl" "$(long_path "$len")" >"$m"
    out=$("$REMEASURE" --manifest "$m" 2>&1 </dev/null) || true
    ! grep -q 'line exceeds\|path too long' <<<"$out"
}
check "runtime_remeasure takes a 4095-character line" takes_line 4095 '\n'
check "runtime_remeasure takes one with no newline" takes_line 4095 ''
check "runtime_remeasure refuses a 4096-character line" \
    eval '! takes_line 4096 "\n"'
check "runtime_remeasure refuses one with no newline" \
    eval '! takes_line 4096 ""'

# run.sh with every tool but openssl on PATH
STUB_BIN="$WORK_DIR/bin"
mkdir -p "$STUB_BIN"
ln -s "$(command -v dirname)" "$STUB_BIN/dirname"
for tool in swtpm swtpm_setup tpm2_readpublic systemd-socket-activate; do
    printf '#!/bin/sh\nexit 0\n' >"$STUB_BIN/$tool"
    chmod 0755 "$STUB_BIN/$tool"
done
names_missing_openssl() {
    local out rc=0
    out=$(PATH="$STUB_BIN" LOTA_BUILD_DIR="$BUILD_DIR" \
        "$BASH" "$REPO_DIR/examples/ci-gate/run.sh" 2>&1) || rc=$?
    [[ "$rc" -eq 1 ]] && grep -q "missing command: openssl" <<<"$out"
}
check "ci-gate run.sh names a missing openssl" names_missing_openssl

# verify-attested.sh: a status left by a hook that is gone, and a file
# the hook writes after the watcher started
VERIFY="$REPO_DIR/examples/cs2/scenarios/verify-attested.sh"
HOOK_DIR="$WORK_DIR/hook"
HOOK_ENV=(env -u XDG_RUNTIME_DIR -u LOTA_HOOK_REFRESH_SEC)
write_status() {
    mkdir -p "$HOOK_DIR"
    printf 'LOTA_ATTESTED=1\nLOTA_OFFLINE=0\nLOTA_UPDATED=%s\n' "$1" \
        >"$HOOK_DIR/lota-status"
}
verify_once() {
    "${HOOK_ENV[@]}" LOTA_HOOK_TOKEN_DIR="$HOOK_DIR/" \
        "$BASH" "$VERIFY" --once "$@"
}
reads() {
    local want="$1" out
    shift
    out=$(verify_once "$@" 2>&1) || true
    [[ "$out" == *" $want" ]] || {
        echo "  got: $out"
        return 1
    }
}
write_status "$(date +%s)"
check "verify-attested reads a fresh status as TRUSTED" reads TRUSTED
write_status $(($(date +%s) - 181))
check "verify-attested reads a status 181s old as stale" \
    reads "OFFLINE (stale)"
check "verify-attested --max-age 300 takes a status 181s old" \
    reads TRUSTED --max-age 300
check "verify-attested exits 2 on a stale status" \
    exits_with 2 "${HOOK_ENV[@]}" LOTA_HOOK_TOKEN_DIR="$HOOK_DIR" \
    "$BASH" "$VERIFY" --once
# a status 25s old against 3 x the period the hook takes
reads_refresh() {
    local out
    out=$("${HOOK_ENV[@]}" LOTA_HOOK_REFRESH_SEC="$1" \
        LOTA_HOOK_TOKEN_DIR="$HOOK_DIR" "$BASH" "$VERIFY" --once 2>&1) ||
        true
    [[ "$out" == *" $2" ]] || {
        echo "  got: $out"
        return 1
    }
}
write_status $(($(date +%s) - 25))
check "verify-attested reads LOTA_HOOK_REFRESH_SEC=08 as 8" \
    reads_refresh 08 "OFFLINE (stale)"
check "verify-attested reads LOTA_HOOK_REFRESH_SEC=5s as 5" \
    reads_refresh 5s "OFFLINE (stale)"
check "verify-attested reads LOTA_HOOK_REFRESH_SEC=10 as 10" \
    reads_refresh 10 TRUSTED
write_status $(($(date +%s) - 200))
check "verify-attested reads LOTA_HOOK_REFRESH_SEC=2147483648 as 60" \
    reads_refresh 2147483648 "OFFLINE (stale)"
check "verify-attested refuses --max-age 0" \
    exits_with 64 "$BASH" "$VERIFY" --once --max-age 0

finds_late_file() {
    local log="$WORK_DIR/watch.log" pid ok=1
    rm -rf "$HOOK_DIR"
    "${HOOK_ENV[@]}" LOTA_HOOK_TOKEN_DIR="$HOOK_DIR" \
        "$BASH" "$VERIFY" >"$log" 2>&1 &
    pid=$!
    sleep 2
    write_status "$(date +%s)"
    for _ in $(seq 1 50); do
        grep -q ' TRUSTED$' "$log" && ok=0 && break
        sleep 0.1
    done
    kill "$pid" 2>/dev/null
    wait "$pid" 2>/dev/null || true
    grep -q "watching $HOOK_DIR/lota-status" "$log" || ok=1
    [[ $ok -eq 0 ]] || sed 's/^/  /' "$log"
    return $ok
}
check "verify-attested finds a status written after it started" \
    finds_late_file

echo ""
if [[ $failures -gt 0 ]]; then
    echo "[examples-cli] $failures check(s) failed"
    exit 1
fi
echo "[examples-cli] all checks passed"
