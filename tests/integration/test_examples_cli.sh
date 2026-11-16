#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Szymon Wilczek
#
# tests/integration/test_examples_cli.sh
#
# The example programs refuse a bad value instead of reading a number off
# its front.
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

for f in "$DEMO_AC" "$CI_ATTEST"; do
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

echo ""
if [[ $failures -gt 0 ]]; then
    echo "[examples-cli] $failures check(s) failed"
    exit 1
fi
echo "[examples-cli] all checks passed"
