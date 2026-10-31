#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Szymon Wilczek
#
# tests/integration/test_report_wire_sizes.sh
#
# Compares report wire sizes compiled from the C headers with the
# constants in src/verifier/types/report.go. src/agent/report.c asserts
# only against Go literals, so a Go-side drift slips through and the
# verifier sees a truncated report instead of a mismatch.
#
# Requires: a C compiler, the in-tree headers, report.go. Unprivileged.

set -euo pipefail

export LC_ALL=C

REPO_DIR=$(cd "$(dirname "$0")/../.." && pwd)
REPORT_GO="$REPO_DIR/src/verifier/types/report.go"
CC="${CC:-cc}"

if ! command -v "$CC" >/dev/null 2>&1; then
    echo "[report-wire-sizes] missing compiler: $CC" >&2
    exit 2
fi

if [[ ! -f "$REPORT_GO" ]]; then
    echo "[report-wire-sizes] missing file: $REPORT_GO" >&2
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

# C side: sizes from the compiler and headers the agent is built with
cat >"$WORK_DIR/sizes.c" <<'PROBE'
#include <stdio.h>

#include "attestation.h"
#include "lota.h"

int main(void)
{
	printf("ExecEventSize %zu\n", sizeof(struct lota_exec_event));
	printf("ESRTWireSize %zu\n", sizeof(struct lota_esrt));
	printf("FixedReportSize %zu\n",
	       sizeof(struct lota_attestation_report));
	return 0;
}
PROBE

if ! "$CC" -I"$REPO_DIR/include" -o "$WORK_DIR/sizes" "$WORK_DIR/sizes.c" \
     2>"$WORK_DIR/cc.err"; then
    echo "[report-wire-sizes] could not build the probe:" >&2
    cat "$WORK_DIR/cc.err" >&2
    exit 2
fi

"$WORK_DIR/sizes" >"$WORK_DIR/sizes.txt"

# Go side: matches `const X = N` and grouped-block `X = N` lines
go_const() {
    local name="$1"
    sed -n -E "s/^[[:space:]]*(const[[:space:]]+)?${name}[[:space:]]*=[[:space:]]*([0-9]+).*/\2/p" \
	"$REPORT_GO" | head -1
}

echo "=== the report's sizes, from both ends ==="

while read -r name c_size; do
    go_size=$(go_const "$name")

    check "$name is stated in the verifier" test -n "$go_size"
    [[ -n "$go_size" ]] || continue

    check "$name: the verifier's $go_size matches the struct's $c_size" \
	  test "$go_size" = "$c_size"
done <"$WORK_DIR/sizes.txt"

echo ""
if [[ $failures -eq 0 ]]; then
    echo "[report-wire-sizes] OK"
    exit 0
fi
echo "[report-wire-sizes] $failures check(s) failed" >&2
exit 1
