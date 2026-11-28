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

. "$(dirname "$0")/../lib/test.sh"
test_begin "report wire sizes"

export LC_ALL=C

REPO_DIR=$(cd "$(dirname "$0")/../.." && pwd)
REPORT_GO="$REPO_DIR/src/verifier/types/report.go"
CC="${CC:-cc}"

if ! command -v "$CC" >/dev/null 2>&1; then
    FAIL "missing compiler: %s" "$CC"
    test_end
fi

if [[ ! -f "$REPORT_GO" ]]; then
    FAIL "missing file: %s" "$REPORT_GO"
    test_end
fi

WORK_DIR=$(mktemp -d)
test_cleanup 'rm -rf "$WORK_DIR"'

# C side: sizes from the compiler and headers the agent is built with
cat >"$WORK_DIR/sizes.c" <<'PROBE'
#include <stdio.h>

#include "attestation.h"
#include "lota.h"

int main(void)
{
	printf("ESRTWireSize %zu\n", sizeof(struct lota_esrt));
	printf("FixedReportSize %zu\n",
	       sizeof(struct lota_attestation_report));
	return 0;
}
PROBE

TEST "the probe builds"
if ! "$CC" -I"$REPO_DIR/include" -o "$WORK_DIR/sizes" "$WORK_DIR/sizes.c" \
     2>"$WORK_DIR/cc.err"; then
    FAIL "%s" "$(cat "$WORK_DIR/cc.err")"
    test_end
fi

"$WORK_DIR/sizes" >"$WORK_DIR/sizes.txt"

# Go side: matches `const X = N` and grouped-block `X = N` lines
go_const() {
    local name="$1"
    sed -n -E "s/^[[:space:]]*(const[[:space:]]+)?${name}[[:space:]]*=[[:space:]]*([0-9]+).*/\2/p" \
	"$REPORT_GO" | head -1
}

while read -r name c_size; do
    go_size=$(go_const "$name")

    TEST "$name is stated in the verifier"
    test -n "$go_size" || FAIL
    [[ -n "$go_size" ]] || continue

    TEST "$name: the verifier's $go_size matches the struct's $c_size"
    test "$go_size" = "$c_size" || FAIL
done <"$WORK_DIR/sizes.txt"

test_end
