#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Szymon Wilczek
#
# tests/integration/test_bench_targets.sh
#
# Checks that `make bench-c` and `make bench-go` exit with the status of
# the runner they invoke, not tee's, using stand-in runners. Unprivileged;
# writes only under a temporary directory.
#
# Requires:
#   - bash, make, go

set -euo pipefail

export LC_ALL=C

REPO_DIR=$(cd "$(dirname "$0")/../.." && pwd)

if ! command -v go >/dev/null 2>&1; then
    echo "[bench-targets] go not installed" >&2
    exit 2
fi

WORK_DIR=$(mktemp -d)
trap 'rm -rf "$WORK_DIR"' EXIT

RESULTS="$WORK_DIR/results"
mkdir -p "$RESULTS"

# Stand-in C runner that exits with the given status.
make_c_runner() {
    local path=$1 status=$2
    cat >"$path" <<EOF
#!/bin/sh
echo "bench_sdk: stand-in runner, exiting $status"
exit $status
EOF
    chmod +x "$path"
}

# Stand-in Go module whose benchmark fails when verdict is true.
make_go_module() {
    local dir=$1 verdict=$2
    mkdir -p "$dir"
    cat >"$dir/go.mod" <<'EOF'
module benchstandin

go 1.25.8
EOF
    cat >"$dir/bench_test.go" <<EOF
package benchstandin

import "testing"

func BenchmarkStandIn(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if $verdict {
			b.Fatal("stand-in benchmark refuses to run")
		}
	}
}
EOF
}

run_make() {
    local target=$1
    shift
    local rc=0
    (cd "$REPO_DIR" && make "$target" BENCH_RESULTS="$RESULTS" "$@" \
		            >"$WORK_DIR/$target.log" 2>&1) || rc=$?
    echo "$rc"
}

fail() {
    echo "[bench-targets] FAIL: $1" >&2
    sed -n '1,40p' "$WORK_DIR/${2}.log" >&2 || true
    exit 1
}

echo "[bench-targets] a C runner that succeeds leaves the target green"
make_c_runner "$WORK_DIR/bench_ok" 0
rc=$(run_make bench-c BENCH_C_BIN="$WORK_DIR/bench_ok")
[[ "$rc" == 0 ]] || fail "make bench-c reported $rc for a runner that succeeded" bench-c
grep -q "stand-in runner" "$RESULTS/c-sdk.txt" ||
    fail "make bench-c wrote no results file" bench-c

echo "[bench-targets] a C runner that fails takes the target down"
make_c_runner "$WORK_DIR/bench_bad" 3
rc=$(run_make bench-c BENCH_C_BIN="$WORK_DIR/bench_bad")
[[ "$rc" != 0 ]] ||
    fail "make bench-c reported success for a runner that exited 3" bench-c

echo "[bench-targets] a Go benchmark that runs leaves the target green"
make_go_module "$WORK_DIR/go-ok" false
rc=$(run_make bench-go GO_BENCH_MODULES="$WORK_DIR/go-ok" \
	      BENCH_COUNT=1 BENCH_TIME=1x)
[[ "$rc" == 0 ]] || fail "make bench-go reported $rc for a benchmark that ran" bench-go
grep -q "BenchmarkStandIn" "$RESULTS/go-$(echo "$WORK_DIR/go-ok" | tr '/' '-').txt" ||
    fail "make bench-go wrote no results file" bench-go

echo "[bench-targets] a Go benchmark that fails takes the target down"
make_go_module "$WORK_DIR/go-bad" true
rc=$(run_make bench-go GO_BENCH_MODULES="$WORK_DIR/go-bad" \
	      BENCH_COUNT=1 BENCH_TIME=1x)
[[ "$rc" != 0 ]] ||
    fail "make bench-go reported success for a benchmark that refused to run" bench-go

echo "[bench-targets] PASS"
