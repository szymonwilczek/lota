#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Szymon Wilczek
#
# Run the L1 micro-benchmark suite (C + Go) and, when benchstat is present,
# print a per-module statistical summary. Raw output lands in
# benchmarks/results/ for archival and benchstat comparison across runs.
#
# Usage: benchmarks/scripts/run_all.sh
# Env:   BENCH_COUNT (Go -count; default 10), BENCH_TIME (Go -benchtime).

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

RESULTS="benchmarks/results"
: "${BENCH_COUNT:=10}"
export BENCH_COUNT

echo "=== LOTA benchmark suite (L1: C + Go micro) ==="
echo "host: $(uname -srm)"
echo "cpu : $(grep -m1 'model name' /proc/cpuinfo 2>/dev/null | cut -d: -f2- | sed 's/^ //' || echo unknown)"
echo "go  : $(go version 2>/dev/null || echo 'go not found')"
echo

make bench-c
make bench-go BENCH_COUNT="$BENCH_COUNT"

echo
if command -v benchstat >/dev/null 2>&1; then
	echo "=== benchstat summary (Go) ==="
	for f in "$RESULTS"/go-*.txt; do
		[ -e "$f" ] || continue
		echo "-- $(basename "$f") --"
		benchstat "$f" || true
	done
else
	cat <<'EOF'
benchstat not installed; raw Go results are in benchmarks/results/go-*.txt.
Install it for statistical summaries and run-to-run comparison:
    go install golang.org/x/perf/cmd/benchstat@latest
EOF
fi

echo
echo "Raw results: $RESULTS/"
echo "C results (machine-readable): $RESULTS/c-sdk.json"
