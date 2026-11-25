#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Szymon Wilczek
#
# Runs block_victim on evil.so against a lota-agent already running in
# enforce mode with strict_mmap; the --test-* modes attach no BPF.
# Exits 0 when dlopen of evil.so fails, 1 when it loads, 2 otherwise.
# The build root is $BUILD_DIR, else $LOTA_BUILD_DIR, else build/ in the tree.

set -euo pipefail

REPO_DIR=$(cd "$(dirname "$0")/../.." && pwd)
BUILD_DIR="${BUILD_DIR:-${LOTA_BUILD_DIR:-$REPO_DIR/build}}"
EXAMPLES_BUILD="$BUILD_DIR/examples"
VICTIM_BIN="$EXAMPLES_BUILD/block_victim"
EVIL_SO="$EXAMPLES_BUILD/evil.so"
SOCKET="/run/lota/lota.sock"

for f in "$VICTIM_BIN" "$EVIL_SO"; do
    if [[ ! -f "$f" ]]; then
	echo "[block-demo] missing artifact: $f" >&2
	echo "[block-demo] run 'make all examples' first" >&2
	exit 2
    fi
done

if [[ ! -S "$SOCKET" ]]; then
    echo "[block-demo] agent socket not found: $SOCKET" >&2
    echo "[block-demo] start lota-agent in enforce mode first;" >&2
    echo "[block-demo] see examples/block-demo/README.rst" >&2
    exit 2
fi

since_ts=$(date +%s)

echo "[block-demo] launching victim against $SOCKET"
set +e
"$VICTIM_BIN" "$EVIL_SO"
victim_rc=$?
set -e

echo ""
echo "[block-demo] kernel-side journal since the demo started:"
journalctl -u lota-agent --since "@$since_ts" --no-pager 2>/dev/null \
    | grep -E "MMAP_BLOCKED|ANON_EXEC_BLOCKED|BLOCK|EPERM" \
    || echo "  (no block events captured -- did the agent attach BPF?)"

case "$victim_rc" in
    0)
	echo ""
	echo "[block-demo] PASS: evil.so blocked by BPF LSM gate"
	exit 0
	;;
    1)
	echo ""
	echo "[block-demo] FAIL: evil.so loaded (gate did not fire)" >&2
	echo "[block-demo] confirm: enforce mode + strict_mmap + BPF attached" >&2
	exit 1
	;;
    *)
	echo ""
	echo "[block-demo] INCONCLUSIVE: victim exit=$victim_rc" >&2
	exit 2
	;;
esac
