#!/bin/bash
# SPDX-License-Identifier: MIT
#
# LOTA block-demo: drive the victim against a running agent.
#
# Assumes the operator has already brought up a full lota-agent
# instance with the BPF LSM programs attached and the enforcement
# mode set to enforce. The diagnostic --test-* paths do NOT load
# BPF and cannot drive this demo; see README.rst for the supported
# bring-up sequence.
#
# Stages:
#   1. Verify the build artifacts are present and the agent IPC
#      socket is reachable.
#   2. Run block_victim ${BUILD_DIR}/examples/evil.so:
#        rc=0  evil.so blocked   -> demo passed
#        rc=1  evil.so loaded    -> demo failed
#        rc=2  inconclusive      -> see stderr for the agent diag
#   3. Tail the kernel journal entries the BPF program emitted
#      while the demo ran, so the operator can audit the block
#      independently of the victim exit code.
#
# BUILD_DIR can be overridden in the environment to point at an
# out-of-tree build root; defaults to $REPO_DIR/build to match the
# Makefile default.
#
# The script is non-destructive: it never touches the agent
# config, the systemd units, or any policy files.

set -euo pipefail

REPO_DIR=$(cd "$(dirname "$0")/../.." && pwd)
BUILD_DIR="${BUILD_DIR:-$REPO_DIR/build}"
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
