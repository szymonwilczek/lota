#!/bin/bash
# SPDX-License-Identifier: MIT
#
# tests/integration/test_bpf_gates.sh
#
# End-to-end verification of every BPF LSM gate that scopes to
# protected_pids. Requires:
#   - root (BPF + ptrace)
#   - a running lota-agent in enforce mode with BPF attached
#   - ${BUILD_DIR}/examples/block_victim + ${BUILD_DIR}/examples/evil.so
#     (build with `make all examples`, or set BUILD_DIR= to point
#     at an out-of-tree build root)
#
# Coverage matrix:
#   mmap_file       -> examples/block-demo/run.sh
#   file_mprotect   -> same gate, covered transitively when ld.so
#                      maps the segment RW then upgrades to RX
#   ptrace_access_check -> this script, "ptrace block" stage
#   task_kill       -> this script, "signal block" stage
#
# Each stage spawns a small victim process that:
#   1. lota_connect()
#   2. lota_protect_self()
#   3. Sleeps until SIGTERM
# A separate attacker process attempts the hostile operation and
# the script asserts the kernel returned -EPERM.
#
# The script is intentionally minimal: it exercises the gates,
# does NOT measure throughput, and does NOT depend on any
# verifier wiring beyond the local IPC socket.

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
	echo "[bpf-gates] must run as root (ptrace + BPF visibility)" >&2
	exit 2
fi

REPO_DIR=$(cd "$(dirname "$0")/../.." && pwd)
BUILD_DIR="${BUILD_DIR:-$REPO_DIR/build}"
VICTIM_BIN="$BUILD_DIR/examples/block_victim"
EVIL_SO="$BUILD_DIR/examples/evil.so"
SOCKET="/run/lota/lota.sock"

if [[ ! -S "$SOCKET" ]]; then
	echo "[bpf-gates] agent socket not found: $SOCKET" >&2
	echo "[bpf-gates] start lota-agent in enforce mode first" >&2
	exit 2
fi

for f in "$VICTIM_BIN" "$EVIL_SO"; do
	if [[ ! -f "$f" ]]; then
		echo "[bpf-gates] missing artifact: $f" >&2
		echo "[bpf-gates] run 'make all examples' first" >&2
		exit 2
	fi
done

# The victim runs as root and reaches the agent over the primary
# /run/lota/lota.sock. That socket lives in a 0750 root:root runtime
# dir, so an unprivileged victim would need a per-UID listener
# (lota-steam-setup --register-uid) plus XDG_RUNTIME_DIR wiring that
# this self-contained gate test deliberately avoids. The LSM gates
# key off the protected-PID set, not the actor's credentials, so a
# root victim is the strongest target: it proves a root attacker is
# still rejected.
PASS=0
FAIL=0

note() { printf '[bpf-gates] %s\n' "$*"; }
ok()   { printf '[bpf-gates] \033[32mPASS\033[0m %s\n' "$*"; PASS=$((PASS+1)); }
bad()  { printf '[bpf-gates] \033[31mFAIL\033[0m %s\n' "$*" >&2; FAIL=$((FAIL+1)); }

#
# Stage 1: security_mmap_file -- file-backed PROT_EXEC mapping
# of an unauthorised .so from inside a protected process.
#
note "stage 1: security_mmap_file (delegated to block-demo run.sh)"
if "$VICTIM_BIN" "$EVIL_SO" >/dev/null 2>&1; then
	ok "mmap_file blocks unauthorised dlopen from protected task"
else
	rc=$?
	if [[ $rc -eq 1 ]]; then
		bad "mmap_file allowed evil.so (gate did not fire)"
	else
		bad "mmap_file stage inconclusive (rc=$rc)"
	fi
fi

#
# Stage 2: ptrace_access_check -- external ptrace against a
# registered PID. Spawns block_victim which self-protects, then
# the parent (this script) attempts gdb-style attach using the
# strace binary as a probe. The kernel returns -EPERM, strace
# exits non-zero with "Operation not permitted".
#
note "stage 2: ptrace_access_check (external attach to protected PID)"
"$VICTIM_BIN" --sleep \
	>/tmp/bpf-gates-victim.log 2>&1 &
VICTIM_PID=$!

# wait for the victim's self-register banner so we don't race the BPF map
for _ in $(seq 1 50); do
	if grep -q "registered self into protected_pids" \
		/tmp/bpf-gates-victim.log 2>/dev/null; then
		break
	fi
	sleep 0.1
done

if ! grep -q "registered self into protected_pids" \
	/tmp/bpf-gates-victim.log 2>/dev/null; then
	bad "victim never registered (no ptrace stage)"
elif ! kill -0 "$VICTIM_PID" 2>/dev/null; then
	bad "victim PID $VICTIM_PID already dead before ptrace stage"
else
	# strace returns 0 only on a successful attach + detach. Under
	# the LSM gate it returns non-zero with "Operation not permitted"
	# in stderr; the trace=none + -o /dev/null pair keeps stdout
	# clean and prevents strace from outliving the victim if the
	# kernel accidentally lets the attach through.
	if timeout 2 strace -p "$VICTIM_PID" -e trace=none \
		-o /dev/null </dev/null \
		2>/tmp/bpf-gates-strace.err; then
		bad "ptrace attach succeeded against protected PID"
	elif grep -q "Operation not permitted\|EPERM" \
		/tmp/bpf-gates-strace.err; then
		ok "ptrace attach rejected with EPERM"
	else
		bad "ptrace stage inconclusive; strace err:"
		cat /tmp/bpf-gates-strace.err >&2
	fi
fi

#
# Stage 3: task_kill -- external SIGKILL against the same
# protected victim. The kernel returns -EPERM and `kill` exits
# with status 1 + "Operation not permitted".
#
note "stage 3: task_kill (external signal to protected PID)"
if kill -KILL "$VICTIM_PID" 2>/tmp/bpf-gates-kill.err; then
	bad "SIGKILL delivered to protected PID"
else
	if grep -q "Operation not permitted\|EPERM" \
		/tmp/bpf-gates-kill.err; then
		ok "SIGKILL rejected with EPERM"
	else
		bad "task_kill stage inconclusive; kill err:"
		cat /tmp/bpf-gates-kill.err >&2
	fi
fi

# tear down the long-lived victim
kill -TERM "$VICTIM_PID" 2>/dev/null || true
wait "$VICTIM_PID" 2>/dev/null || true

echo ""
note "summary: ${PASS} passed, ${FAIL} failed"
if [[ $FAIL -eq 0 ]]; then
	exit 0
fi
exit 1
