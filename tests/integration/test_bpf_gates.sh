#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Szymon Wilczek
#
# tests/integration/test_bpf_gates.sh
#
# End-to-end verification of every BPF LSM gate that scopes to
# protected_pids. Requires:
#   - root (BPF + ptrace)
#   - a running lota-agent in enforce mode with BPF attached
#   - ${BUILD_DIR}/examples/block_victim + ${BUILD_DIR}/examples/evil.so
#     (build with `make all examples`, or set BUILD_DIR= to point
#     at an out-of-tree build root).
#     Unset, BUILD_DIR follows LOTA_BUILD_DIR, which a make recipe exports
#     as the directory that build used.
#
# Coverage matrix:
#   mmap_file       -> examples/block-demo/run.sh
#   file_mprotect   -> same gate, covered transitively when ld.so
#                      maps the segment RW then upgrades to RX
#   ptrace_access_check -> this script, "ptrace block" stage
#   task_kill       -> this script, "signal" stage
#
# Each stage spawns a small victim process that:
#   1. lota_connect()
#   2. lota_protect_self()
#   3. Sleeps until its stdin closes
# A separate attacker process attempts the hostile operation and
# the script asserts the kernel returned -EPERM. A signal is not
# hostile: stage 3 asserts it reaches the protected PID.
#
# The script is intentionally minimal: it exercises the gates,
# does NOT measure throughput, and does NOT depend on any
# verifier wiring beyond the local IPC socket.

set -euo pipefail

. "$(dirname "$0")/../lib/test.sh"
test_begin "bpf gates"

# Stage 2 asserts on the kernel's EPERM string emitted by strace. strerror() is localised, so for example a pl_PL host prints
# and the English grep misses a gate that fired correctly.
# Pin the C locale so the errno string is byte-stable on every host.
export LC_ALL=C

if [[ $EUID -ne 0 ]]; then
    FAIL "must run as root (ptrace + BPF visibility)"
    test_end
fi

REPO_DIR=$(cd "$(dirname "$0")/../.." && pwd)
BUILD_DIR="${BUILD_DIR:-${LOTA_BUILD_DIR:-$REPO_DIR/build}}"
VICTIM_BIN="$BUILD_DIR/examples/block_victim"
EVIL_SO="$BUILD_DIR/examples/evil.so"
SOCKET="/run/lota/lota.sock"

if [[ ! -S "$SOCKET" ]]; then
    FAIL "agent socket not found: %s" "$SOCKET"
    FAIL "start lota-agent in enforce mode first"
    test_end
fi

for f in "$VICTIM_BIN" "$EVIL_SO"; do
    if [[ ! -f "$f" ]]; then
	FAIL "missing artifact: %s" "$f"
	FAIL "run 'make all examples' first"
	test_end
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

#
# Stage 1: security_mmap_file -- file-backed PROT_EXEC mapping
# of an unauthorised .so from inside a protected process.
#
TEST "mmap_file blocks an unauthorised dlopen from a protected task"
rc=0
"$VICTIM_BIN" >/dev/null 2>&1 || rc=$?
if [[ $rc -eq 1 ]]; then
    FAIL "mmap_file allowed evil.so (gate did not fire)"
elif [[ $rc -ne 0 ]]; then
    FAIL "mmap_file stage inconclusive (rc=%d)" "$rc"
fi

#
# Stage 2: ptrace_access_check -- external ptrace against a
# registered PID. Spawns block_victim which self-protects, then
# the parent (this script) attempts gdb-style attach using the
# strace binary as a probe. The kernel returns -EPERM, strace
# exits non-zero with "Operation not permitted".
#
TEST "ptrace_access_check rejects an attach with EPERM"
# Feed the victim's stdin from a FIFO we keep open, so it outlives
# stage 2 until stage 3 signals it.
VICTIM_FIFO=$(mktemp -u /tmp/bpf-gates-victim.fifo.XXXXXX)
mkfifo "$VICTIM_FIFO"
"$VICTIM_BIN" --sleep <"$VICTIM_FIFO" \
	      >/tmp/bpf-gates-victim.log 2>&1 &
VICTIM_PID=$!
exec {VICTIM_IN}>"$VICTIM_FIFO"

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
    FAIL "victim never registered (no ptrace stage)"
elif ! kill -0 "$VICTIM_PID" 2>/dev/null; then
    FAIL "victim PID %d already dead before ptrace stage" "$VICTIM_PID"
else
    # strace returns 0 only on a successful attach + detach. Under
    # the LSM gate it returns non-zero with "Operation not permitted"
    # in stderr; the trace=none + -o /dev/null pair keeps stdout
    # clean and prevents strace from outliving the victim if the
    # kernel accidentally lets the attach through.
    if timeout 2 strace -p "$VICTIM_PID" -e trace=none \
	       -o /dev/null </dev/null \
	       2>/tmp/bpf-gates-strace.err; then
	FAIL "ptrace attach succeeded against protected PID"
    elif ! grep -q "Operation not permitted\|EPERM" \
	   /tmp/bpf-gates-strace.err; then
	FAIL "ptrace stage inconclusive; strace err:"
	FAIL "%s" "$(cat /tmp/bpf-gates-strace.err)"
    fi
fi

#
# Stage 3: task_kill -- external SIGKILL against the same
# protected victim. Only the agent is guarded against signals;
# a killed title cheats in nothing, so the signal is delivered
# and recorded.
#
TEST "task_kill delivers SIGKILL to a protected PID"
if ! kill -KILL "$VICTIM_PID" 2>/tmp/bpf-gates-kill.err; then
    FAIL "SIGKILL to protected PID refused:"
    FAIL "%s" "$(cat /tmp/bpf-gates-kill.err)"
else
    set +e
    wait "$VICTIM_PID" 2>/dev/null
    rc=$?
    set -e
    [[ $rc -eq 137 ]] || FAIL "victim did not die of SIGKILL (rc=%d)" "$rc"
fi

exec {VICTIM_IN}>&-
wait "$VICTIM_PID" 2>/dev/null || true
rm -f "$VICTIM_FIFO"

test_end
