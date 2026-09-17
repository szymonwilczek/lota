#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Szymon Wilczek
#
# tests/integration/test_veristat_gate.sh
#
# Checks what scripts/veristat-gate.sh prints when a program does not pass,
# using stand-in veristat and bpftool that answer as the packaged tools do on
# the deployment kernel.
# Like veristat 0.5.1, the stand-in zeroes the row and marks the program failing
# in verbose mode, whatever the verifier said.
#
# Requires:
#   - bash, sh, awk
#
# Unprivileged; writes only under a temporary directory.

set -euo pipefail

export LC_ALL=C

REPO_DIR=$(cd "$(dirname "$0")/../.." && pwd)
GATE="$REPO_DIR/scripts/veristat-gate.sh"

WORK_DIR=$(mktemp -d)
trap 'rm -rf "$WORK_DIR"' EXIT

STUBS="$WORK_DIR/bin"
mkdir -p "$STUBS"

PROGS="lota_bpf lota_bpf_map lota_bprm_check_security lota_file_mprotect
lota_file_open lota_kernel_load_data lota_kernel_read_file lota_mmap_file
lota_move_mount lota_ptrace_access_check lota_sb_mount lota_task_fix_setuid
lota_task_free lota_task_kill"

# veristat: one table row per program, shaped by $STUB_SCENARIO.
cat >"$STUBS/veristat" <<'EOF'
#!/bin/sh
echo "$*" >>"$STUB_LOG/veristat.args"
verbose=0
for arg in "$@"; do
	case "$arg" in
	-v* | --verbose) verbose=1 ;;
	esac
done
echo "Processing 'lota_lsm.bpf.o'..."
echo "File            Program                   Verdict  Duration (us)  Insns  States  Program size  Jited size"
if [ "$verbose" = 1 ]; then
	echo "   0        0  failure              0      0       0             0           0"
	echo "Done. Processed 1 files, 0 programs. Skipped 0 files, 13 programs."
	exit 0
fi
for p in $STUB_PROGS; do
	case "$STUB_SCENARIO:$p" in
	reject:lota_task_free)
		echo "lota_lsm.bpf.o  $p  failure  123  20  1  29  0" ;;
	reject:* | pass:*)
		echo "lota_lsm.bpf.o  $p  success  2000  800  40  700  3900" ;;
	esac
done
echo "Done. Processed 1 files, 0 programs. Skipped 14 files, 0 programs."
EOF

# bpftool: a whole-object load, answered the way libbpf answers it.
cat >"$STUBS/bpftool" <<'EOF'
#!/bin/sh
echo "$*" >>"$STUB_LOG/bpftool.args"
case "$STUB_SCENARIO" in
reject)
	cat >&2 <<'LOG'
libbpf: prog 'lota_task_free': BPF program load failed: -EACCES
libbpf: prog 'lota_task_free': -- BEGIN PROG LOAD LOG --
0: R1=ctx() R10=fp0
; int BPF_PROG(lota_task_free, struct task_struct *task) @ lota_lsm.bpf.c:2078
; pid += *(volatile u32 *)(unsigned long)tgid; @ lota_lsm.bpf.c:2089
19: (61) r2 = *(u32 *)(r1 +0)
R1 invalid mem access 'scalar'
processed 20 insns (limit 1000000) max_states_per_insn 0 total_states 1 peak_states 1 mark_read 0
-- END PROG LOAD LOG --
libbpf: prog 'lota_task_free': failed to load: -EACCES
libbpf: failed to load object 'lota_lsm.bpf.o'
Error: failed to load object file
LOG
	exit 255
	;;
esac
exit 0
EOF

for tool in mount umount; do
    cat >"$STUBS/$tool" <<'EOF'
#!/bin/sh
exit 0
EOF
done

chmod +x "$STUBS"/*

touch "$WORK_DIR/lota_lsm.bpf.o"

# run_gate SCENARIO: the gate's status, output in $WORK_DIR/SCENARIO.out
run_gate() {
    local scenario=$1 rc=0
    mkdir -p "$WORK_DIR/$scenario"
    PATH="$STUBS:$PATH" STUB_SCENARIO="$scenario" STUB_PROGS="$PROGS" \
	STUB_LOG="$WORK_DIR/$scenario" \
	sh "$GATE" "$WORK_DIR/lota_lsm.bpf.o" \
	>"$WORK_DIR/$scenario.out" 2>&1 || rc=$?
    echo "$rc"
}

fail() {
    echo "[veristat-gate] FAIL: $1" >&2
    sed -n '1,60p' "$WORK_DIR/$2.out" >&2 || true
    exit 1
}

# the lines between a group header naming $1 and the next ::endgroup::
group_block() {
    awk -v prog="$1" '
		$0 == "::group::verifier log: " prog { inb = 1; next }
		inb && $0 == "::endgroup::" { exit }
		inb { print }
	' "$2"
}

echo "[veristat-gate] an object that passes leaves the gate green"
rc=$(run_gate pass)
[[ "$rc" == 0 ]] || fail "gate reported $rc for an object that passes" pass
grep -q "all programs pass the kernel verifier" "$WORK_DIR/pass.out" ||
    fail "gate did not say every program passed" pass

echo "[veristat-gate] a rejection prints the verifier's own log"
rc=$(run_gate reject)
[[ "$rc" == 1 ]] || fail "gate reported $rc for a rejected program" reject
grep -q "::error::veristat: the BPF verifier rejected:.*lota_task_free" \
     "$WORK_DIR/reject.out" ||
    fail "gate did not name the rejected program" reject
block=$(group_block lota_task_free "$WORK_DIR/reject.out")
grep -q "R1 invalid mem access 'scalar'" <<<"$block" ||
    fail "the log block for lota_task_free has no verifier message" reject
grep -q "lota_lsm.bpf.c:2089" <<<"$block" ||
    fail "the log block for lota_task_free names no source line" reject

echo "[veristat-gate] no block contradicts the summary above it"
if grep -Eq -- '(^| )-v|--verbose' "$WORK_DIR/reject/veristat.args"; then
    fail "gate asked veristat for verbose output: $(tr '\n' ';' <"$WORK_DIR/reject/veristat.args")" reject
fi
if grep -Eq '^ *0 +0 +failure' "$WORK_DIR/reject.out"; then
    fail "gate printed a zeroed failure row" reject
fi

echo "[veristat-gate] PASS"
