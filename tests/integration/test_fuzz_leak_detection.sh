#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Szymon Wilczek
#
# tests/integration/test_fuzz_leak_detection.sh
#
# Checks that the C fuzz targets turn LeakSanitizer off, instead of reporting
# a crash, where ptrace attach is refused. A seccomp filter fails ptrace with
# EPERM; a leaking and a clean scratch harness built against
# fuzz/lsan_options.c run under it, and so does a built fuzz target if present.
#
# Requires:
#   - bash, clang with its libFuzzer runtime
#
# Unprivileged; writes only under a temporary directory.

set -euo pipefail

export LC_ALL=C
unset ASAN_OPTIONS LSAN_OPTIONS

REPO_DIR=$(cd "$(dirname "$0")/../.." && pwd)
BUILD_DIR="${BUILD_DIR:-${LOTA_BUILD_DIR:-$REPO_DIR/build}}"
OFF_MSG="leak detection is off for this process"

if ! command -v clang >/dev/null 2>&1; then
    echo "[fuzz-leaks] clang not installed" >&2
    exit 2
fi

WORK_DIR=$(mktemp -d)
trap 'rm -rf "$WORK_DIR"' EXIT

fail() {
    echo "[fuzz-leaks] FAIL: $1" >&2
    if [[ -n "${2:-}" && -f "$2" ]]; then
	sed -n '1,30p' "$2" >&2
    fi
    exit 1
}

# Refuses ptrace with EPERM, then runs its arguments.
cat >"$WORK_DIR/noptrace.c" <<'EOF'
#include <errno.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

int main(int argc, char **argv)
{
	struct sock_filter f[] = {
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
			 offsetof(struct seccomp_data, nr)),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_ptrace, 0, 1),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
	};
	struct sock_fprog prog = { sizeof(f) / sizeof(f[0]), f };

	if (argc < 2 || prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) ||
	    prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog))
		return 125;
	execvp(argv[1], argv + 1);
	return 126;
}
EOF

cat >"$WORK_DIR/leaky.c" <<'EOF'
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

/* each call drops the previous allocation: a leak LSan can see */
unsigned char *kept;

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	kept = malloc(size + 1);
	if (kept && size > 0)
		kept[0] = data[0];
	return 0;
}
EOF

cat >"$WORK_DIR/clean.c" <<'EOF'
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	free(malloc(size + 1));
	(void)data;
	return 0;
}
EOF

clang -O1 -o "$WORK_DIR/noptrace" "$WORK_DIR/noptrace.c"
for h in leaky clean; do
    clang -g -O1 -fsanitize=fuzzer,address -o "$WORK_DIR/$h" \
	  "$WORK_DIR/$h.c" "$REPO_DIR/fuzz/lsan_options.c"
done

# run <name> <wrap: 0|1> <binary> [args...]: leaves rc, log and the run dir
run() {
    local name=$1 wrap=$2
    shift 2
    local dir="$WORK_DIR/run-$name"
    mkdir -p "$dir"
    local rc=0
    if [[ "$wrap" == 1 ]]; then
	(cd "$dir" && "$WORK_DIR/noptrace" "$@" >log 2>&1) || rc=$?
    else
	(cd "$dir" && "$@" >log 2>&1) || rc=$?
    fi
    echo "$rc" >"$dir/rc"
}

no_artifacts() {
    local dir="$WORK_DIR/run-$1"
    ! compgen -G "$dir/crash-*" >/dev/null &&
	! compgen -G "$dir/leak-*" >/dev/null
}

echo "[fuzz-leaks] the seccomp wrapper refuses ptrace"
run probe 1 "$WORK_DIR/clean" -runs=1
[[ "$(cat "$WORK_DIR/run-probe/rc")" != 125 ]] ||
    fail "the wrapper could not install its filter"

echo "[fuzz-leaks] a clean target under refused ptrace runs clean"
run clean-wrapped 1 "$WORK_DIR/clean" -runs=20000
log="$WORK_DIR/run-clean-wrapped/log"
[[ "$(cat "$WORK_DIR/run-clean-wrapped/rc")" == 0 ]] ||
    fail "a clean target exited $(cat "$WORK_DIR/run-clean-wrapped/rc")" "$log"
grep -q "$OFF_MSG" "$log" ||
    fail "the target did not say leak detection is off" "$log"
no_artifacts clean-wrapped ||
    fail "a clean target left a reproducer behind" "$log"

echo "[fuzz-leaks] a leaking target under refused ptrace does not report a crash"
run leaky-wrapped 1 "$WORK_DIR/leaky" -runs=20000
log="$WORK_DIR/run-leaky-wrapped/log"
[[ "$(cat "$WORK_DIR/run-leaky-wrapped/rc")" == 0 ]] ||
    fail "exited $(cat "$WORK_DIR/run-leaky-wrapped/rc") where leaks cannot be checked" "$log"
no_artifacts leaky-wrapped ||
    fail "left a reproducer for a check that could not run" "$log"

echo "[fuzz-leaks] where ptrace works, a leak is still reported"
run leaky-host 0 "$WORK_DIR/leaky" -runs=20000
log="$WORK_DIR/run-leaky-host/log"
if grep -q "$OFF_MSG" "$log"; then
    echo "[fuzz-leaks]   this host refuses ptrace attach; skipped"
else
    [[ "$(cat "$WORK_DIR/run-leaky-host/rc")" != 0 ]] ||
	fail "a leaking target exited 0 on a host where leaks can be checked" "$log"
    grep -q "detected memory leaks" "$log" ||
	fail "the leak was not reported" "$log"
    echo "[fuzz-leaks] a clean target on this host keeps leak detection on"
    run clean-host 0 "$WORK_DIR/clean" -runs=20000
    log="$WORK_DIR/run-clean-host/log"
    [[ "$(cat "$WORK_DIR/run-clean-host/rc")" == 0 ]] ||
	fail "a clean target exited $(cat "$WORK_DIR/run-clean-host/rc")" "$log"
    ! grep -q "$OFF_MSG" "$log" ||
	fail "leak detection was switched off where ptrace works" "$log"
fi

target="$BUILD_DIR/fuzz-bpf-event-budget"
if [[ -x "$target" ]]; then
    echo "[fuzz-leaks] the built fuzz target under refused ptrace runs clean"
    run target-wrapped 1 "$target" -runs=20000
    log="$WORK_DIR/run-target-wrapped/log"
    [[ "$(cat "$WORK_DIR/run-target-wrapped/rc")" == 0 ]] ||
	fail "$target exited $(cat "$WORK_DIR/run-target-wrapped/rc")" "$log"
    no_artifacts target-wrapped ||
	fail "$target left a reproducer behind" "$log"
else
    echo "[fuzz-leaks] $target not built; skipped (run 'make fuzz-all')"
fi

echo "[fuzz-leaks] PASS"
