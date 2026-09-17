#!/bin/sh
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Szymon Wilczek
# Push every program in a LOTA BPF object through the in-kernel verifier
# with veristat and fail on any rejection. Meant to run inside a VM booted
# on the deployment kernel (see the bpf-veristat job) so the verdict matches
# production. On a rejection, print the verifier log of a whole-object
# bpftool load; libbpf stops at the first refused program.
set -eu

obj="${1:?usage: veristat-gate.sh <bpf-object>}"

# the VM shares the checkout read-only over 9p, so write the report to a
# writable temp (guest /tmp is tmpfs)
out="$(mktemp)"
load="$(mktemp)"
bpffs="$(mktemp -d)"
mounted=0
cleanup() {
    if [ "$mounted" = 1 ]; then
	umount "$bpffs" || true
    fi
    rm -rf "$out" "$load" "$bpffs"
}
trap cleanup EXIT

echo "guest kernel: $(uname -r)"
veristat "$obj" | tee "$out"

failed="$(awk '$3 == "failure" { printf "%s%s", sep, $2; sep = " " }' "$out")"
if [ -z "$failed" ]; then
    echo "veristat: all programs pass the kernel verifier"
    exit 0
fi

# veristat -v zeroes the row and segfaults on this object, so take the log
# from a real load, pinned into a private bpffs
if ! command -v bpftool >/dev/null 2>&1; then
    echo "bpftool not found: no verifier log to show" >"$load"
elif mount -t bpf bpf "$bpffs" 2>"$load"; then
    mounted=1
    bpftool prog load "$obj" "$bpffs/prog" >"$load" 2>&1 || true
fi

logged="$(sed -n "s/^libbpf: prog '\([^']*\)': -- BEGIN PROG LOAD LOG --\$/\1/p" "$load" | head -1)"
if [ -n "$logged" ]; then
    echo "::group::verifier log: $logged"
    awk '/-- BEGIN PROG LOAD LOG --$/ { inb = 1; next }
	     inb && /^-- END PROG LOAD LOG --$/ { exit }
	     inb { print }' "$load" | tail -80
    echo "::endgroup::"
fi
for prog in $failed; do
    if [ "$prog" != "$logged" ]; then
	echo "::group::verifier log: $prog"
	if [ -n "$logged" ]; then
	    echo "not shown: the load stopped at $logged; fix it and re-run"
	else
	    tail -40 "$load"
	fi
	echo "::endgroup::"
    fi
done
echo "::error::veristat: the BPF verifier rejected: $failed"
exit 1
