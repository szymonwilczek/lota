#!/bin/sh
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Szymon Wilczek
# Push every program in a LOTA BPF object through the in-kernel verifier
# with veristat and fail on any rejection. Meant to run inside a VM booted
# on the deployment kernel (see the bpf-veristat job) so the verdict matches
# production. On a rejection, print the verifier log of a whole-object
# bpftool load; libbpf stops at the first refused program. A load that fails
# before the verifier is reported as a setup failure.
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
# libbpf blames RLIMIT_MEMLOCK for any EPERM; rule it out
ulimit -l unlimited 2>/dev/null || true
veristat "$obj" | tee "$out"

failed="$(awk '$3 == "failure" { printf "%s%s", sep, $2; sep = " " }' "$out")"
if [ -z "$failed" ]; then
    echo "veristat: all programs pass the kernel verifier"
    exit 0
fi

if [ "$(id -u)" != 0 ]; then
    echo "::error::veristat: not running as root, so the object could not be loaded and no program reached the BPF verifier: $failed"
    echo "Run the gate as root, in a VM booted on the deployment kernel (see the bpf-veristat CI job)."
    exit 1
fi
if ! command -v bpftool >/dev/null 2>&1; then
    echo "::error::veristat: reports failure for: $failed; install bpftool to see whether the verifier rejected them"
    exit 1
fi

# veristat -v zeroes the row and segfaults on this object, so take the log
# from a real load, pinned into a private bpffs
loaded=0
if ! mount -t bpf bpf "$bpffs" 2>"$load"; then
    loaded=1
else
    mounted=1
    bpftool prog load "$obj" "$bpffs/prog" >"$load" 2>&1 || loaded=$?
fi

# libbpf prints the verifier log only for a program the kernel refused
logged="$(sed -n "s/^libbpf: prog '\([^']*\)': -- BEGIN PROG LOAD LOG --\$/\1/p" "$load" | head -1)"
if [ -z "$logged" ]; then
    echo "::group::object load"
    tail -40 "$load"
    echo "::endgroup::"
    if [ "$loaded" = 0 ]; then
	echo "::error::veristat: reports failure for: $failed; the whole object loads with every program accepted"
	exit 1
    fi
    echo "::error::veristat: no program reached the BPF verifier; the object failed to load before it, so nothing was judged: $failed"
    echo "Check the load error above. A host where lota-agent enforces refuses BPF map creation to every other process; run the gate in a VM booted on the deployment kernel (see the bpf-veristat CI job)."
    exit 1
fi

echo "::group::verifier log: $logged"
awk '/-- BEGIN PROG LOAD LOG --$/ { inb = 1; next }
     inb && /^-- END PROG LOAD LOG --$/ { exit }
     inb { print }' "$load" | tail -80
echo "::endgroup::"
for prog in $failed; do
    if [ "$prog" != "$logged" ]; then
	echo "::group::verifier log: $prog"
	echo "not shown: the load stopped at $logged; fix it and re-run"
	echo "::endgroup::"
    fi
done
echo "::error::veristat: the BPF verifier rejected: $failed"
exit 1
