#!/bin/sh
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Szymon Wilczek
# Push every program in a LOTA BPF object through the in-kernel verifier
# with veristat and fail on any rejection. Meant to run inside a VM booted
# on the deployment kernel (see the bpf-veristat job) so the verdict matches
# production. The full verifier log for each rejected program is dumped for
# diagnosis
set -eu

obj="${1:?usage: veristat-gate.sh <bpf-object>}"

# the VM shares the checkout read-only over 9p, so write the report to a
# writable temp (guest /tmp is tmpfs)
out="$(mktemp)"
trap 'rm -f "$out"' EXIT

echo "guest kernel: $(uname -r)"
veristat "$obj" | tee "$out"

failed="$(awk '$3 == "failure" { print $2 }' "$out")"
if [ -n "$failed" ]; then
	for prog in $failed; do
		echo "::group::verifier log: $prog"
		veristat -vl2 -f "$prog" "$obj" 2>&1 | tail -80 || true
		echo "::endgroup::"
	done
	echo "::error::veristat: the BPF verifier rejected:$failed"
	exit 1
fi
echo "veristat: all programs pass the kernel verifier"
