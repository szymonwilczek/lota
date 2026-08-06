#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Szymon Wilczek
#
# Refuse a function in a shipped binary whose stack frame exceeds the limit below.
#
# The agent is a long-running daemon and the installer runs on whatever stack
# the caller has.
# Neither has any business holding a quarter of a megabyte in an automatic:
# the objects that get that large -- configuration, allow-lists, rollback snapshots
# -- have a lifetime the compiler cannot see and belong on the heap, where a failed
# allocation is a value the caller can act on.
#
# Only the shipped sources are checked. Tests are short-lived processes on the main
# thread's full stack, and holding them to a daemon's budget would say nothing
# about what runs on a user's machine.
#
# The flags are pinned here rather than taken from CFLAGS so the number a frame
# is measured at does not move with the build mode.
# The hardening, machine and sanitizer flags change frame sizes; the point of
# the gate is the shape of the source, not the shape of one build.

set -euo pipefail

# Quarter of a megabyte.
# Chosen as a ceiling over the largest frame the tree legitimately needs,
# not as a target: the attestation loop's per-target array in src/agent/attest.c
# is the current high-water mark at ~242 KB.
# Ratchet this down as that comes in; never raise it to admit a new frame.
LIMIT=${STACK_FRAME_LIMIT:-262144}

CC=${CC:-gcc}
SRC_GLOBS=('src/*.c' 'src/**/*.c' 'installer/*.c')

if ! command -v "$CC" >/dev/null 2>&1; then
	echo "check-stack-frames: $CC not found; skipping" >&2
	exit 0
fi

# src/bpf targets the BPF machine and has no host stack frame to speak of
mapfile -t sources < <(git ls-files "${SRC_GLOBS[@]}" | grep -v '^src/bpf/' |
	sort -u)

if [ ${#sources[@]} -eq 0 ]; then
	echo "check-stack-frames: no sources found" >&2
	exit 1
fi

pkg_cflags=$(pkg-config --cflags libsystemd libseccomp dbus-1 libcurl \
	libbpf openssl tss2-esys tss2-mu tss2-tctildr 2>/dev/null || true)

findings=0
for src in "${sources[@]}"; do
	# shellcheck disable=SC2086
	out=$("$CC" -O2 -Iinclude -Isrc -Isrc/agent -D_GNU_SOURCE $pkg_cflags \
		-Wframe-larger-than="$LIMIT" -c -o /dev/null "$src" 2>&1 |
		grep -E 'frame size of [0-9]+ bytes' || true)
	if [ -n "$out" ]; then
		printf '%s\n' "$out"
		findings=$((findings + 1))
	fi
done

if [ "$findings" -gt 0 ]; then
	cat >&2 <<EOF

check-stack-frames: $findings file(s) hold more than $LIMIT bytes in a frame.
Move the object to the heap and give the caller a way to see the allocation
fail; see config_new() in src/agent/config.c for the shape.
EOF
	exit 1
fi

echo "check-stack-frames: no frame over $LIMIT bytes"
