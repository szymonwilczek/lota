#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Szymon Wilczek
#
# Include-hygiene gate.
#
# Fails when a translation unit pulls in a header it does not use
# directly -- a transitive dependency. clang-include-cleaner is the same
# engine clangd's editor diagnostic runs, a clean tree here means a clean
# editor.
#
# Compile database is built with bear so every TU is analyzed with its
# real flags. SDL ships a single public <SDL.h>; its SDL_*.h headers are
# implementation detail and are ignored so the documented umbrella stays.
#
# Usage: scripts/check-includes.sh
# Requires: clang-include-cleaner (clang-tools-extra), bear
set -euo pipefail

cd "$(dirname "$0")/.."

# clang-include-cleaner credits a handful of C/POSIX symbols to the glibc
# /kernel-uapi implementation headers (bits/, asm-generic/) instead of the
# public umbrella, so it wrongly reports the public header as unused.
# Keep the idiomatic public headers and exempt that fixed set.
# SDL ships one public <SDL.h>; its SDL_*.h are implementation detail.
# systemd shuffles symbols between <systemd/sd-bus.h> and its sub-headers
# across releases. exempt it.
# This list mirrors the .clangd IgnoreHeader so the gate and the editor agree.
IGNORE_HEADERS='SDL.*\.h,sys/types\.h,errno\.h,getopt\.h,unistd\.h,termios\.h,sys/time\.h,sys/socket\.h,systemd/sd-bus-protocol\.h'
DB_DIR="build"
DB="$DB_DIR/compile_commands.json"

for tool in clang-include-cleaner bear; do
	command -v "$tool" >/dev/null 2>&1 || {
		echo "check-includes: $tool not found" >&2
		echo "  clang-include-cleaner: install clang-tools-extra" >&2
		echo "  bear: install bear" >&2
		exit 1
	}
done

echo "check-includes: building compile database with bear..."
mkdir -p "$DB_DIR"
# -B so every TU is recompiled and captured.
# examples pull in the SDL and libcurl demos;
# link failure there does not affect the recorded compile commands, so keep going.
# -B recompiles every TU so bear captures it; -o keeps the generated,
# committed vmlinux.h from being rebuilt from the live kernel BTF.
bear --output "$DB" -- "${MAKE:-make}" -B -k -o include/vmlinux.h \
	all examples test-bins fuzz-all bench-c syzkaller-fuzz-loader \
	>/dev/null 2>&1 || true

test -s "$DB" || {
	echo "check-includes: bear produced no database" >&2
	exit 1
}

# Few sources compile more than once (e.g. the initramfs lock helper is
# also built in a -DLOTA_*_NO_MAIN test mode that #ifdefs code out, so some
# includes look unused there).
# `all` builds before the test/fuzz targets, so keep the first -- production
# -- entry per file and drop the rest
python3 - "$DB" <<'PY'
import json, sys
p = sys.argv[1]
seen, out = set(), []
for e in json.load(open(p)):
    if e["file"] in seen:
        continue
    seen.add(e["file"]); out.append(e)
json.dump(out, open(p, "w"), indent=2)
PY

# Every .c the database knows about, minus the BPF program:
# it is built for the bpf target and must include vmlinux.h first,
# which the host analyzer cannot model
mapfile -t files < <(
	python3 - "$DB" <<'PY'
import json, sys
seen = set()
for e in json.load(open(sys.argv[1])):
    f = e["file"]
    if f in seen or not f.endswith(".c"):
        continue
    if "/src/bpf/" in f:
        continue
    seen.add(f)
    print(f)
PY
)

fail=0
for f in "${files[@]}"; do
	[ -f "$f" ] || continue
	unused=$(clang-include-cleaner --print=changes -p "$DB_DIR" \
		--ignore-headers="$IGNORE_HEADERS" "$f" 2>/dev/null |
		grep '^- ' || true)
	if [ -n "$unused" ]; then
		echo "FAIL ${f#"$PWD"/}"
		echo "$unused" | sed 's/^/    /'
		fail=1
	fi
done

if [ "$fail" -ne 0 ]; then
	echo "check-includes: transitive (unused-direct) includes found -- remove them" >&2
	echo "  fix with: scripts/fix-includes.sh" >&2
	exit 1
fi
echo "check-includes: clean"
