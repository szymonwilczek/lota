#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Szymon Wilczek
#
# Rewrites #include lists so every header a file pulls in is used
# directly:
#
# include-what-you-use adds the direct provider of each symbol and drops
# the transitive leftovers.
#
# Public umbrellas are kept via the mapping files under scripts/iwyu/
# (e.g. SDL ships one <SDL.h>).
#
# This is the fixer half of scripts/check-includes.sh.
#
# Review the diff:
# IWYU cannot see symbols reached only through macros or behind conditional
# compilation, so it occasionally drops a still-needed header
# (the build catches those).
# BPF program is skipped on purpose.
#
# Usage: scripts/fix-includes.sh [file.c ...]
#   no args -> every .c in the compile database
# Requires: include-what-you-use, iwyu_tool.py, fix_includes.py, bear
set -euo pipefail

cd "$(dirname "$0")/.."

MAPS=(scripts/iwyu/sdl.imp scripts/iwyu/tss2.imp)
DB_DIR="build"
DB="$DB_DIR/compile_commands.json"

for tool in include-what-you-use iwyu_tool.py fix_includes.py bear; do
	command -v "$tool" >/dev/null 2>&1 || {
		echo "fix-includes: $tool not found (install iwyu and bear)" >&2
		exit 1
	}
done

mkdir -p "$DB_DIR"
# -B recompiles every TU so bear captures it
# -o keeps the generated, committed vmlinux.h from being rebuilt
#    from the live kernel BTF
bear --output "$DB" -- "${MAKE:-make}" -B -k -o include/vmlinux.h \
	all examples test-bins fuzz-all bench-c syzkaller-fuzz-loader \
	>/dev/null 2>&1 || true
test -s "$DB" || {
	echo "fix-includes: bear produced no database" >&2
	exit 1
}

if [ "$#" -gt 0 ]; then
	files=("$@")
else
	mapfile -t files < <(
		python3 - "$DB" <<'PY'
import json, sys
seen = set()
for e in json.load(open(sys.argv[1])):
    f = e["file"]
    if f in seen or not f.endswith(".c") or "/src/bpf/" in f:
        continue
    seen.add(f)
    print(f)
PY
	)
fi

iwyu_args=(-Xiwyu --no_fwd_decls)
for m in "${MAPS[@]}"; do
	iwyu_args+=(-Xiwyu --mapping_file="$PWD/$m")
done

for f in "${files[@]}"; do
	[ -f "$f" ] || continue
	iwyu_tool.py -p "$DB_DIR" "$f" -- "${iwyu_args[@]}" 2>/dev/null |
		fix_includes.py --nocomments --noreorder 2>/dev/null || true
done

echo "fix-includes: done -- review 'git diff' and rebuild"
