#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Szymon Wilczek
#
# Build-directory gate for the test tree.
#
# A test that names the default build directory breaks under any other
# BUILD_DIR, which the quick start and the contributing guide both set.
#
#   C and Go: the path comes as a -D from the test's recipe; an #ifndef
#   fallback naming the default is allowed only when a recipe defines it.
#
#   shell: the directory comes from $LOTA_BUILD_DIR; the default may appear
#   only as its fallback.
#
# Usage: scripts/check-test-build-dir.sh
# Requires: awk, sed, git (no build, no toolchain)
set -euo pipefail

cd "$(dirname "$0")/.."

FAILURES=0

report() {
    printf '  %s\n' "$1" >&2
    FAILURES=$((FAILURES + 1))
}

# default BUILD_DIR, read from the Makefile
DEFAULT_DIR=$(sed -n 's/^BUILD_DIR[[:space:]]*:=[[:space:]]*\([^[:space:]]*\).*/\1/p' Makefile | head -1)
if [[ -z ${DEFAULT_DIR:-} ]]; then
    printf 'check-test-build-dir: no BUILD_DIR assignment in Makefile\n' >&2
    exit 1
fi

# only line a shell test may name the default on
BLESSED="BUILD_DIR=\"\${LOTA_BUILD_DIR:-\$REPO_DIR/$DEFAULT_DIR}\""

# Print the file without comments, keeping string literals.
strip_comments() {
    awk '
	{
		line = $0
		out = ""
		in_str = 0
		i = 1
		n = length(line)
		while (i <= n) {
			c = substr(line, i, 1)
			d = substr(line, i, 2)
			if (in_block) {
				if (d == "*/") { in_block = 0; i += 2; continue }
				i++
				continue
			}
			if (in_str) {
				out = out c
				if (c == "\\") { out = out substr(line, i + 1, 1); i += 2; continue }
				if (c == "\"") in_str = 0
				i++
				continue
			}
			if (d == "/*") { in_block = 1; i += 2; continue }
			if (d == "//") break
			if (c == "\"") { in_str = 1; out = out c; i++; continue }
			out = out c
			i++
		}
		print out
	}
	' "$1"
}

scan_c_or_go() {
    local path="$1" lineno=0 line macro
    while IFS= read -r line; do
	lineno=$((lineno + 1))
	[[ $line =~ (^|[^[:alnum:]_])"$DEFAULT_DIR"/ ]] || continue
	if [[ $line =~ ^#define[[:space:]]+([A-Za-z_][A-Za-z0-9_]*)[[:space:]]+\"$DEFAULT_DIR/ ]]; then
	    macro="${BASH_REMATCH[1]}"
	    if grep -q -- "-D$macro=" Makefile; then
		continue
	    fi
	    report "$path:$lineno: $macro falls back to $DEFAULT_DIR/ and no recipe defines it; compile this test with -D$macro='\"\$(BUILD_DIR)/...\"'"
	    continue
	fi
	report "$path:$lineno: names the default build directory; take the path from the build rather than from \"$DEFAULT_DIR/\""
    done < <(strip_comments "$path")
}

scan_sh() {
    local path="$1" lineno=0 line
    while IFS= read -r line; do
	lineno=$((lineno + 1))
	[[ $line =~ ^[[:space:]]*# ]] && continue
	if [[ $line != *"\$REPO_DIR/$DEFAULT_DIR"* ]] &&
	       ! [[ $line =~ (^|[^[:alnum:]_/])"$DEFAULT_DIR"/ ]]; then
	    continue
	fi
	[[ $line == *"$BLESSED"* ]] && continue
	report "$path:$lineno: names the default build directory; read it from \$LOTA_BUILD_DIR ($BLESSED)"
    done <"$path"
}

main() {
    local path count=0

    while IFS= read -r path; do
	[[ -f $path ]] || continue
	count=$((count + 1))
	case "$path" in
	    *.c | *.h | *.go) scan_c_or_go "$path" ;;
	    *.sh) scan_sh "$path" ;;
	esac
    done < <(git ls-files 'tests/*.c' 'tests/*.h' 'tests/*.go' 'tests/*.sh')

    if ((FAILURES != 0)); then
	printf 'check-test-build-dir: %d test(s) name a directory the build may not have used\n' "$FAILURES" >&2
	printf 'see Documentation/contributor/development/patch-checks.rst\n' >&2
	return 1
    fi

    printf 'check-test-build-dir: clean (%d files)\n' "$count"
}

main "$@"
