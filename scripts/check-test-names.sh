#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Szymon Wilczek
#
# Fails on a TEST name that tests/test.h or tests/lib/test.sh would cut
# short, and on a shell group header wider than the report. Names built
# at run time are not checked.
#
# Usage: scripts/check-test-names.sh
# Requires: awk, git (no build, no toolchain)
set -euo pipefail

cd "$(dirname "$0")/.."
export LC_ALL=C

NAME_MAX=63
WIDTH=80

mapfile -t c_srcs < <(git ls-files 'tests/*.c')
mapfile -t sh_srcs < <(git grep -l -F 'lib/test.sh' -- 'tests/*.sh' || true)

out=$(
    {
	if [ "${#c_srcs[@]}" -gt 0 ]; then
	    awk -v max="$NAME_MAX" '
			# the first string literal at the start of s, or "" with ok = 0
			function literal(s,    i, c, r) {
				ok = 0
				if (substr(s, 1, 1) != "\"")
					return ""
				r = ""
				for (i = 2; i <= length(s); i++) {
					c = substr(s, i, 1)
					if (c == "\\") {
						i++
						r = r substr(s, i, 1)
					} else if (c == "\"") {
						ok = 1
						rest = substr(s, i + 1)
						return r
					} else {
						r = r c
					}
				}
				return ""
			}
			function scan(s,    part) {
				for (;;) {
					sub(/^[ \t]+/, "", s)
					if (s == "")
						return 1
					if (substr(s, 1, 1) == ")") {
						if (length(name) > max)
							printf "%s:%d: test name is %d characters, at most %d: %s\n",
								FILENAME, at, length(name), max, name
						return 0
					}
					part = literal(s)
					if (!ok)
						return 0
					name = name part
					s = rest
				}
			}
			open {
				if (!scan($0))
					open = 0
				next
			}
			match($0, /(^|[^A-Za-z0-9_])TEST\(/) {
				name = ""
				at = FNR
				open = scan(substr($0, RSTART + RLENGTH))
			}
			' "${c_srcs[@]}"
	fi
	if [ "${#sh_srcs[@]}" -gt 0 ]; then
	    awk -v max="$NAME_MAX" -v width="$WIDTH" '
			# the double-quoted word at the start of s, unescaped; dyn
			# is set when it expands a variable
			function word(s,    i, c, r) {
				r = ""
				dyn = 0
				for (i = 2; i <= length(s); i++) {
					c = substr(s, i, 1)
					if (c == "\\") {
						i++
						r = r substr(s, i, 1)
					} else if (c == "\"") {
						return r
					} else {
						if (c == "$")
							dyn = 1
						r = r c
					}
				}
				dyn = 1
				return r
			}
			match($0, /^[ \t]*TEST "/) {
				name = word(substr($0, RSTART + RLENGTH - 1))
				if (!dyn && length(name) > max)
					printf "%s:%d: test name is %d characters, at most %d: %s\n",
						FILENAME, FNR, length(name), max, name
			}
			match($0, /^[ \t]*test_begin "/) {
				name = word(substr($0, RSTART + RLENGTH - 1))
				line = 3 + length(name) + 2 + length(FILENAME) + 2 + 3
				if (!dyn && line > width)
					printf "%s:%d: group header is %d columns, at most %d: %s\n",
						FILENAME, FNR, line, width, name
			}
			' "${sh_srcs[@]}"
	fi
    }
   )

if [ -n "$out" ]; then
    printf '%s\n' "$out" | sed 's/^/  /' >&2
    exit 1
fi
printf 'check-test-names: clean (%d files)\n' $((${#c_srcs[@]} + ${#sh_srcs[@]}))
