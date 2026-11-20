#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Szymon Wilczek
#
# tests/lib/summary.sh FILE
#
# Prints the closing block of a test run from the records in FILE
# (LOTA_TEST_SUMMARY):
#
#   G <group> <passed> <failed> <skipped>   one per finished group
#   F <group> <n> <name>                    one per failed test
#   R <program> <status>                    appended by the runner

set -euo pipefail

file=${1:?usage: summary.sh FILE}

color=0
case ${LOTA_TEST_COLOR:-auto} in
always) color=1 ;;
never) ;;
*)
	if [ -t 1 ] && [ -z "${NO_COLOR:-}" ] && [ "${TERM:-}" != dumb ]; then
		color=1
	fi
	;;
esac

[ -f "$file" ] || : >"$file"

awk -F '\t' -v color="$color" '
function flush_run(prog, rc) {
	if (rc != 0 && run_fails == 0)
		lines[nl++] = sprintf("%s: exited with status %d", prog, rc)
	if (rc != 0)
		bad = 1
	run_fails = 0
}
$1 == "G" {
	groups++
	passed += $3; failed += $4; skipped += $5
	tests += $3 + $4 + $5
}
$1 == "F" {
	lines[nl++] = sprintf("%s: [%3d] %s", $2, $3, $4)
	run_fails++
	bad = 1
}
$1 == "R" { flush_run($2, $3) }
END {
	rule = sprintf("%80s", ""); gsub(/ /, "=", rule)
	tag = color ? "\033[1;31mFAIL\033[0m" : "FAIL"
	print rule
	printf "  %d groups, %d tests: %d passed, %d failed, %d skipped\n",
	       groups, tests, passed, failed, skipped
	for (i = 0; i < nl; i++)
		printf "  %s  %s\n", tag, lines[i]
	print rule
	exit bad
}' "$file"
