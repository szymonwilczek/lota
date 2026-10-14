#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Szymon Wilczek
#
# Refuse a TPM return code rendered with strerror().
#
# The tpm_* functions return LOTA's private codes above the POSIX range,
# so strerror() renders them as "Unknown error 4098".
# 4098 is LOTA_ERR_TPM_AUTH_FAIL, the code whose whole purpose is to be seen
# before a lockout: every failed authorization also spends a dictionary-attack
# attempt, and the counter drains one per two hours out of 32.
# An operator who retries an operation reporting an unknown error is walking
# the machine toward a lockout the message could have named.
#
# tpm_strerror() falls through to strerror() for ordinary errnos, so it is always
# the safe call on a value that came from a tpm_* function; there is no case
# where strerror() on such a value is the better rendering.
#
# What it matches: a variable assigned from a tpm_*() call and then passed to
# strerror() negated, with no intervening assignment to that variable from
# anything else.
# Scope is reset at each closing brace in column one, which is a function boundary
# in this tree's style. It is deliberately a syntactic check and not a dataflow one:
# a value that reaches strerror() through a second variable is not caught,
# and a reviewer is still the backstop.

set -euo pipefail

cd "$(dirname "$0")/.."

# Shipped C only.
# The BPF object has no errno rendering, and a test that deliberately prints
# a raw code is testing the code and not reporting to an operator.
mapfile -t srcs < <(git ls-files '*.c' | grep -v '^src/bpf/' | grep -v '^tests/')

if [ "${#srcs[@]}" -eq 0 ]; then
    echo "check-tpm-strerror: no sources to check" >&2
    exit 0
fi

out=$(awk '
	# A closing brace in column one ends a function in this tree,
        # so nothing a variable held inside one carries into the next.
	/^\}/ { delete from_tpm; next }

	{
		line = $0

		# V = tpm_something(  -- V now holds a TPM code
		if (match(line, /[A-Za-z_][A-Za-z0-9_]*[ \t]*=[ \t]*tpm_[A-Za-z0-9_]*[ \t]*\(/)) {
			v = substr(line, RSTART, RLENGTH)
			sub(/[ \t]*=.*/, "", v)
			from_tpm[v] = FNR
			next
		}

		# V = anything-else(  -- V no longer holds a TPM code
		if (match(line, /[A-Za-z_][A-Za-z0-9_]*[ \t]*=[ \t]*[A-Za-z_][A-Za-z0-9_]*[ \t]*\(/)) {
			v = substr(line, RSTART, RLENGTH)
			sub(/[ \t]*=.*/, "", v)
			delete from_tpm[v]
		}

		while (match(line, /strerror\([ \t]*-[ \t]*[A-Za-z_][A-Za-z0-9_]*[ \t]*\)/)) {
			expr = substr(line, RSTART, RLENGTH)
			v = expr
			sub(/^strerror\([ \t]*-[ \t]*/, "", v)
			sub(/[ \t]*\)$/, "", v)
			if (v in from_tpm)
				printf "%s:%d: strerror(-%s) renders the TPM code assigned at line %d; use tpm_strerror(%s)\n", \
					FILENAME, FNR, v, from_tpm[v], v
			line = substr(line, RSTART + RLENGTH)
		}
	}
' "${srcs[@]}")

if [ -n "$out" ]; then
    echo "$out"
    echo "check-tpm-strerror: TPM codes rendered with strerror() (see above)" >&2
    exit 1
fi

echo "check-tpm-strerror: clean"
