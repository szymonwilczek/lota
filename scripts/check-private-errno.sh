#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Szymon Wilczek
#
# Refuse a LOTA-private return code rendered with strerror().
#
# tpm_* return codes from 4097 and net_* from 4353; strerror() prints both as
# "Unknown error <n>". 4098 (LOTA_ERR_TPM_AUTH_FAIL) warns of a coming
# dictionary-attack lockout; the net block tells a dead peer from a local I/O
# fault. tpm_strerror() and net_strerror() fall through to strerror() for
# ordinary errnos.
#
# Matches a variable assigned from a tpm_*() or net_*() call and later passed
# negated to strerror(), with no other assignment in between. Syntactic only,
# scoped per function: a copy through a second variable is not caught.

set -euo pipefail

cd "$(dirname "$0")/.."

# shipped C only: BPF renders no errno, tests print raw codes on purpose
mapfile -t srcs < <(git ls-files '*.c' | grep -v '^src/bpf/' | grep -v '^tests/')

if [ "${#srcs[@]}" -eq 0 ]; then
    echo "check-private-errno: no sources to check" >&2
    exit 0
fi

out=$(awk '
	# column-one brace ends a function
	/^\}/ { delete layer; delete assigned_at; next }

	{
		line = $0

		# V = tpm_*( or V = net_*(: V holds that layer code
		if (match(line, /[A-Za-z_][A-Za-z0-9_]*[ \t]*=[ \t]*(tpm|net)_[A-Za-z0-9_]*[ \t]*\(/)) {
			expr = substr(line, RSTART, RLENGTH)
			v = expr
			sub(/[ \t]*=.*/, "", v)
			sub(/^[^=]*=[ \t]*/, "", expr)
			sub(/_.*/, "", expr)
			layer[v] = expr
			assigned_at[v] = FNR
			next
		}

		# any other assignment clears V; ==, !=, <=, >= do not match
		if (match(line, /[A-Za-z_][A-Za-z0-9_]*[ \t]*=[^=]/)) {
			v = substr(line, RSTART, RLENGTH)
			sub(/[ \t]*=.*/, "", v)
			delete layer[v]
			delete assigned_at[v]
		}

		while (match(line, /strerror\([ \t]*-[ \t]*[A-Za-z_][A-Za-z0-9_]*[ \t]*\)/)) {
			expr = substr(line, RSTART, RLENGTH)
			v = expr
			sub(/^strerror\([ \t]*-[ \t]*/, "", v)
			sub(/[ \t]*\)$/, "", v)
			if (v in layer)
				printf "%s:%d: strerror(-%s) renders the %s code assigned at line %d; use %s_strerror(%s)\n", \
					FILENAME, FNR, v, toupper(layer[v]), assigned_at[v], layer[v], v
			line = substr(line, RSTART + RLENGTH)
		}
	}
' "${srcs[@]}")

if [ -n "$out" ]; then
    echo "$out"
    echo "check-private-errno: private codes rendered with strerror() (see above)" >&2
    exit 1
fi

echo "check-private-errno: clean"
