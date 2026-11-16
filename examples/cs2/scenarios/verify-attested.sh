#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Szymon Wilczek
#
# Polls the Wine/Proton hook's lota-status file and prints a timestamped
# TRUSTED, UNTRUSTED or OFFLINE line whenever the verdict changes.

set -euo pipefail

usage() {
	cat <<EOF
Usage: $0 [--interval SEC] [--status-path PATH] [--max-age SEC] [--once]

Polls the LOTA hook status file and prints state transitions.

  --interval SEC     polling cadence in seconds (default 1; min 1)
  --status-path PATH explicit status-file path. Without it each read
                     takes the first lota-status that exists in
                     \$LOTA_HOOK_TOKEN_DIR, \$XDG_RUNTIME_DIR/lota-hook
                     (/run/user/<uid>/lota-hook when unset) and
                     /tmp/lota-<uid> -- the order the hook settles its
                     token directory in.
  --max-age SEC      oldest LOTA_UPDATED still read as a verdict
                     (default 3 x the period the hook takes from
                     \$LOTA_HOOK_REFRESH_SEC, 60 when that is unset or
                     not positive, and at least 15)
  --once             print the current verdict once and exit (CI mode)

Verdict mapping, in the order the fields are read:

  OFFLINE   lota-status missing (hook detached, or the container view
            does not include the token sink), or lota-status exists
            and LOTA_OFFLINE=1 (the hook lost the agent and said so)
  OFFLINE (stale)
            LOTA_UPDATED missing or older than --max-age: no hook
            writes the file any more
  TRUSTED   LOTA_OFFLINE=0 and LOTA_ATTESTED=1
  UNTRUSTED LOTA_OFFLINE=0 and LOTA_ATTESTED=0

LOTA_OFFLINE is read before LOTA_ATTESTED because an agent that went
away is not a verdict the agent gave: the hook zeroes the payload it
publishes on a disconnect, and without the marker that zeroed file
would read as UNTRUSTED.

Exit code in --once mode mirrors the verdict:

  0 = TRUSTED
  1 = UNTRUSTED
  2 = OFFLINE
EOF
}

INTERVAL=1
STATUS_PATH=""
MAX_AGE=""
ONCE=0

while [ "$#" -gt 0 ]; do
	case "$1" in
	--interval)
		[ "$#" -ge 2 ] || {
			echo "verify-attested.sh: --interval requires SEC" >&2
			exit 64
		}
		INTERVAL="$2"
		shift 2
		;;
	--status-path)
		[ "$#" -ge 2 ] || {
			echo "verify-attested.sh: --status-path requires PATH" >&2
			exit 64
		}
		STATUS_PATH="$2"
		shift 2
		;;
	--max-age)
		[ "$#" -ge 2 ] || {
			echo "verify-attested.sh: --max-age requires SEC" >&2
			exit 64
		}
		MAX_AGE="$2"
		shift 2
		;;
	--once)
		ONCE=1
		shift
		;;
	--help | -h)
		usage
		exit 0
		;;
	*)
		echo "verify-attested.sh: unknown argument $1" >&2
		usage >&2
		exit 64
		;;
	esac
done

case "$INTERVAL" in
'' | *[!0-9]*)
	echo "verify-attested.sh: --interval must be a positive integer" >&2
	exit 64
	;;
esac
[ "$INTERVAL" -ge 1 ] || {
	echo "verify-attested.sh: --interval must be >= 1" >&2
	exit 64
}

if [ -z "$MAX_AGE" ]; then
	# the period the hook's atoi() takes: leading blanks, a +, digits;
	# 60 past INT_MAX, where atoi() is undefined
	refresh="${LOTA_HOOK_REFRESH_SEC:-}"
	refresh="${refresh#"${refresh%%[!$' \t\n\v\f\r']*}"}"
	refresh="${refresh#+}"
	refresh="${refresh%%[!0-9]*}"
	refresh="${refresh#"${refresh%%[!0]*}"}"
	if [ -z "$refresh" ] || [ "${#refresh}" -gt 10 ] ||
		[ "$refresh" -gt 2147483647 ]; then
		refresh=60
	fi
	MAX_AGE=$((refresh * 3))
	[ "$MAX_AGE" -ge 15 ] || MAX_AGE=15
fi
case "$MAX_AGE" in
'' | *[!0-9]* | 0)
	echo "verify-attested.sh: --max-age must be a positive integer" >&2
	exit 64
	;;
esac

uid="$(id -u)"

# --status-path, else the first candidate that exists, else empty
status_path() {
	local cand

	if [ -n "$STATUS_PATH" ]; then
		printf '%s' "$STATUS_PATH"
		return
	fi
	for cand in \
		"${LOTA_HOOK_TOKEN_DIR:+${LOTA_HOOK_TOKEN_DIR%/}/lota-status}" \
		"${XDG_RUNTIME_DIR:-/run/user/$uid}/lota-hook/lota-status" \
		"/tmp/lota-$uid/lota-status"; do
		if [ -n "$cand" ] && [ -e "$cand" ]; then
			printf '%s' "$cand"
			return
		fi
	done
}

field() {
	grep -E "^$1=" "$2" 2>/dev/null | head -n1 | cut -d= -f2 || true
}

classify() {
	local path="$1"
	local attested
	local offline
	local updated

	if [ -z "$path" ] || [ ! -e "$path" ]; then
		printf 'OFFLINE'
		return
	fi
	offline="$(field LOTA_OFFLINE "$path")"
	if [ "$offline" = "1" ]; then
		printf 'OFFLINE'
		return
	fi
	updated="$(field LOTA_UPDATED "$path")"
	case "$updated" in
	'' | *[!0-9]*) updated=0 ;;
	esac
	if [ $(($(date +%s) - updated)) -gt "$MAX_AGE" ]; then
		printf 'OFFLINE (stale)'
		return
	fi
	attested="$(field LOTA_ATTESTED "$path")"
	case "$attested" in
	1) printf 'TRUSTED' ;;
	0) printf 'UNTRUSTED' ;;
	*) printf 'OFFLINE' ;;
	esac
}

verdict_to_exit() {
	case "$1" in
	TRUSTED) return 0 ;;
	UNTRUSTED) return 1 ;;
	*) return 2 ;;
	esac
}

if [ "$ONCE" -eq 1 ]; then
	verdict="$(classify "$(status_path)")"
	printf '%s %s\n' "$(date +%H:%M:%S)" "$verdict"
	verdict_to_exit "$verdict"
	exit "$?"
fi

printf 'polling every %ds (Ctrl-C to stop)\n' "$INTERVAL"
printf '(verdict transitions are emitted only when the underlying file '
printf 'changes; the LOTA hook itself rewrites the file at its own\n'
printf 'LOTA_HOOK_REFRESH_SEC cadence, default 60s.)\n'
last=""
watched="-"
while :; do
	path="$(status_path)"
	if [ "$path" != "$watched" ]; then
		printf 'watching %s\n' "${path:-no status file}"
		watched="$path"
	fi
	verdict="$(classify "$path")"
	if [ "$verdict" != "$last" ]; then
		printf '%s %s\n' "$(date +%H:%M:%S)" "$verdict"
		last="$verdict"
	fi
	sleep "$INTERVAL"
done
