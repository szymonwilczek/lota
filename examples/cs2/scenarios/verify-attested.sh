#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# Operator-facing watcher for the LOTA Wine/Proton hook.
#
# Polls $XDG_RUNTIME_DIR/lota/lota-status at a fixed cadence and
# prints one timestamped line per state transition: TRUSTED <->
# UNTRUSTED <-> OFFLINE. The watcher does not interpret the rest of
# the status payload; it only translates LOTA_ATTESTED and the
# file's existence into a verdict the operator can read.
#
# The companion walk-throughs in this directory drive the
# transitions intentionally (kill the agent, load an unauthorised
# library, etc) and use this watcher as the single source of truth
# for what the hook observed.

set -euo pipefail

usage() {
	cat <<EOF
Usage: $0 [--interval SEC] [--status-path PATH] [--once]

Polls the LOTA hook status file and prints state transitions.

  --interval SEC     polling cadence in seconds (default 1; min 1)
  --status-path PATH explicit status-file path. Defaults to
                     \$XDG_RUNTIME_DIR/lota/lota-status with a
                     /run/user/<uid>/lota/lota-status fallback.
  --once             print the current verdict once and exit (CI mode)

Verdict mapping:

  TRUSTED   lota-status exists and LOTA_ATTESTED=1
  UNTRUSTED lota-status exists and LOTA_ATTESTED=0
  OFFLINE   lota-status missing (hook detached, agent not running,
            or container view does not include the token sink)

Exit code in --once mode mirrors the verdict:

  0 = TRUSTED
  1 = UNTRUSTED
  2 = OFFLINE
EOF
}

INTERVAL=1
STATUS_PATH=""
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

if [ -z "$STATUS_PATH" ]; then
	uid="$(id -u)"
	for cand in \
		"${XDG_RUNTIME_DIR:-/run/user/$uid}/lota/lota-status" \
		"/run/user/$uid/lota/lota-status"; do
		STATUS_PATH="$cand"
		[ -e "$cand" ] && break
	done
fi

# Translate the file's existence + LOTA_ATTESTED / LOTA_OFFLINE
# values into a canonical verdict. The status file is small and
# rewritten atomically by the hook, so a single grep pass per field
# is enough; no awk / sed pipeline that would race against the writer.
#
# Decision order:
#   - file missing                       -> OFFLINE (hook never ran
#                                           or token dir not mounted)
#   - LOTA_OFFLINE=1                     -> OFFLINE (hook lost agent;
#                                           publish_offline_status())
#   - LOTA_ATTESTED=1                    -> TRUSTED
#   - LOTA_ATTESTED=0                    -> UNTRUSTED
classify() {
	local path="$1"
	local attested
	local offline

	if [ ! -e "$path" ]; then
		printf 'OFFLINE'
		return
	fi
	offline="$(grep -E '^LOTA_OFFLINE=' "$path" 2>/dev/null | head -n1 |
		cut -d= -f2 || true)"
	if [ "$offline" = "1" ]; then
		printf 'OFFLINE'
		return
	fi
	attested="$(grep -E '^LOTA_ATTESTED=' "$path" 2>/dev/null | head -n1 |
		cut -d= -f2 || true)"
	case "$attested" in
	1) printf 'TRUSTED' ;;
	0) printf 'UNTRUSTED' ;;
	*) printf 'OFFLINE' ;;
	esac
}

# map verdict string to the --once exit code so the script can double
# as a CI / shell-test liveness probe
verdict_to_exit() {
	case "$1" in
	TRUSTED) return 0 ;;
	UNTRUSTED) return 1 ;;
	*) return 2 ;;
	esac
}

if [ "$ONCE" -eq 1 ]; then
	verdict="$(classify "$STATUS_PATH")"
	printf '%s %s\n' "$(date +%H:%M:%S)" "$verdict"
	verdict_to_exit "$verdict"
	exit "$?"
fi

printf 'watching %s, polling every %ds (Ctrl-C to stop)\n' \
	"$STATUS_PATH" "$INTERVAL"
printf '(verdict transitions are emitted only when the underlying file '
printf 'changes; the LOTA hook itself rewrites the file at its own\n'
printf 'LOTA_HOOK_REFRESH_SEC cadence, default 60s.)\n'
last=""
while :; do
	verdict="$(classify "$STATUS_PATH")"
	if [ "$verdict" != "$last" ]; then
		printf '%s %s\n' "$(date +%H:%M:%S)" "$verdict"
		last="$verdict"
	fi
	sleep "$INTERVAL"
done
