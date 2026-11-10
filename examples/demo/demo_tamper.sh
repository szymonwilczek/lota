#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Szymon Wilczek
#
# Creates the tamper marker demo_anticheat checks on every heartbeat, which
# then flips the last signature byte. On exit the marker is removed, even
# one that existed before the run.

set -euo pipefail

usage() {
    cat <<EOF
Usage: $0 [--marker PATH] [--demo-dir DIR] [--hold-sec SEC]

Arms the tamper marker watched by demo_anticheat. With no flags the
script picks the newest /tmp/lota-demo.* directory created by
examples/demo/setup.sh and arms <demo-dir>/tamper.marker.

  --marker PATH    explicit marker path; overrides directory discovery
  --demo-dir DIR   sandbox root from setup.sh; marker is DIR/tamper.marker
  --hold-sec SEC   auto-disarm after SEC seconds instead of waiting on
                   SIGINT/SIGTERM. SEC must be a positive integer.

While the marker is armed every heartbeat returns UNTRUSTED, so
trust_pong flips its banner to red and (after two consecutive UNTRUSTED
ticks) freezes the play field. Press Ctrl-C or send SIGTERM to disarm
and restore the green TRUSTED state on the next heartbeat.
EOF
}

die() {
    printf 'demo_tamper.sh: %s\n' "$*" >&2
    exit 1
}

note() {
    printf '    %s\n' "$*"
}

log() {
    printf '\n==> %s\n' "$*"
}

MARKER=""
DEMO_DIR=""
HOLD_SEC=""

while [ "$#" -gt 0 ]; do
    case "$1" in
	--marker)
	    [ "$#" -ge 2 ] || die "--marker requires PATH"
	    MARKER="$2"
	    shift 2
	    ;;
	--demo-dir)
	    [ "$#" -ge 2 ] || die "--demo-dir requires DIR"
	    DEMO_DIR="$2"
	    shift 2
	    ;;
	--hold-sec)
	    [ "$#" -ge 2 ] || die "--hold-sec requires SEC"
	    HOLD_SEC="$2"
	    shift 2
	    ;;
	--help | -h)
	    usage
	    exit 0
	    ;;
	*)
	    die "unknown argument: $1 (try --help)"
	    ;;
    esac
done

if [ -n "$HOLD_SEC" ]; then
    case "$HOLD_SEC" in
	'' | *[!0-9]*)
	    die "--hold-sec must be a positive integer"
	    ;;
    esac
    [ "$HOLD_SEC" -gt 0 ] || die "--hold-sec must be > 0"
fi

if [ -z "$MARKER" ]; then
    if [ -z "$DEMO_DIR" ]; then
	DEMO_DIR="$(ls -1dt /tmp/lota-demo.* 2>/dev/null | head -n1 || true)"
	if [ -z "$DEMO_DIR" ]; then
	    die "no /tmp/lota-demo.* sandbox found; start the demo via examples/demo/setup.sh first"
	fi
    fi
    [ -d "$DEMO_DIR" ] || die "demo dir not found: $DEMO_DIR"
    MARKER="$DEMO_DIR/tamper.marker"
fi

MARKER="$(realpath -m -- "$MARKER")"
case "$MARKER" in
    /tmp/lota-demo.*) ;;
    *)
	die "refusing marker outside /tmp/lota-demo.*: $MARKER"
	;;
esac

marker_dir="$(dirname "$MARKER")"
[ -d "$marker_dir" ] || die "marker dir does not exist: $marker_dir"

tail_pid=""
disarm() {
    trap - EXIT INT TERM
    if [ -n "$tail_pid" ]; then
	kill "$tail_pid" 2>/dev/null || true
    fi
    if [ -e "$MARKER" ]; then
	rm -f "$MARKER" || true
	note "marker disarmed: $MARKER"
    fi
}
trap disarm EXIT INT TERM

log "arming tamper marker"
note "marker: $MARKER"
: >"$MARKER"
note "next heartbeat (cadence depends on demo_anticheat --interval) will return UNTRUSTED"
note "trust_pong needs two consecutive UNTRUSTED ticks to freeze the play field"

if [ -n "$HOLD_SEC" ]; then
    log "holding for ${HOLD_SEC}s, then auto-disarming"
    sleep "$HOLD_SEC"
else
    log "press Ctrl-C to disarm"
    # wait returns on a trapped signal; a foreground sleep would not
    tail -f /dev/null &
    tail_pid=$!
    wait "$tail_pid" 2>/dev/null || true
fi
