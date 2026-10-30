#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Szymon Wilczek
#
# tests/integration/test_steam_setup_no_agent.sh
#
# `lota-steam-setup --verify` with no agent socket. The agent is started
# by lota-agent.socket, and a paused one stays down until the next boot;
# one started from a shell runs outside the unit that sandboxes it.
# The run must not tell the player to start it by hand, but point at
# lota-install's agent service stage, which says what brings it back.
#
# LOTA_AGENT_SOCKET names a path with nothing at it.
#
# Requires:
#   - bash, and a writable temp directory
#
# Runs unprivileged and modifies nothing outside its temp directory.

set -euo pipefail

# the checks grep the script's messages
export LC_ALL=C

REPO_DIR=$(cd "$(dirname "$0")/../.." && pwd)
SETUP="$REPO_DIR/scripts/lota-steam-setup"

if [[ ! -x "$SETUP" ]]; then
    echo "[steam-setup-no-agent] missing artifact: $SETUP" >&2
    exit 2
fi

WORK_DIR=$(mktemp -d)
trap 'rm -rf "$WORK_DIR"' EXIT

failures=0

check() {
    local msg="$1"
    shift
    if "$@"; then
	echo "PASS: $msg"
    else
	echo "FAIL: $msg"
	failures=$((failures + 1))
    fi
}

says() { grep -qi -- "$2" <<<"$1"; }
denies() { ! grep -qi -- "$2" <<<"$1"; }

mkdir -p "$WORK_DIR/run"

rc=0
out=$(LOTA_AGENT_SOCKET="$WORK_DIR/absent.sock" \
	               XDG_RUNTIME_DIR="$WORK_DIR/run" "$SETUP" --verify 2>&1) || rc=$?

check "a missing agent socket is not a pass" \
      test "$rc" -ne 0
check "the missing socket is named" \
      says "$out" "LOTA agent socket not found at $WORK_DIR/absent.sock"
check "the player is not told to start the agent by hand" \
      denies "$out" "lota-agent --daemon"
check "the player is sent to the installer, which says what brings it back" \
      says "$out" "sudo lota-install"

if [[ $failures -gt 0 ]]; then
    echo ""
    echo "--- --verify output ---"
    printf '%s\n' "$out"
    echo ""
    echo "[steam-setup-no-agent] $failures check(s) failed"
    exit 1
fi

echo "[steam-setup-no-agent] all checks passed"
