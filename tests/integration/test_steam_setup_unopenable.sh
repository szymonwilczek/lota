#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Szymon Wilczek
#
# tests/integration/test_steam_setup_unopenable.sh
#
# `lota-steam-setup --verify` from an account outside the `lota` group,
# which owns both sockets (the agent's 0660, the container one in a 0750
# directory). A socket the account cannot open is not OK, and one in a
# directory it cannot enter is not missing: "not found" with register-and-
# reboot advice sends the player through a reboot that changes nothing.
# The run names the group at the socket.
#
# Its own sockets, fenced by mode, so it runs unprivileged; skips under
# root, which opens everything.
#
# Requires:
#   - bash, python3 (to create the sockets), and a writable temp directory
#
# Runs unprivileged and modifies nothing outside its temp directory.

set -euo pipefail

# The assertions grep the script's own messages.
export LC_ALL=C

REPO_DIR=$(cd "$(dirname "$0")/../.." && pwd)
SETUP="$REPO_DIR/scripts/lota-steam-setup"

if [[ ! -x "$SETUP" ]]; then
    echo "[steam-setup-unopenable] missing artifact: $SETUP" >&2
    exit 2
fi

if [[ $EUID -eq 0 ]]; then
    echo "SKIP: [steam-setup-unopenable] root opens every socket"
    exit 0
fi

if ! command -v python3 >/dev/null 2>&1; then
    echo "SKIP: [steam-setup-unopenable] no python3 to create the sockets"
    exit 0
fi

WORK_DIR=$(mktemp -d)
# rm needs the fenced directory searchable again
trap 'chmod -R u+rwx "$WORK_DIR" 2>/dev/null; rm -rf "$WORK_DIR"' EXIT

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

make_socket() {
    python3 -c 'import socket, sys; socket.socket(socket.AF_UNIX).bind(sys.argv[1])' "$1"
}

# Usable: this account's own, 0600
open_run="$WORK_DIR/open"
mkdir -p "$open_run/lota"
make_socket "$open_run/agent.sock"
make_socket "$open_run/lota/lota.sock"
chmod 0600 "$open_run/agent.sock" "$open_run/lota/lota.sock"

open_out=$(LOTA_AGENT_SOCKET="$open_run/agent.sock" \
	                    XDG_RUNTIME_DIR="$open_run" "$SETUP" --verify 2>&1) || true

check "a socket this account can open is reported OK" \
      says "$open_out" "\[OK\] *LOTA agent socket: $open_run/agent.sock"
check "and so is a container socket it can open" \
      says "$open_out" "\[OK\] *Container socket: $open_run/lota/lota.sock"

# The same two, fenced as the group fences an outsider
shut_run="$WORK_DIR/shut"
mkdir -p "$shut_run/lota"
make_socket "$shut_run/agent.sock"
make_socket "$shut_run/lota/lota.sock"
chmod 0000 "$shut_run/agent.sock" "$shut_run/lota"

shut_rc=0
shut_out=$(LOTA_AGENT_SOCKET="$shut_run/agent.sock" \
	                    XDG_RUNTIME_DIR="$shut_run" "$SETUP" --verify 2>&1) || shut_rc=$?

check "the run is not a pass" \
      test "$shut_rc" -ne 0
check "an agent socket this account cannot open is not reported OK" \
      denies "$shut_out" "\[OK\] *LOTA agent socket"
check "it is reported as one this account cannot open" \
      says "$shut_out" "agent socket exists but this account cannot open it"
check "a socket behind a directory it cannot enter is not called missing" \
      denies "$shut_out" "Container socket not found"
check "nor is the account sent to register and reboot" \
      denies "$shut_out" "register-uid"
check "the directory it cannot look into is named" \
      says "$shut_out" "cannot look inside $shut_run/lota"
check "and the group that decides it" \
      says "$shut_out" "handed to the 'lota' group"

if [[ $failures -gt 0 ]]; then
    echo ""
    echo "--- usable sockets ---"
    printf '%s\n' "$open_out"
    echo "--- fenced sockets ---"
    printf '%s\n' "$shut_out"
    echo ""
    echo "[steam-setup-unopenable] $failures check(s) failed"
    exit 1
fi

echo "[steam-setup-unopenable] all checks passed"
