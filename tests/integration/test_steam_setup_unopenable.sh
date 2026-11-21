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

. "$(dirname "$0")/../lib/test.sh"
test_begin "steam setup unopenable"

# The assertions grep the script's own messages.
export LC_ALL=C

REPO_DIR=$(cd "$(dirname "$0")/../.." && pwd)
SETUP="$REPO_DIR/scripts/lota-steam-setup"

if [[ ! -x "$SETUP" ]]; then
    FAIL "missing artifact: %s" "$SETUP"
    test_end
fi

if [[ $EUID -eq 0 ]]; then
    SKIP "root opens every socket"
    test_end
fi

if ! command -v python3 >/dev/null 2>&1; then
    SKIP "no python3 to create the sockets"
    test_end
fi

WORK_DIR=$(mktemp -d)
# rm needs the fenced directory searchable again
test_cleanup 'chmod -R u+rwx "$WORK_DIR" 2>/dev/null; rm -rf "$WORK_DIR"'

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

TEST "a socket this account can open is reported OK"
says "$open_out" "\[OK\] *LOTA agent socket: $open_run/agent.sock" ||
    FAIL "%s" "$open_out"
TEST "and so is a container socket it can open"
says "$open_out" "\[OK\] *Container socket: $open_run/lota/lota.sock" ||
    FAIL "%s" "$open_out"

# The same two, fenced as the group fences an outsider
shut_run="$WORK_DIR/shut"
mkdir -p "$shut_run/lota"
make_socket "$shut_run/agent.sock"
make_socket "$shut_run/lota/lota.sock"
chmod 0000 "$shut_run/agent.sock" "$shut_run/lota"

shut_rc=0
shut_out=$(LOTA_AGENT_SOCKET="$shut_run/agent.sock" \
	                    XDG_RUNTIME_DIR="$shut_run" "$SETUP" --verify 2>&1) || shut_rc=$?

TEST "the run is not a pass"
test "$shut_rc" -ne 0 || FAIL
TEST "an agent socket this account cannot open is not reported OK"
denies "$shut_out" "\[OK\] *LOTA agent socket" || FAIL "%s" "$shut_out"
TEST "it is reported as one this account cannot open"
says "$shut_out" "agent socket exists but this account cannot open it" ||
    FAIL "%s" "$shut_out"
TEST "a socket behind a directory it cannot enter is not called missing"
denies "$shut_out" "Container socket not found" || FAIL "%s" "$shut_out"
TEST "nor is the account sent to register and reboot"
denies "$shut_out" "register-uid" || FAIL "%s" "$shut_out"
TEST "the directory it cannot look into is named"
says "$shut_out" "cannot look inside $shut_run/lota" || FAIL "%s" "$shut_out"
TEST "and the group that decides it"
says "$shut_out" "handed to the 'lota' group" || FAIL "%s" "$shut_out"

test_end
