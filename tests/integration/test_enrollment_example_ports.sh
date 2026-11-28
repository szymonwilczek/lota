#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Szymon Wilczek
#
# tests/integration/test_enrollment_example_ports.sh
#
# The enrollment demo runs beside an attesting host: both listen addresses
# come from the environment, and a taken port is refused by name before
# anything starts. The run itself needs a TPM; this part does not.
#
# Requires:
#   - examples/enrollment/run.sh
#
# Runs unprivileged and starts nothing but a listener of its own.

set -euo pipefail

. "$(dirname "$0")/../lib/test.sh"
test_begin "enrollment ports"

export LC_ALL=C

REPO_DIR=$(cd "$(dirname "$0")/../.." && pwd)
RUN_SH="$REPO_DIR/examples/enrollment/run.sh"

if [[ ! -x "$RUN_SH" ]]; then
    FAIL "missing artifact: %s" "$RUN_SH"
    test_end
fi

# like BIN, CA_DIR and the other inputs
overridable() {
    grep -Eq "^$1=\"\\\$\{$1:-" "$RUN_SH"
}

TEST "CA_ADDR comes from the environment"
overridable CA_ADDR || FAIL
TEST "VERIFIER_ADDR comes from the environment"
overridable VERIFIER_ADDR || FAIL

# a listener the test owns, on a port the kernel picked; its pid is LISTENER
LISTENER=""
start_listener() {
    local host=$1 file=$2

    python3 - "$host" "$file" <<-'PY' &
		import socket, sys, time
		s = socket.socket()
		s.bind((sys.argv[1], 0))
		s.listen(1)
		open(sys.argv[2], "w").write(str(s.getsockname()[1]))
		time.sleep(60)
	PY
    LISTENER=$!

    for _ in $(seq 1 50); do
        [[ -s "$file" ]] && return 0
        sleep 0.1
    done
    return 1
}

stop_listener() {
    kill "$LISTENER" 2>/dev/null || true
    wait "$LISTENER" 2>/dev/null || true
}

# run.sh with the given environment; sets OUT and RC
run_demo() {
    set +e
    OUT=$(cd "$REPO_DIR/examples/enrollment" &&
        env EK_ROOT=/nonexistent CA_DIR=/nonexistent "$@" \
            timeout 30 ./run.sh 2>&1)
    RC=$?
    set -e
}

# a taken CA port is named and stops the run before the CA's bind error
port_collision_is_named() {
    local port work verdict=1

    work=$(mktemp -d)
    if start_listener 127.0.0.1 "$work/port"; then
        port=$(cat "$work/port")
        run_demo CA_ADDR="127.0.0.1:$port"
        if [[ $RC -ne 0 ]] &&
            grep -q "127.0.0.1:$port" <<<"$OUT" &&
            grep -qiE "in use|already" <<<"$OUT"; then
            verdict=0
        fi
    fi
    stop_listener
    rm -rf "$work"
    return "$verdict"
}

# the hint never names the port the verifier is given
hint_skips_the_other_address() {
    local port work verdict=1

    work=$(mktemp -d)
    if start_listener 127.0.0.1 "$work/port"; then
        port=$(cat "$work/port")
        run_demo CA_ADDR="127.0.0.1:$port" \
            VERIFIER_ADDR="127.0.0.1:$((port + 1))"
        if [[ $RC -ne 0 ]] &&
            grep -q "CA_ADDR=127.0.0.1:" <<<"$OUT" &&
            ! grep -q "CA_ADDR=127.0.0.1:$((port + 1)) " <<<"$OUT"; then
            verdict=0
        fi
    fi
    stop_listener
    rm -rf "$work"
    return "$verdict"
}

# a listener on another host of the same port leaves the address free
other_host_is_not_taken() {
    local port work verdict=1

    work=$(mktemp -d)
    if start_listener 127.0.0.2 "$work/port"; then
        port=$(cat "$work/port")
        run_demo CA_ADDR="127.0.0.1:$port"
        if ! grep -qiE "in use" <<<"$OUT"; then
            verdict=0
        fi
    fi
    stop_listener
    rm -rf "$work"
    return "$verdict"
}

# an address with no host listens on every one, so any listener takes it
empty_host_is_taken() {
    local port work verdict=1

    work=$(mktemp -d)
    if start_listener 127.0.0.1 "$work/port"; then
        port=$(cat "$work/port")
        run_demo CA_ADDR=":$port"
        if [[ $RC -ne 0 ]] && grep -qiE "in use" <<<"$OUT"; then
            verdict=0
        fi
    fi
    stop_listener
    rm -rf "$work"
    return "$verdict"
}

if command -v python3 >/dev/null 2>&1; then
    TEST "a taken address is named and refused before anything starts"
    port_collision_is_named || FAIL
    TEST "the suggested port is not the other address's port"
    hint_skips_the_other_address || FAIL
    if command -v ss >/dev/null 2>&1; then
        TEST "a listener on another host does not take the address"
        other_host_is_not_taken || FAIL
        TEST "a listener on the port takes an address with no host"
        empty_host_is_taken || FAIL
    else
        TEST "other host case"
        SKIP "no ss"
    fi
else
    TEST "port collision cases"
    SKIP "no python3"
fi

test_end
