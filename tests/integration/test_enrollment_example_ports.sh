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

export LC_ALL=C

REPO_DIR=$(cd "$(dirname "$0")/../.." && pwd)
RUN_SH="$REPO_DIR/examples/enrollment/run.sh"
README="$REPO_DIR/examples/enrollment/README.rst"

if [[ ! -x "$RUN_SH" ]]; then
    echo "[example-ports] missing artifact: $RUN_SH" >&2
    exit 2
fi

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

# like BIN, CA_DIR and the other inputs
overridable() {
    grep -Eq "^$1=\"\\\$\{$1:-" "$RUN_SH"
}

check "CA_ADDR comes from the environment" overridable CA_ADDR
check "VERIFIER_ADDR comes from the environment" overridable VERIFIER_ADDR

# the header lists the knobs a reader sets
header_names() {
    head -n 30 "$RUN_SH" | grep -q "$1"
}

check "the script header names CA_ADDR" header_names CA_ADDR
check "the script header names VERIFIER_ADDR" header_names VERIFIER_ADDR
check "the README names both addresses" \
    bash -c "grep -q 'CA_ADDR' '$README' && grep -q 'VERIFIER_ADDR' '$README'"

# a taken CA port is named and stops the run before the CA's bind error
port_collision_is_named() {
    local port out rc listener work verdict=1

    work=$(mktemp -d)

    # a listener the test owns, on a port the kernel picked
    python3 - "$work/port" <<-'PY' &
		import socket, sys, time
		s = socket.socket()
		s.bind(("127.0.0.1", 0))
		s.listen(1)
		open(sys.argv[1], "w").write(str(s.getsockname()[1]))
		time.sleep(60)
	PY
    listener=$!

    for _ in $(seq 1 50); do
        [[ -s "$work/port" ]] && break
        sleep 0.1
    done
    port=$(cat "$work/port" 2>/dev/null || true)

    if [[ -n "$port" ]]; then
        set +e
        out=$(cd "$REPO_DIR/examples/enrollment" &&
            CA_ADDR="127.0.0.1:$port" EK_ROOT=/nonexistent \
                timeout 30 ./run.sh 2>&1)
        rc=$?
        set -e
        if [[ $rc -ne 0 ]] &&
            grep -q "127.0.0.1:$port" <<<"$out" &&
            grep -qiE "in use|already" <<<"$out"; then
            verdict=0
        fi
    fi

    kill "$listener" 2>/dev/null || true
    wait "$listener" 2>/dev/null || true
    rm -rf "$work"
    return "$verdict"
}

if command -v python3 >/dev/null 2>&1; then
    check "a taken address is named and refused before anything starts" \
        port_collision_is_named
else
    echo "SKIP: port collision case (no python3)"
fi

if [[ $failures -ne 0 ]]; then
    echo "FAILURES: $failures"
    exit 1
fi
echo "All tests passed"
