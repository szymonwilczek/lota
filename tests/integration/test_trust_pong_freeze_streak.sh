#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Szymon Wilczek
#
# tests/integration/test_trust_pong_freeze_streak.sh
#
# trust_pong freezes after two consecutive UNTRUSTED heartbeats, as its
# overlay and both demo READMEs promise; one flaky heartbeat must not,
# however often it is polled.
# Driven through the binary: the rule lives in the render loop.
#
# Requires:
#   - bash, python3, and ${LOTA_BUILD_DIR}/examples/trust_pong
#     (make examples)
#
# Runs unprivileged, needs no agent and no display (SDL's dummy video
# driver), and listens on the loopback only.

set -uo pipefail

. "$(dirname "$0")/../lib/test.sh"
test_begin "trust pong streak"

export LC_ALL=C

REPO_DIR=$(cd "$(dirname "$0")/../.." && pwd)
BUILD_DIR="${BUILD_DIR:-${LOTA_BUILD_DIR:-$REPO_DIR/build}}"
GAME_BIN="${LOTA_TRUST_PONG:-$BUILD_DIR/examples/trust_pong}"

if ! command -v python3 >/dev/null 2>&1; then
    FAIL "python3 not installed"
    test_end
fi
if [[ ! -x "$GAME_BIN" ]]; then
    FAIL "%s not built; run 'make examples'" "$GAME_BIN"
    test_end
fi

WORK_DIR=$(mktemp -d)
SERVER_PID=""
cleanup() {
    [[ -n "$SERVER_PID" ]] && kill "$SERVER_PID" 2>/dev/null
    rm -rf "$WORK_DIR"
}
test_cleanup cleanup

# One "<state> <verdict_seq> <updated_at_unix>" line per /state request;
# the last one repeats once exhausted.
# A new verdict_seq or updated_at_unix is a new heartbeat.
cat >"$WORK_DIR/verdict_server.py" <<'PY'
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

states = [line.strip() for line in open(sys.argv[1]) if line.strip()]
served = []


class Handler(BaseHTTPRequestHandler):
    def _json(self, body):
        payload = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        if not self.path.startswith("/state"):
            self.send_error(404)
            return
        line = states[len(served)] if len(served) < len(states) else states[-1]
        state, seq, at = line.split()
        served.append(line)
        with open(sys.argv[2], "a") as log:
            log.write(line + "\n")
        self._json('{"state":"%s","license":"lota-demo-CS2-clone",'
                   '"updated_at_unix":%s,"verdict_seq":%s}' % (state, at, seq))

    def do_POST(self):
        # refuse the nonce handshake; the client stays OFFLINE and polls
        self.send_error(404)

    def log_message(self, *args):
        pass


httpd = HTTPServer(("127.0.0.1", 0), Handler)
with open(sys.argv[3], "w") as f:
    f.write(str(httpd.server_address[1]))
httpd.serve_forever()
PY

run_case() { # <label> <seconds> <state>...
    local label="$1" seconds="$2"
    shift 2
    local dir="$WORK_DIR/$label"
    mkdir -p "$dir"
    printf '%s\n' "$@" >"$dir/states"
    : >"$dir/served"

    python3 "$WORK_DIR/verdict_server.py" "$dir/states" "$dir/served" \
            "$dir/port" &
    SERVER_PID=$!
    local port=""
    for _ in $(seq 1 50); do
        [[ -s "$dir/port" ]] && port=$(cat "$dir/port") && break
        sleep 0.1
    done
    if [[ -z "$port" ]]; then
        FAIL "%s: verdict server never bound" "$label"
        return 1
    fi

    SDL_VIDEODRIVER=dummy timeout -s TERM "$seconds" "$GAME_BIN" \
                          --server "http://127.0.0.1:$port" \
                          --game-id trust-pong >"$dir/stdout" 2>"$dir/stderr"

    kill "$SERVER_PID" 2>/dev/null
    wait "$SERVER_PID" 2>/dev/null
    SERVER_PID=""
}

served_count() { grep -c . "$WORK_DIR/$1/served"; }
freeze_line() { grep 'session terminated after' "$WORK_DIR/$1/stderr"; }

stderr_of() { sed -n '1,20p' "$WORK_DIR/$1/stderr"; }

# one UNTRUSTED between TRUSTED ones: absorbed
TEST "one UNTRUSTED response leaves the session running"
run_case one-untrusted 8 "TRUSTED 1 1" "TRUSTED 2 2" "UNTRUSTED 3 3" \
         "TRUSTED 4 4" "TRUSTED 5 5" "TRUSTED 6 6"
if [[ $(served_count one-untrusted) -lt 4 ]]; then
    FAIL "the client asked for %d verdicts, too few to judge" \
         "$(served_count one-untrusted)"
elif freeze_line one-untrusted >/dev/null; then
    FAIL "%s" "$(freeze_line one-untrusted)"
fi

# one UNTRUSTED heartbeat polled again and again: absorbed
TEST "one UNTRUSTED heartbeat, polled again, is absorbed"
run_case one-heartbeat 8 "TRUSTED 1 1" "UNTRUSTED 2 2"
if [[ $(served_count one-heartbeat) -lt 4 ]]; then
    FAIL "too few polls to judge"
elif freeze_line one-heartbeat >/dev/null; then
    FAIL "%s" "$(freeze_line one-heartbeat)"
fi

# two in a row: session ends
TEST "two consecutive UNTRUSTED responses end the session"
run_case two-untrusted 8 "TRUSTED 1 1" "UNTRUSTED 2 2" "UNTRUSTED 3 3" \
         "TRUSTED 4 4" "TRUSTED 5 5" "TRUSTED 6 6"
if ! freeze_line two-untrusted >/dev/null; then
    FAIL "%s" "$(stderr_of two-untrusted)"
elif ! freeze_line two-untrusted | grep -q 'after 2 consecutive'; then
    FAIL "a streak that is not two: %s" "$(freeze_line two-untrusted)"
fi

# two in a row within one second: session ends
TEST "two UNTRUSTED heartbeats in one second end the session"
run_case same-second 8 "TRUSTED 1 1" "UNTRUSTED 2 2" "UNTRUSTED 3 2" \
         "TRUSTED 4 3" "TRUSTED 5 3"
freeze_line same-second | grep -q 'after 2 consecutive' ||
    FAIL "%s" "$(stderr_of same-second)"

# a restarted server numbers its verdicts from 1 again
TEST "a heartbeat after a server restart is counted"
run_case restart 8 "UNTRUSTED 1 10" "PENDING 0 0" "PENDING 0 0" \
         "UNTRUSTED 1 12"
freeze_line restart | grep -q 'after 2 consecutive' ||
    FAIL "%s" "$(stderr_of restart)"

test_end
