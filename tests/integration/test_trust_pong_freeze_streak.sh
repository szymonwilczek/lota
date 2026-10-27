#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Szymon Wilczek
#
# tests/integration/test_trust_pong_freeze_streak.sh
#
# trust_pong freezes after two consecutive UNTRUSTED verdicts, as its
# overlay and both demo READMEs promise; one flaky verdict must not.
# Driven through the binary: the rule lives in the render loop.
#
# Requires:
#   - bash, python3, and ${LOTA_BUILD_DIR}/examples/trust_pong
#     (make examples)
#
# Runs unprivileged, needs no agent and no display (SDL's dummy video
# driver), and listens on the loopback only.

set -uo pipefail

export LC_ALL=C

REPO_DIR=$(cd "$(dirname "$0")/../.." && pwd)
BUILD_DIR="${BUILD_DIR:-${LOTA_BUILD_DIR:-$REPO_DIR/build}}"
GAME_BIN="${LOTA_TRUST_PONG:-$BUILD_DIR/examples/trust_pong}"

if ! command -v python3 >/dev/null 2>&1; then
    echo "[trust-pong] python3 not installed" >&2
    exit 2
fi
if [[ ! -x "$GAME_BIN" ]]; then
    echo "[trust-pong] $GAME_BIN not built; run 'make examples'" >&2
    exit 2
fi

WORK_DIR=$(mktemp -d)
SERVER_PID=""
cleanup() {
    [[ -n "$SERVER_PID" ]] && kill "$SERVER_PID" 2>/dev/null
    rm -rf "$WORK_DIR"
}
trap cleanup EXIT

# One verdict per /state request; the last one repeats once exhausted.
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
        state = states[len(served)] if len(served) < len(states) else states[-1]
        served.append(state)
        with open(sys.argv[2], "a") as log:
            log.write(state + "\n")
        self._json('{"state":"%s","license":"lota-demo-CS2-clone"}' % state)

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

failures=0

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
        echo "[trust-pong] $label: verdict server never bound" >&2
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

# one UNTRUSTED between TRUSTED ones: absorbed
run_case one-untrusted 8 TRUSTED TRUSTED UNTRUSTED TRUSTED TRUSTED TRUSTED
if [[ $(served_count one-untrusted) -lt 4 ]]; then
    echo "[trust-pong] one-untrusted: the client asked for $(served_count one-untrusted) verdicts, too few to judge" >&2
    failures=$((failures + 1))
elif freeze_line one-untrusted >/dev/null; then
    echo "[trust-pong] FAIL: one UNTRUSTED response ended the session:" >&2
    freeze_line one-untrusted >&2
    failures=$((failures + 1))
else
    echo "[trust-pong] ok: one UNTRUSTED response leaves the session running"
fi

# two in a row: session ends
run_case two-untrusted 8 TRUSTED UNTRUSTED UNTRUSTED TRUSTED TRUSTED TRUSTED
if ! freeze_line two-untrusted >/dev/null; then
    echo "[trust-pong] FAIL: two consecutive UNTRUSTED responses did not end the session" >&2
    sed -n '1,20p' "$WORK_DIR/two-untrusted/stderr" >&2
    failures=$((failures + 1))
elif ! freeze_line two-untrusted | grep -q 'after 2 consecutive'; then
    echo "[trust-pong] FAIL: the session ended on a streak that is not two:" >&2
    freeze_line two-untrusted >&2
    failures=$((failures + 1))
else
    echo "[trust-pong] ok: two consecutive UNTRUSTED responses end the session"
fi

if [[ $failures -ne 0 ]]; then
    echo "[trust-pong] $failures check(s) failed" >&2
    exit 1
fi
echo "[trust-pong] PASS"
