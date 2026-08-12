#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Szymon Wilczek
#
# End-to-end proof of the anti-cheat reference, on one host, with no root.
#
# It stands up a throwaway swTPM, runs lota-agent against it under socket
# activation so the agent listens on a path in /tmp rather than /run/lota,
# starts the reference game server on the AIK that TPM provisioned,
# and runs the heartbeat producer against it twice.
#
# The assertions are the two a studio cares about:
#
#   1. heartbeat from an attested host verifies (TRUSTED), and
#   2. heartbeat whose token was altered in flight does not (UNTRUSTED),
#      with the server naming the signature as the reason.
#
# The second case flips one byte inside the signed token and leaves the wire
# well-formed, so what it exercises is the integrity path rather than the parser.
#
# Requires: swtpm, swtpm_setup, tpm2_readpublic, systemd-socket-activate,
# and `make all examples` already run.
# Override the binaries with BIN and the examples with EXAMPLES_BIN.

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
BIN="${BIN:-$ROOT/build}"
EXAMPLES_BIN="${EXAMPLES_BIN:-$ROOT/build/examples}"

agent="$BIN/lota-agent"
server="$EXAMPLES_BIN/demo_server"
producer="$EXAMPLES_BIN/demo_anticheat"

for b in "$agent" "$server" "$producer"; do
	[ -x "$b" ] || {
		echo "missing binary: $b (run 'make all examples')" >&2
		exit 1
	}
done

for c in swtpm swtpm_setup tpm2_readpublic systemd-socket-activate; do
	command -v "$c" >/dev/null 2>&1 || {
		echo "missing command: $c" >&2
		exit 1
	}
done

# agent socket lives here,
# so the directory has to stay well inside the 108-byte sockaddr_un limit.
RUN_DIR="$(mktemp -d /tmp/lota-anticheat.XXXXXX)"
TPM_PORT="${TPM_PORT:-42531}"
SERVER_ADDR="${SERVER_ADDR:-127.0.0.1:7543}"
TCTI="swtpm:host=127.0.0.1,port=$TPM_PORT"

cleanup() {
	[ -n "${SERVER_PID:-}" ] && kill "$SERVER_PID" 2>/dev/null || true
	[ -n "${AGENT_PID:-}" ] && kill "$AGENT_PID" 2>/dev/null || true
	[ -n "${SWTPM_PID:-}" ] && kill "$SWTPM_PID" 2>/dev/null || true
	if [ -n "${KEEP_LOGS:-}" ]; then
		echo "logs kept in $RUN_DIR" >&2
		return
	fi
	rm -rf "$RUN_DIR"
}
trap cleanup EXIT

fail() {
	echo "FAIL: $*" >&2
	exit 1
}

echo "== 1/5 start a throwaway swTPM =="
mkdir -p "$RUN_DIR/tpm"
swtpm_setup --tpm2 --tpmstate "$RUN_DIR/tpm" --createek --decryption \
	--overwrite >"$RUN_DIR/swtpm_setup.log" 2>&1
swtpm socket --tpm2 --tpmstate "dir=$RUN_DIR/tpm" \
	--server "type=tcp,port=$TPM_PORT" \
	--ctrl "type=tcp,port=$((TPM_PORT + 1))" \
	--flags not-need-init,startup-clear >"$RUN_DIR/swtpm.log" 2>&1 &
SWTPM_PID=$!
sleep 1

echo "== 2/5 start lota-agent on a socket-activated path =="
# Socket activation is what keeps this rootless:
# systemd-socket-activate binds the listener,
# so the agent never has to create /run/lota.
systemd-socket-activate -l "$RUN_DIR/lota.sock" \
	-E LOTA_TCTI="$TCTI" \
	-E LOTA_AIK_META_PATH="$RUN_DIR/aik_meta.dat" \
	"$agent" --test-signed >"$RUN_DIR/agent.log" 2>&1 &
AGENT_PID=$!

for _ in $(seq 1 30); do
	[ -S "$RUN_DIR/lota.sock" ] && break
	sleep 1
done
[ -S "$RUN_DIR/lota.sock" ] || fail "agent socket never appeared"

echo "== 3/5 export the AIK the server will trust =="
# producer connects to the agent before it reaches the server,
# so running it against a server that is not up yet is what brings
# the socket-activated agent to life and makes it provision its AIK.
"$producer" --server "http://$SERVER_ADDR/heartbeat" \
	--socket "$RUN_DIR/lota.sock" --once >/dev/null 2>&1 || true

for _ in $(seq 1 30); do
	if TPM2TOOLS_TCTI="$TCTI" tpm2_readpublic -c 0x81010002 -f pem \
		-o "$RUN_DIR/aik.pem" >"$RUN_DIR/readpublic.log" 2>&1; then
		break
	fi
	sleep 1
done
[ -s "$RUN_DIR/aik.pem" ] || fail "could not export the AIK public key"

"$producer" --print-runtime-objects >"$RUN_DIR/runtime-manifest.txt" 2>/dev/null
[ -s "$RUN_DIR/runtime-manifest.txt" ] || fail "producer emitted no runtime manifest"

echo "== 4/5 an attested host is TRUSTED =="
"$server" --listen "$SERVER_ADDR" --aik-pub "$RUN_DIR/aik.pem" \
	--anticheat-binary "$producer" \
	--anticheat-runtime-manifest "$RUN_DIR/runtime-manifest.txt" \
	>"$RUN_DIR/server.log" 2>&1 &
SERVER_PID=$!
sleep 1

set +e
"$producer" --server "http://$SERVER_ADDR/heartbeat" \
	--socket "$RUN_DIR/lota.sock" --once >"$RUN_DIR/trusted.log" 2>&1
rc=$?
set -e

# --once exits with the server's verdict: 0 TRUSTED, 1 UNTRUSTED, 2 REJECT
if [ "$rc" -ne 0 ]; then
	cat "$RUN_DIR/trusted.log" "$RUN_DIR/server.log" >&2
	fail "an attested host was not TRUSTED (exit $rc)"
fi
echo "   heartbeat verified against a real TPM quote"

echo "== 5/5 an altered token is UNTRUSTED =="
# one byte flipped inside the signed token, wire format left intact,
# so the server's signature check is what has to catch it.
touch "$RUN_DIR/tamper"
set +e
"$producer" --server "http://$SERVER_ADDR/heartbeat" \
	--socket "$RUN_DIR/lota.sock" --once \
	--tamper-marker "$RUN_DIR/tamper" >"$RUN_DIR/tampered.log" 2>&1
rc=$?
set -e

[ "$rc" -eq 1 ] || fail "expected UNTRUSTED (exit 1), got $rc"
grep -qi "untrusted" "$RUN_DIR/tampered.log" ||
	fail "the producer did not report the UNTRUSTED verdict"
grep -qi "signature" "$RUN_DIR/server.log" ||
	fail "the server did not name the signature as the reason"
echo "   tampered token refused on the signature"

echo
echo "PASS: the reference verifies an attested host and refuses a tampered token"
