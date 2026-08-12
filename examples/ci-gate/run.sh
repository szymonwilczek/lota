#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Szymon Wilczek
#
# End-to-end proof of the CI release gate, on one host, with no root.
#
# It stands up a throwaway swTPM, runs lota-agent against it under socket
# activation so the agent listens on a path in $TMPDIR rather than /run/lota,
# starts the release gate on the AIK that TPM provisioned, and then runs
# the pipeline step twice: once as a host that can attest, and once against a gate
# that trusts a different TPM.
#
# The assertions are the two that matter to a buyer:
#
#   1. attested host gets the secret, and
#   2. host the gate does not trust gets a non-zero exit and no file.
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
gate="$EXAMPLES_BIN/lota-release-gate"
step="$EXAMPLES_BIN/lota-ci-attest"

for b in "$agent" "$gate" "$step"; do
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

# The agent socket lives here,
# so the directory has to stay well inside the 108-byte sockaddr_un limit.
RUN_DIR="$(mktemp -d /tmp/lota-ci-gate.XXXXXX)"
TPM_PORT="${TPM_PORT:-42521}"
GATE_ADDR="${GATE_ADDR:-127.0.0.1:8500}"
TCTI="swtpm:host=127.0.0.1,port=$TPM_PORT"

cleanup() {
	[ -n "${GATE_PID:-}" ] && kill "$GATE_PID" 2>/dev/null || true
	[ -n "${AGENT_PID:-}" ] && kill "$AGENT_PID" 2>/dev/null || true
	[ -n "${SWTPM_PID:-}" ] && kill "$SWTPM_PID" 2>/dev/null || true
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

echo "== 3/5 export the AIK the gate will trust =="
# Socket activation starts the agent on the first connection,
# and the agent provisions its AIK on startup.
# The step connects to the agent before it talks to the gate,
# so running it against a gate that is not up yet is enough to bring the agent
# to life.
"$step" --gate "http://$GATE_ADDR" --socket "$RUN_DIR/lota.sock" \
	--out "$RUN_DIR/warmup" >/dev/null 2>&1 || true

for _ in $(seq 1 30); do
	if TPM2TOOLS_TCTI="$TCTI" tpm2_readpublic -c 0x81010002 -f pem \
		-o "$RUN_DIR/aik.pem" >"$RUN_DIR/readpublic.log" 2>&1; then
		break
	fi
	sleep 1
done
[ -s "$RUN_DIR/aik.pem" ] || fail "could not export the AIK public key"

printf '%s' 'release-me-only-on-an-attested-host' >"$RUN_DIR/secret.txt"

echo "== 4/5 attested host gets the secret =="
"$gate" --listen "$GATE_ADDR" --aik-pub "$RUN_DIR/aik.pem" \
	--secret-file "$RUN_DIR/secret.txt" --require attested,tpm \
	>"$RUN_DIR/gate.log" 2>&1 &
GATE_PID=$!
sleep 1

rm -f "$RUN_DIR/released"
if ! "$step" --gate "http://$GATE_ADDR" --socket "$RUN_DIR/lota.sock" \
	--out "$RUN_DIR/released"; then
	cat "$RUN_DIR/gate.log" >&2
	fail "an attested host was refused"
fi

[ -f "$RUN_DIR/released" ] || fail "no secret was written"
diff -q "$RUN_DIR/secret.txt" "$RUN_DIR/released" >/dev/null ||
	fail "the released secret does not match"
[ "$(stat -c %a "$RUN_DIR/released")" = "600" ] ||
	fail "the released secret is not 0600"
echo "   secret released and written 0600"

kill "$GATE_PID" 2>/dev/null || true
wait "$GATE_PID" 2>/dev/null || true
GATE_PID=""

echo "== 5/5 a host the gate does not trust is refused =="
# Same host, same agent:
# only the key the gate trusts changes, which is what a token minted on somebody
# else's machine looks like from here.
openssl genrsa -out "$RUN_DIR/other.key" 2048 >/dev/null 2>&1
openssl rsa -in "$RUN_DIR/other.key" -pubout -out "$RUN_DIR/other.pem" \
	>/dev/null 2>&1

"$gate" --listen "$GATE_ADDR" --aik-pub "$RUN_DIR/other.pem" \
	--secret-file "$RUN_DIR/secret.txt" --require attested,tpm \
	>"$RUN_DIR/gate-negative.log" 2>&1 &
GATE_PID=$!
sleep 1

rm -f "$RUN_DIR/refused"
set +e
"$step" --gate "http://$GATE_ADDR" --socket "$RUN_DIR/lota.sock" \
	--out "$RUN_DIR/refused" >"$RUN_DIR/step-negative.log" 2>&1
rc=$?
set -e

[ "$rc" -ne 0 ] || fail "an untrusted host was released the secret"
[ "$rc" -eq 6 ] || fail "expected exit 6 (refused), got $rc"
[ ! -e "$RUN_DIR/refused" ] || fail "a refused step still wrote a file"
grep -q "release refused" "$RUN_DIR/gate-negative.log" ||
	fail "the gate did not audit the refusal"
echo "   refused, nothing written, refusal audited"

echo
echo "PASS: the gate releases to an attested host and refuses everything else"
