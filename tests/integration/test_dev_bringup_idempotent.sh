#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Szymon Wilczek
#
# tests/integration/test_dev_bringup_idempotent.sh
#
# A re-run of lota-dev-bringup.sh leaves a brought-up host's artefacts,
# AIK included, untouched; only --reset clears them. Checks the calls the
# script makes, since a deterministic Ed25519 re-sign leaves the
# artefact identical.
#
# Requires:
#   - bash, and a writable temp directory
#
# Runs unprivileged under LOTA_BRINGUP_ROOT, with TPM, fs-verity
# and systemd tools stubbed on PATH; the host is not touched.

set -euo pipefail

export LC_ALL=C

REPO_DIR=$(cd "$(dirname "$0")/../.." && pwd)
BRINGUP="$REPO_DIR/scripts/lota-dev-bringup.sh"
TPM_HEADER="$REPO_DIR/src/agent/tpm.h"

if [[ ! -x "$BRINGUP" ]]; then
    echo "[dev-bringup] missing artifact: $BRINGUP" >&2
    exit 2
fi

WORK_DIR=$(mktemp -d)
trap 'rm -rf "$WORK_DIR"' EXIT

ROOT="$WORK_DIR/root"
STUB_BIN="$WORK_DIR/bin"
AGENT_LOG="$WORK_DIR/agent.log"
TPM_LOG="$WORK_DIR/tpm.log"
STATE_DIR="$ROOT/var/lib/lota"

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

says() { grep -qi -e "$2" <<<"$1"; }
denies() { ! grep -qi -e "$2" <<<"$1"; }

# LOTA's persistent handles, read from the agent's header
read_define() {
    sed -n "s/^#define[[:space:]]\+$2[[:space:]]\+\(0x[0-9a-fA-F]\+\).*/\1/p" \
        "$1" | head -1
}

AIK_HANDLE=$(read_define "$TPM_HEADER" TPM_AIK_HANDLE)
SEAL_HANDLE=$(read_define "$TPM_HEADER" TPM_SEAL_PRIMARY_HANDLE)
if [[ -z "$AIK_HANDLE" || -z "$SEAL_HANDLE" ]]; then
    echo "[dev-bringup] could not read the LOTA handles from $TPM_HEADER" >&2
    exit 2
fi

# stub agent: logs its verbs; --verify-policy passes once a .sig exists
mkdir -p "$STUB_BIN" "$ROOT/usr/bin" "$ROOT/usr/lib/lota" "$STATE_DIR"
cat >"$ROOT/usr/bin/lota-agent" <<'AGENT'
#!/bin/bash
set -euo pipefail
printf '%s\n' "$*" >>"$LOTA_TEST_AGENT_LOG"
case "${1:-}" in
--gen-signing-key)
	: >"$2.key"
	: >"$2.pub"
	;;
--sign-policy)
	printf 'signature\n' >"$2.sig"
	;;
--verify-policy)
	[[ -s "$2.sig" ]] || exit 1
	;;
esac
exit 0
AGENT
chmod 0755 "$ROOT/usr/bin/lota-agent"
printf 'bpf object\n' >"$ROOT/usr/lib/lota/lota_lsm.bpf.o"

# fsverity measure fails until enable has run once
cat >"$STUB_BIN/fsverity" <<'FSVERITY'
#!/bin/bash
case "${1:-}" in
measure) [[ -e "$LOTA_TEST_VERITY_MARK" ]] || exit 1 ;;
enable) : >"$LOTA_TEST_VERITY_MARK" ;;
esac
exit 0
FSVERITY
cat >"$STUB_BIN/tpm2_evictcontrol" <<'TPM2'
#!/bin/bash
for arg in "$@"; do
	case "$arg" in
	0x*) printf '%s\n' "$arg" >>"$LOTA_TEST_TPM_LOG" ;;
	esac
done
exit 0
TPM2
cat >"$STUB_BIN/systemctl" <<'SYSTEMCTL'
#!/bin/bash
if [[ "${1:-}" == "is-active" ]]; then
	[[ "${LOTA_TEST_AGENT_ACTIVE:-0}" == "1" ]] && exit 0
	exit 3
fi
exit 0
SYSTEMCTL
chmod 0755 "$STUB_BIN"/*

export LOTA_TEST_AGENT_LOG="$AGENT_LOG"
export LOTA_TEST_TPM_LOG="$TPM_LOG"
export LOTA_TEST_VERITY_MARK="$WORK_DIR/verity.mark"
export LOTA_BRINGUP_ROOT="$ROOT"
export PATH="$STUB_BIN:$PATH"

run_bringup() {
    : >"$AGENT_LOG"
    : >"$TPM_LOG"
    "$BRINGUP" "$@" 2>&1
}

# first run brings up the empty root; later runs are re-runs
if ! first=$(run_bringup); then
    echo "[dev-bringup] first run failed:" >&2
    printf '%s\n' "$first" >&2
    exit 1
fi
check "first run signs the BPF object" says "$first" "signing"
check "first run leaves a signature" test -s "$ROOT/usr/lib/lota/lota_lsm.bpf.o.sig"

# agent state of a provisioned host
printf 'aik\n' >"$STATE_DIR/aik_meta"
printf 'clock\n' >"$STATE_DIR/clock_state"
printf 'commit\n' >"$STATE_DIR/boot_commit"

second=$(run_bringup) || {
    echo "FAIL: the re-run exited non-zero"
    failures=$((failures + 1))
}
tpm_calls=$(cat "$TPM_LOG")
agent_calls=$(cat "$AGENT_LOG")

check "a re-run does not sign an object whose signature verifies" \
    denies "$agent_calls" "sign-policy"
check "a re-run says the signature is already good" \
    says "$second" "signature already valid"
check "a re-run keeps the agent's state files" \
    test -f "$STATE_DIR/aik_meta" -a -f "$STATE_DIR/clock_state"
check "a re-run evicts nothing from the TPM" test -z "$tpm_calls"
check "a re-run names the flag that would reset the state" \
    says "$second" "--reset"

# --reset is the only destructive path
reset=$(run_bringup --reset) || {
    echo "FAIL: --reset exited non-zero"
    failures=$((failures + 1))
}
tpm_calls=$(cat "$TPM_LOG")
check "--reset clears the state files" test ! -e "$STATE_DIR/aik_meta"
check "--reset evicts the profile-less AIK" says "$tpm_calls" "$AIK_HANDLE"
check "--reset evicts the seal primary" says "$tpm_calls" "$SEAL_HANDLE"
check "--reset evicts no handle LOTA does not own" \
    denies "$tpm_calls" "0x81010004"
check "--reset says the per-profile AIKs are left alone" \
    says "$reset" "profile"

# --reset must refuse while the agent runs
printf 'aik\n' >"$STATE_DIR/aik_meta"
export LOTA_TEST_AGENT_ACTIVE=1
if live=$(run_bringup --reset 2>&1); then
    echo "FAIL: --reset ran while the agent was active"
    failures=$((failures + 1))
else
    echo "PASS: --reset refuses while the agent is active"
fi
tpm_calls=$(cat "$TPM_LOG")
check "the refused reset says which unit is holding the key" \
    says "$live" "lota-agent.service is active"
check "the refused reset keeps the state files" test -f "$STATE_DIR/aik_meta"
check "the refused reset evicts nothing" test -z "$tpm_calls"
unset LOTA_TEST_AGENT_ACTIVE

header_drops_the_rollback_claim() { ! grep -q "rolls back" "$BRINGUP"; }
check "the header does not promise a rollback the script does not do" \
    header_drops_the_rollback_claim

echo ""
if [[ $failures -gt 0 ]]; then
    echo "[dev-bringup] $failures check(s) failed"
    exit 1
fi
echo "[dev-bringup] all checks passed"
