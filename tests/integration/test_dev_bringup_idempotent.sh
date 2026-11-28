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
# Runs unprivileged under LOTA_BRINGUP_ROOT, with TPM and systemd tools
# stubbed on PATH; the host is not touched.

set -euo pipefail

. "$(dirname "$0")/../lib/test.sh"
test_begin "dev bringup idempotent"

export LC_ALL=C

REPO_DIR=$(cd "$(dirname "$0")/../.." && pwd)
BRINGUP="$REPO_DIR/scripts/lota-dev-bringup.sh"
TPM_HEADER="$REPO_DIR/src/agent/tpm.h"
BUILD_DIR="${BUILD_DIR:-${LOTA_BUILD_DIR:-$REPO_DIR/build}}"
REAL_AGENT="$BUILD_DIR/lota-agent"

for f in "$BRINGUP" "$REAL_AGENT"; do
    if [[ ! -x "$f" ]]; then
        FAIL "missing artifact: %s" "$f"
        test_end
    fi
done

WORK_DIR=$(mktemp -d)
test_cleanup 'rm -rf "$WORK_DIR"'

ROOT="$WORK_DIR/root"
STUB_BIN="$WORK_DIR/bin"
AGENT_LOG="$WORK_DIR/agent.log"
TPM_LOG="$WORK_DIR/tpm.log"
STATE_DIR="$ROOT/var/lib/lota"

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
    FAIL "could not read the LOTA handles from %s" "$TPM_HEADER"
    test_end
fi

# stub agent: logs its verbs; --verify-policy passes once a .sig exists;
# --dump-config goes to the real parser
mkdir -p "$STUB_BIN" "$ROOT/usr/bin" "$ROOT/usr/lib/lota" "$STATE_DIR"
cat >"$ROOT/usr/bin/lota-agent" <<'AGENT'
#!/bin/bash
set -euo pipefail
printf '%s\n' "$*" >>"$LOTA_TEST_AGENT_LOG"
for arg in "$@"; do
	[[ "$arg" == --dump-config ]] && exec "$LOTA_TEST_REAL_AGENT" "$@"
done
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
	unit="${*: -1}"
	[[ "$unit" == lota-agent.service &&
		"${LOTA_TEST_AGENT_ACTIVE:-0}" == "1" ]] && exit 0
	[[ "$unit" == lota-attest.service &&
		"${LOTA_TEST_ATTEST_ACTIVE:-0}" == "1" ]] && exit 0
	exit 3
fi
exit 0
SYSTEMCTL
chmod 0755 "$STUB_BIN"/*

export LOTA_TEST_REAL_AGENT="$REAL_AGENT"
export LOTA_TEST_AGENT_LOG="$AGENT_LOG"
export LOTA_TEST_TPM_LOG="$TPM_LOG"
export LOTA_BRINGUP_ROOT="$ROOT"
export PATH="$STUB_BIN:$PATH"

run_bringup() {
    : >"$AGENT_LOG"
    : >"$TPM_LOG"
    "$BRINGUP" "$@" 2>&1
}

# first run brings up the empty root; later runs are re-runs
TEST "first run succeeds"
if ! first=$(run_bringup); then
    FAIL "%s" "$first"
    test_end
fi
TEST "first run signs the BPF object"
says "$first" "signing" || FAIL "%s" "$first"
TEST "first run leaves a signature"
test -s "$ROOT/usr/lib/lota/lota_lsm.bpf.o.sig" || FAIL

# agent state of a provisioned host
printf 'aik\n' >"$STATE_DIR/aik_meta"
printf 'clock\n' >"$STATE_DIR/clock_state"
printf 'commit\n' >"$STATE_DIR/boot_commit"

TEST "the re-run succeeds"
second=$(run_bringup) || FAIL "%s" "$second"
tpm_calls=$(cat "$TPM_LOG")
agent_calls=$(cat "$AGENT_LOG")

TEST "a re-run does not sign an object whose signature verifies"
denies "$agent_calls" "sign-policy" || FAIL "%s" "$agent_calls"
TEST "a re-run says the signature is already good"
says "$second" "signature already valid" || FAIL "%s" "$second"
TEST "a re-run keeps the agent's state files"
test -f "$STATE_DIR/aik_meta" -a -f "$STATE_DIR/clock_state" || FAIL
TEST "a re-run evicts nothing from the TPM"
test -z "$tpm_calls" || FAIL
TEST "a re-run leaves the seal primary alone"
denies "$agent_calls" "seal-evict-primary" || FAIL "%s" "$agent_calls"
TEST "a re-run names the flag that would reset the state"
says "$second" "--reset" || FAIL "%s" "$second"

# the IMA policy step reads the loaded rules the way the agent does
IMA_RUNTIME="$ROOT/sys/kernel/security/ima/policy"
CMDLINE="$ROOT/proc/cmdline"
EFIVARS="$ROOT/sys/firmware/efi/efivars"
SB_VAR="$EFIVARS/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"
MOK_VAR="$EFIVARS/MokSBStateRT-605dab50-e046-4300-abb6-3dd810dd8b23"
SETUP_VAR="$EFIVARS/SetupMode-8be4df61-93ca-11d2-aa0d-00e098032b8c"
VMLINUX_BTF="$ROOT/sys/kernel/btf/vmlinux"
mkdir -p "$(dirname "$IMA_RUNTIME")" "$(dirname "$CMDLINE")" "$EFIVARS" \
      "$(dirname "$VMLINUX_BTF")"
printf 'BTF\0ima_appraise_measurement\0' >"$VMLINUX_BTF"
no_exec_rules() {
    printf '%s\n' 'dont_appraise fsmagic=0x9fa0' \
           'appraise func=POLICY_CHECK appraise_type=imasig' >"$IMA_RUNTIME"
}
loads_policy() {
    local out
    no_exec_rules
    out=$(run_bringup) || true
    says "$out" "loading IMA appraisal policy" &&
        grep -q "^appraise func=BPRM_CHECK" "$IMA_RUNTIME"
}
lacks_exec_rule() { ! grep -q "^appraise func=BPRM_CHECK" "$IMA_RUNTIME"; }
refuses_policy() {
    local out
    no_exec_rules
    out=$(run_bringup) || true
    says "$out" "not loading" &&
        ! grep -q "^appraise func=BPRM_CHECK" "$IMA_RUNTIME"
}

printf 'ro quiet\n' >"$CMDLINE"
TEST "the default enforce does not get the shipped rules"
refuses_policy || FAIL
printf 'ro ima_appraise=enforcex\n' >"$CMDLINE"
TEST "an unknown ima_appraise= value is enforce"
refuses_policy || FAIL
printf 'ro ima_appraise=off -- ima_appraise=fix\n' >"$CMDLINE"
TEST "ima_appraise=off gets the shipped rules"
loads_policy || FAIL
printf 'ro ima_appraise=enforce -- ima_appraise=fix\n' >"$CMDLINE"
TEST "an ima_appraise= past -- does not count"
refuses_policy || FAIL
printf 'ro ima_appraise=fix\n' >"$CMDLINE"
printf '\x06\x00\x00\x00\x01' >"$SB_VAR"
TEST "Secure Boot keeps enforce whatever ima_appraise= says"
refuses_policy || FAIL
printf '\x06\x00\x00\x00\x01' >"$MOK_VAR"
TEST "shim's insecure mode leaves ima_appraise= in force"
loads_policy || FAIL
rm -f "$MOK_VAR"
printf '\x06\x00\x00\x00\x01' >"$SETUP_VAR"
TEST "setup mode leaves ima_appraise= in force"
loads_policy || FAIL
rm -f "$SB_VAR" "$MOK_VAR" "$SETUP_VAR"
printf 'BTF\0ima_measure\0' >"$VMLINUX_BTF"
printf 'ro quiet\n' >"$CMDLINE"
no_exec_rules
ima_out=$(run_bringup) || true
TEST "a kernel without IMA appraisal says so"
says "$ima_out" "kernel does not appraise files" || FAIL "%s" "$ima_out"
TEST "a kernel without IMA appraisal is not said to be in enforce"
denies "$ima_out" "IMA appraisal in enforce" || FAIL "%s" "$ima_out"
printf 'ro ima_appraise=fix\n' >"$CMDLINE"
no_exec_rules
ima_out=$(run_bringup) || true
TEST "a kernel without IMA appraisal gets no policy"
lacks_exec_rule || FAIL
printf 'BTF\0ima_appraise_measurement\0' >"$VMLINUX_BTF"

no_exec_rules
ima_out=$(run_bringup) || true
TEST "dont_appraise and POLICY_CHECK alone get the shipped rules"
says "$ima_out" "loading IMA appraisal policy" || FAIL "%s" "$ima_out"
TEST "the shipped rules reach the policy file"
grep -q "^appraise func=BPRM_CHECK" "$IMA_RUNTIME" || FAIL
ima_out=$(run_bringup) || true
TEST "an exec appraise rule is left alone"
says "$ima_out" "already appraises exec" || FAIL "%s" "$ima_out"
rm -f "$IMA_RUNTIME"
mkdir "$IMA_RUNTIME"
ima_out=$(run_bringup) || true
TEST "an unreadable policy is not written blind"
says "$ima_out" "cannot be read" || FAIL "%s" "$ima_out"
TEST "an unreadable policy is left as it was"
test -d "$IMA_RUNTIME" || FAIL
rmdir "$IMA_RUNTIME"

# --reset is the only destructive path
TEST "--reset succeeds"
reset=$(run_bringup --reset) || FAIL "%s" "$reset"
tpm_calls=$(cat "$TPM_LOG")
agent_calls=$(cat "$AGENT_LOG")
TEST "--reset clears the state files"
test ! -e "$STATE_DIR/aik_meta" || FAIL
TEST "--reset evicts the profile-less AIK"
says "$tpm_calls" "$AIK_HANDLE" || FAIL "%s" "$tpm_calls"
TEST "--reset evicts the seal primary through the agent"
says "$agent_calls" "^--config $ROOT/etc/lota/lota.conf --seal-evict-pri" ||
    FAIL "%s" "$agent_calls"
TEST "--reset leaves the seal handle to the agent's check"
denies "$tpm_calls" "$SEAL_HANDLE" || FAIL "%s" "$tpm_calls"
TEST "--reset evicts no handle LOTA does not own"
denies "$tpm_calls" "0x81010004" || FAIL "%s" "$tpm_calls"
TEST "--reset says the per-profile AIKs are left alone"
says "$reset" "profile" || FAIL "%s" "$reset"

# --reset must refuse while the agent runs
printf 'aik\n' >"$STATE_DIR/aik_meta"
export LOTA_TEST_AGENT_ACTIVE=1
TEST "--reset refuses while the agent is active"
live=$(run_bringup --reset 2>&1) && FAIL "%s" "$live"
tpm_calls=$(cat "$TPM_LOG")
TEST "the refused reset says which unit is holding the key"
says "$live" "lota-agent.service is active" || FAIL "%s" "$live"
TEST "the refused reset keeps the state files"
test -f "$STATE_DIR/aik_meta" || FAIL
TEST "the refused reset evicts nothing"
test -z "$tpm_calls" || FAIL
unset LOTA_TEST_AGENT_ACTIVE

# --reset must refuse while the attestation loop holds the AIK
export LOTA_TEST_ATTEST_ACTIVE=1
TEST "--reset refuses while lota-attest.service is active"
live=$(run_bringup --reset 2>&1) && FAIL "%s" "$live"
tpm_calls=$(cat "$TPM_LOG")
TEST "the refused reset names the attestation unit"
says "$live" "lota-attest.service is active" || FAIL "%s" "$live"
TEST "the attest-held reset keeps the state files"
test -f "$STATE_DIR/aik_meta" || FAIL
TEST "the attest-held reset evicts nothing"
test -z "$tpm_calls" || FAIL
unset LOTA_TEST_ATTEST_ACTIVE

# --reset must refuse while a daemon runs outside an active unit
mkdir -p "$ROOT/run/lota"
sleep 60 &
live_pid=$!
printf '%s\n' "$live_pid" >"$ROOT/run/lota/lota-agent.pid"
TEST "--reset refuses while a daemon is running"
held=$(run_bringup --reset 2>&1) && FAIL "%s" "$held"
tpm_calls=$(cat "$TPM_LOG")
TEST "the refusal names the running daemon"
says "$held" "pid $live_pid" || FAIL "%s" "$held"
TEST "the held reset keeps the state files"
test -f "$STATE_DIR/aik_meta" || FAIL
TEST "the held reset evicts nothing"
test -z "$tpm_calls" || FAIL
kill "$live_pid" 2>/dev/null || true
wait "$live_pid" 2>/dev/null || true

# a stale pid file does not block --reset
printf '%s\n' "$live_pid" >"$ROOT/run/lota/lota-agent.pid"
TEST "--reset runs behind a stale pid file"
stale=$(run_bringup --reset 2>&1) || FAIL "%s" "$stale"
tpm_calls=$(cat "$TPM_LOG")
TEST "a stale pid file does not block a reset"
test ! -e "$STATE_DIR/aik_meta" || FAIL
TEST "the reset behind a stale pid file evicts the AIK"
says "$tpm_calls" "$AIK_HANDLE" || FAIL "%s" "$tpm_calls"
rm -f "$ROOT/run/lota/lota-agent.pid"

# a config with a profile keeps policy_pubkey at top level
CONF="$ROOT/etc/lota/lota.conf"
printf '%s\n' '[profile "demo"]' 'ca = ca.example.invalid' \
       'ca_cert = /etc/lota/demo.pem' 'verifier = none' >"$CONF"
prof_out=$(run_bringup) || true
TEST "policy_pubkey is wired into a config with a profile"
grep -q '^policy_pubkey' "$CONF" || FAIL
loads() { "$REAL_AGENT" --config "$1" --dump-config >/dev/null 2>&1; }
TEST "the agent loads the config the script wrote"
loads "$CONF" || FAIL
TEST "the profile survives the edit"
grep -q '^\[profile "demo"\]' "$CONF" || FAIL

# a umask that lets the group write does not reach the config
printf '%s\n' '# local settings' >"$CONF"
chmod 0644 "$CONF"
(umask 002 && run_bringup >/dev/null) || true
TEST "policy_pubkey is wired in under umask 002"
grep -q '^policy_pubkey' "$CONF" || FAIL
TEST "the config keeps mode 0644 under umask 002"
test "$(stat -c %a "$CONF")" = 644 || FAIL
TEST "no edited copy is left beside the config"
test ! -e "$CONF.new" || FAIL

# an edited copy left group-writable by an earlier run is written anew
printf '%s\n' '# local settings' >"$CONF"
printf 'stale\n' >"$CONF.new"
chmod 0664 "$CONF.new"
stale_out=$(run_bringup) || true
TEST "a stale group-writable copy does not stop the edit"
grep -q '^policy_pubkey' "$CONF" || FAIL
TEST "the stale copy is gone after the edit"
test ! -e "$CONF.new" || FAIL

# --reset evicts the AIK at the handle lota.conf names
printf 'aik_handle = 0x81010020\n' >>"$CONF"
TEST "--reset with aik_handle succeeds"
handle_out=$(run_bringup --reset 2>&1) || FAIL "%s" "$handle_out"
tpm_calls=$(cat "$TPM_LOG")
TEST "--reset evicts the AIK at aik_handle"
says "$tpm_calls" "0x81010020" || FAIL "%s" "$tpm_calls"
TEST "--reset leaves the default AIK handle alone"
denies "$tpm_calls" "$AIK_HANDLE" || FAIL "%s" "$tpm_calls"

header_drops_the_rollback_claim() { ! grep -q "rolls back" "$BRINGUP"; }
TEST "the header does not promise a rollback the script does not do"
header_drops_the_rollback_claim || FAIL

test_end
