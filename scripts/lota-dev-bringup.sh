#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Szymon Wilczek
#
# lota-dev-bringup.sh
#
# Prepare a developer host for the agent: an Ed25519 key at
# /etc/lota/policy.key, a signature on the BPF object and policy_pubkey in
# /etc/lota/lota.conf. Not meant for hardened production hosts.
#
# Each step skips what is already in place. There is no rollback: a failed run
# keeps its partial work.
#
# Environment:
#   LOTA_BRINGUP_ROOT
#     Prefix the /etc, /usr, /var, /run, /proc and /sys paths with this
#     directory, for tests; root is then not required. systemd and the TPM are
#     not redirected.

set -euo pipefail

usage() {
    cat <<'EOF'
Usage: lota-dev-bringup.sh [--reset]

  --reset   Clear the agent state under /var/lib/lota and evict the
            persistent handles LOTA owns from the TPM. This destroys
            the host's attestation identity; the next agent start
            provisions a new one. Refused while the agent is
            running.
  --help    Show this help
EOF
}

do_reset=false
for arg in "$@"; do
    case "$arg" in
        --reset) do_reset=true ;;
        -h | --help)
            usage
            exit 0
            ;;
        *)
            echo "lota-dev-bringup: unknown option: $arg" >&2
            usage >&2
            exit 2
            ;;
    esac
done

BRINGUP_ROOT="${LOTA_BRINGUP_ROOT:-}"
redirected=false
[[ -n "$BRINGUP_ROOT" ]] && redirected=true

if ! $redirected && [[ $EUID -ne 0 ]]; then
    echo "lota-dev-bringup: must run as root (TPM + IMA)" >&2
    exit 2
fi

POLICY_DIR="$BRINGUP_ROOT/etc/lota"
POLICY_KEY="$POLICY_DIR/policy.key"
POLICY_PUB="$POLICY_DIR/policy.pub"
LOTA_CONF="$POLICY_DIR/lota.conf"
AGENT_BIN="$BRINGUP_ROOT/usr/bin/lota-agent"
BPF_OBJ="$BRINGUP_ROOT/usr/lib/lota/lota_lsm.bpf.o"
BPF_SIG="$BPF_OBJ.sig"
STATE_DIR="$BRINGUP_ROOT/var/lib/lota"
PID_FILE="$BRINGUP_ROOT/run/lota/lota-agent.pid"
AGENT_HELD_BY=""
IMA_POLICY_SRC="$(dirname "$0")/../configs/ima/lota-ima-policy"
IMA_POLICY_RUNTIME="$BRINGUP_ROOT/sys/kernel/security/ima/policy"
VMLINUX_BTF="$BRINGUP_ROOT/sys/kernel/btf/vmlinux"
CMDLINE="$BRINGUP_ROOT/proc/cmdline"
EFIVARS="$BRINGUP_ROOT/sys/firmware/efi/efivars"
SB_VAR="SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"
SETUP_VAR="SetupMode-8be4df61-93ca-11d2-aa0d-00e098032b8c"
MOK_VAR="MokSBStateRT-605dab50-e046-4300-abb6-3dd810dd8b23"

info() { printf '[lota-dev-bringup] %s\n' "$*"; }
warn() { printf '[lota-dev-bringup] WARN: %s\n' "$*" >&2; }
fail() {
    printf '[lota-dev-bringup] FAIL: %s\n' "$*" >&2
    exit 1
}

ensure_artifact() {
    [[ -e "$1" ]] || fail "missing artifact: $1 (run 'sudo make install' first)"
}

TPM_HEADER="$(dirname "$0")/../src/agent/tpm.h"
PROFILE_HEADER="$(dirname "$0")/../src/agent/profile.h"

read_define() {
    sed -n "s/^#define[[:space:]]\+$2[[:space:]]\+\([0-9a-fA-Fx]\+\).*/\1/p" \
        "$1" 2>/dev/null | head -1
}

AIK_HANDLE=$(read_define "$TPM_HEADER" TPM_AIK_HANDLE)
SEAL_HANDLE=$(read_define "$TPM_HEADER" TPM_SEAL_PRIMARY_HANDLE)
PROFILE_BASE=$(read_define "$TPM_HEADER" TPM_AIK_PROFILE_HANDLE_BASE)
PROFILE_COUNT=$(read_define "$PROFILE_HEADER" LOTA_PROFILE_MAX_AIK_HANDLES)
PROFILE_RANGE=""
if [[ -n "$PROFILE_BASE" && -n "$PROFILE_COUNT" ]]; then
    PROFILE_RANGE=$(printf '%s-0x%08x' "$PROFILE_BASE" \
                           $((PROFILE_BASE + PROFILE_COUNT - 1)))
fi

ensure_artifact "$AGENT_BIN"
ensure_artifact "$BPF_OBJ"

if [[ ! -f "$POLICY_KEY" || ! -f "$POLICY_PUB" ]]; then
    info "generating Ed25519 keypair at $POLICY_DIR/policy.{key,pub}"
    install -d -m 0700 "$POLICY_DIR"
    "$AGENT_BIN" --gen-signing-key "$POLICY_DIR/policy"
    chmod 0600 "$POLICY_KEY"
    chmod 0644 "$POLICY_PUB"
else
    info "operator keypair already present, skipping --gen-signing-key"
fi

if [[ -f "$BPF_SIG" ]] && [[ -f "$POLICY_PUB" ]] &&
       "$AGENT_BIN" --verify-policy "$BPF_OBJ" \
                    --policy-pubkey "$POLICY_PUB" >/dev/null 2>&1; then
    info "BPF object signature already valid, skipping --sign-policy"
else
    info "signing $BPF_OBJ"
    "$AGENT_BIN" --sign-policy "$BPF_OBJ" --signing-key "$POLICY_KEY"
    ensure_artifact "$BPF_SIG"
fi

if [[ ! -f "$LOTA_CONF" ]]; then
    info "seeding $LOTA_CONF from configs/lota.conf.example"
    src="$(dirname "$0")/../configs/lota.conf.example"
    [[ -f "$src" ]] || fail "configs/lota.conf.example not found relative to $0"
    # a root agent refuses a config not owned by root
    if $redirected; then
        install -m 0644 "$src" "$LOTA_CONF"
    else
        install -m 0644 -o root -g root "$src" "$LOTA_CONF"
    fi
fi
if ! grep -Eq "^[[:space:]]*policy_pubkey[[:space:]]*=" "$LOTA_CONF"; then
    info "wiring policy_pubkey = $POLICY_PUB into $LOTA_CONF"
    # every key after a [profile] header belongs to that profile
    # the agent refuses a group- or world-writable config
    rm -f "$LOTA_CONF.new"
    (umask 077 && awk -v key="policy_pubkey = $POLICY_PUB" \
                      -v note="# Added by lota-dev-bringup" '
        !done && /^[[:space:]]*\[/ { print note; print key; print ""; done = 1 }
        { print }
        END { if (!done) { print ""; print note; print key } }
    ' "$LOTA_CONF" >"$LOTA_CONF.new")
    "$AGENT_BIN" --config "$LOTA_CONF.new" --dump-config >/dev/null || {
        rm -f "$LOTA_CONF.new"
        fail "the agent refuses $LOTA_CONF once edited; left unchanged"
    }
    cat "$LOTA_CONF.new" >"$LOTA_CONF"
    rm -f "$LOTA_CONF.new"
else
    info "policy_pubkey already configured, leaving $LOTA_CONF alone"
fi

# an efivar as decimal bytes: 4 attribute bytes, then the value
efivar_bytes() {
    od -An -tu1 -v "$EFIVARS/$1" 2>/dev/null | tr -s ' \n' ' '
}

# lota_secure_boot_judge(): SecureBoot=1, not in setup mode, shim validating
secure_boot_on() {
    local -a sb setup mok
    read -ra sb <<<"$(efivar_bytes "$SB_VAR")"
    [[ ${#sb[@]} -ge 5 && ${sb[4]} -eq 1 ]] || return 1
    read -ra setup <<<"$(efivar_bytes "$SETUP_VAR")"
    [[ ${#setup[@]} -ge 5 && ${setup[4]} -eq 1 ]] && return 1
    read -ra mok <<<"$(efivar_bytes "$MOK_VAR")"
    ! [[ ${#mok[@]} -ge 5 && $((mok[0] & 1)) -eq 0 && ${mok[4]} -eq 1 ]]
}

# the value lota_ima_cmdline_enforce() reads: the last ima_appraise= before --
ima_cmdline_value() {
    awk '{
        s = $0; n = length(s); i = 1
        while (i <= n) {
            while (i <= n && substr(s, i, 1) ~ /[ \t\n]/) i++
            if (i > n) break
            lead = substr(s, i, 1) == "\""; q = lead; i += lead; start = i
            while (i <= n) {
                c = substr(s, i, 1)
                if (!q && c ~ /[ \t\n]/) break
                if (c == "\"") q = !q
                i++
            }
            tok = substr(s, start, i - start)
            if (lead && substr(tok, length(tok)) == "\"")
                tok = substr(tok, 1, length(tok) - 1)
            eq = index(tok, "=")
            if (!eq && tok == "--") break
            if (!eq) continue
            name = substr(tok, 1, eq - 1); gsub(/-/, "_", name)
            if (name != "ima_appraise") continue
            val = substr(tok, eq + 1); sub(/^"/, "", val); set = 1
        }
    } END { if (set) print val }' "$CMDLINE" 2>/dev/null || true
}

# as lota_ima_appraise_built(): without CONFIG_IMA_APPRAISE,
# ima_appraise_measurement() has no BTF entry and no appraise rule refuses
if ! grep -qa ima_appraise_measurement "$VMLINUX_BTF" 2>/dev/null; then
    ima_mode=none
    warn "kernel does not appraise files (no ima_appraise_measurement in"
    warn "$VMLINUX_BTF); tokens will say KERNEL_APPRAISAL is clear, and"
    warn "the IMA policy is not loaded"
elif secure_boot_on; then
    ima_mode=enforce
    info "IMA appraisal in enforce: Secure Boot makes the kernel ignore"
    info "ima_appraise="
else
    ima_value=$(ima_cmdline_value)
    case "$ima_value" in
        off* | log* | fix*) ima_mode=${ima_value:0:3} ;;
        *) ima_mode=enforce ;;
    esac
    if [[ "$ima_mode" == enforce ]]; then
        info "IMA appraisal in enforce"
    else
        warn "kernel cmdline sets ima_appraise=$ima_value; tokens will say"
        warn "KERNEL_APPRAISAL is clear. $ima_mode does not block on"
        warn "integrity failures"
    fi
fi

# the agent's test: an appraise rule whose first func= is BPRM_CHECK, or none
appraises_exec() {
    awk '$1 == "appraise" {
        f = ""
        for (i = 2; i <= NF; i++)
            if ($i ~ /^func=/) { f = substr($i, 6); break }
        if (f == "" || f == "BPRM_CHECK") found = 1
    } END { exit !found }'
}

if [[ "$ima_mode" != none && -f "$IMA_POLICY_SRC" ]]; then
    if ! ima_rules=$(cat "$IMA_POLICY_RUNTIME" 2>/dev/null); then
        warn "$IMA_POLICY_RUNTIME cannot be read; not loading"
        warn "$IMA_POLICY_SRC over rules that may already be there"
    elif appraises_exec <<<"$ima_rules"; then
        info "IMA policy already appraises exec"
    elif [[ "$ima_mode" == enforce ]]; then
        warn "not loading $IMA_POLICY_SRC: in enforce its rules refuse, until"
        warn "reboot, every exec and executable mmap of a file without an IMA"
        warn "signature outside the pseudo filesystems and tmpfs it exempts"
    else
        info "loading IMA appraisal policy from $IMA_POLICY_SRC"
        if ! cat "$IMA_POLICY_SRC" >"$IMA_POLICY_RUNTIME" 2>/dev/null; then
            warn "writing to $IMA_POLICY_RUNTIME failed; kernel may need"
            warn "ima_policy=appraise_tcb on cmdline or a custom policy"
        fi
    fi
fi

state_files() {
    [[ -d "$STATE_DIR" ]] || return 0
    find "$STATE_DIR" -mindepth 1 -maxdepth 1 \
         \( -name 'aik*' -o -name 'clock*' -o -name 'boot_commit*' \
         -o -name 'snapshot*' \) 2>/dev/null || true
}

# Active unit, or a live pid in the daemon's pid file: after a refused
# stop the unit is not active and the daemon still runs.
agent_is_running() {
    local pid=""

    if command -v systemctl >/dev/null 2>&1 &&
            systemctl is-active --quiet lota-agent.service; then
        AGENT_HELD_BY="lota-agent.service is active"
        return 0
    fi
    if [[ -r "$PID_FILE" ]]; then
        read -r pid <"$PID_FILE" || true
        if [[ "$pid" =~ ^[0-9]+$ ]] && kill -0 "$pid" 2>/dev/null; then
            AGENT_HELD_BY="a lota-agent daemon is running as pid $pid"
            return 0
        fi
    fi
    return 1
}

if ! $do_reset; then
    stale=$(state_files | wc -l)
    if [[ "$stale" -gt 0 ]]; then
        info "leaving $stale agent state file(s) under $STATE_DIR alone"
        info "  re-run with --reset to clear them and the persistent"
        info "  handles; that destroys this host's attestation identity"
    else
        info "no agent state under $STATE_DIR to clear"
    fi
else
    if agent_is_running; then
        warn "$AGENT_HELD_BY."
        warn "--reset destroys the attestation key it is using."
        warn "Stop it first:"
        warn "  systemctl stop lota-agent.service lota-agent.socket"
        fail "refusing to reset the state of a running agent"
    fi
    info "clearing agent state under $STATE_DIR"
    state_files | while read -r stale_file; do
        rm -f "$stale_file"
    done

    if [[ -z "$AIK_HANDLE" || -z "$SEAL_HANDLE" ]]; then
        fail "could not read the persistent handles from $TPM_HEADER"
    fi

    if command -v tpm2_evictcontrol >/dev/null 2>&1; then
        for handle in "$AIK_HANDLE" "$SEAL_HANDLE"; do
            if tpm2_evictcontrol -C o -c "$handle" 2>/dev/null; then
                info "evicted persistent object at $handle"
            fi
        done
        if [[ -n "$PROFILE_RANGE" ]]; then
            info "leaving the per-profile AIKs at $PROFILE_RANGE in"
            info "  place; a publisher's key goes when its profile does"
        fi
    else
        warn "tpm2-tools not installed; persistent handles cannot be evicted"
        warn "install tpm2-tools and re-run if PCR14 errors persist"
    fi
fi

info ""
info "Bring-up complete. Next steps:"
info "  1. Reboot the host (cold boot if possible) so PCR14 resetCount"
info "     advances and the agent's first run binds to the new baseline."
info "  2. After reboot:"
info "       sudo systemctl daemon-reload"
info "       sudo systemctl start lota-agent.socket lota-agent.service"
info "       sudo systemctl status lota-agent.service"
info "  3. Confirm 'Active: active (running)' and 'BPF programs attached: 11'"
info "     in 'journalctl -u lota-agent --no-pager | tail -20'."
info ""
info "If systemctl start still fails after reboot, inspect the journal for"
info "the first ERR-level line; the bring-up gates report which check is"
info "still unsatisfied. Documentation/operator/production-bringup/index.rst has the full reference."
