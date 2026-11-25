#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Szymon Wilczek
#
# lota-dev-bringup.sh
#
# Prepare a developer host for the agent: an Ed25519 key at
# /etc/lota/policy.key, a signature on the BPF object, policy_pubkey in
# /etc/lota/lota.conf and fs-verity on /usr/bin/lota-agent. Not meant for
# hardened production hosts.
#
# Each step skips what is already in place. There is no rollback: a failed run
# keeps its partial work.
#
# Environment:
#   LOTA_BRINGUP_ROOT
#     Prefix the /etc, /usr, /var, /run and /sys paths with this directory, for
#     tests; root is then not required. /proc/cmdline, systemd and the TPM are
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
    echo "lota-dev-bringup: must run as root (TPM + fs-verity + IMA)" >&2
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
    printf '\n# Added by lota-dev-bringup\npolicy_pubkey = %s\n' \
        "$POLICY_PUB" >>"$LOTA_CONF"
else
    info "policy_pubkey already configured, leaving $LOTA_CONF alone"
fi

if command -v fsverity >/dev/null 2>&1; then
    if fsverity measure "$AGENT_BIN" >/dev/null 2>&1; then
        info "fs-verity already enabled on $AGENT_BIN"
    else
        info "enabling fs-verity on $AGENT_BIN"
        if ! fsverity enable "$AGENT_BIN"; then
            warn "fsverity enable failed; filesystem may lack the verity feature"
            warn "agent will refuse to start without --insecure-allow-mutable-rootfs"
        fi
    fi
else
    warn "fsverity utility not installed; install fsverity-utils and re-run"
fi

if grep -qE 'ima_appraise=(enforce|fix)' /proc/cmdline 2>/dev/null; then
    info "IMA appraisal already in an enforcing mode"
else
    warn "kernel cmdline lacks ima_appraise=enforce|fix; the agent will"
    warn "refuse to start. For a dev host run:"
    warn "  sudo grubby --update-kernel=ALL --args='ima_appraise=fix'"
    warn "  sudo reboot"
    warn "(enforce on a rootfs without IMA signatures blocks every exec;"
    warn "see Documentation/operator/production-bringup/index.rst before using it)"
fi

if [[ -f "$IMA_POLICY_SRC" ]] &&
    ! grep -q "appraise" "$IMA_POLICY_RUNTIME" 2>/dev/null; then
    info "loading IMA appraisal policy from $IMA_POLICY_SRC"
    if ! cat "$IMA_POLICY_SRC" >"$IMA_POLICY_RUNTIME" 2>/dev/null; then
        warn "writing to $IMA_POLICY_RUNTIME failed; kernel may need"
        warn "ima_policy=appraise_tcb on cmdline or a custom policy"
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
