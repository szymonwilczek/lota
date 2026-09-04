#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Szymon Wilczek
#
# lota-dev-bringup.sh
#
# Walk an operator's host through the full production bring-up
# contract LOTA's agent expects at startup:
#
#   1. Operator Ed25519 signing key at /etc/lota/policy.key + .pub.
#   2. Signed BPF object at /usr/lib/lota/lota_lsm.bpf.o.sig.
#   3. policy_pubkey reference in /etc/lota/lota.conf so the agent
#      consults the right public key when verifying the .sig.
#   4. fs-verity enabled on /usr/bin/lota-agent so the agent's
#      anti-tamper self-check passes.
#   5. IMA appraisal in an enforcing mode (ima_appraise=enforce|fix
#      on the kernel cmdline) so the kernel-floor gate passes.
#   6. With --reset only: persistent state under /var/lib/lota wiped
#      and the persistent AIK handle evicted from the TPM, so PCR14
#      starts from a known baseline after the next cold reboot.
#   7. Final instruction to cold-reboot before starting the daemon
#      via systemd, because PCR14 (and the TPM clock resetCount /
#      restartCount the agent binds against) can only advance on
#      hardware reset.
#
# Each step skips an artefact that already exists, so a re-run is a no-op
# on a gated host. There is no rollback: a failed run keeps its partial
# work and the next run continues from it.
#
# --reset destroys the host's attestation identity (the agent provisions
# a new AIK on next start), so it is opt-in and refused while the agent
# runs.
#
# Production deployments run the same chain with operator policy
# tooling (cosign-signed RPM / signed BPF object shipped by
# packaging, IMA policy provisioned at boot via the distro's
# integrity profile, /etc/lota/lota.conf managed by Ansible or
# similar). This script is the developer-host equivalent and is
# explicitly NOT meant for hardened production hosts.
#
# Environment:
#   LOTA_BRINGUP_ROOT
#     Prefix every path with this directory instead of /, for tests;
#     root is then not required. TPM access is not redirected:
#     tpm2_evictcontrol from PATH still runs.

set -euo pipefail

usage() {
    cat <<'EOF'
Usage: lota-dev-bringup.sh [--reset]

  --reset   Clear the agent state under /var/lib/lota and evict the
            persistent handles LOTA owns from the TPM. This destroys
            the host's attestation identity; the next agent start
            provisions a new one. Refused while lota-agent.service
            is running.
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

# LOTA's persistent handles, from the agent's headers
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

# 1. Verify the agent + BPF object are installed before doing anything else.
ensure_artifact "$AGENT_BIN"
ensure_artifact "$BPF_OBJ"

# 2. Sign-key + pubkey
if [[ ! -f "$POLICY_KEY" || ! -f "$POLICY_PUB" ]]; then
    info "generating Ed25519 keypair at $POLICY_DIR/policy.{key,pub}"
    install -d -m 0700 "$POLICY_DIR"
    "$AGENT_BIN" --gen-signing-key "$POLICY_DIR/policy"
    chmod 0600 "$POLICY_KEY"
    chmod 0644 "$POLICY_PUB"
else
    info "operator keypair already present, skipping --gen-signing-key"
fi

# 3. Sign the in-tree BPF object so bpf_loader_verify_bpf_object_signature passes.
#    Skip when the signature on disk already verifies against the pubkey.
if [[ -f "$BPF_SIG" ]] && [[ -f "$POLICY_PUB" ]] &&
    "$AGENT_BIN" --verify-policy "$BPF_OBJ" \
        --policy-pubkey "$POLICY_PUB" >/dev/null 2>&1; then
    info "BPF object signature already valid, skipping --sign-policy"
else
    info "signing $BPF_OBJ"
    "$AGENT_BIN" --sign-policy "$BPF_OBJ" --signing-key "$POLICY_KEY"
    ensure_artifact "$BPF_SIG"
fi

# 4. /etc/lota/lota.conf must reference the pubkey so the daemon path knows
#    where to read it. Append once; do not duplicate the line on re-run.
if [[ ! -f "$LOTA_CONF" ]]; then
    info "seeding $LOTA_CONF from configs/lota.conf.example"
    src="$(dirname "$0")/../configs/lota.conf.example"
    [[ -f "$src" ]] || fail "configs/lota.conf.example not found relative to $0"
    # the agent refuses a config not owned by root; redirected runs are not root
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

# 5. fs-verity on the agent binary. Filesystem must already have the verity
#    feature enabled (`tune2fs -O verity /dev/sdX` on ext4, mkfs-time for
#    btrfs/f2fs). The fsverity tool reports a friendly error if not.
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

# 6. IMA appraisal mode. The kernel-floor check inside the agent parses
#    /proc/cmdline and requires ima_appraise=enforce|fix; log and the
#    default off do not block on integrity failures. The cmdline only
#    sets the appraisal mode -- a loaded policy with appraise rules is
#    still required for anything to actually be checked.
#    Suggest fix, not enforce, on a dev host:
#    developer baseline policy loaded below appraises every exec, and
#    under enforce a rootfs without IMA signatures blocks every execution.
#    fix satisfies the agent's kernel floor and writes the missing xattrs
#    as files are matched; production routes to enforce are the operator's
#    call (see Documentation/operator/production-bringup/index.rst, "IMA appraisal policy")
if grep -qE 'ima_appraise=(enforce|fix)' /proc/cmdline 2>/dev/null; then
    info "IMA appraisal already in an enforcing mode"
else
    warn "kernel cmdline lacks ima_appraise=enforce|fix; the agent will"
    warn "refuse to start. For a dev host run:"
    warn "  sudo grubby --update-kernel=ALL --args='ima=on ima_appraise=fix'"
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

# 7. Wipe stale agent state, on request. The clock-state snapshot under
#    $STATE_DIR is the agent's witness for PCR14 history; mismatched
#    snapshots after a partial install force tpm_extend_boot_commitment
#    to refuse with EBADMSG, and clearing them plus the persistent AIK
#    is how a host gets back to a known baseline. It is also how a host
#    loses the identity it attests with, so the caller asks for it.
state_files() {
    [[ -d "$STATE_DIR" ]] || return 0
    find "$STATE_DIR" -mindepth 1 -maxdepth 1 \
        \( -name 'aik*' -o -name 'clock*' -o -name 'boot_commit*' \
        -o -name 'snapshot*' \) 2>/dev/null || true
}

agent_unit_is_active() {
    command -v systemctl >/dev/null 2>&1 &&
        systemctl is-active --quiet lota-agent.service
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
    if agent_unit_is_active; then
        warn "lota-agent.service is active and is using the attestation"
        warn "key --reset destroys. Stop it first:"
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

# 8. Cold reboot. PCR14 resetCount only advances on hardware reset, so the
#    agent's first run after this script must follow a reboot for the
#    boot-commitment baseline to bind to the freshly-signed binary.
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
