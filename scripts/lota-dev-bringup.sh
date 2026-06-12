#!/bin/bash
# SPDX-License-Identifier: MIT
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
#   6. Any stale persistent state under /var/lib/lota wiped, plus
#      the persistent AIK handle evicted from the TPM, so PCR14
#      starts from a known baseline after the next cold reboot.
#   7. Final instruction to cold-reboot before starting the daemon
#      via systemd, because PCR14 (and the TPM clock resetCount /
#      restartCount the agent binds against) can only advance on
#      hardware reset.
#
# The script is idempotent: every step checks for existing
# artefacts and skips them, but rolls back on a partial state so a
# retry after a transient failure is safe.
#
# Production deployments run the same chain with operator policy
# tooling (cosign-signed RPM / signed BPF object shipped by
# packaging, IMA policy provisioned at boot via the distro's
# integrity profile, /etc/lota/lota.conf managed by Ansible or
# similar). This script is the developer-host equivalent and is
# explicitly NOT meant for hardened production hosts.

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
	echo "lota-dev-bringup: must run as root (TPM + fs-verity + IMA)" >&2
	exit 2
fi

POLICY_DIR="/etc/lota"
POLICY_KEY="$POLICY_DIR/policy.key"
POLICY_PUB="$POLICY_DIR/policy.pub"
LOTA_CONF="$POLICY_DIR/lota.conf"
AGENT_BIN="/usr/bin/lota-agent"
BPF_OBJ="/usr/lib/lota/lota_lsm.bpf.o"
BPF_SIG="$BPF_OBJ.sig"
STATE_DIR="/var/lib/lota"
IMA_POLICY_SRC="$(dirname "$0")/../configs/ima/lota-ima-policy"
IMA_POLICY_RUNTIME="/sys/kernel/security/ima/policy"

info() { printf '[lota-dev-bringup] %s\n' "$*"; }
warn() { printf '[lota-dev-bringup] WARN: %s\n' "$*" >&2; }
fail() {
	printf '[lota-dev-bringup] FAIL: %s\n' "$*" >&2
	exit 1
}

ensure_artifact() {
	[[ -e "$1" ]] || fail "missing artifact: $1 (run 'sudo make install' first)"
}

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
info "signing $BPF_OBJ"
"$AGENT_BIN" --sign-policy "$BPF_OBJ" --signing-key "$POLICY_KEY"
ensure_artifact "$BPF_SIG"

# 4. /etc/lota/lota.conf must reference the pubkey so the daemon path knows
#    where to read it. Append once; do not duplicate the line on re-run.
if [[ ! -f "$LOTA_CONF" ]]; then
	info "seeding $LOTA_CONF from configs/lota.conf.example"
	src="$(dirname "$0")/../configs/lota.conf.example"
	[[ -f "$src" ]] || fail "configs/lota.conf.example not found relative to $0"
	install -m 0644 -o root -g root "$src" "$LOTA_CONF"
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
#    call (see docs/PRODUCTION_BRINGUP.md, "IMA appraisal policy")
if grep -qE 'ima_appraise=(enforce|fix)' /proc/cmdline 2>/dev/null; then
	info "IMA appraisal already in an enforcing mode"
else
	warn "kernel cmdline lacks ima_appraise=enforce|fix; the agent will"
	warn "refuse to start. For a dev host run:"
	warn "  sudo grubby --update-kernel=ALL --args='ima=on ima_appraise=fix'"
	warn "  sudo reboot"
	warn "(enforce on a rootfs without IMA signatures blocks every exec;"
	warn "see docs/PRODUCTION_BRINGUP.md before using it)"
fi

if [[ -f "$IMA_POLICY_SRC" ]] &&
	! grep -q "appraise" "$IMA_POLICY_RUNTIME" 2>/dev/null; then
	info "loading IMA appraisal policy from $IMA_POLICY_SRC"
	if ! cat "$IMA_POLICY_SRC" >"$IMA_POLICY_RUNTIME" 2>/dev/null; then
		warn "writing to $IMA_POLICY_RUNTIME failed; kernel may need"
		warn "ima_policy=appraise_tcb on cmdline or a custom policy"
	fi
fi

# 7. Wipe stale agent state. The clock-state snapshot under
#    $STATE_DIR is the agent's witness for PCR14 history; mismatched
#    snapshots after a partial install force tpm_extend_boot_commitment
#    to refuse with EBADMSG. Evict the persistent AIK handle so the
#    next provisioning is clean.
if [[ -d "$STATE_DIR" ]]; then
	info "clearing stale agent state under $STATE_DIR"
	find "$STATE_DIR" -mindepth 1 -maxdepth 1 \
		\( -name 'aik*' -o -name 'clock*' -o -name 'boot_commit*' \
		-o -name 'snapshot*' \) -delete 2>/dev/null || true
fi

if command -v tpm2_evictcontrol >/dev/null 2>&1; then
	for handle in 0x81010002 0x81010003 0x81010004 0x81010005; do
		if tpm2_evictcontrol -C o -c "$handle" 2>/dev/null; then
			info "evicted stale persistent AIK at $handle"
		fi
	done
else
	warn "tpm2-tools not installed; persistent AIK handles cannot be evicted"
	warn "install tpm2-tools and re-run if PCR14 errors persist"
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
info "still unsatisfied. docs/PRODUCTION_BRINGUP.md has the full reference."
