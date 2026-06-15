#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# Anti-rollback for *versioned* sealed secrets, via a TPM NV monotonic
# counter. Reference recipe, built on tpm2-tools (not lota-agent).
#
# Why this is a separate recipe and not a lota-agent feature:
#
#   LOTA sealing binds a secret to a boot/PCR *state*. That is the intended
#   contract for the DRM / offline use case: booting the same good state
#   must release the key every time -- "replaying" a recurring good state is
#   correct behaviour, not a rollback attack. PCR binding already fails
#   closed on a *different* (tampered) state.
#
#   A monotonic counter solves a different problem: revoking an OLD secret
#   so it stops unsealing even though the host can still reproduce the PCR
#   state it was sealed against (a key/version downgrade). That matters only
#   when you version and revoke sealed secrets -- which LOTA core does not.
#   So the mechanism lives here as an operator recipe instead of as
#   speculative machinery in the agent. See the "Anti-rollback" section of
#   examples/sealed-key/README.rst.
#
# The recipe seals a secret under a compound policy: PolicyPCR AND
# PolicyNV(counter <= seal-time value). While the counter has not advanced,
# the secret unseals. Incrementing the counter (bumping the "version")
# revokes every secret sealed at or below the old value -- they fail closed.
#
# Needs tpm2-tools and access to a TPM (root, or TPM2TOOLS_TCTI pointed at a
# swtpm sandbox). It defines and then cleans up its own NV index and a
# persistent parent handle.

set -euo pipefail

# Override these if they collide with handles already in use on the host.
NV_INDEX="${NV_INDEX:-0x1500016}"
PARENT_HANDLE="${PARENT_HANDLE:-0x81000010}"
PCR_LIST="${PCR_LIST:-sha256:0,7}"

WORK="$(mktemp -d /tmp/lota-antiroll.XXXXXX)"

cleanup() {
	# Best-effort teardown so the recipe leaves no NV index or persistent
	# object behind, even on failure.
	tpm2_evictcontrol -C o -c "$PARENT_HANDLE" >/dev/null 2>&1 || true
	tpm2_nvundefine -C o "$NV_INDEX" >/dev/null 2>&1 || true
	rm -rf "$WORK"
}
trap cleanup EXIT

die() {
	printf 'anti-rollback-recipe: %s\n' "$*" >&2
	exit 1
}

command -v tpm2_nvdefine >/dev/null 2>&1 ||
	die "tpm2-tools required (tpm2_nvdefine not found)"

cd "$WORK"

echo "==> Define a monotonic counter at $NV_INDEX and prime it"
tpm2_nvdefine -C o "$NV_INDEX" -s 8 \
	-a "nt=counter|ownerread|ownerwrite|authread|authwrite" >/dev/null
tpm2_nvincrement -C o "$NV_INDEX"
tpm2_nvread -C o "$NV_INDEX" -o operand.bin 2>/dev/null
echo "    seal-time counter: $(xxd -p operand.bin)"

echo "==> Persist a storage parent and free the transient slots"
# Persistent parent keeps the later tpm2_load from exhausting the small
# transient-object memory some TPMs (and swtpm) expose.
tpm2_createprimary -C o -g sha256 -G ecc -c prim.ctx >/dev/null
tpm2_evictcontrol -C o -c prim.ctx "$PARENT_HANDLE" >/dev/null
tpm2_flushcontext -t >/dev/null

echo "==> Build the compound policy: PolicyPCR AND PolicyNV(counter <= now)"
tpm2_startauthsession -S trial.ctx >/dev/null
tpm2_policypcr -S trial.ctx -l "$PCR_LIST" >/dev/null
tpm2_policynv -S trial.ctx -C o -i operand.bin "$NV_INDEX" ule -L policy.dat \
	>/dev/null
tpm2_flushcontext trial.ctx >/dev/null

echo "==> Seal a versioned secret under that policy"
printf 'versioned-asset-key-gen1' >secret.bin
tpm2_create -C "$PARENT_HANDLE" -i secret.bin -L policy.dat \
	-u seal.pub -r seal.priv >/dev/null
tpm2_load -C "$PARENT_HANDLE" -u seal.pub -r seal.priv -c seal.ctx >/dev/null

echo "==> Unseal while the counter is unchanged (must recover)"
tpm2_startauthsession --policy-session -S ps.ctx >/dev/null
tpm2_policypcr -S ps.ctx -l "$PCR_LIST" >/dev/null
tpm2_policynv -S ps.ctx -C o -i operand.bin "$NV_INDEX" ule >/dev/null
got="$(tpm2_unseal -p session:ps.ctx -c seal.ctx)"
tpm2_flushcontext ps.ctx >/dev/null
[ "$got" = "versioned-asset-key-gen1" ] ||
	die "RESULT: MISMATCH - recovered '$got'"
echo "    RESULT: OK - recovered the secret in-policy"

echo "==> Bump the version: increment the counter (revokes gen1)"
tpm2_nvincrement -C o "$NV_INDEX"
echo "    counter is now: $(tpm2_nvread -C o "$NV_INDEX" 2>/dev/null | xxd -p)"

echo "==> Unseal after the bump (must fail closed)"
tpm2_startauthsession --policy-session -S ps2.ctx >/dev/null
tpm2_policypcr -S ps2.ctx -l "$PCR_LIST" >/dev/null
if tpm2_policynv -S ps2.ctx -C o -i operand.bin "$NV_INDEX" ule >/dev/null 2>&1 &&
	tpm2_unseal -p session:ps2.ctx -c seal.ctx >/dev/null 2>&1; then
	tpm2_flushcontext ps2.ctx >/dev/null 2>&1 || true
	die "RESULT: LEAK - unseal succeeded after the counter advanced"
fi
tpm2_flushcontext ps2.ctx >/dev/null 2>&1 || true
echo "    RESULT: REVOKED - unseal failed closed after the counter advanced"

echo
echo "All steps passed: the secret unseals only while the counter has not"
echo "advanced past its seal-time value. Bumping the counter revokes it."
