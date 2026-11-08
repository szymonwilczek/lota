#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Szymon Wilczek
#
# Revokes old sealed secrets with a TPM NV counter, using tpm2-tools only.
# The secret is sealed under PolicyPCR AND PolicyNV(counter <= seal-time
# value), so incrementing the counter stops every secret sealed at or below
# the old value from unsealing, though the PCRs still match.
#
# Needs tpm2-tools and a TPM (root, or TPM2TOOLS_TCTI at a swtpm).

set -euo pipefail

# On exit whatever is at NV_INDEX and PARENT_HANDLE is removed, even when
# this run did not create it.
NV_INDEX="${NV_INDEX:-0x1500016}"
PARENT_HANDLE="${PARENT_HANDLE:-0x81000010}"
PCR_LIST="${PCR_LIST:-sha256:0,7}"

WORK="$(mktemp -d /tmp/lota-antiroll.XXXXXX)"

cleanup() {
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
# A persistent parent leaves the transient slots free for tpm2_load.
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
