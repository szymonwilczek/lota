#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Szymon Wilczek
#
# Offline sealed-key round-trip for LOTA.
#
# Demonstrates the local, verifier-free TPM boundary: a secret sealed to
# the boot/PCR state is released by the TPM only when the host is in that
# state. This is the single-player / offline-DRM use case -- no network,
# no verifier round-trip.
#
# The script:
#   1. seals a per-title key to the current PCR state,
#   2. unseals it again and checks it round-trips,
#   3. seals to a PCR that the script then extends, and shows the unseal
#      now fails closed -- proving the secret is bound to the state.
#
# It needs a working TPM and a built lota-agent, and runs as root because
# the agent binds the TPM. Point it at a writable build with AGENT=...

set -euo pipefail

AGENT="${AGENT:-/usr/bin/lota-agent}"
WORK="$(mktemp -d /tmp/lota-seal-demo.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

die() {
	printf 'seal-demo: %s\n' "$*" >&2
	exit 1
}

[ -x "$AGENT" ] || die "lota-agent not found at $AGENT (set AGENT=...)"
command -v tpm2_pcrextend >/dev/null 2>&1 ||
	die "tpm2-tools (tpm2_pcrextend) required for the fail-closed step"

PER_TITLE_KEY='super-secret-per-title-key-v1'

echo "==> 1. Seal a per-title key to the current boot state"
printf '%s' "$PER_TITLE_KEY" | "$AGENT" --seal >"$WORK/title.sealed"
echo "    sealed blob: $(wc -c <"$WORK/title.sealed") bytes"

echo "==> 2. Unseal it back (same boot state -> succeeds)"
GOT="$("$AGENT" --unseal <"$WORK/title.sealed")"
if [ "$GOT" = "$PER_TITLE_KEY" ]; then
	echo "    RESULT: OK - recovered the key"
else
	die "RESULT: MISMATCH - recovered key differs"
fi

echo "==> 3. Bind to a single PCR, then change it -> unseal must fail"
# PCR 16 is the debug/resettable PCR.
# Sealing to it lets the demo move the state without a reboot.
# Production seals to PCRs 0-7 + PCR14 (the default).
printf '%s' "$PER_TITLE_KEY" | "$AGENT" --seal-pcrs 0x10000 --seal \
	>"$WORK/title-pcr16.sealed"
echo "    sealed to PCR16; extending PCR16 to simulate a state change..."
tpm2_pcrextend 16:sha256=$(printf 'tamper' | sha256sum | cut -d' ' -f1) \
	>/dev/null 2>&1 || die "tpm2_pcrextend failed (need access to the TPM)"

if "$AGENT" --unseal <"$WORK/title-pcr16.sealed" >/dev/null 2>&1; then
	die "RESULT: LEAK - unseal succeeded after the PCR changed"
fi
echo "    RESULT: SEALED SHUT - unseal failed closed after the state changed"

echo "==> 4. Seal a large payload (> 128 B) via the AES-256-GCM envelope"
# Direct TPM2_Seal caps the sensitive data at 128 bytes.
# A larger payload -- an asset blob, a bundle of per-title keys,
# a small save file -- is sealed by wrapping a random KEK in the
# TPM and encrypting the payload under it.
# The unseal path auto-detects the envelope from its magic.
head -c 4096 /dev/urandom >"$WORK/asset.bin"
"$AGENT" --seal <"$WORK/asset.bin" >"$WORK/asset.sealed"
echo "    sealed $(wc -c <"$WORK/asset.bin")-byte payload into a \
$(wc -c <"$WORK/asset.sealed")-byte envelope"
"$AGENT" --unseal <"$WORK/asset.sealed" >"$WORK/asset.out"
if cmp -s "$WORK/asset.bin" "$WORK/asset.out"; then
	echo "    RESULT: OK - large payload round-trips through the envelope"
else
	die "RESULT: MISMATCH - large payload differs after unseal"
fi

# An envelope is authenticated: a single flipped ciphertext bit must fail the
# GCM tag, not silently return corrupt data.
# Flip the last byte (XOR 0xFF) so the change is deterministic regardless of
# its original value.
cp "$WORK/asset.sealed" "$WORK/asset.tampered"
last_off=$(($(wc -c <"$WORK/asset.tampered") - 1))
orig=$(tail -c1 "$WORK/asset.tampered" | od -An -tu1 | tr -d ' ')
flipped=$((orig ^ 0xFF))
printf "$(printf '\\%03o' "$flipped")" |
	dd of="$WORK/asset.tampered" bs=1 seek="$last_off" conv=notrunc status=none
if "$AGENT" --unseal <"$WORK/asset.tampered" >/dev/null 2>&1; then
	die "RESULT: LEAK - tampered envelope unsealed"
fi
echo "    RESULT: AUTHENTICATED - tampered envelope rejected (GCM tag)"

echo
echo "All steps passed: the key only unseals in the sealed boot state."
