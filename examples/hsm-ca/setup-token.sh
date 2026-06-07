#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# Set up a SoftHSM token holding an RSA CA signing key for lota-attest-ca,
# then print the flags that point the CA at it.
#
# This is the local-test stand-in for a hardware HSM:
# the same -ca-key-pkcs11-* flags drive both.
#
# Usage:
#   examples/hsm-ca/setup-token.sh [token-label] [key-label] [pin]
#
# Requires softhsm2-util and pkcs11-tool (opensc).
#
# The token store is created under a throwaway SOFTHSM2_CONF so the run
# does not touch a system token.

set -euo pipefail

TOKEN_LABEL="${1:-lota-ca}"
KEY_LABEL="${2:-lota-ca-key}"
PIN="${3:-1234}"
SO_PIN="12345678"
KEY_ID="01"

die() {
  echo "hsm-ca: $*" >&2
  exit 1
}

command -v softhsm2-util >/dev/null 2>&1 || die "softhsm2-util not found (install softhsm2)"
command -v pkcs11-tool >/dev/null 2>&1 || die "pkcs11-tool not found (install opensc)"

# locate the SoftHSM PKCS#11 module across the common distro paths
MODULE=""
for cand in \
  /usr/lib/softhsm/libsofthsm2.so \
  /usr/lib64/softhsm/libsofthsm2.so \
  /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so; do
  [ -e "$cand" ] && MODULE="$cand" && break
done
[ -n "$MODULE" ] || die "libsofthsm2.so not found; set MODULE by hand"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/lota-hsm-ca.XXXXXX")"
export SOFTHSM2_CONF="$WORK/softhsm2.conf"
mkdir -p "$WORK/tokens"
printf 'directories.tokendir = %s\nobjectstore.backend = file\n' \
  "$WORK/tokens" >"$SOFTHSM2_CONF"

softhsm2-util --init-token --free --label "$TOKEN_LABEL" \
  --pin "$PIN" --so-pin "$SO_PIN" >/dev/null

pkcs11-tool --module "$MODULE" --token-label "$TOKEN_LABEL" --login --pin "$PIN" \
  --keypairgen --key-type rsa:2048 --label "$KEY_LABEL" --id "$KEY_ID" >/dev/null

cat <<EOF
SoftHSM token ready.

  export SOFTHSM2_CONF=$SOFTHSM2_CONF
  export LOTA_CA_PKCS11_PIN=$PIN

Build the CA with PKCS#11 support and point it at the token:

  make attest-ca GO_TAGS=pkcs11
  lota-attest-ca -ca-cert ca.crt \\
      -ca-key-pkcs11-module $MODULE \\
      -ca-key-pkcs11-token $TOKEN_LABEL \\
      -ca-key-pkcs11-label $KEY_LABEL \\
      -tls-cert tls.crt -tls-key tls.key \\
      -pseudonym-key pseudonym.key \\
      -ek-root-bundle /var/lib/lota/ek-roots

ca.crt must be a CA certificate bound to this token key -- see
examples/hsm-ca/README.md for issuing it from the HSM key.
EOF
