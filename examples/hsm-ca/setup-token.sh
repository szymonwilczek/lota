#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Szymon Wilczek
#
# Stand up an HSM-backed attestation CA: a SoftHSM token holding the CA
# signing key, and every file lota-attest-ca needs to start against it.
#
# Local stand-in for a hardware HSM; the same steps work against a real module.
#
# Writes into the output directory:
#   softhsm2.conf   token store configuration (SOFTHSM2_CONF)
#   tokens/         the token, holding the CA signing key
#   ca.crt          CA certificate over the token key
#   tls.crt/tls.key listener keypair, signed by the token key
#   pseudonym.key   device-pseudonym secret
#
# The CA key never leaves the token; OpenSSL signs through PKCS#11.
#
# Usage:
#   examples/hsm-ca/setup-token.sh [out-dir] [token-label] [key-label] [pin]
#
# Requires softhsm2-util, pkcs11-tool (opensc) and openssl with the
# pkcs11 provider (pkcs11-provider or libp11).
#
# Runs unprivileged: the token store lives in the output directory,
# so the run never touches a system token.

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
# build dir the printed CA commands use; default $LOTA_BUILD_DIR, then the tree's
BUILD_DIR="${BUILD_DIR:-${LOTA_BUILD_DIR:-$HERE/../../build}}"
OUT_DIR="${1:-./hsm-ca}"
TOKEN_LABEL="${2:-lota-ca}"
KEY_LABEL="${3:-lota-ca-key}"
PIN="${4:-1234}"
SO_PIN="12345678"
KEY_ID="01"

die() {
    echo "hsm-ca: $*" >&2
    exit 1
}

command -v softhsm2-util >/dev/null 2>&1 || die "softhsm2-util not found (install softhsm2)"
command -v pkcs11-tool >/dev/null 2>&1 || die "pkcs11-tool not found (install opensc)"
command -v openssl >/dev/null 2>&1 || die "openssl not found"

# honor an explicit MODULE override; otherwise probe the common distro paths
# (Fedora ships it under /usr/lib64/pkcs11, Debian under softhsm/)
MODULE="${MODULE:-}"
if [ -z "$MODULE" ]; then
    for cand in \
        /usr/lib/softhsm/libsofthsm2.so \
        /usr/lib64/softhsm/libsofthsm2.so \
        /usr/lib64/pkcs11/libsofthsm2.so \
        /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so; do
        [ -e "$cand" ] && MODULE="$cand" && break
    done
fi
[ -n "$MODULE" ] || die "libsofthsm2.so not found; set MODULE=/path/to/libsofthsm2.so"

mkdir -p "$OUT_DIR"
OUT_DIR=$(cd "$OUT_DIR" && pwd)
umask 077

export SOFTHSM2_CONF="$OUT_DIR/softhsm2.conf"
mkdir -p "$OUT_DIR/tokens"
printf 'directories.tokendir = %s\nobjectstore.backend = file\n' \
    "$OUT_DIR/tokens" >"$SOFTHSM2_CONF"

softhsm2-util --init-token --free --label "$TOKEN_LABEL" \
    --pin "$PIN" --so-pin "$SO_PIN" >/dev/null

pkcs11-tool --module "$MODULE" --token-label "$TOKEN_LABEL" --login --pin "$PIN" \
    --keypairgen --key-type rsa:2048 --label "$KEY_LABEL" --id "$KEY_ID" >/dev/null

# PIN in the URI so the commands below run unattended;
# the CA itself reads LOTA_CA_PKCS11_PIN
KEY_URI="pkcs11:token=$TOKEN_LABEL;object=$KEY_LABEL;type=private?pin-value=$PIN"
PROVIDERS=(-provider pkcs11 -provider default)

# Self-signed by the token key; lota-attest-ca matches the two at startup
openssl req -new -x509 -days 365 "${PROVIDERS[@]}" \
    -key "$KEY_URI" \
    -subj "/CN=lota-attest-ca" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign" \
    -out "$OUT_DIR/ca.crt" </dev/null >/dev/null 2>&1 ||
    die "could not issue ca.crt from the token key (is the pkcs11 provider installed?)"

# Listener keypair signed by the token key: the agent verifies it against
# the same ca.crt it enrolls with
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
    -out "$OUT_DIR/tls.key" >/dev/null 2>&1
openssl req -new -key "$OUT_DIR/tls.key" -out "$OUT_DIR/tls.csr" \
    -subj "/CN=lota-attest-ca" >/dev/null 2>&1
openssl x509 -req -in "$OUT_DIR/tls.csr" -days 825 -sha256 "${PROVIDERS[@]}" \
    -CA "$OUT_DIR/ca.crt" -CAkey "$KEY_URI" -CAcreateserial \
    -out "$OUT_DIR/tls.crt" \
    -extfile <(printf '%s\n%s\n%s\n' \
        "subjectAltName=IP:127.0.0.1,DNS:localhost" \
        "keyUsage=critical,digitalSignature,keyEncipherment" \
        "extendedKeyUsage=serverAuth") </dev/null >/dev/null 2>&1 ||
    die "could not issue tls.crt from the token key"
rm -f "$OUT_DIR/tls.csr"

# Key of the EK -> device-id hash; rotating it re-pseudonymises the fleet
[ -f "$OUT_DIR/pseudonym.key" ] || openssl rand -out "$OUT_DIR/pseudonym.key" 32

cat <<EOF2
SoftHSM token ready, and the CA material beside it in $OUT_DIR:

  ca.crt          CA certificate, public key from the token
  tls.crt/tls.key listener keypair, issued by the token key
  pseudonym.key   device-pseudonym secret
  softhsm2.conf   token store (SOFTHSM2_CONF)

Point a PKCS#11-enabled CA at the token:

  export SOFTHSM2_CONF=$SOFTHSM2_CONF
  export LOTA_CA_PKCS11_PIN=$PIN

  make BUILD_DIR=$BUILD_DIR attest-ca GO_TAGS=pkcs11
  $BUILD_DIR/lota-attest-ca -listen :8444 \\
      -ca-cert $OUT_DIR/ca.crt \\
      -ca-key-pkcs11-module $MODULE \\
      -ca-key-pkcs11-token $TOKEN_LABEL \\
      -ca-key-pkcs11-label $KEY_LABEL \\
      -tls-cert $OUT_DIR/tls.crt -tls-key $OUT_DIR/tls.key \\
      -pseudonym-key $OUT_DIR/pseudonym.key \\
      -ek-root-bundle /var/lib/lota/ek-roots

The enrolling agent takes ca.crt as its --ca-cert: it anchors the
listener above and is the publisher identity the host enrolls with.
EOF2
