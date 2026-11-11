#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Szymon Wilczek
#
# Creates a SoftHSM token holding the attestation CA's signing key, and
# writes into the output directory the files lota-attest-ca needs with it,
# all but the EK roots:
#   softhsm2.conf   token store configuration (SOFTHSM2_CONF)
#   tokens/         the token, holding the CA signing key
#   ca.crt          CA certificate over the token key
#   tls.crt/tls.key listener keypair, signed by the token key
#   pseudonym.key   device-pseudonym secret, kept when it exists
#
# OpenSSL signs with the token key through PKCS#11. Needs softhsm2-util,
# pkcs11-tool and the OpenSSL pkcs11 provider; no root, and no system token
# is touched.
#
#   examples/hsm-ca/setup-token.sh [out-dir] [token-label] [key-label] [pin]

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
# only the printed commands use it
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

# the PIN in the URI is for openssl; lota-attest-ca reads LOTA_CA_PKCS11_PIN
KEY_URI="pkcs11:token=$TOKEN_LABEL;object=$KEY_LABEL;type=private?pin-value=$PIN"
PROVIDERS=(-provider pkcs11 -provider default)

# lota-attest-ca refuses a certificate that does not match the token key
openssl req -new -x509 -days 365 "${PROVIDERS[@]}" \
    -key "$KEY_URI" \
    -subj "/CN=lota-attest-ca" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -out "$OUT_DIR/ca.crt" </dev/null >/dev/null 2>&1 ||
    die "could not issue ca.crt from the token key (is the pkcs11 provider installed?)"

openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
    -out "$OUT_DIR/tls.key" >/dev/null 2>&1
openssl req -new -key "$OUT_DIR/tls.key" -out "$OUT_DIR/tls.csr" \
    -subj "/CN=lota-attest-listener" >/dev/null 2>&1
openssl x509 -req -in "$OUT_DIR/tls.csr" -days 825 -sha256 "${PROVIDERS[@]}" \
    -CA "$OUT_DIR/ca.crt" -CAkey "$KEY_URI" -CAcreateserial \
    -out "$OUT_DIR/tls.crt" \
    -extfile <(printf '%s\n%s\n%s\n' \
        "subjectAltName=IP:127.0.0.1,DNS:localhost" \
        "keyUsage=critical,digitalSignature,keyEncipherment" \
        "extendedKeyUsage=serverAuth") </dev/null >/dev/null 2>&1 ||
    die "could not issue tls.crt from the token key"
rm -f "$OUT_DIR/tls.csr"

# HMAC key of the device id over the EK modulus, with a named tenant prefixed
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
