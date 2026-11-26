#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Szymon Wilczek
#
# What the shipped CA examples hand an operator, driven through the scripts.
#
# The publisher a host answers to is the SHA-256 of the SubjectPublicKeyInfo of
# whatever file --ca-cert names, and the agent verifies the CA server's TLS chain
# against that same file. Those two roles only agree when the listener certificate
# is issued by the anchor: otherwise an operator either binds the identity to
# a certificate that rotates -- making the host a new device, with a new AIK
# in a new TPM handle, on every rotation -- or passes the anchor and the handshake
# fails.
#
# Requires:
#   - examples/enrollment/gen-ca.sh
#   - examples/mtls/gen-certs.sh
#   - openssl
#
# Runs unprivileged and writes only into a temporary directory.

set -euo pipefail

export LC_ALL=C

REPO_DIR=$(cd "$(dirname "$0")/../.." && pwd)
GEN_CA="$REPO_DIR/examples/enrollment/gen-ca.sh"
GEN_CERTS="$REPO_DIR/examples/mtls/gen-certs.sh"

for f in "$GEN_CA" "$GEN_CERTS"; do
    if [[ ! -x "$f" ]]; then
	echo "[ca-material] missing artifact: $f" >&2
	exit 2
    fi
done
if ! command -v openssl >/dev/null 2>&1; then
    echo "[ca-material] openssl not found" >&2
    exit 2
fi

WORK_DIR=$(mktemp -d)
trap 'rm -rf "$WORK_DIR"' EXIT

failures=0

check() {
    local msg="$1"
    shift
    if "$@"; then
	echo "PASS: $msg"
    else
	echo "FAIL: $msg"
	failures=$((failures + 1))
    fi
}

# The identity the agent derives from a trust anchor:
# SHA-256 over the DER SubjectPublicKeyInfo, which is what
# profile_paths_from_anchor() hashes.
spki_id() {
    openssl x509 -in "$1" -noout -pubkey |
	openssl pkey -pubin -outform DER |
	openssl dgst -sha256 -r | cut -d' ' -f1
}

"$GEN_CA" "$WORK_DIR/ca" >/dev/null

CA_DIR="$WORK_DIR/ca"

check "the example generates a CA anchor" test -s "$CA_DIR/ca.crt"
check "the example generates a listener certificate" test -s "$CA_DIR/tls.crt"

# The property the whole flow rests on: one file works as both the identity
# anchor and the TLS trust anchor.
check "the listener certificate is issued by the CA anchor" \
      openssl verify -CAfile "$CA_DIR/ca.crt" "$CA_DIR/tls.crt"

# OpenSSL 4 takes a leaf without key identifiers whose subject is its
# issuer and whose key type is the issuer's for self-signed
subject_differs() {
    [[ "$(openssl x509 -in "$1" -noout -subject)" != \
       "$(openssl x509 -in "$2" -noout -subject)" ]]
}
check "the listener certificate names a subject other than the CA" \
      subject_differs "$CA_DIR/tls.crt" "$CA_DIR/ca.crt"

# The verifier revokes AIK certificates through a CRL from this anchor and
# refuses one from an issuer without cRLSign. openssl verify applies the same
# rule; the listener certificate stands in for an AIK certificate.
crl_from_anchor_verifies() {
    local dir="$WORK_DIR/crl"

    mkdir -p "$dir"
    : >"$dir/index"
    echo 1000 >"$dir/number"
    cat >"$dir/ca.cnf" <<EOF_CNF
[ca]
default_ca = lota
[lota]
database = $dir/index
crlnumber = $dir/number
default_md = sha256
default_crl_days = 1
certificate = $CA_DIR/ca.crt
private_key = $CA_DIR/ca.key
EOF_CNF
    openssl ca -config "$dir/ca.cnf" -gencrl -out "$dir/ca.crl" 2>/dev/null &&
	openssl verify -crl_check -CAfile "$CA_DIR/ca.crt" \
		-CRLfile "$dir/ca.crl" "$CA_DIR/tls.crt" >/dev/null 2>&1
}
check "a CRL from the anchor verifies" crl_from_anchor_verifies

# A listener certificate is the one certificate in the deployment that is
# rotated on a schedule.
# Rotating it -- with a new key, which is the point of rotating -- must not
# move the publisher identity.
before=$(spki_id "$CA_DIR/ca.crt")

rm -f "$CA_DIR/tls.key" "$CA_DIR/tls.crt"
"$GEN_CA" "$CA_DIR" >/dev/null

after=$(spki_id "$CA_DIR/ca.crt")

check "the anchor survives a listener rotation" test "$before" = "$after"
check "the rotated listener still chains to the anchor" \
      openssl verify -CAfile "$CA_DIR/ca.crt" "$CA_DIR/tls.crt"

# And the identity really would move if it were taken from the listener,
# which is what makes the choice of file the whole finding.
tls_before_rotation_differs() {
    local anchor_id listener_id
    anchor_id=$(spki_id "$CA_DIR/ca.crt")
    listener_id=$(spki_id "$CA_DIR/tls.crt")
    [[ "$anchor_id" != "$listener_id" ]]
}
check "the listener has an identity of its own, which is not the anchor's" \
      tls_before_rotation_differs

# A certificate lost next to its key is issued again from that key.
lost_certs_come_back() {
    rm -f "$CA_DIR/ca.crt" "$CA_DIR/tls.crt"
    "$GEN_CA" "$CA_DIR" >/dev/null &&
	test -s "$CA_DIR/ca.crt" &&
	test "$(spki_id "$CA_DIR/ca.crt")" = "$before" &&
	openssl verify -CAfile "$CA_DIR/ca.crt" "$CA_DIR/tls.crt" >/dev/null
}
check "a lost anchor and listener certificate come back from their keys" \
      lost_certs_come_back

# A self-signed listener left by an older script, which ca.crt does not
# verify, is issued again; one that verifies is kept.
stale_listener_reissued() {
    local first

    openssl req -x509 -new -key "$CA_DIR/tls.key" -days 1 \
	    -subj "/CN=lota-attest-ca" -out "$CA_DIR/tls.crt" 2>/dev/null &&
	! openssl verify -CAfile "$CA_DIR/ca.crt" "$CA_DIR/tls.crt" \
		>/dev/null 2>&1 &&
	"$GEN_CA" "$CA_DIR" >/dev/null &&
	openssl verify -CAfile "$CA_DIR/ca.crt" "$CA_DIR/tls.crt" >/dev/null &&
	first=$(cksum <"$CA_DIR/tls.crt") &&
	"$GEN_CA" "$CA_DIR" >/dev/null &&
	test "$(cksum <"$CA_DIR/tls.crt")" = "$first"
}
check "a listener certificate ca.crt does not verify is issued again" \
      stale_listener_reissued

# A single leaf is issued only from an existing provisioning CA.
leaf_without_ca_refused() {
    ! OUT_DIR="$WORK_DIR/mtls" "$GEN_CERTS" -server >/dev/null 2>&1 &&
	test ! -e "$WORK_DIR/mtls/ca.key" &&
	test ! -e "$WORK_DIR/mtls/server.crt"
}
check "gen-certs -server without ca.key is refused" leaf_without_ca_refused

leaf_chains_to_existing_ca() {
    OUT_DIR="$WORK_DIR/mtls" "$GEN_CERTS" >/dev/null 2>&1 &&
	rm -f "$WORK_DIR/mtls/ca.crt" &&
	OUT_DIR="$WORK_DIR/mtls" "$GEN_CERTS" -server >/dev/null 2>&1 &&
	openssl verify -CAfile "$WORK_DIR/mtls/ca.crt" \
		"$WORK_DIR/mtls/producer.crt" "$WORK_DIR/mtls/server.crt" \
		>/dev/null
}
check "gen-certs -server reissues a lost ca.crt from ca.key" \
      leaf_chains_to_existing_ca

# What the script tells the operator to do with each file has to name
# the anchor, since that is the file the identity may be bound to.
check "the script does not tell the operator to enroll against the listener" \
      bash -c "! grep -q -- '--ca-cert tls.crt' '$GEN_CA'"

if [[ $failures -ne 0 ]]; then
    echo "FAILURES: $failures"
    exit 1
fi
echo "All tests passed"
