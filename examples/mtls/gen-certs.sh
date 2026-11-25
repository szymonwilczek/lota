#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Szymon Wilczek
#
# Provision the mutual-TLS material that authenticates the anti-cheat
# heartbeat producer to the game server and the game server back to the
# producer.
#
# The CA here is not the attestation CA: it certifies the two services, not
# a device's AIK.
#
# Output (in OUT_DIR, default ./mtls):
#   ca.crt / ca.key            provisioning CA (trust root for both ends)
#   server.crt / server.key    game server identity (serverAuth, SAN-bound)
#   producer.crt / producer.key  anti-cheat producer identity (clientAuth)
#
# -server or -producer issues only that leaf and needs an existing ca.key.
# A missing ca.crt is issued again from ca.key.

set -euo pipefail

OUT_DIR="${OUT_DIR:-./mtls}"
SERVER_SAN="${SERVER_SAN:-IP:127.0.0.1,DNS:localhost}"
CA_DAYS="${CA_DAYS:-1825}"
LEAF_DAYS="${LEAF_DAYS:-365}"

what="all"
case "${1:-}" in
    "") ;;
    -server) what="server" ;;
    -producer) what="producer" ;;
    -h | --help)
	sed -n '2,/^$/p' "$0"
	exit 0
	;;
    *)
	echo "usage: $0 [-server|-producer]" >&2
	exit 64
	;;
esac

mkdir -p "$OUT_DIR"
cd "$OUT_DIR"
umask 077

if [ ! -f ca.key ] && [ "$what" != "all" ]; then
    echo "no ca.key in $(pwd): run without -$what first" >&2
    exit 1
fi

if [ ! -f ca.key ]; then
    openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out ca.key
    rm -f ca.crt
fi
if [ ! -f ca.crt ]; then
    openssl req -x509 -new -key ca.key -days "$CA_DAYS" -out ca.crt \
	    -subj "/CN=lota-mtls-provisioning-ca" \
	    -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
	    -addext "keyUsage=critical,keyCertSign,cRLSign"
    echo "generated provisioning CA"
elif [ "$what" = "all" ]; then
    echo "reusing existing provisioning CA (ca.key/ca.crt)"
fi

# issue_leaf <name> <subject-CN> <ext-block>
issue_leaf() {
    local name="$1" cn="$2" ext="$3"
    openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
	    -out "$name.key"
    openssl req -new -key "$name.key" -subj "/CN=$cn" -out "$name.csr"
    printf '%s\n' "$ext" >"$name.ext"
    openssl x509 -req -in "$name.csr" -CA ca.crt -CAkey ca.key \
	    -CAcreateserial -days "$LEAF_DAYS" -extfile "$name.ext" \
	    -out "$name.crt"
    rm -f "$name.csr" "$name.ext"
    echo "issued $name.crt ($cn)"
}

if [ "$what" = "all" ] || [ "$what" = "server" ]; then
    issue_leaf server lota-demo-game-server "$(
		printf '%s\n' \
			"basicConstraints=critical,CA:FALSE" \
			"keyUsage=critical,digitalSignature,keyEncipherment" \
			"extendedKeyUsage=serverAuth" \
			"subjectAltName=$SERVER_SAN"
	)"
fi

if [ "$what" = "all" ] || [ "$what" = "producer" ]; then
    issue_leaf producer lota-demo-anticheat-producer "$(
		printf '%s\n' \
			"basicConstraints=critical,CA:FALSE" \
			"keyUsage=critical,digitalSignature" \
			"extendedKeyUsage=clientAuth"
	)"
fi

echo
echo "mTLS material in $(pwd):"
echo "  ca.crt                 -> both ends pin this trust root"
echo "  server.crt/server.key  -> demo_server -tls-cert/-tls-key, -client-ca ca.crt"
echo "  producer.crt/producer.key -> demo_anticheat --client-cert/--client-key,"
echo "                            --ca-cert ca.crt"
