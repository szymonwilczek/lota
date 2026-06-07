#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# Turn a live EK certificate into a candidate sources line for the EK root
# bundle. Given an Endorsement Key certificate, the tool walks the
# Authority Information Access "CA Issuers" chain up to the self-signed
# root, then prints the root PEM and a ready-to-paste sources line carrying
# the SHA-256 over the root DER.
#
# The pin it prints is NOT trusted: it is computed over what the network
# handed back. Confirm it out of band against the vendor's published value
# before adding the line to a sources file. The tool exists to find the
# right root for a platform and format the line, not to vouch for it.
#
# Usage:
#   scripts/lota-ek-root-pin.sh <ek-cert | -> [output-dir]
#
#   <ek-cert>    EK certificate in DER or PEM, or - to read from stdin.
#   output-dir   optional; the root PEM is written here (default: stdout).
#
# See configs/ek-roots/README.md for how EK certificates are read from a TPM.

set -euo pipefail

MAX_DEPTH=10

die() {
	echo "lota-ek-root-pin: $*" >&2
	exit 1
}

[ $# -ge 1 ] && [ $# -le 2 ] || die "usage: $0 <ek-cert | -> [output-dir]"
EK_INPUT="$1"
OUTDIR="${2:-}"

command -v openssl >/dev/null 2>&1 || die "openssl not found"
command -v curl >/dev/null 2>&1 || die "curl not found"
command -v sha256sum >/dev/null 2>&1 || die "sha256sum not found"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/lota-ek-root-pin.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

# to_pem reads a certificate in DER or PEM and writes it back as PEM
to_pem() {
	local in="$1" out="$2"
	if openssl x509 -inform DER -in "$in" -outform PEM -out "$out" 2>/dev/null; then
		return 0
	fi
	openssl x509 -inform PEM -in "$in" -outform PEM -out "$out" 2>/dev/null
}

# ca_issuer_url prints the first AIA "CA Issuers" URI of a PEM certificate,
# empty if the certificate carries none
ca_issuer_url() {
	openssl x509 -in "$1" -noout -ext authorityInfoAccess 2>/dev/null |
		sed -n 's/.*CA Issuers - URI:\(.*\)/\1/p' | head -n1
}

# is_self_signed succeeds when a PEM certificate is its own issuer and its
# signature verifies against itself -- i.e. a trust-anchor root
is_self_signed() {
	local cert="$1" subj issu
	subj="$(openssl x509 -in "$cert" -noout -subject_hash 2>/dev/null)"
	issu="$(openssl x509 -in "$cert" -noout -issuer_hash 2>/dev/null)"
	[ -n "$subj" ] && [ "$subj" = "$issu" ] || return 1
	openssl verify -CAfile "$cert" "$cert" >/dev/null 2>&1
}

# materialize the EK certificate as PEM
if [ "$EK_INPUT" = "-" ]; then
	cat >"$WORK/in.raw"
else
	[ -r "$EK_INPUT" ] || die "cannot read EK certificate: $EK_INPUT"
	cp "$EK_INPUT" "$WORK/in.raw"
fi
to_pem "$WORK/in.raw" "$WORK/cur.pem" || die "input is not a certificate"

# walk CA Issuers up to the self-signed root
url=""
depth=0
while ! is_self_signed "$WORK/cur.pem"; do
	depth=$((depth + 1))
	[ "$depth" -le "$MAX_DEPTH" ] ||
		die "issuer chain exceeds $MAX_DEPTH hops without reaching a self-signed root"

	url="$(ca_issuer_url "$WORK/cur.pem")"
	[ -n "$url" ] ||
		die "certificate at depth $((depth - 1)) has no AIA CA Issuers URL; fetch its issuer out of band and re-run from that root"
	case "$url" in
	https://* | http://*) ;;
	*) die "refusing non-HTTP CA Issuers URL: $url" ;;
	esac

	curl -fsSL --proto '=https,http' --tlsv1.2 -o "$WORK/next.raw" "$url" ||
		die "failed to fetch issuer from $url"
	to_pem "$WORK/next.raw" "$WORK/cur.pem" ||
		die "issuer fetched from $url is not a certificate"
done

# at this point cur.pem is the self-signed root
pin="$(openssl x509 -in "$WORK/cur.pem" -outform DER 2>/dev/null | sha256sum | cut -d' ' -f1)"
[ -n "$pin" ] || die "failed to fingerprint the root certificate"

label="$(openssl x509 -in "$WORK/cur.pem" -noout -subject -nameopt sep_comma_plus,utf8 2>/dev/null | sed 's/^subject=//')"
# slugify the label into a bare filename
slug="$(printf '%s' "$label" | tr '[:upper:]' '[:lower:]' | tr -c 'a-z0-9' '-' | sed 's/--*/-/g; s/^-//; s/-$//')"
[ -n "$slug" ] || slug="ek-root"
filename="${slug}.pem"
[ "${#filename}" -le 96 ] || filename="${slug:0:90}.pem"

src_url="${url:-REPLACE_WITH_VENDOR_PUBLISHED_URL}"

# stdout carries only the sources line so it can be appended to a sources
# file; everything else is diagnostics on stderr. The root PEM is written
# only when an output dir is given -- the normal flow re-fetches it from the
# URL when lota-ek-roots-update.sh materializes the bundle
if [ -n "$OUTDIR" ]; then
	mkdir -p "$OUTDIR"
	install -m 0644 "$WORK/cur.pem" "$OUTDIR/$filename"
	echo "wrote root certificate to $OUTDIR/$filename" >&2
fi

echo "# self-signed root: $label" >&2
echo "# candidate sources line -- verify the pin out of band before trusting it:" >&2
echo "$pin  $filename  $src_url  $label"
