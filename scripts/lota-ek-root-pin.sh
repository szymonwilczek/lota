#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Szymon Wilczek
#
# Turn a live EK certificate into candidate sources lines for the EK root
# bundle. The tool walks the Authority Information Access "CA Issuers" chain up
# to the self-signed root and prints a line for the root and every certificate
# the walk fetched. Each line is classed: "root" is a trust anchor,
# "intermediate" is path material the CA builds through but never anchors a
# chain at.
#
# The pins are computed over the certificates as received and are NOT trusted.
# Confirm each out of band against the vendor's published value before adding
# the line to a sources file.
#
# An Intel PTT EK certificate can carry no Authority Information Access
# extension. Its nearest issuers are then on the chip, at NV index 0x01c00100,
# as concatenated DER. --nv-chain hands that blob over: the walk climbs it
# first, then continues online from the highest certificate it found.
#
# Usage:
#   scripts/lota-ek-root-pin.sh [--nv-chain FILE] <ek-cert | -> [output-dir]
#
#   --nv-chain FILE  certificates the TPM carries (DER blob or PEM bundle),
#                    read from NV 0x01c00100 on Intel PTT:
#                        sudo tpm2_nvread 0x01c00100 -o nvchain.bin
#   <ek-cert>        EK certificate in DER or PEM, or - to read from stdin.
#   output-dir       optional; every certificate that gets a line is written
#                    here as PEM (default: the lines alone, on stdout).
#
# See configs/ek-roots/README.rst for how EK certificates are read from a TPM.

set -euo pipefail

MAX_DEPTH=10

die() {
    echo "lota-ek-root-pin: $*" >&2
    exit 1
}

NV_CHAIN=""
while [ $# -gt 0 ]; do
    case "$1" in
	--nv-chain)
	    [ $# -ge 2 ] || die "--nv-chain needs a file"
	    NV_CHAIN="$2"
	    shift 2
	    ;;
	--nv-chain=*)
	    NV_CHAIN="${1#--nv-chain=}"
	    shift
	    ;;
	--)
	    shift
	    break
	    ;;
	-*)
	    [ "$1" = "-" ] && break
	    die "unknown option: $1"
	    ;;
	*)
	    break
	    ;;
    esac
done

[ $# -ge 1 ] && [ $# -le 2 ] ||
    die "usage: $0 [--nv-chain FILE] <ek-cert | -> [output-dir]"
EK_INPUT="$1"
OUTDIR="${2:-}"

command -v openssl >/dev/null 2>&1 || die "openssl not found"
command -v curl >/dev/null 2>&1 || die "curl not found"
command -v sha256sum >/dev/null 2>&1 || die "sha256sum not found"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/lota-ek-root-pin.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

to_pem() {
    local in="$1" out="$2"
    if openssl x509 -inform DER -in "$in" -outform PEM -out "$out" 2>/dev/null; then
	return 0
    fi
    openssl x509 -inform PEM -in "$in" -outform PEM -out "$out" 2>/dev/null
}

ca_issuer_url() {
    openssl x509 -in "$1" -noout -ext authorityInfoAccess 2>/dev/null |
	sed -n 's/.*CA Issuers - URI:\(.*\)/\1/p' | head -n1
}

is_self_signed() {
    local cert="$1" subj issu
    subj="$(openssl x509 -in "$cert" -noout -subject_hash 2>/dev/null)"
    issu="$(openssl x509 -in "$cert" -noout -issuer_hash 2>/dev/null)"
    [ -n "$subj" ] && [ "$subj" = "$issu" ] || return 1
    openssl verify -CAfile "$cert" "$cert" >/dev/null 2>&1
}

# split_certs writes each certificate of a blob as PEM under $WORK/chain. A blob
# is a PEM bundle or concatenated DER, which has no separators and no count: a
# certificate's SEQUENCE header gives its length, and the next starts after it.
split_certs() {
    local blob="$1" n=0 off=0 size hdr len bytes tag lenbyte b1 b2

    mkdir -p "$WORK/chain"

    if grep -q -- "-----BEGIN CERTIFICATE-----" "$blob" 2>/dev/null; then
	awk -v dir="$WORK/chain" '
			/-----BEGIN CERTIFICATE-----/ { n++; f = sprintf("%s/%03d.pem", dir, n) }
			f { print > f }
			/-----END CERTIFICATE-----/ { f = "" }
		' "$blob"
	[ -n "$(ls -A "$WORK/chain" 2>/dev/null)" ]
	return
    fi

    size=$(wc -c <"$blob")
    while [ "$off" -lt "$size" ]; do
	bytes="$(od -An -tu1 -j "$off" -N 4 "$blob" 2>/dev/null)"
	# shellcheck disable=SC2086
	set -- $bytes
	tag="${1:-}"
	lenbyte="${2:-}"
	b1="${3:-}"
	b2="${4:-}"
	[ "$tag" = "48" ] || break # 0x30, SEQUENCE

	case "$lenbyte" in
	    130) # 0x82: two length bytes
		hdr=4
		len=$((b1 * 256 + b2))
		;;
	    129) # 0x81: one length byte
		hdr=3
		len=$b1
		;;
	    *)
		[ "$lenbyte" -lt 128 ] 2>/dev/null || break
		hdr=2
		len=$lenbyte
		;;
	esac

	n=$((n + 1))
	dd if="$blob" of="$WORK/der.tmp" bs=1 skip="$off" \
	   count=$((hdr + len)) status=none 2>/dev/null || break
	openssl x509 -inform DER -in "$WORK/der.tmp" -outform PEM \
		-out "$(printf '%s/%03d.pem' "$WORK/chain" "$n")" \
		2>/dev/null || n=$((n - 1))
	off=$((off + hdr + len))
    done

    [ "$n" -gt 0 ]
}

# issuer_from_chain finds the split certificate that issued $1: a subject match
# is only a claim, the signature confirms it
issuer_from_chain() {
    local cert="$1" want cand
    want="$(openssl x509 -in "$cert" -noout -issuer_hash 2>/dev/null)"
    [ -n "$want" ] || return 1

    for cand in "$WORK"/chain/*.pem; do
	[ -r "$cand" ] || continue
	[ "$(openssl x509 -in "$cand" -noout -subject_hash 2>/dev/null)" = "$want" ] ||
	    continue
	openssl verify -no_check_time -partial_chain -trusted "$cand" \
		"$cert" >/dev/null 2>&1 || continue
	printf '%s' "$cand"
	return 0
    done
    return 1
}

if [ "$EK_INPUT" = "-" ]; then
    cat >"$WORK/in.raw"
else
    [ -r "$EK_INPUT" ] || die "cannot read EK certificate: $EK_INPUT"
    cp "$EK_INPUT" "$WORK/in.raw"
fi
to_pem "$WORK/in.raw" "$WORK/cur.pem" || die "input is not a certificate"

if [ -n "$NV_CHAIN" ]; then
    [ -r "$NV_CHAIN" ] || die "cannot read chain file: $NV_CHAIN"
    split_certs "$NV_CHAIN" ||
	die "no certificate found in $NV_CHAIN"
    echo "# on-chip chain: $(ls "$WORK"/chain/*.pem 2>/dev/null | wc -l) certificate(s) from $NV_CHAIN" >&2
fi

fetched_pem=()
fetched_url=()
depth=0
while ! is_self_signed "$WORK/cur.pem"; do
    depth=$((depth + 1))
    [ "$depth" -le "$MAX_DEPTH" ] ||
	die "issuer chain exceeds $MAX_DEPTH hops without reaching a self-signed root"

    if [ -d "$WORK/chain" ]; then
	next="$(issuer_from_chain "$WORK/cur.pem" || true)"
	if [ -n "$next" ]; then
	    cp "$next" "$WORK/cur.pem"
	    continue
	fi
    fi

    url="$(ca_issuer_url "$WORK/cur.pem")"
    [ -n "$url" ] ||
	die "certificate at depth $((depth - 1)) has no AIA CA Issuers URL and no issuer for it is in the chain file; on a firmware TPM the certificates above the EK live on the chip -- read them with 'tpm2_nvread 0x01c00100 -o nvchain.bin' and pass --nv-chain nvchain.bin"
    case "$url" in
	https://* | http://*) ;;
	*) die "refusing non-HTTP CA Issuers URL: $url" ;;
    esac

    curl -fsSL --proto '=https,http' --tlsv1.2 -o "$WORK/next.raw" "$url" ||
	die "failed to fetch issuer from $url"
    to_pem "$WORK/next.raw" "$WORK/cur.pem" ||
	die "issuer fetched from $url is not a certificate"

    cp "$WORK/cur.pem" "$WORK/fetched.$depth.pem"
    fetched_pem+=("$WORK/fetched.$depth.pem")
    fetched_url+=("$url")
done

der_sha256() {
    openssl x509 -in "$1" -outform DER 2>/dev/null | sha256sum | cut -d' ' -f1
}

emit_line() {
    local cert="$1" class="$2" url="$3" pin label slug filename

    pin="$(der_sha256 "$cert")"
    [ -n "$pin" ] || die "failed to fingerprint a certificate on the path"

    label="$(openssl x509 -in "$cert" -noout -subject -nameopt sep_comma_plus,utf8 2>/dev/null | sed 's/^subject=//')"
    slug="$(printf '%s' "$label" | tr '[:upper:]' '[:lower:]' | tr -c 'a-z0-9' '-' | sed 's/--*/-/g; s/^-//; s/-$//')"
    [ -n "$slug" ] || slug="ek-$class"
    filename="${slug}.pem"
    [ "${#filename}" -le 96 ] || filename="${slug:0:90}.pem"

    if [ -n "$OUTDIR" ]; then
	mkdir -p "$OUTDIR"
	install -m 0644 "$cert" "$OUTDIR/$filename"
	echo "wrote $class certificate to $OUTDIR/$filename" >&2
    fi

    echo "# $class: $label" >&2
    echo "$pin  $filename  $class  ${url:-REPLACE_WITH_VENDOR_PUBLISHED_URL}  $label"
}

root_pin="$(der_sha256 "$WORK/cur.pem")"
[ -n "$root_pin" ] || die "failed to fingerprint the root certificate"

# a root the walk did not fetch has no URL to record
root_url=""
for i in "${!fetched_pem[@]}"; do
    [ "$(der_sha256 "${fetched_pem[$i]}")" = "$root_pin" ] || continue
    root_url="${fetched_url[$i]}"
done

# stdout carries only the sources lines, so it can be appended to a sources file
echo "# candidate sources lines -- verify each pin out of band before trusting it:" >&2
emit_line "$WORK/cur.pem" root "$root_url"
for i in "${!fetched_pem[@]}"; do
    [ "$(der_sha256 "${fetched_pem[$i]}")" = "$root_pin" ] && continue
    emit_line "${fetched_pem[$i]}" intermediate "${fetched_url[$i]}"
done
