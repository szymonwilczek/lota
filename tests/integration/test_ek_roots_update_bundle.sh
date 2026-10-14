#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Szymon Wilczek
#
# tests/integration/test_ek_roots_update_bundle.sh
#
# What lota-ek-roots-update.sh materializes from a sources file.
#
# The bundle is the operator's half of an EK path: the anchors a chain may
# terminate at, and the intermediates that join a device's on-chip
# certificates to one of them. The CA treats the two differently, so the
# manifest has to record which is which -- and a sources file that anchors
# nothing has to be refused here, where the operator is still holding it,
# not at CA startup.
#
# Requires: openssl, sha256sum, and scripts/lota-ek-roots-update.sh.
# The vendor distribution point is a curl stub serving local files,
# so the test needs no network and no TLS.

set -euo pipefail

export LC_ALL=C

REPO_DIR=$(cd "$(dirname "$0")/../.." && pwd)
UPDATE_TOOL="$REPO_DIR/scripts/lota-ek-roots-update.sh"

if [[ ! -x "$UPDATE_TOOL" ]]; then
    echo "[ek-roots-update] missing artifact: $UPDATE_TOOL" >&2
    exit 2
fi
if ! command -v openssl >/dev/null 2>&1; then
    echo "[ek-roots-update] openssl not found" >&2
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

cd "$WORK_DIR"
mkdir -p www bin

# A curl that serves the distribution point out of a local directory.
# The tool fetches over HTTPS only, which is right and which no test should
# have to stand up a certificate authority for.
cat >bin/curl <<'STUB'
#!/bin/bash
out=""
url=""
while [[ $# -gt 0 ]]; do
	case "$1" in
	-o)
		out="$2"
		shift 2
		;;
	https://* | http://*)
		url="$1"
		shift
		;;
	*) shift ;;
	esac
done
[[ -n "$out" && -n "$url" ]] || exit 1
cp "$CURL_ROOT/${url##*/}" "$out"
STUB
chmod 0755 bin/curl
export CURL_ROOT="$WORK_DIR/www"

openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out root.key 2>/dev/null
openssl req -x509 -new -key root.key -days 2 -out root.pem \
	-subj "/CN=Example TPM Root CA" \
	-addext "basicConstraints=critical,CA:TRUE" \
	-addext "keyUsage=critical,keyCertSign" 2>/dev/null

openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out int.key 2>/dev/null
openssl req -new -key int.key -out int.csr -subj "/CN=Example TPM Issuing CA" 2>/dev/null
openssl x509 -req -in int.csr -days 2 -CA root.pem -CAkey root.key -CAcreateserial \
	-out int.pem -extfile <(printf 'basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign\n') 2>/dev/null

openssl x509 -in root.pem -outform DER -out www/root.der 2>/dev/null
openssl x509 -in int.pem -outform DER -out www/int.der 2>/dev/null

root_pin=$(openssl x509 -in root.pem -outform DER | sha256sum | cut -d' ' -f1)
int_pin=$(openssl x509 -in int.pem -outform DER | sha256sum | cut -d' ' -f1)

run_update() {
    PATH="$WORK_DIR/bin:$PATH" "$UPDATE_TOOL" "$1" "$2"
}

# The path a firmware TPM needs: one anchor, one intermediate the device does
# not carry.
{
    echo "$root_pin  vendor-root.pem  root  https://example.invalid/root.der  Example TPM Root CA"
    echo "$int_pin  vendor-issuing.pem  intermediate  https://example.invalid/int.der  Example TPM Issuing CA"
} >sources.ok

rc=0
run_update sources.ok bundle >out.txt 2>&1 || rc=$?
check "a sources file with an anchor and path material materializes" \
      test "$rc" -eq 0
check "the anchor is written" test -f bundle/vendor-root.pem
check "the path material is written" test -f bundle/vendor-issuing.pem
check "the manifest classes the anchor" \
      grep -qE "^$root_pin[[:space:]]+vendor-root\.pem[[:space:]]+root[[:space:]]" bundle/ek-roots.manifest
check "the manifest classes the path material" \
      grep -qE "^$int_pin[[:space:]]+vendor-issuing\.pem[[:space:]]+intermediate[[:space:]]" bundle/ek-roots.manifest

# A bundle of intermediates anchors nothing. Refusing it here names the problem;
# letting it through moves the same failure to CA startup.
echo "$int_pin  vendor-issuing.pem  intermediate  https://example.invalid/int.der  Example TPM Issuing CA" >sources.noanchor
rc=0
run_update sources.noanchor bundle-noanchor >noanchor.txt 2>&1 || rc=$?
check "a sources file with no anchor is refused" test "$rc" -ne 0
check "the refusal says the bundle anchors no chain" \
      grep -qi "anchors no chain" noanchor.txt

# An unclassed line is not a line whose class can be guessed: it is a line
# written against a format that no longer exists.
echo "$root_pin  vendor-root.pem  https://example.invalid/root.der  Example TPM Root CA" >sources.unclassed
rc=0
run_update sources.unclassed bundle-unclassed >unclassed.txt 2>&1 || rc=$?
check "a line carrying no class is refused" test "$rc" -ne 0

echo "$root_pin  vendor-root.pem  anchor  https://example.invalid/root.der  Example TPM Root CA" >sources.badclass
rc=0
run_update sources.badclass bundle-badclass >badclass.txt 2>&1 || rc=$?
check "a line carrying an unknown class is refused" test "$rc" -ne 0
check "the refusal names the classes it accepts" \
      grep -qi "must be root or intermediate" badclass.txt

# The pin is still the gate: a fetched certificate that does not match it is
# refused whatever its class says.
echo "$int_pin  vendor-root.pem  root  https://example.invalid/root.der  Example TPM Root CA" >sources.mismatch
rc=0
run_update sources.mismatch bundle-mismatch >mismatch.txt 2>&1 || rc=$?
check "a fingerprint mismatch is still refused" test "$rc" -ne 0

if [[ $failures -ne 0 ]]; then
    echo "FAILURES: $failures"
    sed -n '1,10p' out.txt 2>/dev/null
    exit 1
fi
echo "All tests passed"
