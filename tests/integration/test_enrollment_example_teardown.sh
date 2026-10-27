#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Szymon Wilczek
#
# tests/integration/test_enrollment_example_teardown.sh
#
# The enrollment demo consents to its CA directory as a publisher anchor,
# even when the run later fails; each new directory takes another slot of
# the agent's bounded publisher budget. The demo never forgets a publisher
# itself (it talks to the host's real agent), so it must name the one it
# created and the command that releases it.
#
# Requires:
#   - examples/enrollment/run.sh, gen-ca.sh, README.rst
#   - openssl (for the anchor-identity case)
#
# Runs unprivileged, writes only into a temporary directory, and enrolls
# nothing.

set -euo pipefail

export LC_ALL=C

REPO_DIR=$(cd "$(dirname "$0")/../.." && pwd)
RUN_SH="$REPO_DIR/examples/enrollment/run.sh"
GEN_CA="$REPO_DIR/examples/enrollment/gen-ca.sh"
README="$REPO_DIR/examples/enrollment/README.rst"

for f in "$RUN_SH" "$GEN_CA"; do
    if [[ ! -x "$f" ]]; then
        echo "[example-teardown] missing artifact: $f" >&2
        exit 2
    fi
done

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

# release command in both the script output and the README
check "the script names the command that takes the publisher back" \
    grep -q -- "--forget-publisher" "$RUN_SH"
check "the README names the command that takes the publisher back" \
    grep -q -- "--forget-publisher" "$README"

# Failed run still holds the slot. Fail it after consent and expect the
# release command; stubbed binaries and sudo need no TPM, root or build
teardown_survives_failure() {
    local work out rc
    work=$(mktemp -d)

    mkdir -p "$work/bin" "$work/ca"
    for stub in lota-agent lota-attest-ca lota-verifier; do
        printf '#!/bin/sh\nexit 1\n' >"$work/bin/$stub"
        chmod +x "$work/bin/$stub"
    done
    # the script runs the agent under sudo; here that is a passthrough
    printf '#!/bin/sh\nexec "$@"\n' >"$work/bin/sudo"
    chmod +x "$work/bin/sudo"

    "$GEN_CA" "$work/ca" >/dev/null 2>&1 || {
        rm -rf "$work"
        return 1
    }

    set +e
    out=$(cd "$REPO_DIR/examples/enrollment" &&
        PATH="$work/bin:$PATH" BIN="$work/bin" CA_DIR="$work/ca" \
            EK_ROOT="$work/ca/ca.crt" RUN_DIR="$work/run" \
            CA_ADDR=127.0.0.1:0 VERIFIER_ADDR=127.0.0.1:0 \
            timeout 60 ./run.sh 2>&1)
    rc=$?
    set -e
    rm -rf "$work"

    # the run has to have failed, and to have said what it kept anyway
    [[ $rc -ne 0 ]] && grep -q -- "--forget-publisher" <<<"$out"
}
check "a run that fails after consent still says what it kept" \
    teardown_survives_failure

check "the README says the CA directory is the publisher identity" \
    bash -c "grep -qi 'publisher' '$README' && grep -qiE 'CA_DIR|ca directory|the same ca' '$README'"

# one directory is one anchor across gen-ca.sh reruns, two are two
anchor_id() {
    openssl x509 -in "$1/ca.crt" -noout -pubkey |
        openssl pkey -pubin -outform DER |
        openssl dgst -sha256 -r | cut -d' ' -f1
}

if command -v openssl >/dev/null 2>&1; then
    work=$(mktemp -d)
    trap 'rm -rf "$work"' EXIT

    "$GEN_CA" "$work/one" >/dev/null 2>&1
    first=$(anchor_id "$work/one")
    "$GEN_CA" "$work/one" >/dev/null 2>&1
    again=$(anchor_id "$work/one")
    "$GEN_CA" "$work/two" >/dev/null 2>&1
    other=$(anchor_id "$work/two")

    check "re-running gen-ca.sh over one directory keeps the publisher" \
        test "$first" = "$again"
    check "a second directory is a second publisher" \
        test "$first" != "$other"
else
    echo "SKIP: anchor identity cases (no openssl)"
fi

if [[ $failures -ne 0 ]]; then
    echo "FAILURES: $failures"
    exit 1
fi
echo "All tests passed"
