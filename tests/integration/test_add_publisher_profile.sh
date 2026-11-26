#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Szymon Wilczek
#
# tests/integration/test_add_publisher_profile.sh
#
# What `lota-agent --add-publisher` writes into lota.conf, driven through
# the binary, because the defect this covers lives in the wiring: the CLI
# resolves a default verifier before the writer ever sees one, so a publisher
# who runs none cannot be expressed.
#
# Requires:
#   - ${BUILD_DIR}/lota-agent (build with `make all`).
#     Unset, BUILD_DIR follows LOTA_BUILD_DIR, which a make recipe exports
#     as the directory that build used.
#   - openssl, for the trust anchor a publisher is identified by
#
# Runs unprivileged:
# --add-publisher reads the anchor and appends to the config it is given,
# and touches no state under /var/lib/lota.

set -euo pipefail

# assertions grep the agent's own messages, and strerror() is localised
export LC_ALL=C

REPO_DIR=$(cd "$(dirname "$0")/../.." && pwd)
BUILD_DIR="${BUILD_DIR:-${LOTA_BUILD_DIR:-$REPO_DIR/build}}"
AGENT_BIN="$BUILD_DIR/lota-agent"

if [[ ! -x "$AGENT_BIN" ]]; then
    echo "[add-publisher] missing artifact: $AGENT_BIN" >&2
    exit 2
fi
if ! command -v openssl >/dev/null 2>&1; then
    echo "[add-publisher] openssl not found" >&2
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

has_line() { grep -qx "$2" "$1"; }
lacks() { ! grep -q "$2" "$1"; }
says() { grep -qi -- "$2" <<<"$1"; }
loads() { "$AGENT_BIN" --dump-config --config "$1" >/dev/null 2>&1; }

anchor() {
    local name="$1"
    openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
	    -subj "/CN=$name" \
	    -keyout "$WORK_DIR/$name.key" \
	    -out "$WORK_DIR/$name.pem" 2>/dev/null
    echo "$WORK_DIR/$name.pem"
}

# A publisher who runs no verifier: nothing is reported from this machine
# and their backend checks the tokens their titles fetch.
# Naming no --server is the only way to ask for it.
tokenonly_pem=$(anchor tokenonly)
conf="$WORK_DIR/tokenonly.conf"
printf 'mode = enforce\n' >"$conf"

out=$("$AGENT_BIN" --add-publisher ca.tokenonly.example --ca-port 8564 \
	           --ca-cert "$tokenonly_pem" --publisher-name tokenonly \
	           --config "$conf" 2>&1)
check "the section says the publisher runs no verifier" \
      has_line "$conf" 'verifier = none'
check "no port is written for a verifier declared absent" \
      lacks "$conf" 'verifier_port'
check "the command says nothing is reported from this machine" \
      says "$out" 'no verifier'
check "the config the command wrote loads" loads "$conf"

# A publisher who runs one: the verifier and its port are the operator's,
# and the section has to carry both.
reporting_pem=$(anchor reporting)
conf="$WORK_DIR/reporting.conf"
printf 'mode = enforce\n' >"$conf"

out=$("$AGENT_BIN" --add-publisher ca.reporting.example --ca-port 8564 \
	           --ca-cert "$reporting_pem" --publisher-name reporting \
	           --server verifier.reporting.example --port 9443 \
	           --config "$conf" 2>&1)
check "the section names the verifier the operator gave" \
      has_line "$conf" 'verifier = verifier.reporting.example'
check "the section carries that verifier's port" \
      has_line "$conf" 'verifier_port = 9443'
check "the command names the verifier it wrote" \
      says "$out" 'verifier.reporting.example'
check "the config the command wrote loads" loads "$conf"

# A config that exists and holds nothing: an installer that created the file
# before configuring it, or an operator who cleared it.
# There is nothing to preserve, so the section is appended to it like any other.
empty_pem=$(anchor empty)
conf="$WORK_DIR/empty.conf"
: >"$conf"

rc=0
out=$("$AGENT_BIN" --add-publisher ca.empty.example --ca-port 8564 \
	           --ca-cert "$empty_pem" --publisher-name empty \
	           --server verifier.empty.example \
	           --config "$conf" 2>&1) || rc=$?
check "a publisher is added to a config file that is empty" test "$rc" -eq 0
check "the section is written into the empty file" \
      has_line "$conf" 'verifier = verifier.empty.example'
check "the config the command wrote loads" loads "$conf"
[[ $rc -eq 0 ]] || echo "  reported: $out"

# An operator-owned host reports whether or not a title runs:
# a fleet verifier that hears only during a session hears nothing.
fleet_pem=$(anchor fleet)
conf="$WORK_DIR/fleet.conf"
: >"$conf"

rc=0
out=$("$AGENT_BIN" --add-publisher ca.fleet.example \
	           --ca-cert "$fleet_pem" --publisher-name fleet \
	           --server verifier.fleet.example --reporting continuous \
	           --config "$conf" 2>&1) || rc=$?
check "a continuous publisher is added" test "$rc" -eq 0
check "the section reports continuously" \
      has_line "$conf" 'reporting = continuous'
check "the config the command wrote loads" loads "$conf"
[[ $rc -eq 0 ]] || echo "  reported: $out"

# A typo must not quietly fall back to session reporting.
typo_pem=$(anchor typo)
conf="$WORK_DIR/typo.conf"
: >"$conf"

rc=0
out=$("$AGENT_BIN" --add-publisher ca.typo.example \
	           --ca-cert "$typo_pem" --publisher-name typo \
	           --server verifier.typo.example --reporting continous \
	           --config "$conf" 2>&1) || rc=$?
check "an unknown reporting mode is refused" test "$rc" -ne 0
check "nothing is written for an unknown reporting mode" \
      lacks "$conf" 'typo'

# A profile whose anchor moved away may be the publisher being added,
# so a second profile of the same CA is not appended beside it.
# Another CA's broken profile names some other publisher and blocks nothing.
moved_pem=$(anchor moved)
conf="$WORK_DIR/moved.conf"
: >"$conf"
"$AGENT_BIN" --add-publisher ca.moved.example --ca-port 8564 \
	     --ca-cert "$moved_pem" --publisher-name moved \
	     --server verifier.moved.example --config "$conf" >/dev/null 2>&1
mv "$moved_pem" "$WORK_DIR/moved-new.pem"
before=$(cksum <"$conf")

rc=0
out=$("$AGENT_BIN" --add-publisher ca.moved.example --ca-port 8564 \
	           --ca-cert "$WORK_DIR/moved-new.pem" \
	           --server verifier.moved.example \
	           --config "$conf" 2>&1) || rc=$?
check "an unreadable anchor of the same CA is refused" test "$rc" -ne 0
check "the refusal names the profile and the anchor to point it at" \
      says "$out" "Profile \"moved\" in $conf names the anchor $moved_pem"
check "nothing is appended beside it" test "$(cksum <"$conf")" = "$before"

other_pem=$(anchor other)
rc=0
out=$("$AGENT_BIN" --add-publisher ca.other.example --ca-port 8564 \
	           --ca-cert "$other_pem" --publisher-name other \
	           --server verifier.other.example \
	           --config "$conf" 2>&1) || rc=$?
check "another CA's publisher is added beside it" test "$rc" -eq 0
check "its section is written" has_line "$conf" 'ca = ca.other.example'
[[ $rc -eq 0 ]] || echo "  reported: $out"

if [[ $failures -ne 0 ]]; then
    echo "FAILURES: $failures"
    exit 1
fi
echo "All tests passed"
