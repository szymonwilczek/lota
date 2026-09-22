#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Szymon Wilczek
#
# tests/integration/test_package_manifest_lists.sh
#
# A comment or blank line inside an nfpm yaml list must not end it.
# scripts/check-package-manifests.sh walks a list by its dash-led lines;
# a reader that stops at the first other line drops every entry below,
# and the gate then fails a correct manifest or passes a divergent one.
#
# Each case edits a copy of what the gate reads, never the checkout.
# The last case is the control: a dependency really removed must still fail.
#
# Requires:
#   - the in-tree packaging manifests and the gate script
#
# Runs unprivileged: nothing is installed and no package is built.

set -euo pipefail

export LC_ALL=C

REPO_DIR=$(cd "$(dirname "$0")/../.." && pwd)
GATE=scripts/check-package-manifests.sh
AGENT_YAML=packaging/nfpm/lota-agent.yaml
DEVEL_YAML=packaging/nfpm/lota-sdk-devel.yaml

for f in "$GATE" "$AGENT_YAML" "$DEVEL_YAML" Makefile VERSION \
    Documentation/conf.py; do
    if [[ ! -e "$REPO_DIR/$f" ]]; then
	echo "[package-manifest-lists] missing file: $f" >&2
	exit 2
    fi
done

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

# Fresh copy of everything the gate reads; cases share nothing
fixture() {
    rm -rf "$WORK_DIR/tree"
    mkdir -p "$WORK_DIR/tree/scripts" "$WORK_DIR/tree/Documentation"
    cp -a "$REPO_DIR/packaging" "$WORK_DIR/tree/packaging"
    cp -a "$REPO_DIR/Documentation/conf.py" "$WORK_DIR/tree/Documentation/"
    cp -a "$REPO_DIR/Makefile" "$REPO_DIR/VERSION" "$WORK_DIR/tree/"
    cp -a "$REPO_DIR/$GATE" "$WORK_DIR/tree/$GATE"
}

# Gate verdict on the fixture; output kept for the failure report
gate_passes() {
    "$WORK_DIR/tree/$GATE" >"$WORK_DIR/gate.out" 2>&1
}

# Insert text above the first line of file containing what
insert_above() {
    local file="$1" what="$2" text="$3"

    awk -v what="$what" -v text="$text" '
		index($0, what) && !done { print text; done = 1 }
		{ print }
	' "$WORK_DIR/tree/$file" >"$WORK_DIR/edited"
    mv "$WORK_DIR/edited" "$WORK_DIR/tree/$file"
}

drop_line() {
    local file="$1" what="$2"

    grep -v -F -- "$what" "$WORK_DIR/tree/$file" >"$WORK_DIR/edited"
    mv "$WORK_DIR/edited" "$WORK_DIR/tree/$file"
}

echo "=== what a commented manifest list reads as ==="

# Unedited copy must pass, or the cases below test the copy
fixture
check "the fixture tree passes the gate unedited" gate_passes

# lota-sdk = is the version lock the gate checks against the spec
fixture
insert_above "$AGENT_YAML" "lota-sdk = " \
	     "      # the player page tells the reader to run what this ships"
check "a comment inside depends leaves the entries under it in place" \
      gate_passes

fixture
insert_above "$DEVEL_YAML" "pkgconfig(lota-server)" \
	     "      # the server half, for a title's own back end"
check "a comment inside provides leaves the entries under it in place" \
      gate_passes

fixture
insert_above "$AGENT_YAML" "lota-sdk = " ""
check "a blank line inside depends leaves the entries under it in place" \
      gate_passes

# Control: a reader that skips too much passes this too
fixture
drop_line "$AGENT_YAML" "lota-sdk = "
if gate_passes; then
    echo "FAIL: a dependency genuinely taken out is still caught"
    failures=$((failures + 1))
else
    echo "PASS: a dependency genuinely taken out is still caught"
fi

echo ""
if [[ $failures -eq 0 ]]; then
    echo "[package-manifest-lists] OK"
    exit 0
fi
echo "[package-manifest-lists] $failures check(s) failed" >&2
echo "last gate output:" >&2
cat "$WORK_DIR/gate.out" >&2
exit 1
