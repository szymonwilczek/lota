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
# A Requires, a sibling pin or a pkgconfig() provide that only one manifest
# makes fails the gate, in either direction.
#
# A Summary or %description the spec words apart from the nfpm description
# fails the gate.
#
# The same manifests take every file from ./build, so `make packages` with
# another BUILD_DIR must stop before it builds anything.
#
# Requires:
#   - the in-tree packaging manifests and the gate script
#
# Runs unprivileged: nothing is installed and no package is built.

set -euo pipefail

. "$(dirname "$0")/../lib/test.sh"
test_begin "package manifest lists"

export LC_ALL=C

REPO_DIR=$(cd "$(dirname "$0")/../.." && pwd)
GATE=scripts/check-package-manifests.sh
AGENT_YAML=packaging/nfpm/lota-agent.yaml
DEVEL_YAML=packaging/nfpm/lota-sdk-devel.yaml

for f in "$GATE" "$AGENT_YAML" "$DEVEL_YAML" Makefile VERSION \
    Documentation/conf.py; do
    if [[ ! -e "$REPO_DIR/$f" ]]; then
	FAIL "missing file: %s" "$f"
	test_end
    fi
done

WORK_DIR=$(mktemp -d)
test_cleanup 'rm -rf "$WORK_DIR"'

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

gate_failed() {
    FAIL "%s" "$(tail -n 20 "$WORK_DIR/gate.out")"
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

# Replace the first line of file equal to what
replace_line() {
    local file="$1" what="$2" text="$3"

    awk -v what="$what" -v text="$text" '
		$0 == what && !done { print text; done = 1; next }
		{ print }
	' "$WORK_DIR/tree/$file" >"$WORK_DIR/edited"
    mv "$WORK_DIR/edited" "$WORK_DIR/tree/$file"
}

# Unedited copy must pass, or the cases below test the copy
fixture
TEST "the fixture tree passes the gate unedited"
gate_passes || gate_failed

# lota-sdk = is the version lock the gate checks against the spec
fixture
insert_above "$AGENT_YAML" "lota-sdk = " \
	     "      # the player page tells the reader to run what this ships"
TEST "a comment inside depends leaves the entries under it in place"
gate_passes || gate_failed

fixture
insert_above "$DEVEL_YAML" "pkgconfig(lota-server)" \
	     "      # the server half, for a title's own back end"
TEST "a comment inside provides leaves the entries under it in place"
gate_passes || gate_failed

fixture
insert_above "$AGENT_YAML" "lota-sdk = " ""
TEST "a blank line inside depends leaves the entries under it in place"
gate_passes || gate_failed

# Control: a reader that skips too much passes this too
fixture
drop_line "$AGENT_YAML" "lota-sdk = "
TEST "a dependency genuinely taken out is still caught"
! gate_passes || gate_failed

# Fails, naming what
gate_fails_with() {
    ! gate_passes && grep -qF -- "$1" "$WORK_DIR/gate.out"
}

fixture
insert_above "$AGENT_YAML" "lota-sdk = " "      - fsverity-utils"
TEST "a Requires only nfpm makes fails"
gate_fails_with "lota-agent require fsverity-utils and packaging/rpm" || gate_failed

fixture
drop_line "$AGENT_YAML" "      - dracut"
TEST "a Requires only the spec makes fails"
gate_fails_with "makes lota-agent require dracut and packaging/nfpm" || gate_failed

fixture
drop_line "$AGENT_YAML" "      - libseccomp"
TEST "a soname Requires nfpm leaves out fails"
gate_fails_with "soname_requires lists libseccomp for lota-agent" || gate_failed

fixture
replace_line packaging/rpm/lota.spec \
	     "Requires:       %{name}-sdk%{?_isa} = %{version}-%{release}" \
	     "Requires:       %{name}-sdk%{?_isa}"
TEST "a sibling pin only nfpm makes fails"
gate_fails_with "lota-agent to one build of lota-sdk and packaging/rpm" || gate_failed

fixture
replace_line "$AGENT_YAML" "      - lota-sdk = \${LOTA_RPM_VERSION}" \
	     "      - lota-sdk >= \${LOTA_RPM_VERSION}"
TEST "a lower bound in nfpm against a spec pin fails"
gate_fails_with "lota-agent to one build of lota-sdk and packaging/nfpm" || gate_failed

fixture
replace_line packaging/rpm/lota.spec \
	     "Requires:       %{name}-sdk%{?_isa} = %{version}-%{release}" \
	     "Requires:       %{name}-sdk%{?_isa} >= %{version}-%{release}"
TEST "a lower bound in the spec against an nfpm pin fails"
gate_fails_with "lota-agent to one build of lota-sdk and packaging/rpm" || gate_failed

fixture
insert_above packaging/rpm/lota.spec "Requires:       dracut" \
	     "Requires(post): coreutils"
TEST "a scriptlet Requires only the spec makes fails"
gate_fails_with "makes lota-agent require coreutils and packaging/nfpm" || gate_failed

fixture
insert_above "$DEVEL_YAML" "pkgconfig(lota-server)" \
	     "      - pkgconfig(lota-made-up)"
TEST "a pkgconfig() provide with no .pc behind it fails"
gate_fails_with "provides pkgconfig(lota-made-up) and ships no" || gate_failed

gate_fails_on_description() {
    ! gate_passes &&
	grep -q 'lota-sdk-devel reads differently' "$WORK_DIR/gate.out"
}

fixture
replace_line packaging/rpm/lota.spec \
	     "Summary:        LOTA SDK development files" \
	     "Summary:        LOTA SDK headers and shared libraries"
TEST "a Summary the nfpm description does not open with fails"
gate_fails_on_description || gate_failed

fixture
replace_line packaging/rpm/lota.spec \
	     "Requires lota-sdk." \
	     "Requires lota-sdk and ships the Proton/Steam helpers."
TEST "a %description that differs from the nfpm description fails"
gate_fails_on_description || gate_failed

TEST "packages refuses a BUILD_DIR other than ./build"
if make -C "$REPO_DIR" -n BUILD_DIR="$WORK_DIR/out" packages \
	>"$WORK_DIR/gate.out" 2>&1; then
    gate_failed
# A refusal from the recipe would follow the recipes of all it needs
elif ! grep -q 'packages builds from ' "$WORK_DIR/gate.out" ||
	grep -v -e 'packages builds from ' -e 'ing directory' \
	    "$WORK_DIR/gate.out" | grep -q .; then
    FAIL "not refused before a build"
    gate_failed
fi

DEFAULT_DIR=$(sed -n 's/^BUILD_DIR[[:space:]]*:=[[:space:]]*//p' \
    "$REPO_DIR/Makefile")
packages_dry_run() {
    make -C "$REPO_DIR" -s -n BUILD_DIR="$1" packages \
	>"$WORK_DIR/gate.out" 2>&1 || true
    ! grep -q 'packages builds from ' "$WORK_DIR/gate.out"
}
TEST "packages takes the default BUILD_DIR however it is spelled"
packages_dry_run "$REPO_DIR/$DEFAULT_DIR/." || gate_failed

test_end
