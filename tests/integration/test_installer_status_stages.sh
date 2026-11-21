#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Szymon Wilczek
#
# tests/integration/test_installer_status_stages.sh
#
# `lota-install --status` reports every step of the guided install,
# the self-check last, under the same numbering, without attesting.
# Checks the binary's output rather than the stage table.
#
# Requires:
#   - bash, and the built installer
#
# Runs unprivileged: --status changes nothing.

set -uo pipefail

. "$(dirname "$0")/../lib/test.sh"
test_begin "installer stages"

export LC_ALL=C

REPO_DIR=$(cd "$(dirname "$0")/../.." && pwd)
BUILD_DIR="${BUILD_DIR:-${LOTA_BUILD_DIR:-$REPO_DIR/build}}"
INSTALL_BIN="${LOTA_INSTALL_BIN:-$BUILD_DIR/lota-install}"

if [[ ! -x "$INSTALL_BIN" ]]; then
    FAIL "missing artifact: %s" "$INSTALL_BIN"
    test_end
fi

# non-zero exit while any step needs work, as on any build host
out=$("$INSTALL_BIN" --status 2>&1)

steps=$(grep -oE 'stage [0-9]+/[0-9]+' <<<"$out")
last_step=$(tail -1 <<<"$steps")
last_index=${last_step#stage }
last_index=${last_index%/*}
total=${last_step#*/}
counted=$(grep -c . <<<"$steps")
summary_total=$(grep -oE 'of [0-9]+ stages need work' <<<"$out" | head -1)
summary_total=${summary_total#of }
summary_total=${summary_total% stages need work}

says() { grep -qi -e "$2" <<<"$1"; }

TEST "every step announces itself"
test "$counted" -gt 0 || FAIL
TEST "the last step is the last of the total it names"
test "$last_index" = "$total" || FAIL
TEST "the steps counted are the total announced"
test "$counted" = "$total" || FAIL
TEST "the summary counts out of the same total"
test "$summary_total" = "$total" || FAIL

TEST "the report names the self-check"
says "$out" "self-check" || FAIL "%s" "$out"

selfcheck_line=$(grep -iE 'stage [0-9]+/[0-9]+: .*self-check' <<<"$out" |
    head -1)
selfcheck_index=${selfcheck_line#*stage }
selfcheck_index=${selfcheck_index%%/*}
TEST "the self-check is the last step"
test "$selfcheck_index" = "$total" || FAIL

# --status reports the self-check's round-trip without running it
report_ran_no_round_trip() {
    ! grep -qiE 'Attestation round-trip against' <<<"$out"
}
TEST "the report does not attest from a read-only run"
report_ran_no_round_trip || FAIL

test_end
