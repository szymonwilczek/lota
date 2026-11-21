#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Szymon Wilczek
#
# tests/integration/test_pr_quality_skipped_range.sh
#
# scripts/check-pr-quality.sh --pr-diff skips merge commits and commits made
# before the gate existed. A range it skips whole has no commit to fail and
# passes with zero checked commits.
#
# Requires:
#   - git
#
# Runs unprivileged in a throwaway repository.

set -euo pipefail

. "$(dirname "$0")/../lib/test.sh"
test_begin "pr quality range"

export LC_ALL=C

REPO_DIR=$(cd "$(dirname "$0")/../.." && pwd)

WORK_DIR=$(mktemp -d)
test_cleanup 'rm -rf "$WORK_DIR"'

export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1
export GIT_AUTHOR_NAME=Test GIT_AUTHOR_EMAIL=test@example.com
export GIT_COMMITTER_NAME=Test GIT_COMMITTER_EMAIL=test@example.com

cd "$WORK_DIR"
git init -q -b work .
git commit -q --allow-empty -m "root" \
    -m "Signed-off-by: Test <test@example.com>"
base=$(git rev-parse HEAD)

# a side commit made before the gate, so --pr-diff skips it
git switch -q -c side
git commit -q --allow-empty -m "side without sign-off"
git switch -q work

mkdir -p scripts/lib .github
cp "$REPO_DIR/scripts/check-pr-quality.sh" scripts/
cp "$REPO_DIR/scripts/lib/commit-limits.sh" scripts/lib/
: >.github/pr-quality-hotpaths.txt
git add -A
git commit -q -m "gate" -m "Signed-off-by: Test <test@example.com>"
gate=$(git rev-parse HEAD)
git merge -q --no-ff --no-edit side

rc=0
out=$(scripts/check-pr-quality.sh --pr-diff "$gate" HEAD 2>&1) || rc=$?
TEST "a skipped range passes"
[[ $rc -eq 0 ]] || FAIL "exit %d: %s" "$rc" "$out"
TEST "the summary counts no checked commit"
[[ $out == *"passed for 0 checked commit(s)"* ]] || FAIL "%s" "$out"

# control: without --pr-diff the side commit is checked and fails
TEST "a missing sign-off fails without --pr-diff"
! scripts/check-pr-quality.sh "$base" HEAD >/dev/null 2>&1 || FAIL

test_end
