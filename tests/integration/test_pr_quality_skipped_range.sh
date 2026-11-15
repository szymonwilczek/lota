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

export LC_ALL=C

REPO_DIR=$(cd "$(dirname "$0")/../.." && pwd)

WORK_DIR=$(mktemp -d)
trap 'rm -rf "$WORK_DIR"' EXIT

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

if ! out=$(scripts/check-pr-quality.sh --pr-diff "$gate" HEAD 2>&1); then
    printf '%s\n' "$out" >&2
    echo "[pr-quality-skipped-range] FAIL: a skipped range did not pass" >&2
    exit 1
fi
if [[ $out != *"passed for 0 checked commit(s)"* ]]; then
    printf '%s\n' "$out" >&2
    echo "[pr-quality-skipped-range] FAIL: unexpected summary" >&2
    exit 1
fi

# control: without --pr-diff the side commit is checked and fails
if scripts/check-pr-quality.sh "$base" HEAD >/dev/null 2>&1; then
    echo "[pr-quality-skipped-range] FAIL: missing sign-off passed" >&2
    exit 1
fi

echo "[pr-quality-skipped-range] all cases passed"
