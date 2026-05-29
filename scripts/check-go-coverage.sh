#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# scripts/check-go-coverage.sh
#
# Coverage ratchet for the Go modules. Runs `go test -cover ./...` in
# each module and fails if any package drops below the floor recorded
# in .github/go-coverage-baseline. The target is 100%; floors are only
# ever raised as tests land, never lowered, so coverage moves toward
# 100% monotonically and a regression breaks the build.
#
# After adding tests, re-run this script, read the printed percentages,
# and bump the matching floors in the baseline file.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BASELINE="${1:-$ROOT/.github/go-coverage-baseline}"
MODULES=(src/verifier src/sdk/server)

if [[ ! -f "$BASELINE" ]]; then
	echo "baseline file not found: $BASELINE" >&2
	exit 2
fi

declare -A floor
while read -r pkg min _; do
	[[ -z "$pkg" || "$pkg" == \#* ]] && continue
	floor["$pkg"]="$min"
done <"$BASELINE"

out="$(mktemp)"
trap 'rm -f "$out"' EXIT

for m in "${MODULES[@]}"; do
	(cd "$ROOT/$m" && go test -cover ./...) | tee -a "$out"
done

rc=0
declare -A seen
while IFS= read -r line; do
	[[ "$line" == *"coverage:"* ]] || continue
	pkg="$(grep -oE 'github\.com/[^ 	]+' <<<"$line" | head -1)"
	pct="$(sed -nE 's/.*coverage: ([0-9]+\.[0-9]+)%.*/\1/p' <<<"$line")"
	[[ -z "$pkg" || -z "$pct" ]] && continue
	seen["$pkg"]=1
	min="${floor[$pkg]:-0}"
	if awk "BEGIN{exit !($pct < $min)}"; then
		echo "REGRESSION: $pkg $pct% < floor ${min}%" >&2
		rc=1
	else
		echo "ok: $pkg ${pct}% >= ${min}%"
	fi
done <"$out"

# A package listed in the baseline that produced no coverage line means
# it was renamed or lost its tests; treat that as a regression too.
for pkg in "${!floor[@]}"; do
	if [[ -z "${seen[$pkg]:-}" && "${floor[$pkg]}" != "0" ]]; then
		echo "MISSING: $pkg has floor ${floor[$pkg]}% but reported no coverage" >&2
		rc=1
	fi
done

exit $rc
