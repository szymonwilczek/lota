#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Szymon Wilczek
# Check commit-level pull request quality rules.

set -euo pipefail

# Infrastructure commit types:
# capped at the recommended tier even against a required rule, because by convention
# they do not change a documented contract
INFRA_TYPES=" ci build test tests chore style refactor perf release "

# Exempt commit types:
# the change is documentation or housekeeping by nature and never needs a companion doc
EXEMPT_TYPES=" docs license gitignore "

usage() {
	cat >&2 <<'USAGE'
usage: scripts/check-pr-quality.sh [--pr-diff] <base-commit> <head-commit>

Checks every commit in base..head for:
  - DCO Signed-off-by trailer,
  - hotpath changes without the documentation their tier requires.

Hotpath rule is either "required" (the change must touch a companion doc or
the commit must carry a "Docs-Not-Needed: <reason>" trailer) or "recommended"
(a missing doc only warns). The commit type caps the tier: an infrastructure
type (ci, build, test, chore, style, refactor, perf, release) is capped at
recommended, and docs/license/gitignore are exempt. See
.github/pr-quality-hotpaths.txt.

With --pr-diff, DCO is checked only for non-merge commits made on top of a tree
that already carried this gate, and a companion doc anywhere in the pull-request
diff satisfies a required rule. This keeps newly added rules from being applied
retroactively to historical integration commits.

AI assistant co-author or generator trailers are reported through the
ai_assisted=true output when GITHUB_OUTPUT is set. They do not fail this
script; the workflow labels the pull request instead.
USAGE
}

die() {
	printf 'ERROR: %s\n' "$*" >&2
	exit 2
}

short_commit() {
	git rev-parse --short=12 "$1"
}

commit_subject() {
	git log -1 --format=%s "$1"
}

# Type token of a commit:
# prefix before the first colon, with any conventional-commit scope "(...)"
# and "docs/ima" style sub-scope removed
commit_type() {
	local subject type
	subject=$(commit_subject "$1")
	type=${subject%%:*}
	# no colon -> no recognizable type
	[[ $type == "$subject" ]] && return 0
	type=${type%%(*}
	type=${type%%/*}
	type=${type// /}
	printf '%s' "${type,,}"
}

# non-empty reason from a "Docs-Not-Needed: <reason>" trailer, if present
docs_not_needed_reason() {
	git log -1 --format=%B "$1" |
		sed -n -E \
			's/^[Dd]ocs-[Nn]ot-[Nn]eeded:[[:space:]]*(.+[^[:space:]])[[:space:]]*$/\1/p' |
		head -n1
}

is_merge_commit() {
	local commit=$1
	local parent_count

	parent_count=$(git rev-list --parents -n1 "$commit" | awk '{ print NF - 1 }')
	((parent_count > 1))
}

gate_existed_for_commit() {
	local commit=$1
	local parent

	parent=$(git rev-list --parents -n1 "$commit" | awk '{ print $2 }')
	[[ -n ${parent:-} ]] || return 1
	git cat-file -e "$parent:.github/pr-quality-hotpaths.txt" 2>/dev/null
}

is_test_only_path() {
	local path=$1

	case "$path" in
	*_test.go | tests/* | test/* | */testdata/* | src/*/fuzz/*)
		return 0
		;;
	esac

	return 1
}

# does any hot glob in the manifest match one of the given files?
files_touch_hotpath() {
	local manifest=$1
	shift
	local -a files=("$@")
	local tier hot_globs rest hot_glob path
	local -a hot_patterns

	while IFS='|' read -r tier hot_globs rest; do
		[[ -z ${tier// /} || ${tier:0:1} == "#" ]] && continue
		read -r -a hot_patterns <<<"$hot_globs"
		for path in "${files[@]}"; do
			for hot_glob in "${hot_patterns[@]}"; do
				[[ $path == $hot_glob ]] && return 0
			done
		done
	done <"$manifest"

	return 1
}

# Classify one commit against the manifest.
# Args: <commit> <manifest> <doc-pool files...>
# doc pool is the commit's own files (commit mode) or the aggregate
# pull-request diff (pr-diff mode);
# doc there satisfies a required rule.
# Returns 1 only on an unwaived required miss; recommended misses warn.
classify_commit() {
	local commit=$1 manifest=$2
	shift 2
	local -a doc_pool=("$@")

	local type cap reason
	type=$(commit_type "$commit")
	[[ " $EXEMPT_TYPES " == *" $type "* ]] && return 0

	cap="none"
	[[ " $INFRA_TYPES " == *" $type "* ]] && cap="recommended"

	local -a files effective_files
	mapfile -t files < <(git diff-tree --no-commit-id --name-only -r "$commit")
	effective_files=()
	local path
	for path in "${files[@]}"; do
		is_test_only_path "$path" || effective_files+=("$path")
	done
	((${#effective_files[@]} == 0)) && return 0

	# explicit Docs-Not-Needed:
	# trailer waives the requirement for this commit;
	# note it once if it actually covers a hotpath change
	reason=$(docs_not_needed_reason "$commit")
	if [[ -n $reason ]]; then
		if files_touch_hotpath "$manifest" "${effective_files[@]}"; then
			printf 'docs waived: %s %s\n' \
				"$(short_commit "$commit")" "$(commit_subject "$commit")" >&2
			printf '  Docs-Not-Needed: %s\n' "$reason" >&2
		fi
		return 0
	fi

	local tier hot_globs doc_globs why eff doc_ok failed=0
	local -a hot_patterns doc_patterns hot_hits
	local hot_glob doc_glob

	while IFS='|' read -r tier hot_globs doc_globs why; do
		[[ -z ${tier// /} || ${tier:0:1} == "#" ]] && continue

		read -r -a hot_patterns <<<"$hot_globs"
		read -r -a doc_patterns <<<"$doc_globs"

		hot_hits=()
		for path in "${effective_files[@]}"; do
			for hot_glob in "${hot_patterns[@]}"; do
				[[ $path == $hot_glob ]] && {
					hot_hits+=("$path")
					break
				}
			done
		done
		((${#hot_hits[@]} == 0)) && continue

		doc_ok=0
		for path in "${doc_pool[@]}"; do
			for doc_glob in "${doc_patterns[@]}"; do
				[[ $path == $doc_glob ]] && {
					doc_ok=1
					break 2
				}
			done
		done
		((doc_ok == 1)) && continue

		eff=$tier
		[[ $cap == "recommended" && $eff == "required" ]] && eff="recommended"

		if [[ $eff == "required" ]]; then
			failed=1
			printf 'required docs missing: %s %s\n' \
				"$(short_commit "$commit")" "$(commit_subject "$commit")" >&2
		else
			printf 'recommended docs (not blocking): %s %s\n' \
				"$(short_commit "$commit")" "$(commit_subject "$commit")" >&2
		fi
		printf '  reason: %s\n' "$why" >&2
		printf '  hotpath files:\n' >&2
		printf '    %s\n' "${hot_hits[@]}" >&2
		printf '  %s one of:\n' \
			"$([[ $eff == required ]] && printf update || printf consider)" >&2
		printf '    %s\n' "${doc_patterns[@]}" >&2
		printf '  or record a "Docs-Not-Needed: <reason>" trailer if no docs are warranted\n' >&2
	done <"$manifest"

	((failed == 0))
}

check_signoff() {
	local commit=$1

	if ! git log -1 --format=%B "$commit" |
		grep -Eiq '^Signed-off-by: [^<]+ <[^>]+>$'; then
		printf 'missing Signed-off-by: %s %s\n' \
			"$(short_commit "$commit")" "$(commit_subject "$commit")" >&2
		return 1
	fi
}

check_ai_assistance() {
	local commit=$1
	local identity_re
	local trailer_re
	local bad_lines
	local actor

	identity_re='(codex|claude|anthropic|antrophic|antigravity|openai|copilot|cursor)'
	trailer_re='^(co-authored-by|generated-by|assisted-by|ai-assisted-by|written-by):'

	bad_lines=$(
		git log -1 --format=%B "$commit" |
			grep -Ein "$trailer_re" |
			grep -Ei "$identity_re" || true
	)
	actor=$(
		git log -1 --format='%an <%ae>%n%cn <%ce>' "$commit" |
			grep -Ei "$identity_re" || true
	)

	if [[ -n $bad_lines || -n $actor ]]; then
		printf 'AI-assisted commit marker: %s %s\n' \
			"$(short_commit "$commit")" "$(commit_subject "$commit")" >&2
		if [[ -n $bad_lines ]]; then
			printf '%s\n' "$bad_lines" >&2
		fi
		if [[ -n $actor ]]; then
			printf '%s\n' "$actor" >&2
		fi
		return 0
	fi

	return 1
}

main() {
	local mode="commit"
	local base
	local head
	local manifest=".github/pr-quality-hotpaths.txt"
	local rc=0
	local ai_assisted=0
	local commit
	local -a commits checked_commits pr_files commit_files

	if [[ ${1:-} == "--pr-diff" ]]; then
		mode="pr-diff"
		shift
	fi

	base=${1:-${BASE_SHA:-}}
	head=${2:-${HEAD_SHA:-}}

	if [[ -z $base || -z $head ]]; then
		usage
		exit 2
	fi

	[[ -f $manifest ]] || die "missing $manifest"
	git cat-file -e "$base^{commit}" || die "base commit not found: $base"
	git cat-file -e "$head^{commit}" || die "head commit not found: $head"

	mapfile -t commits < <(git rev-list --reverse "$base..$head")
	if ((${#commits[@]} == 0)); then
		printf 'No commits to check.\n'
		return 0
	fi

	if [[ $mode == "pr-diff" ]]; then
		mapfile -t pr_files < <(git diff --name-only "$base" "$head")
	fi

	for commit in "${commits[@]}"; do
		if [[ $mode == "pr-diff" ]]; then
			if is_merge_commit "$commit"; then
				continue
			fi
			if ! gate_existed_for_commit "$commit"; then
				continue
			fi
		fi

		checked_commits+=("$commit")
		check_signoff "$commit" || rc=1
		if check_ai_assistance "$commit"; then
			ai_assisted=1
		fi

		if [[ $mode == "pr-diff" ]]; then
			classify_commit "$commit" "$manifest" \
				${pr_files[@]+"${pr_files[@]}"} || rc=1
		else
			mapfile -t commit_files < \
				<(git diff-tree --no-commit-id --name-only -r "$commit")
			classify_commit "$commit" "$manifest" \
				${commit_files[@]+"${commit_files[@]}"} || rc=1
		fi
	done

	if [[ -n ${GITHUB_OUTPUT:-} ]]; then
		printf 'ai_assisted=%s\n' "$([[ $ai_assisted -eq 1 ]] && printf true || printf false)" \
			>>"$GITHUB_OUTPUT"
	fi

	if ((rc != 0)); then
		printf '\nPR quality gate failed.\n' >&2
		return "$rc"
	fi

	if ((ai_assisted == 1)); then
		printf 'PR quality gate passed for %d checked commit(s); AI-assisted marker found.\n' \
			"${#checked_commits[@]}"
	else
		printf 'PR quality gate passed for %d checked commit(s).\n' \
			"${#checked_commits[@]}"
	fi
}

main "$@"
