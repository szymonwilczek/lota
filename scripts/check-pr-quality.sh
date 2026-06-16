#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Szymon Wilczek
# Check commit-level pull request quality rules.

set -euo pipefail

usage() {
	cat >&2 <<'USAGE'
usage: scripts/check-pr-quality.sh [--pr-diff] <base-commit> <head-commit>

Checks every commit in base..head for:
  - DCO Signed-off-by trailer,
  - hotpath changes without same-commit documentation updates.

With --pr-diff, DCO is checked only for non-merge commits made on top of a tree
that already carried this gate, and hotpath documentation is checked against
the aggregate pull-request diff. This keeps newly added rules from being
applied retroactively to historical integration commits.

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

check_hotpath_docs_for_files() {
	local manifest=$1
	local scope=$2
	shift 2

	local rc=0
	local hot_globs doc_globs reason
	local hot_hits doc_hits hot_glob doc_glob path
	local -a files hot_patterns doc_patterns effective_files

	files=("$@")
	effective_files=()
	for path in "${files[@]}"; do
		if ! is_test_only_path "$path"; then
			effective_files+=("$path")
		fi
	done

	if ((${#effective_files[@]} == 0)); then
		return 0
	fi

	while IFS='|' read -r hot_globs doc_globs reason; do
		[[ -z ${hot_globs// /} ]] && continue
		[[ ${hot_globs:0:1} == "#" ]] && continue

		read -r -a hot_patterns <<<"$hot_globs"
		read -r -a doc_patterns <<<"$doc_globs"
		hot_hits=()
		doc_hits=()

		for path in "${effective_files[@]}"; do
			for hot_glob in "${hot_patterns[@]}"; do
				if [[ $path == $hot_glob ]]; then
					hot_hits+=("$path")
					break
				fi
			done

			for doc_glob in "${doc_patterns[@]}"; do
				if [[ $path == $doc_glob ]]; then
					doc_hits+=("$path")
					break
				fi
			done
		done

		if ((${#hot_hits[@]} > 0 && ${#doc_hits[@]} == 0)); then
			printf 'hotpath changed without %s docs update\n' "$scope" >&2
			printf 'reason: %s\n' "$reason" >&2
			printf 'hotpath files:\n' >&2
			printf '  %s\n' "${hot_hits[@]}" >&2
			printf 'expected one of:\n' >&2
			printf '  %s\n' "${doc_patterns[@]}" >&2
			rc=1
		fi
	done <"$manifest"

	return "$rc"
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

check_hotpath_docs() {
	local commit=$1
	local manifest=$2
	local rc=0
	local -a files

	mapfile -t files < <(git diff-tree --no-commit-id --name-only -r "$commit")
	check_hotpath_docs_for_files "$manifest" "same-commit" "${files[@]}" || rc=1

	if ((rc != 0)); then
		printf 'commit: %s %s\n' \
			"$(short_commit "$commit")" "$(commit_subject "$commit")" >&2
	fi

	return "$rc"
}

main() {
	local mode="commit"
	local base
	local head
	local manifest=".github/pr-quality-hotpaths.txt"
	local rc=0
	local ai_assisted=0
	local commit
	local -a commits changed_files checked_commits

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
		if [[ $mode == "commit" ]]; then
			check_hotpath_docs "$commit" "$manifest" || rc=1
		fi
	done

	if [[ $mode == "pr-diff" ]]; then
		mapfile -t changed_files < <(git diff --name-only "$base" "$head")
		check_hotpath_docs_for_files "$manifest" "PR diff" "${changed_files[@]}" || rc=1
	fi

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
