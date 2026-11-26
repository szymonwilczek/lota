#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Szymon Wilczek
# Check commit-level pull request quality rules.

set -euo pipefail

# shellcheck source=scripts/lib/commit-limits.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib/commit-limits.sh"

# Exempt commit types:
# the change is documentation or housekeeping by nature and gets no docs note
EXEMPT_TYPES=" docs license gitignore "

usage() {
    cat >&2 <<'USAGE'
usage: scripts/check-pr-quality.sh [--pr-diff] <base-commit> <head-commit>

Checks every commit in base..head for:
  - DCO Signed-off-by trailer,
  - subject and body lines within 75 columns,
  - branch name within 75 columns, and the pull request title under the subject
    rules when PR_TITLE is set.

Merge commits and subjects starting with "Merge " are exempt from the column
limit, and so is every commit when the branch under test is lota-next. Body
lines that are a single word, a trailer, a URL, a merge line, a diffstat line,
or led by a file path are exempt too. PR_BRANCH overrides the checked-out
branch; CI sets it.

A subject with "a/b:" or "a: b:" prints a note asking whether the form is the
intended one: "/" joins two surfaces, ": " names a submodule. Notes do not fail.

A change to a file listed in .github/pr-quality-hotpaths.txt without the docs
named there prints a note. docs, license and gitignore commits print none.

With --pr-diff, DCO is checked only for non-merge commits made on top of a tree
that already carried this gate, and no docs note is printed. This keeps newly
added rules from being applied retroactively to historical integration commits.

AI assistant co-author or generator trailers are reported through the
ai_assisted=true output when GITHUB_OUTPUT is set. They do not fail this
script; the workflow labels the pull request.
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

# Print a note per manifest rule the commit touches without its docs.
# Args: <commit> <manifest>
note_missing_docs() {
    local commit=$1 manifest=$2

    local type
    type=$(commit_type "$commit")
    [[ " $EXEMPT_TYPES " == *" $type "* ]] && return 0

    local -a files effective_files
    mapfile -t files < <(git diff-tree --no-commit-id --name-only -r "$commit")
    effective_files=()
    local path
    for path in "${files[@]}"; do
	is_test_only_path "$path" || effective_files+=("$path")
    done
    ((${#effective_files[@]} == 0)) && return 0

    local hot_globs doc_globs why doc_ok hot_hit
    local -a hot_patterns doc_patterns
    local hot_glob doc_glob

    while IFS='|' read -r hot_globs doc_globs why; do
	[[ -z ${hot_globs// /} || ${hot_globs:0:1} == "#" ]] && continue

	read -r -a hot_patterns <<<"$hot_globs"
	read -r -a doc_patterns <<<"$doc_globs"

	hot_hit=0
	for path in "${effective_files[@]}"; do
	    for hot_glob in "${hot_patterns[@]}"; do
		[[ $path == $hot_glob ]] && {
		    hot_hit=1
		    break 2
		}
	    done
	done
	((hot_hit == 0)) && continue

	doc_ok=0
	for path in "${files[@]}"; do
	    for doc_glob in "${doc_patterns[@]}"; do
		[[ $path == $doc_glob ]] && {
		    doc_ok=1
		    break 2
		}
	    done
	done
	((doc_ok == 1)) && continue

	printf 'note: %s: docs not updated: %s\n' \
	       "$(short_commit "$commit")" "$why"
	printf 'note:   consider updating %s\n' "${doc_patterns[*]}"
    done <"$manifest"
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

# Args: <subject> <what to name in a report>
check_subject() {
    local subject=$1 where=$2

    [[ $subject == "Merge "* ]] && return 0

    if [[ $subject =~ ^[^\ :]+/[^\ :]*: ]]; then
	printf 'note: %s: "/" joins two surfaces. Submodule? Use "a: b:".\n' \
	       "$where"
    elif [[ $subject =~ ^[^\ :]+:\ [^\ :]+: ]]; then
	printf 'note: %s: ": " names a submodule. Two surfaces? Use "a/b:".\n' \
	       "$where"
    fi

    if ((${#subject} > COMMIT_COLUMNS)); then
	printf 'subject is %d columns, limit %d: %s %s\n' \
	       "${#subject}" "$COMMIT_COLUMNS" "$where" "$subject" >&2
	printf '  shorten it by hand\n' >&2
	return 1
    fi
}

check_branch() {
    local branch=$1

    if ((${#branch} > COMMIT_COLUMNS)); then
	printf 'branch name is %d columns, limit %d: %s\n' \
	       "${#branch}" "$COMMIT_COLUMNS" "$branch" >&2
	printf '  rename it with git branch -m\n' >&2
	return 1
    fi
}

check_message_limits() {
    local commit=$1
    local subject long_lines
    local rc=0

    subject=$(commit_subject "$commit")
    if is_merge_commit "$commit" || [[ $subject == "Merge "* ]]; then
	return 0
    fi

    check_subject "$subject" "$(short_commit "$commit")" || rc=1

    long_lines=$(
	git log -1 --format=%B "$commit" | awk '
			NR == 1 { next }
			length($0) > ENVIRON["COMMIT_COLUMNS"] + 0 &&
			$0 ~ /[[:space:]]/ &&
			$0 !~ ENVIRON["COMMIT_LINE_EXEMPT"] {
				printf "  %d: %d columns\n", NR, length($0)
			}
		'
	      )
    if [[ -n $long_lines ]]; then
	printf 'body lines over %d columns: %s %s\n' \
	       "$COMMIT_COLUMNS" "$(short_commit "$commit")" "$subject" >&2
	printf '%s\n' "$long_lines" >&2
	printf '  run scripts/format-patch over the same base..head range\n' >&2
	rc=1
    fi

    return "$rc"
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
    local commit branch
    local -a commits checked_commits

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

    branch=${PR_BRANCH:-$(git symbolic-ref --quiet --short HEAD || true)}

    if [[ $branch != lota-next ]]; then
	check_branch "$branch" || rc=1
	if [[ -n ${PR_TITLE:-} ]]; then
	    check_subject "$PR_TITLE" "pull request title" || rc=1
	fi
    fi

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
	if [[ $branch != lota-next ]]; then
	    check_message_limits "$commit" || rc=1
	fi
	if check_ai_assistance "$commit"; then
	    ai_assisted=1
	fi

	if [[ $mode != "pr-diff" ]]; then
	    note_missing_docs "$commit" "$manifest"
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
