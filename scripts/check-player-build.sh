#!/bin/sh
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Szymon Wilczek
#
# Player build-from-source gate.
#
# Runs the commands of the player page's "Building it yourself" section,
# read from the page, in a clean Fedora. A development host already
# carries every package an earlier build needed; only an empty image shows
# a package the page fails to name. The clone is replaced by a copy of the
# tree under test, and sudo is dropped: the container runs as root.
#
# Two entry modes, one run:
#   host      : spawn the Fedora container and re-invoke self
#   container : run directly (LOTA_PLAYER_IN_CONTAINER=1; CI runs the
#               job inside the image already). LOTA_PLAYER_SRC points at
#               the checkout (default /src, the podman mount).
#
# Usage: scripts/check-player-build.sh
# Requires: podman (host mode only)
set -eu

IMAGE="${LOTA_PLAYER_IMAGE:-registry.fedoraproject.org/fedora:44}"
SRC="${LOTA_PLAYER_SRC:-/src}"
PAGE=Documentation/player/index.rst

run_host() {
    command -v podman >/dev/null 2>&1 || {
	echo "check-player-build: podman not found; needed to spawn $IMAGE" >&2
	exit 1
    }
    repo_root=$(cd "$(dirname "$0")/.." && pwd)
    echo "check-player-build: spawning $IMAGE (repo mounted read-only at /src)"
    # label=disable: :Z relabel trips on stray xattr files in the tree
    # the build runs in a copy, so the mount stays read-only
    exec podman run --rm \
	 --security-opt label=disable \
	 -v "$repo_root":/src:ro \
	 -e LOTA_PLAYER_IN_CONTAINER=1 \
	 "$IMAGE" \
	 /bin/sh /src/scripts/check-player-build.sh
}

# Command lines of the section's literal blocks, continuations joined;
# a block that starts with output rather than a command is skipped
page_commands() {
    awk '
	{ l[NR] = $0 }
	END {
		for (i = 1; i <= NR; i++)
			if (l[i] == "Building it yourself")
				break
		for (i += 2; i <= NR; i++) {
			# the next heading ends the section
			if (l[i] ~ /^[^ ]/ && l[i + 1] ~ /^[-=~^]+$/)
				break
			if (l[i] ~ /^    [^ ]/ && l[i - 1] == "")
				block = (l[i] ~ /^    (sudo |\.\/|make |git )/)
			else if (l[i] !~ /^    / && l[i] != "")
				block = 0
			if (!block || l[i] !~ /^    /)
				continue
			s = l[i]
			sub(/^ +/, "", s)
			if (cont != "")
				s = cont " " s
			if (sub(/ *\\$/, "", s)) {
				cont = s
				continue
			}
			print s
			cont = ""
		}
	}
	' "$SRC/$PAGE"
}

run_page() {
    cmds=/tmp/lota-player-build.cmds
    log=/tmp/lota-player-build.log
    page_commands >"$cmds"
    test -s "$cmds" || {
	echo "check-player-build: no commands found under" \
	     "'Building it yourself' in $PAGE" >&2
	exit 1
    }

    work=$(mktemp -d)
    cd "$work"
    n=0
    while IFS= read -r cmd; do
	n=$((n + 1))
	echo "check-player-build: [$n] $cmd"
	case "$cmd" in
	    "git clone "*)
		# the tree under test, without the host's build output
		run="mkdir lota && tar -C '$SRC' --exclude=./build -cf - . | tar -xf - -C lota"
		;;
	    *)
		run=$(printf '%s\n' "$cmd" |
			  sed -e 's/^sudo //' \
			      -e 's/^dnf install /dnf -y install /')
		;;
	esac
	# no subshell, so the page's cd holds
	if ! eval "$run" >"$log" 2>&1; then
	    tail -20 "$log" | sed 's/^/    /'
	    echo "check-player-build: step $n of $PAGE fails in a" \
		 "clean $IMAGE -- name the package it needs" >&2
	    exit 1
	fi
    done <"$cmds"

    for f in /usr/bin/lota-install /usr/bin/lota-steam-setup \
		                   /usr/bin/lota-proton-hook /usr/lib64/liblota_wine_hook.so.1 \
		                   /usr/lib/liblota_wine_hook.so.1; do
	test -e "$f" || {
	    echo "check-player-build: the install left no $f" >&2
	    exit 1
	}
    done
    echo "check-player-build: clean ($n commands)"
}

main() {
    if [ "${LOTA_PLAYER_IN_CONTAINER:-0}" != "1" ]; then
	run_host
    fi
    run_page
}

main "$@"
