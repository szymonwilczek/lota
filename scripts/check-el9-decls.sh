#!/bin/sh
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Szymon Wilczek
#
# Second-toolchain declaration gate.
#
# Compiles every shipped C translation unit -fsyntax-only against el9
# headers with the flags the build uses, so a symbol used without the header
# that declares it fails here.
#
# Fedora's headers include more than el9's, so a missing include compiles on
# the development host and fails on el9. clang-include-cleaner does not report
# it: a declaration that arrives through another header is not an unused
# include, and one that arrives through a compiler builtin has no header.
#
# Every unit is compiled and every failure reported; the sweep does not stop
# at the first one.
#
# Two entry modes, one sweep:
#   host      : spawn the el9 container and re-invoke self
#   container : sweep directly (LOTA_DECLS_IN_CONTAINER=1; CI runs the job inside
#               the image already). LOTA_DECLS_SRC points at the checkout
#               (default /src, the podman mount).
#
# Usage: scripts/check-el9-decls.sh
# Requires: podman (host mode only)
set -eu

IMAGE="${LOTA_DECLS_IMAGE:-quay.io/rockylinux/rockylinux:9}"
SRC="${LOTA_DECLS_SRC:-/src}"

run_host() {
    command -v podman >/dev/null 2>&1 || {
        echo "check-el9-decls: podman not found; needed to spawn $IMAGE" >&2
        exit 1
    }
    repo_root=$(cd "$(dirname "$0")/.." && pwd)
    echo "check-el9-decls: spawning $IMAGE (repo mounted read-only at /src)"
    # label=disable: :Z relabel trips on stray xattr files in the tree
    # sweep writes nothing, so the mount stays read-only
    exec podman run --rm \
        --security-opt label=disable \
        -v "$repo_root":/src:ro \
        -e LOTA_DECLS_IN_CONTAINER=1 \
        "$IMAGE" \
        /bin/sh /src/scripts/check-el9-decls.sh
}

install_toolchain() {
    echo "check-el9-decls: installing the el9 headers and compiler"
    # baseos + appstream + crb carry all of it; no EPEL, so nothing
    # outside the distribution decides whether a declaration is there
    dnf -y install dnf-plugins-core >/dev/null
    dnf config-manager --set-enabled crb >/dev/null
    dnf -y install \
        gcc make pkgconf-pkg-config clang llvm bpftool \
        libbpf-devel elfutils-libelf-devel zlib-devel tpm2-tss-devel \
        openssl-devel systemd-devel libseccomp-devel dbus-devel >/dev/null
}

# Every compile command `all` would run, with the build's own flags.
# -B so make prints them all; -n so it prints and does not build.
# The BPF program is skipped: it is built -target bpf against a generated
# vmlinux.h, not against el9 headers.
compile_lines() {
    make -Bn all 2>/dev/null |
        grep -- ' -c -o ' |
        grep -v -- '-target bpf'
}

sweep() {
    cd "$SRC"
    lines=/tmp/lota-el9-decls.lines
    compile_lines >"$lines" || true
    total=$(wc -l <"$lines")
    test "$total" -gt 0 || {
        echo "check-el9-decls: make printed no compile commands" >&2
        exit 1
    }

    echo "check-el9-decls: $total translation units against el9 headers"
    fail=0
    while read -r line; do
        src=${line##* }
        # -fsyntax-only writes nothing, so the object and the dependency file
        # the build asks for go away with it
        cmd=$(printf '%s\n' "$line" |
            sed -e 's/ -o [^ ]*\.o//' \
                -e 's/ -MMD//' -e 's/ -MP//' \
                -e 's/ -MF [^ ]*//' \
                -e 's/ -c / -fsyntax-only /')
        if ! out=$(eval "$cmd" 2>&1); then
            echo "FAIL $src"
            printf '%s\n' "$out" | sed 's/^/    /'
            fail=1
        fi
    done <"$lines"

    test "$fail" -eq 0 || {
        echo "check-el9-decls: a unit uses a symbol el9 does not" \
            "declare for it -- include the header the note names" >&2
        exit 1
    }
    echo "check-el9-decls: clean"
}

main() {
    if [ "${LOTA_DECLS_IN_CONTAINER:-0}" != "1" ]; then
        run_host
    fi
    install_toolchain
    sweep
}

main "$@"
