#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Szymon Wilczek
#
#   stage RPM_DIR OUT_DIR       unpack each RPM into OUT_DIR/NAME/ and write
#                               its header fields to OUT_DIR/NAME.header
#   manifest OUT_DIR FILE       hash every file under OUT_DIR into FILE
#   check MANIFEST RPM_DIR      require the RPMs in RPM_DIR to hash as in
#                               MANIFEST, then verify the BPF signature
#   compare MANIFEST REBUILT    require the same hashes but for the BPF
#                               signature and its key, which a rebuild
#                               makes with a key of its own
#   rebuild IMAGE MANIFEST      build HEAD in the builder image IMAGE and
#                               compare the result with MANIFEST
#   NAME is the file name of an RPM without .rpm

set -euo pipefail

export LC_ALL=C

ROOT=$(cd "$(dirname "$0")/.." && pwd)
# files a rebuild cannot reproduce: the job signed the object with its key
UNREPRODUCIBLE='/usr/lib/lota/(lota_lsm\.bpf\.o\.sig|enforcement\.pub)$'
# the package, then each file: mode, owner, group, flags, path, link target
QF='%{NAME} %{EPOCHNUM}:%{VERSION}-%{RELEASE} %{ARCH}\n'
QF+='[%{FILEMODES:perms} %{FILEUSERNAME} %{FILEGROUPNAME} %{FILEFLAGS:fflags}'
QF+=' %{FILENAMES} -> %{FILELINKTOS}\n]'
TMP=
trap '[[ -z "$TMP" ]] || rm -rf -- "$TMP"' EXIT

die() {
    echo "verify-rpm-release: $*" >&2
    exit 1
}

usage() {
    sed -n '5,15s/^# \{0,1\}//p' "$0" >&2
    exit 2
}

need() {
    local t
    for t in "$@"; do
        command -v "$t" >/dev/null 2>&1 || die "$t is not installed"
    done
}

header() {
    local rpm="$1" q
    rpm -qp --nosignature --qf "$QF" "$rpm"
    for q in scripts triggers requires provides conflicts obsoletes \
                     recommends suggests supplements enhances; do
        echo "== $q"
        rpm -qp --nosignature "--$q" "$rpm"
    done
}

stage() {
    local rpm_dir="$1" out="$2" rpm name n=0
    need rpm rpm2archive tar
    rm -rf -- "$out"
    mkdir -p -- "$out"
    for rpm in "$rpm_dir"/*.rpm; do
        [[ -f "$rpm" ]] || continue
        name=$(basename -- "$rpm" .rpm)
        mkdir -- "$out/$name"
        if ! rpm2archive -n - <"$rpm" |
                tar -xf - -C "$out/$name" --no-same-owner ||
                ! header "$rpm" >"$out/$name.header"; then
            echo "FAIL: $rpm does not unpack"
            exit 1
        fi
        n=$((n + 1))
    done
    [[ $n -gt 0 ]] || die "no RPM in $rpm_dir"
}

manifest() {
    local dir="$1" file
    file=$(realpath -m -- "$2")
    (cd -- "$dir" && find . -type f -printf '%P\0' | sort -z |
             xargs -0 -r sha256sum --) >"$file"
    [[ -s "$file" ]] || die "no file under $dir"
}

# lines of MANIFEST that belong to the packages staged in DIR
restrict() {
    local manifest="$1" dir="$2"
    find "$dir" -mindepth 1 -maxdepth 1 -type d -printf '%f\n' |
        awk 'NR == FNR { pkg[$0] = 1; next }
            { p = substr($0, 67); sub(/(\/.*|\.header)$/, "", p) }
            p in pkg' - "$manifest"
}

check() {
    local manifest="$1" rpm_dir="$2" sig name fail=0
    [[ -r "$manifest" ]] || die "cannot read $manifest"
    TMP=$(mktemp -d)
    stage "$rpm_dir" "$TMP/stage"
    manifest "$TMP/stage" "$TMP/got"
    restrict "$manifest" "$TMP/stage" >"$TMP/want"
    if ! diff -u --label "$manifest" --label "$rpm_dir" \
         "$TMP/want" "$TMP/got"; then
        echo "FAIL: the RPMs in $rpm_dir differ from $manifest"
        fail=1
    fi
    while IFS= read -r -d '' sig; do
        need openssl
        name=${sig#"$TMP/stage/"}
        if openssl pkeyutl -verify -rawin -pubin \
                   -inkey "${sig%/lota_lsm.bpf.o.sig}/enforcement.pub" \
                   -in "${sig%.sig}" -sigfile "$sig" >/dev/null 2>&1; then
            echo "PASS: $name verifies against enforcement.pub"
        else
            echo "FAIL: $name does not verify against enforcement.pub"
            fail=1
        fi
    done < <(find "$TMP/stage" -path '*/usr/lib/lota/lota_lsm.bpf.o.sig' \
                  -print0)
    [[ $fail -eq 0 ]] || exit 1
    echo "PASS: the RPMs in $rpm_dir match $manifest"
}

compare() {
    local a="$1" b="$2"
    [[ -r "$a" ]] || die "cannot read $a"
    [[ -r "$b" ]] || die "cannot read $b"
    if ! diff -u <(grep -Ev "$UNREPRODUCIBLE" "$a") \
         <(grep -Ev "$UNREPRODUCIBLE" "$b"); then
        echo "FAIL: $b differs from $a"
        exit 1
    fi
    echo "PASS: $b matches $a but for the BPF signature and its key"
}

rebuild() {
    local image="$1" manifest="$2" engine="${CONTAINER_ENGINE:-podman}"
    [[ -r "$manifest" ]] || die "cannot read $manifest"
    need git "$engine"
    manifest=$(realpath -- "$manifest")
    TMP=$(mktemp -d -p "${TMPDIR:-/var/tmp}")
    git clone -q --no-checkout -- "$ROOT" "$TMP/src"
    git -C "$TMP/src" checkout -q --detach "$(git -C "$ROOT" rev-parse HEAD)"
    # shellcheck disable=SC2016 # $key expands in the container
    "$engine" run --rm -v "$TMP/src:/src:Z" -w /src "$image" bash -c '
        set -eu
        git config --global --add safe.directory /src
        # the engine may run as root: remove what the build wrote
        trap "git clean -qfdx" EXIT
        key="SIGNING_KEY=/tmp/rebuild.key SIGNING_PUBKEY=/tmp/rebuild.pub"
        {
            openssl genpkey -algorithm ed25519 -out /tmp/rebuild.key
            openssl pkey -in /tmp/rebuild.key -pubout -out /tmp/rebuild.pub
            make reproducible-build
            make sign-bpf $key
            make packages $key
            make release-manifest-fedora
        } >&2
        cat build/SHA256SUMS-fedora' >"$TMP/rebuilt"
    compare "$manifest" "$TMP/rebuilt"
}

[[ $# -eq 3 ]] || usage
cmd="$1"
shift
case "$cmd" in
    stage | manifest | check | compare | rebuild) "$cmd" "$@" ;;
    *) usage ;;
esac
