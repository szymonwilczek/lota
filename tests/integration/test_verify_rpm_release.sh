#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Szymon Wilczek
#
# tests/integration/test_verify_rpm_release.sh
#
# scripts/verify-rpm-release.sh against RPMs built here.
#
# Requires:
#   - rpmbuild, rpm2archive, tar and openssl
#
# Runs unprivileged: the packages are built and unpacked under a temporary
# directory, never installed.

set -euo pipefail

. "$(dirname "$0")/../lib/test.sh"
test_begin "verify rpm release"

export LC_ALL=C

REPO_DIR=$(cd "$(dirname "$0")/../.." && pwd)
TOOL="$REPO_DIR/scripts/verify-rpm-release.sh"

for t in rpmbuild rpm2archive tar openssl; do
    if ! command -v "$t" >/dev/null 2>&1; then
        SKIP "%s is not installed" "$t"
        test_end
    fi
done

WORK=$(mktemp -d)
test_cleanup 'rm -rf -- "$WORK"'

# a payload tree: a tool, a link to it, and a signed object with its key
make_payload() {
    local dir="$1" key="$2"
    mkdir -p "$dir/usr/bin" "$dir/usr/lib/lota"
    printf 'example tool\n' >"$dir/usr/bin/example-tool"
    ln -s example-tool "$dir/usr/bin/example-link"
    printf 'example object\n' >"$dir/usr/lib/lota/lota_lsm.bpf.o"
    sign_payload "$dir" "$key"
}

sign_payload() {
    local dir="$1" key="$2"
    openssl pkey -in "$key" -pubout -out "$dir/usr/lib/lota/enforcement.pub"
    openssl pkeyutl -sign -rawin -inkey "$key" \
            -in "$dir/usr/lib/lota/lota_lsm.bpf.o" \
            -out "$dir/usr/lib/lota/lota_lsm.bpf.o.sig"
}

# build_rpm NAME PAYLOAD OUT_DIR [MODE [POST]]
build_rpm() {
    local name="$1" payload="$2" out="$3" mode="${4:-0755}"
    local post="${5:-echo installed}" top
    top=$(mktemp -d -p "$WORK")
    mkdir -p "$top/SPECS" "$out"
    cat >"$top/SPECS/$name.spec" <<EOF
%global __os_install_post %{nil}
%global debug_package %{nil}
%global _build_id_links none
Name: $name
Version: 1.0
Release: 1
Summary: Example package
License: MIT
BuildArch: noarch

%description
Example package.

%install
cp -a $payload/. %{buildroot}/

%post
$post

%files
%defattr(-,root,root,-)
%attr($mode,root,root) /usr/bin/example-tool
/usr/bin/example-link
/usr/lib/lota
EOF
    rpmbuild -bb --quiet --define "_topdir $top" "$top/SPECS/$name.spec" \
             >"$top/rpmbuild.log" 2>&1 || {
        FAIL "%s" "$(tail -n 20 "$top/rpmbuild.log")"
        exit 1
    }
    cp "$top"/RPMS/noarch/*.rpm "$out/"
}

# expect_check WANT MANIFEST RPM_DIR MESSAGE
expect_check() {
    local want="$1" manifest="$2" dir="$3" rc=0
    TEST "$4"
    "$TOOL" check "$manifest" "$dir" >"$WORK/check.log" 2>&1 || rc=$?
    if [[ "$want" == pass && $rc -ne 0 ]] ||
           [[ "$want" == fail && $rc -eq 0 ]]; then
        FAIL "%s" "$(cat "$WORK/check.log")"
    fi
}

openssl genpkey -algorithm ed25519 -out "$WORK/release.key" 2>/dev/null
openssl genpkey -algorithm ed25519 -out "$WORK/rebuild.key" 2>/dev/null

make_payload "$WORK/payload" "$WORK/release.key"
build_rpm example-agent "$WORK/payload" "$WORK/release"
build_rpm example-sdk "$WORK/payload" "$WORK/release"
"$TOOL" stage "$WORK/release" "$WORK/stage"
"$TOOL" manifest "$WORK/stage" "$WORK/SHA256SUMS-fedora"

TEST "the manifest names each file and header by package"
grep -q 'example-agent-1.0-1.noarch/usr/bin/example-tool$' \
     "$WORK/SHA256SUMS-fedora" &&
     grep -q 'example-agent-1.0-1.noarch.header$' "$WORK/SHA256SUMS-fedora" &&
     ! grep -q 'example-link$' "$WORK/SHA256SUMS-fedora" ||
     FAIL "%s" "$(cat "$WORK/SHA256SUMS-fedora")"
hdr="$WORK/stage/example-agent-1.0-1.noarch.header"
TEST "the header file records the link and the scriptlet"
grep -q '^lrwxrwxrwx root root .* /usr/bin/example-link -> example-tool$' \
     "$hdr" && grep -q '^echo installed$' "$hdr" || FAIL "%s" "$(cat "$hdr")"

expect_check pass "$WORK/SHA256SUMS-fedora" "$WORK/release" \
             "the RPMs the manifest was made from pass"

sleep 1
build_rpm example-agent "$WORK/payload" "$WORK/again"
build_rpm example-sdk "$WORK/payload" "$WORK/again"
expect_check pass "$WORK/SHA256SUMS-fedora" "$WORK/again" \
             "the same packages built again pass"

mkdir -p "$WORK/subset"
cp "$WORK"/release/example-agent-*.rpm "$WORK/subset/"
expect_check pass "$WORK/SHA256SUMS-fedora" "$WORK/subset" \
             "a directory with one of the packages passes"

cp -a "$WORK/payload" "$WORK/byte"
printf 'example tool!\n' >"$WORK/byte/usr/bin/example-tool"
build_rpm example-agent "$WORK/byte" "$WORK/byte-rpm"
expect_check fail "$WORK/SHA256SUMS-fedora" "$WORK/byte-rpm" \
             "one changed byte in a file fails"

mkdir -p "$WORK/torn"
head -c 2000 "$WORK"/release/example-agent-*.rpm \
     >"$WORK/torn/example-agent-1.0-1.noarch.rpm"
TEST "an RPM that does not unpack fails with a FAIL line"
if "$TOOL" check "$WORK/SHA256SUMS-fedora" "$WORK/torn" \
           >"$WORK/check.log" 2>&1 ||
           ! grep -q '^FAIL: .* does not unpack$' "$WORK/check.log"; then
    FAIL "%s" "$(cat "$WORK/check.log")"
fi

build_rpm example-agent "$WORK/payload" "$WORK/mode-rpm" 4755
expect_check fail "$WORK/SHA256SUMS-fedora" "$WORK/mode-rpm" \
             "a changed file mode fails"

build_rpm example-agent "$WORK/payload" "$WORK/post-rpm" 0755 'echo other'
expect_check fail "$WORK/SHA256SUMS-fedora" "$WORK/post-rpm" \
             "a changed scriptlet fails"

mkdir -p "$WORK/extra"
cp "$WORK"/release/*.rpm "$WORK/extra/"
build_rpm example-other "$WORK/payload" "$WORK/extra"
expect_check fail "$WORK/SHA256SUMS-fedora" "$WORK/extra" \
             "a package the manifest does not name fails"

cp -a "$WORK/payload" "$WORK/badsig"
printf 'example object!\n' >"$WORK/badsig/usr/lib/lota/lota_lsm.bpf.o"
build_rpm example-agent "$WORK/badsig" "$WORK/badsig-rpm"
"$TOOL" stage "$WORK/badsig-rpm" "$WORK/badsig-stage"
"$TOOL" manifest "$WORK/badsig-stage" "$WORK/badsig.sums"
expect_check fail "$WORK/badsig.sums" "$WORK/badsig-rpm" \
             "a bad signature fails, even in its own manifest"

cp -a "$WORK/payload" "$WORK/rebuild"
sign_payload "$WORK/rebuild" "$WORK/rebuild.key"
build_rpm example-agent "$WORK/rebuild" "$WORK/rebuild-rpm"
build_rpm example-sdk "$WORK/rebuild" "$WORK/rebuild-rpm"
"$TOOL" stage "$WORK/rebuild-rpm" "$WORK/rebuild-stage"
"$TOOL" manifest "$WORK/rebuild-stage" "$WORK/rebuild.sums"
TEST "compare accepts a rebuild signed with another key"
"$TOOL" compare "$WORK/SHA256SUMS-fedora" "$WORK/rebuild.sums" \
        >"$WORK/compare.log" 2>&1 || FAIL "%s" "$(cat "$WORK/compare.log")"
expect_check fail "$WORK/SHA256SUMS-fedora" "$WORK/rebuild-rpm" \
             "check refuses the rebuild's own signature and key"

sign_payload "$WORK/byte" "$WORK/rebuild.key"
build_rpm example-agent "$WORK/byte" "$WORK/rebuild-byte-rpm"
build_rpm example-sdk "$WORK/rebuild" "$WORK/rebuild-byte-rpm"
"$TOOL" stage "$WORK/rebuild-byte-rpm" "$WORK/rebuild-byte-stage"
"$TOOL" manifest "$WORK/rebuild-byte-stage" "$WORK/rebuild-byte.sums"
TEST "compare refuses a rebuild with one changed byte"
"$TOOL" compare "$WORK/SHA256SUMS-fedora" "$WORK/rebuild-byte.sums" \
        >"$WORK/compare.log" 2>&1 && FAIL "%s" "$(cat "$WORK/compare.log")"

test_end
