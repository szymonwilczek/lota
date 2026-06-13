# Reproducible builds

LOTA is part of an anti-cheat trust chain, so it must be provable -- not assumed --
that a shipped `lota-agent` is the one built from its tagged source. Every release
is built reproducibly and its artifact hashes are signed, so anyone can rebuild a
tag and confirm the bytes match what the project shipped.

## What makes the build reproducible

The build output depends only on the source tree, not on where or when it was
built:

- **C and BPF** are compiled with `-ffile-prefix-map=$(CURDIR)=.`, so the
  absolute build directory is not embedded in DWARF (`DW_AT_comp_dir`) or
  `__FILE__`.
- **Go** (`lota-verifier`, `lota-attest-ca`) is built with `-trimpath`, which
  strips the module and build paths the toolchain would otherwise bake in.
- `make reproducible-build` pins the remaining environmental inputs:
  `SOURCE_DATE_EPOCH` (default: the HEAD commit time), `TZ=UTC` and `LC_ALL=C`.

These flags are always ON for every build. `make reproducible-build` only adds
the timestamp/timezone/locale pins. CI rebuilds the tree twice, from different
paths and under different time zones, and fails if any artifact differs
(`.github/workflows/reproducible-builds.yml`).

### Toolchain

Bit-for-bit equality holds for a given toolchain. The canonical toolchain is the
one in CI: `ubuntu-24.04` with its `clang`/`llvm` and `gcc`, Go pinned by
`src/verifier/go.mod`, and `libbpf v1.4.6`. A different compiler version can
produce a different (still correct) binary; match the toolchain to match the
bytes.

## Reproduce a release

```sh
git checkout vX.Y.Z          # the released tag
make reproducible-build      # builds into ./build
cd build && sha256sum -- \
  lota-agent lota-install lota-verifier lota-attest-ca lota-pcr14-lock \
  liblotagaming.so liblotaserver.so liblota_wine_hook.so \
  liblota_anticheat.so lota_lsm.bpf.o
```

Compare the hashes against the `SHA256SUMS` attached to the release. Or, with
the release's `SHA256SUMS` next to the rebuilt artifacts:

```sh
sha256sum -c SHA256SUMS
```

## Verify the signature

The release `SHA256SUMS` is signed with cosign keyless (Sigstore). The
`SHA256SUMS.cosign.bundle` carries the ephemeral certificate and the Rekor
transparency-log proof, so no key distribution is needed -- only the workflow
identity and the OIDC issuer:

```sh
cosign verify-blob \
  --bundle SHA256SUMS.cosign.bundle \
  --certificate-identity-regexp \
    '^https://github\.com/szymonwilczek/lota/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  SHA256SUMS
```

A valid signature proves the manifest -- and therefore every artifact whose hash
it lists -- was produced by the release workflow at a `v*` tag. Verify the
signature first, then check the artifact hashes against the manifest.

## Scope

The signed manifest covers the binaries and shared libraries plus the BPF
object. The detached BPF signature (`lota_lsm.bpf.o.sig`) is produced by the
operator's own signing key at deploy time (`make sign-bpf`), not by the release
workflow, so it is not part of the release manifest.
