# Developer & testing policy

All new work lands on the **`lota-next`** integration branch first. `main`
carries only stable, released code. See [BRANCHING.md](BRANCHING.md) for the
full model and the release flow.

## Where the checks run

- **Every pull request** (the `pull_request` trigger has no branch filter, so
  it covers PRs aimed at `lota-next`): build, unit tests, linters, Go static
  analysis, cross-arch build, the reproducible-build gate, security analysis,
  and the Go fuzz targets (short, seeded smoke run).
- **Every push to `lota-next`**: the same workflows run on the branch tip, so
  the integration line is continuously built and fuzzed.
- **Out of band**: Syzkaller fuzzes the BPF LSM / kernel surface against
  `lota-next` (configured separately, not in `.github/workflows`).

## Testing policy

| Layer | What | How |
|-------|------|-----|
| Unit | Go (`verifier`, `attestca`, `sdk/server`) and C (agent, SDK) | `make test-unit`, `go test ./...` |
| Sanitizers | ASan / UBSan on the C side | `SANITIZE=address,undefined make test-unit` |
| Memory | valgrind memcheck | `make valgrind-unit`, `make valgrind-smoke` |
| Fuzz (Go) | verifier / SDK / attest-CA parsers of untrusted bytes | `go test -run x -fuzz=Fuzz... ./...`; CI runs every target per PR |
| Fuzz (C) | IPC, config, TLS-pin, wire decoders | `make fuzz-all` |
| Kernel | BPF LSM live in a guest | Syzkaller harness `lota_bpf_fuzz` (see `syzkaller/README.md`) |
| Repro | bit-for-bit build | `make reproducible-build`; gated in CI |

A fuzz crash leaves a reproducer under `testdata/fuzz/<Target>/`. Commit it so the regression is locked in.

## Pull request quality gate

The `PR quality` workflow checks each commit in a pull request before the
build matrix runs:

- every commit must carry a DCO `Signed-off-by` trailer,
- commits with AI assistant co-author or generator trailers are labeled
  `AI-Assisted`,
- a commit that changes a hotpath file must update one of the documented
  companion files in the same commit.

The hotpath-to-documentation contract is versioned in
[`.github/pr-quality-hotpaths.txt`](../.github/pr-quality-hotpaths.txt).
It intentionally keys off critical surfaces rather than commit size: TPM
enrollment, verifier policy, BPF LSM enforcement, SDK token formats,
deployment policy, CI, build, and release process.

## How the fuzzers work

- **Go fuzzing** is native (`func FuzzXxx(f *testing.F)`). Targets cover the
  bytes that arrive from an untrusted peer: attestation tokens, TPM
  quote/attest blobs, event logs, certificates, signed policies, and the
  enrollment wire protocol. Each target seeds from its own encoder and asserts
  the real contract. CI discovers the targets and shards them across runners,
  so wall-clock stays bounded as targets are added.
- **C fuzzers** are libFuzzer harnesses built by `make fuzz-*`.
- **Syzkaller** loads the production BPF LSM object and attaches every hook in
  enforce mode inside a guest, so `syz-executor`'s syscalls actually traverse
  the LOTA kernel surface (MODE A). It runs against `lota-next`.

## Release candidates

Tagging releases is a maintainer action; contributors do not push tags. For
context, this is how a candidate is cut on `lota-next`:

- The tag sits on a single commit that changes only `VERSION`.
- `release.yml` builds reproducibly, signs `SHA256SUMS` with cosign keyless,
  and -- because the tag is `0.x` or carries a `-` suffix -- marks the GitHub
  release as a **pre-release**.
- Candidates iterate `-rc1`, `-rc2`, ... until one is stable.

## Promotion to `main`

When a candidate is stable, the maintainer -- `@szymonwilczek` -- promote `lota-next`
to `main` through a pull request merged as a **merge commit** (no squash, no rebase),
then tag the stable release (`vX.0.0`) on `main`.

See [BUILD-REPRODUCIBLE.md](BUILD-REPRODUCIBLE.md) for how a tag is built and
signed and how to verify it yourself.
