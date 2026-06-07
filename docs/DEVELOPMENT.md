# Developer & testing policy

All new work lands on the **`lota-next`** integration branch first. `main`
carries only stable, released code. See [BRANCHING.md](BRANCHING.md) for the
full model and the release flow.

## Where the checks run

- **Every pull request** (the `pull_request` trigger has no branch filter, so
  it covers PRs aimed at `lota-next`): build, unit tests, linters, Go static
  analysis, cross-arch build, the reproducible-build gate, security analysis,
  and the Go fuzz targets (short, seeded smoke run).
- **Cross-architecture build**: the arm64 workflow starts on every pull
  request, but skips QEMU and the arm64 container when the commit range does
  not change source, build, BPF, policy, or deployment inputs.
- **Every push to `lota-next`**: the same workflows run on the branch tip, so
  the integration line is continuously built and fuzzed.
- **Out of band**: Syzkaller fuzzes the BPF LSM / kernel surface against
  `lota-next` (configured separately, not in `.github/workflows`).
- **Continuous external fuzzing**: a push to `lota-next` also fires the
  `notify-fuzz` workflow, which posts to an `ntfy.sh` topic so a standalone
  host running the Go fuzz targets resyncs to the new tip at once.

## Go toolchain and dependencies

Every module and the workspace pin the same `go` directive (`1.25.8`) and
carry **no** `toolchain` directive, so the system or CI Go selects the
build (`go-version-file` plus `GOTOOLCHAIN=auto` on the runners). Bump the
directive across all modules and `go.work` together, and refresh module
dependencies in the same change, so the graph stays consistent. The
govulncheck job pins an explicit patched `1.25.x` because it reports against
the toolchain standard library, not the directive. golangci-lint runs at v2
(`.golangci.yml` carries `version: "2"`).

`lota-attest-ca` has an optional PKCS#11 build for an HSM-backed CA signing
key: `make attest-ca GO_TAGS=pkcs11` (or `go build -tags pkcs11`) compiles
in the `crypto11` dependency and needs cgo plus a PKCS#11 module. The
default build is pure-Go and carries no PKCS#11 code, so the reproducible
build and the standard binary are unaffected. The `pkcs11-softhsm` job in
`go-static-analysis.yml` exercises that path against SoftHSM on every PR.

## Testing policy

| Layer | What | How |
|-------|------|-----|
| Unit | Go (`verifier`, `attestca`, `sdk/server`) and C (agent, SDK) | `make test-unit`, `go test ./...` |
| Sanitizers | ASan / UBSan on the C side | `SANITIZE=address,undefined make test-unit` |
| Memory | valgrind memcheck | `make valgrind-unit`, `make valgrind-smoke` |
| Fuzz (Go) | verifier / SDK / attest-CA parsers of untrusted bytes | `go test -run x -fuzz=Fuzz... ./...`; CI runs every target per PR |
| Fuzz (C) | IPC, config, TLS-pin, wire, enrollment-reply decoders, sealed-envelope parser/AEAD, TPM attest unmarshal, policy signature verify | `make fuzz-all` |
| Kernel | BPF LSM live in a guest | Syzkaller harness `lota_bpf_fuzz` (see `syzkaller/README.md`) |
| Repro | bit-for-bit build | `make reproducible-build`; gated in CI |

A fuzz crash leaves a reproducer under `testdata/fuzz/<Target>/`. Commit it so the regression is locked in.

## Local patch checks

Contributors can run `scripts/check-patch [<base> [<head>]]` before pushing a
branch. The script reports each check with `PASS` or `FAIL` and includes a
suggested fix for failures. It validates commit message shape, DCO trailers,
message and patch whitespace, clang-format, gofmt, the full build, and the same
hotpath documentation policy enforced by CI.

Commit body headings must use standalone `Problem:` and `Solution:` lines, with
the explanatory text starting on the next line. Body text is wrapped to 75
columns, with a two-column tolerance when the final word reaches column 76 or
77. The DCO `Signed-off-by` trailer must be separated from the description by
one blank line.

The local hotpath check delegates to `scripts/check-pr-quality.sh`, using the
same `.github/pr-quality-hotpaths.txt` manifest as the `PR quality` workflow.
This keeps local contributor feedback aligned with the server-side gate.

Use `scripts/format-patch [<base> [<head>]]` only to normalize local commit
messages before pushing. It rewrites commits in `base..head` to remove trailing
spaces, trailing tabs, and blank lines after the final content line. It does not
change file trees. It also fixes simple inline `Problem:` and `Solution:`
headings, inserts the required blank line before `Signed-off-by`, wraps body
paragraphs, and tells the developer to review the rewritten descriptions. The
script requires a clean index and working tree, refuses merge commits, and
creates a backup branch before updating the current branch.

## Pull request quality gate

The `PR quality` workflow checks commit metadata and the aggregate pull request
diff before the build matrix runs:

- every non-merge commit created on top of a tree that already carries the
  quality gate must carry a DCO `Signed-off-by` trailer,
- commits with AI assistant co-author or generator trailers are labeled
  `AI-Assisted`,
- a pull request that changes a hotpath file must update one of the documented
  companion files in the same pull request diff.

The hotpath-to-documentation contract is versioned in
[`.github/pr-quality-hotpaths.txt`](../.github/pr-quality-hotpaths.txt).
It intentionally keys off critical surfaces rather than commit size: TPM
enrollment, verifier policy, BPF LSM enforcement, SDK token formats,
deployment policy, CI, build, and release process.

Scripts are split by audience: developer-workflow tooling (`check-*`,
`format-patch`, the CI gate scripts) maps to the contributor docs above,
while operator provisioning and host bring-up scripts (`lota-*`,
`setup-fsverity.sh`) are deployment steps and map to the operator-facing
[`PRODUCTION_BRINGUP.md`](PRODUCTION_BRINGUP.md) and the relevant example
READMEs instead.

Module and workspace manifests (`go.mod`, `go.sum`, `go.work`) map to this
file rather than a runtime surface: a dependency or Go-directive change is a
contributor concern, not a trust-model or integrator-contract change, so a
dependency refresh does not drag in a security-doc edit.

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
