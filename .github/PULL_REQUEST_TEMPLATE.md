<!--
Title: bare-prefix subject, no Conventional-Commit parentheses.

Use module prefix (agent:, verifier:, attestca:, fleetctl:, bpf:)
or type prefix (feat:, fix:, docs:, ci:, build:).
Never fix(agent:) or feat(ca):.

Open against lota-next, not main.
Delete any section below that genuinely does not apply; do not leave it blank.
-->

## Problem

What is wrong or missing, and why it matters.

## Solution

The approach, in prose. Add one `## <Area>` section per touched surface
(for example `## Verifier`, `## Agent`, `## CA`, `## CLI`, `## Build and CI`)
describing what changed there.

## Docs

Documentation updated for the changed behavior (CLI flags, policy syntax, IPC
wire format, systemd units, SELinux labels, SDK APIs, verifier config), or
`N/A - no external contract changed`.

## Tests

What was added and run. If runtime validation needs operator hardware (TPM,
UEFI+SB), say so and describe what was exercised.

## Security boundary

Effect on the production security contract - attestation chain, TPM enrollment,
verifier policy, BPF LSM enforcement, SELinux confinement, release integrity,
SDK token validation - or `No trust-boundary change`.

---

- [ ] Opened against `lota-next`.
- [ ] Commits are DCO signed-off (`git commit -s`) and GPG/SSH signed.
- [ ] No generated build artifacts, private operator files, local logs, TPM state, or credentials.
