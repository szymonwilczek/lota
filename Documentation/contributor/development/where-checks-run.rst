.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

====================
Where the checks run
====================

* **Every pull request** (the ``pull_request`` trigger has no branch filter, so
  it covers PRs aimed at ``lota-next``): build, unit tests, linters, Go static
  analysis, cross-arch build, the reproducible-build gate and security
  analysis.
* **Cross-architecture build**: the arm64 workflow starts on every pull
  request, but skips QEMU and the arm64 container when the commit range does
  not change source, build, BPF, policy, or deployment inputs.
* **Every push to** ``lota-next``: the same workflows run on the branch tip, so
  the integration line is continuously built and fuzzed.
* **Out of band**: Syzkaller fuzzes the BPF LSM / kernel surface against
  ``lota-next`` (configured separately, not in ``.github/workflows``).
* **Continuous external fuzzing**: a push to ``lota-next`` also fires the
  ``notify-fuzz`` workflow, which posts to an ``ntfy.sh`` topic so a standalone
  host running the Go fuzz targets resyncs to the new tip at once.

Go toolchain and dependencies
=============================

Every module and the workspace pin the same ``go`` directive (``1.25.8``) and
carry **no** ``toolchain`` directive, so the system or CI Go selects the build
(``go-version-file`` plus ``GOTOOLCHAIN=auto`` on the runners). Bump the
directive across all modules and ``go.work`` together, and refresh module
dependencies in the same change, so the graph stays consistent.

``src/crl`` is a dependency-free library module shared by the verifier (AIK
revocation feed) and the attestation CA (EK manufacturer revocation feed).

Both consumers' ``go.mod`` carry a ``replace`` directive pointing at the
in-repo path, so the module is never fetched from a proxy, needs no version
tags, and a change under ``src/crl`` rebuilds both binaries (the Makefile lists
it in their prerequisites). The govulncheck job pins an explicit patched
``1.25.x`` because it reports against the toolchain standard library, not the
directive. golangci-lint runs at v2 (``.golangci.yml`` carries
``version: "2"``).

``lota-attest-ca`` has an optional PKCS#11 build for an HSM-backed CA signing
key: ``make attest-ca GO_TAGS=pkcs11`` (or ``go build -tags pkcs11``) compiles
in the ``crypto11`` dependency and needs cgo plus a PKCS#11 module. The default
build is pure-Go and carries no PKCS#11 code, so the reproducible build and the
standard binary are unaffected. The ``pkcs11-softhsm`` job in
``go-static-analysis.yml`` exercises that path against SoftHSM on every PR.
