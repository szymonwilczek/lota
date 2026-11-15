.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

======================
Continuous integration
======================

The workflows live in ``.github/workflows/``. Every job runs on a GitHub
hosted x86_64 runner, some of them inside a container image pinned by
digest. Most jobs call the same ``make`` target a contributor runs locally,
so a failure reproduces with the command named below.

Triggers
========

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Workflow
     - Runs on
   * - ``ci.yml``, ``c-static-analysis.yml``, ``go-static-analysis.yml``,
       ``security-analysis.yml``, ``reproducible-builds.yml``,
       ``systemd-validate.yml``
     - every pull request, whatever its base, and every push to ``main``
       or ``lota-next``
   * - ``docs.yml``
     - a pull request or a push to ``main`` or ``lota-next`` that touches
       ``Documentation/``, ``include/``, the license-boundary script, the
       kernel-doc warning test or the workflow itself
   * - ``packages.yml``
     - a pull request that touches ``packaging/``, ``deploy/helm/``,
       ``deploy/observability/``, ``Makefile``, ``src/``, ``include/`` or
       the workflow; every push to ``lota-next``;
       a manual dispatch
   * - ``pr-quality.yml``
     - a pull request being opened, reopened, edited or pushed to
   * - ``pr-router.yml``
     - a pull request opened or reopened against ``main``
   * - ``docs-deploy.yml``
     - a push to ``main`` or ``lota-next``, a ``v*`` tag, a manual dispatch
   * - ``release.yml``
     - a ``v*`` tag
   * - ``notify-fuzz.yml``
     - a push to ``lota-next``

Build and tests
===============

``ci.yml`` holds the C build, the tests and the tree gates. Each job is
independent; only ``examples`` waits for ``build``.

``build``
  ``make all`` and ``make test-unit`` on Ubuntu 22.04 and 24.04, with
  ``CLANG=clang-22`` and libbpf built from source.

``fedora-build``
  ``make all`` and ``make test-unit`` in Fedora 43 and 44 containers,
  against the distribution libbpf.

``examples``
  ``make all examples``, a dry run of ``examples/demo/setup.sh``, the CI
  release gate example end to end (``examples/ci-gate/run.sh``) and a check
  that the block demo artifacts were built.

``sanitizers`` and its variants
  ``make SANITIZE=address,undefined test-unit`` under gcc
  (``sanitizers``) and under clang (``sanitizers-clang``),
  ``make SANITIZE=thread test-unit`` (``sanitizers-thread``), and on
  Fedora 43 and 44 the address and undefined run followed by
  ``make valgrind-unit`` (``sanitizers-fedora``).

``sanitizers-full-build``
  ``make CC=clang sanitizer-build``, which builds ``all``, the examples,
  ``bench_sdk``, ``lota-bench`` and the syzkaller loader under ASan and
  UBSan without running them.

``valgrind``, ``valgrind-smoke``
  ``make valgrind-unit`` and ``make valgrind-smoke``.

``benchmarks``
  ``make bench-c`` and one iteration of ``make bench-go``, to catch a
  benchmark that no longer builds.

``fuzz``
  ``make fuzz-regress``, replaying the committed reproducers
  (:doc:`fuzzing`).

:doc:`testing` describes the targets these jobs call.

Tree gates
==========

Also in ``ci.yml``, each a single ``make`` target or script:

* ``format``: ``clang-format-22 --dry-run --Werror`` over every ``.c`` and
  ``.h`` under ``src/``, ``include/`` and ``tests/`` except ``vmlinux.h``,
* ``include-hygiene``: ``make check-includes``,
* ``player-build``: ``scripts/check-player-build.sh`` in a Fedora 44
  container,
* ``package-manifests``: ``make check-package-manifests``,
* ``abi``: ``make check-abi``,
* ``doc-references``: ``make check-doc-references``,
* ``doc-diagnostics``: ``make check-doc-diagnostics`` and
  ``make check-config-commands``,
* ``syzkaller-matrix``, ``header-paths``, ``test-build-dir``,
  ``license-boundary``: the ``make check-*`` target of the same name,
* ``shellcheck``: ``shellcheck -S error`` over two fixed lists of scripts
  and integration tests, one with ``-s bash`` and one with ``-s sh``,
* ``yamllint``: ``policies/``, ``.github/``, ``.golangci.yml`` and
  ``.yamllint`` against ``.yamllint``,
* ``clang-analyzer``: ``scan-build --status-bugs`` over the ``make``
  targets ``test-unit`` (which builds ``all`` first), ``examples``,
  ``syzkaller-fuzz-loader`` and the ``bench_sdk`` file in its build
  directory, excluding ``src/bpf/`` and ``include/vmlinux.h``.

:doc:`testing` and :doc:`../process/patch-checks` describe what each gate
enforces.

BPF object
==========

Both jobs run in a Fedora 44 container and build the object with
``make bpf``.

``bpf-veristat``
  Links the object with ``bpftool gen object`` and runs
  ``scripts/veristat-gate.sh`` inside a virtme-ng guest booted with the
  container's newest kernel and ``lsm=bpf``. Without ``/dev/kvm`` the guest
  runs under TCG.

``bpf-elf-inspect``
  Fails unless the object is a BPF ELF with ``lsm/`` program sections, a
  ``license`` section, a ``.maps`` section and a BTF that dumps as C.

C static analysis
=================

``c-static-analysis.yml`` runs ``make sparse`` followed by
``make check-stack-frames``, ``make coccicheck``, and ``make smatch``
against smatch built from source.

Go
==

Every Go job installs the newest ``1.26.x`` toolchain. The modules declare
``go 1.25.8`` and no ``toolchain`` directive, so the installed toolchain
builds them; only the steps that install ``go-licenses``, ``gosec`` and
``govulncheck`` set ``GOTOOLCHAIN=auto``. A ``go`` directive bump changes
every ``go.mod`` and ``go.work`` together.

``src/crl`` is a module shared by the verifier and the attestation CA.
Both ``go.mod`` files replace it with the in-tree path, so it is never
fetched and needs no version tag.

``go-static-analysis.yml``:

``golangci-lint``
  Fails when ``go mod tidy`` changes a ``go.mod`` or ``go.sum`` in
  ``src/verifier``, ``src/attestca``, ``sdk/server``, ``src/crl`` or
  ``src/fleetctl``. Runs ``go test ./...`` in ``src/verifier``,
  ``src/attestca``, ``src/crl`` and ``src/fleetctl``, then golangci-lint
  v2.12.2 in those four modules, ``sdk/server``, ``examples/demo_server``
  and ``examples/ci-gate/gate``.

``pkcs11-softhsm``
  Initialises a SoftHSM token and runs ``TestPKCS11SignerIssuesAIK`` in
  ``src/attestca`` with ``-tags pkcs11``. That tag is the only build that
  carries the PKCS#11 signer; the default build is pure Go.

``go-coverage``
  ``scripts/check-go-coverage.sh`` with a Postgres service, so the
  ``pg_integration`` packages are measured as well.

``postgres-integration``
  ``go test -tags pg_integration -p 1`` over ``./store/`` and ``./verify/``
  in ``src/verifier`` against a Postgres service.

``go-licenses``
  ``go-licenses check`` in every Go module except ``src/crl``. Allowed:
  MIT, BSD-3-Clause, BSD-2-Clause, Apache-2.0, ISC and MPL-2.0. The
  project's own packages and ``modernc.org/mathutil`` are ignored.

Security analysis
=================

``security-analysis.yml``:

``codeql``
  C and Go databases with the ``security-extended`` and
  ``security-and-quality`` suites and ``.github/codeql/codeql-config.yml``.
  The C database is built from the same targets as ``clang-analyzer``,
  the Go database by ``go test ./...`` in the modules gosec scans.

``actionlint``, ``zizmor``
  Lint the workflow files.

``gosec``
  gosec v2.27.1 at ``-severity=low`` in ``src/verifier``,
  ``src/attestca``, ``sdk/server``, ``src/crl``, ``examples/demo_server``
  and ``src/fleetctl``, with G104, G304 and G115 excluded.

``trivy-deps``
  A filesystem vulnerability scan. Every severity is uploaded to code
  scanning; a HIGH or CRITICAL finding with a fix available fails the job.

``govulncheck``
  govulncheck v1.1.4 in the same modules as gosec. It fails only when the code
  reaches a vulnerable symbol, including one in the standard library of the
  toolchain the job installed.

Reproducibility and units
=========================

``reproducible-builds.yml`` runs ``make reproducible-build`` in two copies
of the tree, one with ``TZ=UTC`` and one with ``TZ=Asia/Tokyo``, and
compares the agent, verifier, attestation CA, ``lota-pcr14-lock``, the four
shared libraries and the BPF object byte for byte. A missing or differing
artifact fails the job; diffoscope reports for the differences are uploaded.
:doc:`../security/reproducible-builds` covers verifying a release.

``systemd-validate.yml`` runs ``systemd-analyze verify`` on the agent's
service and socket units, against a stub ``/usr/bin/lota-agent``, and
``udevadm verify`` on ``configs/udev/99-lota-tpm.rules``.

Documentation
=============

``docs.yml`` checks the license boundary of the documentation packages,
then runs ``make -C Documentation lint``, ``html``, the kernel-doc warning
test and ``linkcheck``. ``docs-deploy.yml`` publishes the site
(:doc:`../process/branching`).

Packages
========

``packages.yml``:

``rpms``
  In a Fedora 44 container: ``make all``, an ephemeral enforcement key from
  ``lota-agent --gen-signing-key``, ``make sign-bpf`` and ``make packages``.

``helm``
  ``make helm-lint`` and ``make helm-template``.

``observability``
  ``make observability-lint``.

``images``
  ``make container-images``.

Pull request automation
=======================

``pr-quality.yml`` runs ``scripts/check-pr-quality.sh --pr-diff`` over the
pull request range (:doc:`../process/patch-checks`) and adds the
``AI-Assisted`` label when the check reports AI-assisted commits.

``pr-router.yml`` retargets a pull request opened against ``main`` to
``lota-next`` and comments why, unless the author is the maintainer or a
bot.

Release and fuzzing hosts
=========================

``release.yml`` runs on a ``v*`` tag (:doc:`../process/branching`).

``notify-fuzz.yml`` posts the pushed commit to a notification topic, so the
host that runs the long Go fuzzing campaigns moves to the new
``lota-next`` tip. Kernel fuzzing with syzkaller runs outside GitHub
Actions (:ghsrc:`syzkaller/README.rst`).
