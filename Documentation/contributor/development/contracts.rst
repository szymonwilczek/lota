.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

=========================
Cross-component contracts
=========================

Surfaces that two components must agree on. Changing one side without the other
ships either a build that fails to link or a mixed-version fleet that silently
stops interoperating.

Attestation report wire format
==============================

The attestation report (``include/attestation.h``, serialized by
``src/agent/report.c``, parsed by ``src/verifier/types/report.go``) ends with
optional variable-length sections. A new trailing section must be appended
after the existing ones and parsed defensively -- absent for older agents -- so
a mixed-version fleet keeps interoperating without a wire-version bump. The
ESRT firmware-version section (``src/agent/esrt.c``, ``test_esrt``) follows
that pattern.

Keep the C serializer and the Go parser in lockstep when the layout changes.

Baseline store migrations
=========================

The verifier's per-client baseline lives in the ``baselines`` table
(``src/verifier/store/db.go``) and evolves through append-only migrations:
never edit a shipped migration, add a new one, so a database at any
intermediate revision still upgrades cleanly.

The ``ReanchorStorer`` interface (``verify/baseline.go``) has three backends
(in-memory, SQLite, Postgres) that must stay behaviourally identical; the
in-memory store is the contract reference exercised by ``boot_baseline_test.go``.

Installer probes and agent gates
================================

The guided installer's stage probes (``installer/probe.c``) must mirror the
agent's startup gates in ``src/agent/bpf_loader.c``. When a gate changes,
change the matching probe and the pinned parser tests in
``tests/test_installer_probe.c`` (part of ``make test-unit``); otherwise the
installer reports a host green that the agent would refuse to run on.
