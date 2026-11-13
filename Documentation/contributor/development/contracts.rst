.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

=========================
Cross-component contracts
=========================

Surfaces that two components must agree on. Changing one side without the other
ships either a build that fails to link or a mixed-version fleet that silently
stops interoperating.

Installer probes and agent gates
================================

The guided installer's stage probes (``installer/probe.c``) must mirror the
agent's startup gates in ``src/agent/bpf_loader.c``. When a gate changes,
change the matching probe and the pinned parser tests in
``tests/test_installer_probe.c`` (part of ``make test-unit``); otherwise the
installer reports a host green that the agent would refuse to run on.
