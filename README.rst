.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

==============================
Linux Open Trusted Attestation
==============================

Linux Open Trusted Attestation, or LOTA, is a Linux attestation and
runtime-integrity framework.

It lets a remote verifier or game server decide whether a host was enrolled
through a manufacturer-backed TPM, booted into an approved firmware and Secure
Boot state, runs the expected LOTA agent image, and enforces the configured
runtime gates through BPF LSM.

LOTA is not an anti-cheat engine. It is a hardware-backed trust substrate that
game, anti-cheat and fleet policy can build on.

Trust chain overview
====================

The production trust chain is::

    TPM 2.0 EK certificate -> Attestation CA (1) -> LOTA agent (2) -> Verifier / SDK consumer (3)

    (1) Attestation CA
      - verifies EK roots
      - runs TPM2 credential activation
      - issues an AIK certificate

    (2) LOTA agent
      - owns TPM interaction
      - measures boot and runtime state
      - loads signed BPF LSM policy

    (3) Verifier or SDK consumer
      - checks AIK certificate trust
      - verifies TPM quote freshness
      - enforces PCR, boot, runtime, and token policy

The verifier trusts a CA-issued AIK certificate, not an agent-asserted public
key. Firmware and Secure Boot state are pinned through PCR 0, PCR 1, and PCR 7.
LOTA's own boot commitment is bound through PCR14. Runtime protection is
enforced by the agent and BPF LSM hooks, with fs-verity, SELinux, lockdown,
module signing, and signed BPF objects forming the production floor.

For the complete security boundary, read
`Documentation/security/threat-model.rst
<Documentation/security/threat-model.rst>`_.

Quick start
===========

* Install LOTA on your PC: see
  `Documentation/player/index.rst <Documentation/player/index.rst>`_
* Bring up a production host: see
  `Documentation/operator/production-bringup/index.rst
  <Documentation/operator/production-bringup/index.rst>`_
* Build the tree: ``make all``
* Report a vulnerability: see `SECURITY.md <SECURITY.md>`_
* Contribute a patch: see `CONTRIBUTING.rst <CONTRIBUTING.rst>`_

Documentation
=============

The documentation, organised by reader role, is at
https://lota.szymon-wilczek.me and under
`Documentation/ <Documentation/index.rst>`_.

Licensing
=========

Userspace is MIT (`LICENSE <LICENSE>`_). BPF programs are GPL-2.0-only
(`LICENSE.GPL-2.0-only <LICENSE.GPL-2.0-only>`_). Every source file carries an
``SPDX-License-Identifier`` naming the license that applies to it.
