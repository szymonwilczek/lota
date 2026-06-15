.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

===============
Security Policy
===============

LOTA is security-sensitive infrastructure. Reports that affect the attestation
chain, TPM enrollment, verifier policy, BPF LSM enforcement, release integrity,
or SDK token validation should use a private channel.

Supported versions
==================

Before the first stable release, security fixes land on ``lota-next`` and are
included in the next release candidate. After a stable release, supported
versions are listed in the release notes for that series.

Reporting a vulnerability
=========================

Preferred encrypted channel:

* GitHub Private Vulnerability Reporting for ``github.com/szymonwilczek/lota``.

Fallback encrypted channel:

* Email: ``swilczek.lx@gmail.com``
* GPG fingerprint: ``3EE5 3281 2DF0 F36A B7A1 F178 B8E9 4407 1CB7 EB8A``

Reports should include:

* affected component and version or commit,
* reproduction steps or a minimal proof of impact,
* expected and observed security boundary,
* relevant logs, crash traces, attestation reports, tokens, or policy files,
* whether the report is already shared with another party.

Do not file public issues for exploitable vulnerabilities until the issue is
triaged and disclosure is coordinated.

Response targets
================

The project targets this response process:

* acknowledge receipt within 72 hours,
* complete initial triage within 72 hours after enough detail is available,
* target a fix for critical vulnerabilities within 14 calendar days after
  reproduction,
* coordinate disclosure timing with the reporter when a public advisory is
  required.

These targets can change when a report needs hardware TPM validation, vendor
coordination, or a downstream release embargo.

Disclosure handling
===================

Security fixes are reviewed on private branches when public review would expose
an active exploit. Public commits should describe the functional fix without
publishing exploit details before the advisory date.

When the issue affects a released artifact, the maintainer (Szymon Wilczek)
publishes a GitHub Security Advisory and a signed release artifact manifest.
See `reproducible-builds.rst <reproducible-builds.rst>`_ for release artifact
verification.

Security scope
==============

In scope:

* TPM 2.0 credential activation and AIK certificate issuance,
* EK root validation and pinning,
* TPM quote, nonce, PCR, boot-commitment, and event-log verification,
* runtime protection digest and SDK token verification,
* BPF LSM enforcement, signed BPF object loading, and fs-verity gates,
* SELinux policy and systemd hardening that protect the LOTA agent,
* reproducible build and release signing paths.

Out of scope for this repository:

* generic game-cheat behavior detection,
* kernel vulnerabilities outside the LOTA BPF LSM surface,
* distribution packaging not produced from this repository,
* operator policy choices that intentionally disable required production gates.
