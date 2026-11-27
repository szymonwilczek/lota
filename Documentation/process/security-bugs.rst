.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

=============
Security bugs
=============

A suspected vulnerability in LOTA is reported privately, never in a public
issue, pull request or review comment. This covers the attestation chain,
TPM enrollment, verifier policy, BPF LSM enforcement, release integrity and
SDK token validation, and any other path listed under `Scope`_.

Contact
=======

The primary channel is GitHub Private Vulnerability Reporting for
``github.com/szymonwilczek/lota``. It opens a private security advisory
visible only to the reporter and the maintainer. The new-issue chooser
links it as **Private Security Reporting**.

When that channel is not available, send the report by encrypted email:

* Email: ``swilczek.lx@gmail.com``
* GPG fingerprint: ``3EE5 3281 2DF0 F36A B7A1 F178 B8E9 4407 1CB7 EB8A``

What to include
===============

* the affected component, and the version or commit,
* reproduction steps or a minimal proof of impact,
* the security boundary expected and the one observed,
* the relevant logs, crash traces, attestation reports, tokens or policy
  files,
* whether the report has been shared with anyone else.

Response
========

The maintainer:

* acknowledges a report within 72 hours,
* completes the initial triage within 72 hours of enough detail being
  available,
* aims to fix a critical vulnerability within 14 calendar days of
  reproducing it,
* agrees the disclosure date with the reporter when a public advisory is
  needed.

A report that needs validation on a hardware TPM, coordination with a
vendor, or a downstream release embargo can take longer.

Disclosure
==========

A fix whose public review would expose an active exploit is reviewed on a
private branch. Until the advisory date, its public commits describe the
functional change and carry no exploit details.

When the vulnerability affects a released artifact, the maintainer publishes
a GitHub security advisory and a release whose ``SHA256SUMS`` manifest is
signed with cosign. :doc:`../security/reproducible-builds` describes how to
verify the artifacts against it.

Supported versions
==================

While every release is published as a pre-release (:doc:`branching`),
security fixes land on ``lota-next`` and ship in the next release. Once a
normal release is published, the release notes of each series list the
versions that receive fixes.

Scope
=====

In scope:

* TPM 2.0 credential activation and AIK certificate issuance,
* EK root validation and pinning,
* verification of TPM quotes, nonces, PCRs, boot commitments and event
  logs,
* the runtime protection digest and SDK token verification,
* BPF LSM enforcement, signed BPF object loading and the fs-verity gates,
* the SELinux policy and the systemd hardening that protect the agent,
* the reproducible build and the release signing paths.

Out of scope:

* detecting cheat behaviour in games,
* kernel vulnerabilities outside the LOTA BPF LSM,
* distribution packages not built from this repository,
* operator policy that deliberately disables a required production gate.
