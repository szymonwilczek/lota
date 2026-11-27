.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

========
Verifier
========

``lota-verifier`` is the publisher's attestation service. It challenges each
host that connects, checks the TPM quote and the boot evidence in the reply
against the attestation CA, the PCR policy and the host's pinned baseline, and
answers with a verdict. The agent turns a passing verdict into the tokens a
title reads. Its options are in :doc:`command-line`, and the source is under
:ghsrc:`src/verifier`.

.. toctree::
   :maxdepth: 1

   command-line
   report-format
   store
   monitoring-api

Roles
=====

Attestation listener
  The TLS listener on ``--addr``. It runs one exchange per connection and
  keeps no session between them.

Monitoring API
  The HTTP API on ``--http-addr``: health, metrics, the client inventory, the
  audit and decision logs, and the operator actions below
  (:doc:`monitoring-api`).

Reporting instance
  ``--report-only`` opens the monitoring API alone, over a Postgres database
  it never writes. It binds no attestation listener and refuses every
  endpoint that changes state.

Exchange
========

Each connection carries one round (:ghsrc:`src/verifier/server/server.go`).

#. The client completes a TLS 1.3 handshake within the read timeout of 30
   seconds. A peer that hangs up before the protocol starts is logged at debug
   level only.
#. The verifier sends a 48-byte challenge: a fresh 32-byte nonce, the PCR mask
   and the boot-commitment flag. The mask is the union of the PCRs the active
   policy and every tenant-bound policy pin, with PCR 0, 1, 7, 9 and 14 always
   set, and PCR 8 when such a policy pins the kernel command line.
#. The client sends its report (:doc:`report-format`). A frame with a foreign
   magic, or a size outside 32 to 562416 bytes, is answered with
   ``report_malformed`` before the body is read. The read timeout covers the
   whole report.
#. The verifier checks the report and sends the 24-byte result: the verdict
   code and, for ``ok``, the time the verdict is valid until, one hour
   later. A write has 10 seconds. The agent sets the validity of its tokens
   from its own interval (:doc:`../agent/tokens`).

The listener accepts 256 connections at once by default; one past the cap is
closed at accept and logged as ``connection limit reached, rejecting``.

Verification
============

The checks run in this order, and the first that fails gives the verdict
(:ghsrc:`src/verifier/verify/verify.go`). A round that reaches these checks,
passed or refused, is queued for the decision log. An instance on
``--allow-insecure-memory-state`` keeps no decision log, and a full queue
drops rows, counted (:doc:`store`).

#. The report parses, and its TPM fields fit their buffers.
#. The report carries an AIK public key and an AIK certificate, the
   certificate chains to an ``--aik-ca-cert`` root, holds the same key, lies
   within its validity period and is on no ``--aik-crl`` list.
#. The certificate's ``CommonName`` is a 64-digit hex device pseudonym, the
   client ID. Its single ``OrganizationalUnit`` names the tenant; with none,
   the tenant is ``default`` (:doc:`../admin-guide/multi-tenancy`).
#. The client ID is not revoked, and the pseudonym is not banned in its
   tenant.
#. The nonce is the one this connection was sent, is unused and at most five
   minutes old, and the quote binds it. A client is held to 30 rounds per
   minute.
#. The quote signature verifies with the AIK, and the quoted PCR digest
   matches the PCR values in the report.
#. The report carries an event log whose replay matches each quoted PCR it
   extends. PCR 9 and 14 are left out, and PCR 8 is checked only when the
   policy pins the kernel command line.
#. The report meets the tenant's policy: PCR pins, kernel and agent hash
   lists, and each ``require_*`` key (:ghsrc:`policies/README.rst`).
#. The event log holds a quote-authenticated ``SecureBoot`` variable, which
   only UEFI firmware measures.
#. The report header sets the boot-commitment and initramfs-lock flags, and
   the mask holds PCR 0, 1 and 7.
#. PCR 14 equals the value the initramfs lock and the reported agent hash
   derive from the pre-lock PCR 14 in the event log.
#. The agent hash, PCR 14 and PCR 0, 1 and 7 match the client's baseline, or
   pin it on first use (`Baselines`_).
#. The tenant is recorded for the client.

A passing round also records the kernel digest and the machine keys, and
logs ``kernel_hash changed`` or ``machine_keys changed`` when they differ from
the last round. Neither changes the verdict.

Verdicts
========

The result carries one code (:ghsrc:`src/verifier/types/report.go`). The
``lota_rejections_total`` metric counts refusals by reason
(:doc:`../admin-guide/observability`).

.. list-table::
   :header-rows: 1
   :widths: 5 25 70

   * - Code
     - Name
     - Cause
   * - 0
     - ``ok``
     - Every check passed.
   * - 1
     - ``nonce_fail``
     - The nonce is unknown, used, expired, bound to another connection or
       absent from the quote, the client passed 30 rounds in a minute, or the
       used-nonce history could not be read.
   * - 2
     - ``sig_fail``
     - The AIK key or the quote signature does not verify, or the AIK
       certificate does not parse, does not chain to a trusted root or is on
       a CRL.
   * - 3
     - ``pcr_fail``
     - The quoted digest, the event log or a PCR pin of the policy does not
       match, the log proves no UEFI boot, the boot-commitment or
       initramfs-lock flag is missing, or the mask omits PCR 0, 1 or 7.
   * - 4
     - ``iommu_fail``
     - The policy sets ``require_iommu`` and DMA remapping is off.
   * - 5
     - ``old_version``
     - The report version differs from the verifier's, in a report of at
       least 5360 bytes; a shorter one is ``report_malformed``. Upgrade the
       agent or the verifier so the two match
       (:doc:`../admin-guide/protocol-versions`).
   * - 6
     - ``integrity_mismatch``
     - The agent hash is off the policy's list, PCR 14 does not match its
       derivation, or the agent hash, PCR 14 or PCR 0, 1 and 7 moved from the
       baseline and no re-anchor applied.
   * - 7
     - ``revoked``
     - The client ID is revoked.
   * - 8
     - ``banned``
     - The device pseudonym is banned in the tenant.
   * - 9
     - ``internal_error``
     - The verifier has no CA root, a store failed, or the tenant could not be
       recorded. Nothing on the host fixes it.
   * - 10
     - ``identity_fail``
     - The AIK certificate holds another key, or its pseudonym or tenant is
       invalid. Re-enrolling fixes it.
   * - 11
     - ``policy_requirement``
     - A first-use boot baseline has no enrollment road (`Baselines`_).
   * - 12
     - ``certificate_validity``
     - The AIK certificate expired or is not yet valid. Renew it, or check the
       clocks.
   * - 13
     - ``certificate_missing``
     - The report carries no AIK certificate: the host is not enrolled.
   * - 14
     - ``secureboot_required``
     - The policy sets ``require_secureboot`` and the event log does not prove
       Secure Boot on.
   * - 15
     - ``lockdown_required``
     - The policy sets ``require_lockdown`` and kernel lockdown is off.
   * - 16
     - ``module_sig_required``
     - The policy sets ``require_module_sig`` and module signatures are not
       enforced.
   * - 17
     - ``enforce_required``
     - The policy sets ``require_enforce`` and the agent is not in enforce
       mode.
   * - 18
     - ``ima_appraisal_required``
     - The policy sets ``require_ima_appraisal`` and the host does not appraise
       executables.
   * - 19
     - ``kernel_image_required``
     - The policy lists kernel hashes and the kernel image is not measured or
       not listed.
   * - 20
     - ``cmdline_required``
     - The policy pins the kernel command line and the measured one does not
       match.
   * - 21
     - ``report_malformed``
     - The report does not parse for a reason other than its version.

Baselines
=========

The verifier pins three things per client in the first round whose other
checks pass: the agent hash with PCR 14, and PCR 0, 1 and 7. If storing the
client's tenant fails after the pin, the round answers ``internal_error`` and
the pin stays. Later rounds must match the three; a change is
``integrity_mismatch`` unless one of the re-anchor paths below moves the pin.
The baselines live in the ``--db`` or Postgres store; ``--state-db`` keeps
none, so an instance on it pins in memory and forgets on restart.

A first-use PCR 0, 1 and 7 pin needs one of these roads, logged as
``allowed_by`` with ``boot baseline TOFU first-use accepted``:

``policy PCR0/1/7 pins``
  The tenant's policy pins PCR 0, 1 and 7, and the policy check already
  matched them.

``event-log Secure Boot anchor``
  The policy sets ``require_secureboot`` and the event log proves Secure Boot
  on. The pin then anchors the device against rollback.

``baseline store enrollment``
  The store already holds a boot baseline for the client.

``operator force-reanchor``
  An operator forced a re-anchor of the client (`Operator actions`_). The
  pin spends that consent.

With none of them the round is refused with ``policy_requirement`` and the
log line ``boot baseline not enrolled; refusing TOFU first-use``.
``--allow-tofu-boot-baseline`` pins whatever the host reports instead.

Re-anchor
=========

Four paths move a pinned baseline without an operator
(:ghsrc:`src/verifier/verify/reanchor.go`). Each logs at security level and
counts in ``lota_reanchors_total`` under the outcome named below. A refused
move ends the round in ``integrity_mismatch``.

Firmware and Secure Boot drift
------------------------------

When PCR 0, 1 or 7 moved, the baseline is re-pinned if self-service
re-anchor is on for the tenant, its policy sets ``require_secureboot``, and
the event log proves Secure Boot on. A policy with ``profile: consumer`` turns
self-service on; ``enterprise`` or no profile leaves it off;
``--enable-self-service-reanchor`` given on the command line overrides every
profile.

The move compares this boot's event log with the one recorded with the pin.
It escalates when:

* no event log is on record for the pin;
* the firmware version is below the ESRT's lowest supported version, lower
  than the one on record, or the ESRT disappeared;
* the previous re-anchor is less than 30 days old, or 90 days when this one
  would take the low-assurance path;
* Secure Boot is off, ``PK``, ``KEK``, ``db`` or ``SecureBoot`` changed,
  ``dbx`` changed other than by appending, or the set of PCR 7 variables
  changed.

A higher firmware version re-pins on the strong path (``strong``). The same
version, or no firmware version on record for the pin, re-pins on the
low-firmware-assurance path (``lfa``). That path logs ``ALERT: boot baseline
re-anchored on the low-firmware-assurance path (operator review
recommended)`` and lists the client under ``GET /api/v1/reanchor/review``
until an operator acknowledges it.

Boot entries
------------

When PCR 0 and 7 match the pin and the only PCR 1 events that differ from the
log on record are ``BootOrder`` and ``Boot####`` variables, PCR 1 is
re-pinned alone (``boot_entries``). The same gate as above applies, but
neither interval nor the review list does.

Machine Owner Keys
------------------

When PCR 14 moved and the only events that changed in it are ``MokList``,
``MokListX`` and ``MokListTrusted``, PCR 14 is re-pinned (``mok``), under the
same gate. A moved ``MokList`` must match the list the agent sent. Neither
interval nor the review list applies.

Agent updates
-------------

When the agent hash moved to a build on the policy's ``agent_hashes`` list,
the pin moves to it with PCR 14 (``agent_hash``), at most once every 24 hours
per client (:ghsrc:`src/verifier/verify/agent_hash_reanchor.go`). With an
empty list the pin stands. This path needs no self-service profile.

Operator actions
================

The admin endpoints of :doc:`monitoring-api` act on one client:

Force a re-anchor
  ``POST /api/v1/clients/{id}/reanchor`` drops the client's baselines and
  records consent, so its next round pins afresh, through the enrollment gate
  on that consent.

Acknowledge a review
  ``POST /api/v1/clients/{id}/reanchor-review-ack`` takes the client off the
  low-assurance review list. The baseline does not change.

Delete a client
  ``DELETE /api/v1/clients/{id}`` drops the baselines, a pending forced
  re-anchor and the client's challenge state. The host keeps its certificate,
  and its next round is a first use (`Baselines`_).

Revoke and ban
  ``POST /api/v1/clients/{id}/revoke`` refuses the client ID and
  ``POST /api/v1/bans`` refuses the device pseudonym in a tenant. Both
  survive a delete.
