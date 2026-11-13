.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

=============
Boot evidence
=============

A token quotes PCRs 0, 1, 7 and 14 by one digest over their values
(:doc:`tokens`). Boot evidence is what a relying party with no verifier needs
to read how the machine booted from that digest: the values of the quoted
PCRs and the PCR 7 events behind them. The agent builds it in
:ghsrc:`src/agent/boot_evidence.c`; the wire format is in
:ghsrc:`include/lota_token.h`.

The agent vouches for none of it. Every byte is checked against a token
whose signature the relying party has verified, so evidence that anybody on
the host, root included, edits fails to match the token.

Request
=======

``LOTA_IPC_CMD_GET_BOOT_EVIDENCE`` takes no payload (:doc:`ipc`). The agent
reads the quoted PCRs from the TPM and the firmware event log from
``/sys/kernel/security/tpm0/binary_bios_measurements``, and answers with the
evidence. Each request counts against the per-user ``GET_TOKEN`` limit, as
it reads the TPM and the log, and is refused with
``LOTA_IPC_ERR_RATE_LIMITED`` past it.

The agent answers ``LOTA_IPC_ERR_NO_TPM`` while it signs no tokens, and
``LOTA_IPC_ERR_INTERNAL`` when the evidence cannot be built: the log does not
parse, a PCR 7 event carries no SHA-256 digest, or the evidence exceeds the
8192-byte IPC payload. The journal names the cause (``cannot build boot
evidence: …``).

The PCR values are read when the request is answered. Evidence matches a
token only while the quoted PCRs hold the values the token quoted, so it is
fetched next to its token.

Format
======

All integers are little-endian.

.. list-table::
   :header-rows: 1
   :widths: 12 10 78

   * - Offset
     - Size
     - Field
   * - 0
     - 2
     - Version, ``LOTA_BOOT_EVIDENCE_VERSION`` (1).
   * - 2
     - 2
     - Number of events.
   * - 4
     - 4
     - PCR mask: the token's.
   * - 8
     - 32 × N
     - The SHA-256 value of each PCR in the mask, lowest first.
   * - --
     - --
     - The events, in log order.

Each event is the 32-byte SHA-256 digest the firmware extended into PCR 7,
a 2-byte data size and the data. Every PCR 7 event of the log is there except
``EV_NO_ACTION``, which is never extended. An event carries data only when it
measures the EFI global variable ``SecureBoot``; the rest of PCR 7 is mostly
the firmware's key databases, which do not fit an IPC frame.
``LOTA_BOOT_EVIDENCE_MAX_SIZE`` (8192) holds any evidence the agent sends.

Verification
============

``lota_server_verify_boot_evidence()`` in :ghsrc:`include/lota_server.h`
verifies the evidence against the claims of a verified token and reports
whether the firmware measured Secure Boot on. ``VerifyBootEvidence()`` in
:ghsrc:`sdk/server/boot_evidence.go` applies the same rules, and
``lota_ac_verify_boot_evidence()`` in :ghsrc:`include/lota_anticheat.h`
takes the information of a verified heartbeat. The evidence is refused
(``LOTA_SERVER_ERR_BAD_EVIDENCE``, ``ErrBadEvidence`` or
``LOTA_AC_ERR_BAD_EVIDENCE``) when:

* the version is another, or the mask differs from the token's, lacks PCR 7
  or names a PCR past the last;
* the PCR values do not hash, in mask order, to the token's PCR digest;
* an event with data does not hash to its digest;
* replaying every event digest from zero does not give the PCR 7 value;
* bytes are missing or left over.

Accepted evidence reads Secure Boot on only when all of these hold:

* an event extends the SHA-256 of four zero bytes, the firmware's
  separator;
* at least one ``SecureBoot`` measurement comes before the first such
  event;
* every ``SecureBoot`` measurement before it carries the single byte 1.

The log carries event types outside the digests, so the check reads none and
takes the separator from its digest. A log whose firmware reports an error
separator holds no such event, and its evidence reads Secure Boot off: no
point remains after which an extend from the running system stops counting.

What root can change
--------------------

Root can extend PCR 7 only after the firmware has handed over, so whatever
it adds replays after the separator and casts no vote. Root can also send a
``SecureBoot`` event without its data: the digest still replays, the event
is not checked, and it counts as absent. Either way Secure Boot reads off,
never on.

Getting the evidence
====================

``lota_get_boot_evidence()`` in :ghsrc:`include/lota_gaming.h` sends the
request, and ``lota_ac_boot_evidence()`` fetches it for an anti-cheat
session. The Wine hook writes it to ``lota-boot-evidence.bin`` in its token
directory after the first token of a connection, and removes it with the
token.
