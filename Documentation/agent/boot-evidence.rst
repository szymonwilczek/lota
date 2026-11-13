.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

=============
Boot evidence
=============

A token quotes PCRs 0, 1, 7 and 14 by their digest alone, so a publisher who
runs no verifier cannot read how the machine booted from it.
``LOTA_IPC_CMD_GET_BOOT_EVIDENCE`` answers with the values of the PCRs the
token quotes and every extended PCR 7 event: its SHA-256 digest, and its data
only when it measures the EFI global ``SecureBoot`` variable. The rest of PCR 7
is the firmware's key databases, tens of kilobytes that fit no frame. The wire
format is in ``include/lota_token.h``; ``src/agent/boot_evidence.c`` builds it.

The agent vouches for none of it. The relying party hashes the PCR values
against the digest a verified token quotes and replays the events to the
PCR 7 value, so evidence root edits no longer matches its token.
``lota_get_boot_evidence()`` in ``liblotagaming`` fetches it, and the Wine
hook writes it to ``lota-boot-evidence.bin`` next to the token.

``lota_server_verify_boot_evidence()`` in ``liblotaserver`` is the check, and
``VerifyBootEvidence`` in ``sdk/server`` holds the same rules for Go. Event
types sit outside the digests, so it reads none: the separator is the first
event that extends SHA-256 of four zero bytes, and Secure Boot reads on only
when every ``SecureBoot`` measurement before it carries the single byte 1 and
there is at least one. Evidence with no separator reads off: firmware that
reports an error separator leaves no point after which root's extends stop
counting. Root extends PCR 7 only after the firmware is done, so
a measurement it adds lands past the separator, and one it sends without data
reads as missing.
