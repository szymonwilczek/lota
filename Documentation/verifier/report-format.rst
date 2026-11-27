.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

=============
Report format
=============

One round carries three frames over the TLS connection (:doc:`index`): the
verifier's challenge, the agent's report and the verifier's result. The C
side is :ghsrc:`include/attestation.h`, serialized by
:ghsrc:`src/agent/report.c`; the Go side is
:ghsrc:`src/verifier/types/report.go`. The verifier reads and writes every
integer little-endian, and the structs have no padding.

All three frames open with the same two words:

``magic``
  ``0x41544F4C``, ``LOTA`` in little-endian (``LOTA_MAGIC``).

``version``
  The report version, ``major << 16 | minor << 8 | patch``
  (``LOTA_REPORT_VERSION`` in :ghsrc:`include/lota.h`). It is ``0x00010000``,
  1.0.0.

Challenge
=========

48 bytes, sent by the verifier when the TLS handshake completes.

====== ==== ============ ==================================================
Offset Size Field        Content
====== ==== ============ ==================================================
0      4    ``magic``
4      4    ``version``
8      32   ``nonce``    Fresh random nonce.
40     4    ``pcr_mask`` The PCRs to quote, bit *n* for PCR *n*.
44     4    ``flags``    Bit 0, ``LOTA_CHALLENGE_FLAG_BOOT_COMMITMENT_V1``:
                         the PCR 14 derivation the verifier checks. Always
                         set.
====== ==== ============ ==================================================

The agent refuses a challenge with another magic and does not check the
version.

Report
======

A fixed part of 5324 bytes, then three sections of which two vary in length:

============== ===================================================
Offset         Content
============== ===================================================
0              Header, 16 bytes.
16             TPM evidence, 4912 bytes.
4928           System measurement, 396 bytes.
5324           ``event_log_size``, 4 bytes.
5328           The TPM event log, ``event_log_size`` bytes.
5328 + *L*     ESRT entry, 28 bytes.
5356 + *L*     ``mok_list_size``, 4 bytes.
5360 + *L*     The MOK list, ``mok_list_size`` bytes.
============== ===================================================

*L* is ``event_log_size``. Every section is present in every report, so the
smallest report is 5360 bytes. A host with nothing to put in a section says so
in it: an event log or a MOK list of size 0, an ESRT entry with ``present``
0.

The event log holds at most 524288 bytes and the MOK list at most 32768, so
the largest report is 562416 bytes. The agent sends a longer event log or MOK
list as size 0.

Header
------

====== ==== ================ ==============================================
Offset Size Field            Content
====== ==== ================ ==============================================
0      4    ``magic``
4      4    ``version``
8      4    ``report_size``  The length of the whole report in bytes.
12     4    ``flags``        `Report flags`_.
====== ==== ================ ==============================================

The verifier reads the first 32 bytes, then ``report_size`` bytes in all.
Bytes past the end of the MOK list are read and ignored.

Report flags
~~~~~~~~~~~~

==== ============================ ==========================================
Bit  Flag                         Meaning
==== ============================ ==========================================
0    ``IOMMU_OK``                 The agent verified the IOMMU.
1    ``TPM_QUOTE_OK``             The TPM quote succeeded.
2    ``KERNEL_HASH_OK``           The boot measurement digest was captured.
3    ``BPF_ACTIVE``               The agent has its LSM loaded.
4    ``MODULE_SIG``               The kernel enforces module signatures.
5    ``LOCKDOWN``                 Kernel lockdown is on.
6    ``SECUREBOOT``               Secure Boot is on, as the agent sees it.
7    ``ENFORCE``                  The agent enforces with its LSM.
8    ``BOOT_COMMITMENT_V1``       The agent extended its boot commitment
                                  into PCR 14.
9    ``INITRAMFS_LOCK_V1``        The initramfs extended its lock into PCR
                                  14 before the agent ran.
10   ``IMA_APPRAISAL``            IMA appraises executables in a blocking
                                  mode.
11   ``BENCH``                    The agent runs with ``--bench``.
12   ``STRICT_MMAP``              The agent applies this policy key.
13   ``STRICT_EXEC``              The agent applies this policy key.
14   ``STRICT_MODULES``           The agent applies this policy key.
15   ``BLOCK_ANON_EXEC``          The agent applies this policy key.
16   ``BLOCK_PTRACE``             The agent applies this policy key.
17   ``EVENTS_LOST``              The kernel left events out of the agent's
                                  log.
==== ============================ ==========================================

The C names carry the prefix ``LOTA_REPORT_FLAG_``. Bits 12 to 16 are set
only with ``ENFORCE``.

The verifier refuses a report without bits 8 and 9 with ``pcr_fail``. Bits 4,
5, 7 and 10 meet the ``require_module_sig``, ``require_lockdown``,
``require_enforce`` and ``require_ima_appraisal`` keys of the policy
(:ghsrc:`policies/README.rst`). Bit 6 meets no key: ``require_secureboot``
reads the event log. Bits 0, 6, 11 and 12 to 17 are logged and change no
verdict; bits 1 to 3 are not read.

TPM evidence
------------

====== ==== ======================== ======================================
Offset Size Field                    Content
====== ==== ======================== ======================================
16     768  ``pcr_values``           24 SHA-256 PCR values, PCR 0 first.
784    4    ``pcr_mask``             The quoted PCRs, bit *n* for PCR *n*.
788    512  ``quote_signature``      The quote signature.
1300   2    ``quote_sig_size``       Its length, at most 512.
1302   1024 ``attest_data``          The ``TPMS_ATTEST`` the TPM signed.
2326   2    ``attest_size``          Its length, at most 1024.
2328   512  ``aik_public``           The AIK public key, DER SPKI.
2840   2    ``aik_public_size``      Its length, at most 512.
2842   2048 ``aik_certificate``      The AIK certificate, DER X.509.
4890   2    ``aik_cert_size``        Its length, at most 2048.
4892   32   ``nonce``                The challenge nonce.
4924   2    ``quote_sig_alg``        ``TPM2_ALG_RSASSA`` or
                                     ``TPM2_ALG_RSAPSS``.
4926   2    ``quote_sig_hash_alg``   ``TPM2_ALG_SHA256``, ``SHA384`` or
                                     ``SHA512``.
====== ==== ======================== ======================================

The ``extraData`` in ``attest_data`` holds a binding nonce, which ties the
quote to the report fields it does not sign:

.. code-block:: none

   SHA-256(nonce || flags & ~TPM_QUOTE_OK || kernel_hash || agent_hash ||
           iommu.vendor || iommu.flags || iommu.unit_count ||
           iommu.cmdline_param)

``TPM_QUOTE_OK`` is left out because the agent sets it after the quote
(:ghsrc:`src/verifier/verify/attest.go`).

System measurement
------------------

====== ==== ======================== ======================================
Offset Size Field                    Content
====== ==== ======================== ======================================
4928   32   ``kernel_hash``          The boot measurement digest, SHA-256.
4960   32   ``agent_hash``           SHA-256 of the agent binary.
4992   256  ``kernel_path``          The kernel image path, as text. The
                                     verifier does not read it.
5248   4    ``iommu.vendor``         0 none, 1 Intel VT-d, 2 AMD-Vi.
5252   4    ``iommu.flags``          `IOMMU flags`_.
5256   4    ``iommu.unit_count``     The number of IOMMU units.
5260   64   ``iommu.cmdline_param``  The IOMMU boot parameter, as text.
====== ==== ======================== ======================================

IOMMU flags
~~~~~~~~~~~

=== ================= =====================================================
Bit Flag              Meaning
=== ================= =====================================================
0   ``SYSFS_PRESENT`` ``/sys/class/iommu`` has entries.
1   ``CMDLINE_SET``   The boot parameter is set.
2   ``DMA_REMAP``     A device group is in a translating domain.
3   ``IRQ_REMAP``     An interrupt goes through interrupt remapping.
4   ``STRICT``        Strict mode, no lazy unmap.
=== ================= =====================================================

The C names carry the prefix ``IOMMU_FLAG_``
(:ghsrc:`include/iommu_types.h`). ``require_iommu`` reads bit 2 alone and
refuses with ``iommu_fail`` when it is clear.

Event log
---------

The TCG event log the firmware and boot chain wrote, read from
``/sys/kernel/security/tpm0/binary_bios_measurements``. The verifier replays
it against the quoted PCRs (:doc:`index`); the agent's side is in
:doc:`../agent/boot-evidence`.

ESRT entry
----------

====== ==== ======================== ======================================
Offset Size Field                    Content
====== ==== ======================== ======================================
0      4    ``present``              1 when the ESRT holds a System
                                     Firmware entry, else 0.
4      4    ``fw_version``           Its ``fw_version``.
8      4    ``lowest_supported``     Its ``lowest_supported_fw_version``.
12     16   ``fw_class``             Its ``fw_class`` GUID, raw.
====== ==== ======================== ======================================

Offsets are from the start of the entry. The agent reads it from
``/sys/firmware/efi/esrt/entries``. The firmware version guards a
self-service re-anchor against rollback. ``present`` 0 puts it on the
low-firmware-assurance path when the pinned baseline had no ESRT either, and
escalates it when the baseline had one ("Re-anchor" in :doc:`index`).

MOK list
--------

The data of the ``MokListRT`` EFI variable, a run of ``EFI_SIGNATURE_LIST``
structures, without the 4 attribute bytes ``efivarfs`` prefixes. The verifier
compares it with the ``MokList`` events of PCR 14 when it re-pins on a Machine
Owner Key change.

Result
======

24 bytes, sent by the verifier once the report is checked.

====== ==== ================ ==============================================
Offset Size Field            Content
====== ==== ================ ==============================================
0      4    ``magic``
4      4    ``version``
8      4    ``result``       The verdict code ("Verdicts" in :doc:`index`).
12     4    ``flags``        0.
16     8    ``valid_until``  For ``ok``, the Unix time in seconds the
                             verdict holds until; else 0.
====== ==== ================ ==============================================

The agent reads exactly 24 bytes (``struct verifier_result`` in
:ghsrc:`src/agent/net.h`), refuses another magic and does not check the
version. It prints ``valid_until`` in verbose mode and sets the validity of
its tokens from its own interval (:doc:`../agent/tokens`).

Refused reports
===============

========================================= ==================================
Report                                    Verdict
========================================= ==================================
Another magic                             ``report_malformed``, before the
                                          body is read.
``report_size`` below 32 or above         ``report_malformed``, before the
562416 bytes                              body is read.
Shorter than 5360 bytes, in any version   ``report_malformed``.
Another version                           ``old_version``.
A length field above its buffer, a        ``report_malformed``.
section above its limit, or a section
cut off
========================================= ==================================

Versions
========

The verifier accepts the one version it is built with. A layout change, a
field added, removed or moved or a section added, changes
``LOTA_REPORT_VERSION`` and ``ReportVersion`` together, and agents and
verifiers cross it together (:doc:`../admin-guide/protocol-versions`).
``lota-verifier --print-versions`` prints the version a build speaks.

Layout checks
=============

The serializer copies the packed C structs, and the parser walks offsets of
its own, so no build links the two. Four checks hold them together:

* :ghsrc:`src/agent/report.c` pins the size of each report struct with
  ``_Static_assert``, and :ghsrc:`src/agent/net.c` the challenge and the
  result.
* :ghsrc:`tests/integration/test_report_wire_sizes.sh` compares the sizes
  compiled from the C headers with the constants in ``report.go``.
* ``TestParseReport_FieldOffsetsMatchCLayout`` in
  :ghsrc:`src/verifier/types/report_test.go` writes a marker at each offset
  and requires the parsed report to show it in the matching field.
* :ghsrc:`tests/cross_lang/report_gen.c` serializes a report whose every
  field carries a pattern derived from its position, and
  :ghsrc:`tests/cross_lang/report_verify.go` parses it with the verifier's
  parser and checks each field.

``make test`` runs the shell check and the pair; the Go test runs with
``go test ./...`` in :ghsrc:`src/verifier`.
