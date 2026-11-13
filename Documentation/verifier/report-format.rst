.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

==============================
Attestation report wire format
==============================

The attestation report (``include/attestation.h``, serialized by
``src/agent/report.c``, parsed by ``src/verifier/types/report.go``) has a fixed
struct followed by the TPM event log, the ESRT firmware-version descriptor and
the MOK list.

**Every section is mandatory.** The verifier accepts exactly one report wire
version and rejects any other, so there is no mixed-version fleet to parse
defensively for: a report that stops before a section is truncated, not old. A
platform with nothing to report says so in the section's own fields -- the ESRT
descriptor carries ``present = 0`` where the firmware exposes no System
Firmware entry, and the MOK list is size 0 where there is none to send.

A breaking layout change -- adding, removing or reordering a field, or adding a
section -- bumps the version in ``include/lota.h`` and ``ReportVersion`` in
``types/report.go`` together, the major for the report and the minor for the
verifier's result. That is a flag-day either way: roll the verifier tier first,
then the agents.

The result travels the same way as the report and under the same version. It is
``struct verifier_result`` in ``src/agent/net.h``, serialized by
``VerifyResult.Serialize``, and its length is pinned on the C side by the same
``_Static_assert`` discipline -- the agent reads exactly that many bytes before
it parses, so a length change on one side is a hang on the other rather than a
parse error.

Nothing links the C serializer and the Go parser at build time: the serializer
``memcpy``\ s a packed struct, the parser walks hand-computed offsets. Four
checks stand in for that missing link, and a layout change must satisfy all
four:

* ``src/agent/report.c`` pins ``sizeof`` for each wire struct with
  ``_Static_assert``, so a field added or removed on the C side fails the build
  with the name of the constant to update. A new wire struct gets one too.
* ``tests/integration/test_report_wire_sizes.sh`` compares sizes compiled from
  the agent's headers with the constants in ``types/report.go``, catching a
  stale Go constant the asserts above cannot see.
* ``TestParseReport_FieldOffsetsMatchCLayout`` (``types/report_test.go``)
  writes a distinct marker at each expected offset and requires the parsed
  report to expose it in the matching field -- a positive check, not a bounds
  test.
* ``make test`` runs the pair
  ``tests/cross_lang/report_gen.c`` -> ``report_verify.go``: C serializes a
  report whose every field carries a position-derived pattern, Go parses it
  with the production parser and checks each field against the same patterns.
  The patterns are restated in both files on purpose.
