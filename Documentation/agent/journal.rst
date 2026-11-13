.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

=============
Agent journal
=============

What the agent journals about a measurement round
=================================================

Every token round measures each protected process, but an fs-verity digest
does not change while mapped, so the answer rarely differs from the last one.
The journal carries only answers that differ:

- **A first answer is written**, unless every object measured.
- **A changed answer is written, both ways.** The line ending a run says how
  many further rounds the replaced answer held.
- **The sentence is compared**, not the verdict, so a new unmeasurable object
  mid-session is news.
- **An answer with no room in the table is written**, not assumed a repeat.

The sentence names the object's path and role. ``LOTA_RT_REASON_MAX`` and
``MEASURE_REPORT_STATEMENT_MAX`` must hold a whole path, or two objects cut to
one prefix compare equal; a new field grows both.

A standing answer has no window, unlike a decision-log row: every token
carries the measured coverage in ``LOTA_FLAG_IMAGE_FULLY_MEASURED``, so a
quiet journal hides no evidence. Shutdown reports the quiet as
``Runtime measurement reports: repeated=`` and ``unremembered=``.

The decision lives in the pure header ``src/agent/measure_report.h``, tested
both ways: a missing line fails as readily as a repeated one.

What the agent journals about a refused token
=============================================

Token requests come on the same timer, and a refusal's cause (no publisher
named, no TPM) does not move between rounds. A refusal follows the rules
above: written as a first answer or a change, counted while it stands.
It differs from the measurement path in three ways:

- **The subject is the connection.** The publisher and peer a refusal turns
  on are bound there, so a reconnect's refusal is a first answer.
- **The client is refused every round.** Only the line is withheld; tests
  check the result code each round beside the line count.
- **Silent refusals stay silent** and are not counted.

Shutdown reports the quiet as ``Token answer reports: repeated=``.

Both paths share ``src/agent/standing_answer.h``: what is remembered, when a
round is news, and the clause carrying the ended run's length. Only the
keying differs: a table swept against the protected set for measurements, a
connection field for tokens.
