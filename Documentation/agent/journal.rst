.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

=============
Agent journal
=============

The agent writes its messages to the systemd journal or to standard error
(:ghsrc:`src/agent/journal.c`). Token rounds repeat on a timer, so the
measurement and refusal lines of a round are written only when they differ
from the last round's.

Where messages go
=================

With ``JOURNAL_STREAM`` or ``INVOCATION_ID`` set, as systemd sets them for
a unit, every message is a journal entry with these fields:

``MESSAGE``
  The text, cut at 1023 bytes.
``PRIORITY``
  The syslog priority.
``SYSLOG_IDENTIFIER``
  ``lota-agent``.
``CODE_FILE``, ``CODE_LINE``, ``CODE_FUNC``
  Where the message was written.

Otherwise a message is one line on standard error,
``lota-agent: WRN: text``, with ``ERR``, ``WRN``, ``NTC``, ``INF`` or
``DBG`` for the priority. A daemon started with ``--daemon`` writes to the
journal once it has detached.

``log_level`` (:doc:`configuration`) drops messages less severe than
``error``, ``warn``, ``info`` (the default) or ``debug``. A reload applies
a new value.

To follow the daemon:

.. code-block:: sh

   journalctl -u lota-agent -f

Measurement lines
=================

Every token round measures the code each protected process has mapped
(:doc:`runtime-measurement`). The answer for one process is one of:

* ``runtime image measurement for pid=P covers every object it has
  mapped``, at ``info``;
* ``runtime image measurement for pid=P covers M objects and misses U:
  why``, at ``warn``;
* ``runtime image measurement failed for pid=P, which is not the caller
  (pid=C); the token reports partial coverage: why``, at ``warn``: the
  process is left out of the coverage;
* ``runtime image measurement failed for the requesting pid=P: why``, at
  ``error``: the round is refused.

The ``why`` part names the object; a path longer than 319 bytes, of the
executable or of a mapped object, is cut to ``...`` and its last 316 bytes.

A line is written when the process's answer differs from its last one,
answer and text compared, so a new unmeasurable object in the same answer
is written too. The first answer for a process is written unless it is
full coverage. A line that replaces an answer ends with ``(the previous
answer held N further rounds)`` when the old one repeated. A process that
leaves the protected set is forgotten, and its next answer is written as a
first one.

The agent remembers the answers of up to ``LOTA_IPC_TOKEN_MAX_PROTECT_PIDS``
processes (:ghsrc:`src/agent/measure_report.h`). An answer for a process
past that is written every round.

The journal is no record of coverage: every token carries it in
``LOTA_STATUS_IMAGE_FULLY_MEASURED`` (:doc:`tokens`).

Token refusal lines
===================

A refused ``GET_TOKEN`` (:doc:`ipc`) follows the same rule, per
connection: its first refusal is written, a refusal that differs from the
last one is written, and a repeat is not. A new connection starts with no
answer. The client gets the error code every round; only the line is
withheld. A token issued after a refusal that repeated is written as
``GET_TOKEN for pid=P is answered again (the previous answer held N
further rounds)``.

The refusals that go through this rule:

* ``rate limited GET_TOKEN for session pid=P uid=U`` and ``rate limited
  GET_TOKEN for uid=U pid=P``, at ``warn``;
* ``Refusing GET_TOKEN for pid=P: this agent answers for N publishers and
  the connection named none. Send SET_PROFILE first``, at ``error``;
* ``Refusing GET_TOKEN for pid=P: no TPM on this agent, and an unsigned
  token is not evidence``, at ``error``.

A measurement refusal is held back by the measurement rule.
``LOTA_IPC_ERR_NOT_ATTESTED`` writes no line, nor does
``LOTA_IPC_ERR_TPM_LOCKOUT`` once the status carries the lockout; the
quote that finds the lockout first writes ``tpm_quote failed: why``. Any
other refusal that writes a line writes it every round.

Shutdown
========

When the daemon leaves its event loop it writes at ``info`` what the two
rules did:

.. code-block:: text

   Runtime measurement reports: repeated=R unremembered=U
   Token answer reports: repeated=T

``repeated`` counts rounds that repeated a written answer, ``unremembered``
the measurement lines written for a process past the remembered ones.
