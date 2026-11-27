.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

=================
runtime_remeasure
=================

``runtime_remeasure`` computes the runtime measure of the anti-cheat
heartbeat for its own process, with no agent, verifier or TPM. It shows
that the measure of the mapped image equals the one a backend computes
from the files, that a one-byte change to code changes it, and that it
stays the same while the process does not change.

The runtime measure, its layout and the functions that compute it are
described in
`the anti-cheat SDK <../../Documentation/userspace-api/anticheat.rst>`_.
It is computed inside the measured process, which controls the result;
what the agent measures of a protected process from outside it is in
`runtime measurement <../../Documentation/agent/runtime-measurement.rst>`_.

Building
========

``make examples`` builds ``build/examples/runtime_remeasure`` against
``lota-anticheat`` from the staged SDK (see `Building <../README.rst>`__).

Running
=======

.. code-block:: console

   $ build/examples/runtime_remeasure --list-objects > manifest.txt
   $ build/examples/runtime_remeasure --manifest manifest.txt
   live (mapped image):   <64 hex digits>
   set (manifest files):  <64 hex digits>
   RESULT: MATCH - live image matches the manifest

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Mode
   * - none
     - Compare the measure of the mapped image with the measure computed
       from the files of the objects ``lota_ac_list_runtime_objects()``
       lists.
   * - ``--list-objects``
     - Print those files, one path per line.
   * - ``--manifest FILE``
     - Compare the measure of the mapped image with the measure computed
       from the files ``FILE`` lists.
   * - ``--patch-demo``
     - Measure a copy of an executable, change one byte of its code and
       measure it again.
   * - ``--exe PATH``
     - The executable ``--patch-demo`` copies, default
       ``/proc/self/exe``.
   * - ``--watch SEC``
     - Measure the mapped image, then again every ``SEC`` seconds.
   * - ``--count N``
     - Number of ``--watch`` measurements after the first, default 5.
   * - ``-h``, ``--help``
     - Print the usage to stderr and exit 0.

Given several modes, the first of ``--list-objects``, ``--manifest``,
``--patch-demo`` and ``--watch`` in that order runs.

The modes
=========

The default mode prints the number of objects and both digests, then
``RESULT: MATCH - live image matches its on-disk objects`` or
``RESULT: MISMATCH - live image differs from on-disk objects``. The
objects are the main executable and each shared library the process has
mapped; the vDSO is left out.

``--manifest`` reads one path per line, skipping blank lines and lines
starting with ``#``, and trimming spaces and tabs around each path. It
refuses an empty manifest, more than 512 paths and a line of 4095
characters or more. The output of ``--list-objects``, or of
``demo_anticheat --print-runtime-objects`` for that program, is such a
manifest, and ``demo_server -anticheat-runtime-manifest`` takes the same
format (see `demo_server <../demo_server/README.rst>`_).

``--patch-demo`` copies the executable to ``/tmp/lota_remeasure_XXXXXX``,
measures the copy, inverts the last byte of its first executable segment
and measures it again. It prints both digests and
``RESULT: DETECTED - code patch flipped the runtime digest``, or
``RESULT: UNDETECTED - patch did not change the digest``, and removes
the copy.

``--watch`` prints the first digest as ``baseline:`` and then
``tick <i>: stable`` for each later measurement that equals it, ending
with ``RESULT: STABLE - <n> re-measurements matched the baseline``. The
first measurement that differs prints ``tick <i>: CHANGED - live code
pages drifted`` and its digest, and ends the run.

Exit codes
----------

.. list-table::
   :header-rows: 1
   :widths: 10 90

   * - Code
     - Meaning
   * - 0
     - ``MATCH``, ``DETECTED`` or ``STABLE``; ``--list-objects`` done;
       ``--help``.
   * - 1
     - ``MISMATCH``, ``UNDETECTED`` or ``CHANGED``, or a step failed with
       a line on stderr.
   * - 2
     - An unknown option, an option without its value, a negative
       ``--watch`` or a ``--count`` below 1. The usage follows on stderr.
