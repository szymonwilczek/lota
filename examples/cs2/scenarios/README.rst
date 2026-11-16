.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

=============
CS2 scenarios
=============

Three checks against Counter-Strike 2 launched as in
`Counter-Strike 2 under Proton <../README.rst>`_:

``verify-attested.sh``
  Follows the status file of the hook and prints each change of the
  verdict.

`agent-down <agent-down.rst>`_
  Takes the agent away from a running title and shows what the hook
  writes, and how it reconnects.

`lib-block <lib-block.rst>`_
  Preloads a library the agent does not allow into the title and shows
  the refusal.

verify-attested.sh
==================

.. code-block:: console

   $ examples/cs2/scenarios/verify-attested.sh [--interval SEC]
         [--status-path PATH] [--max-age SEC] [--once]

.. list-table::
   :header-rows: 1
   :widths: 30 20 50

   * - Option
     - Default
     - Meaning
   * - ``--interval SEC``
     - 1
     - Seconds between two reads, an integer of at least 1.
   * - ``--status-path PATH``
     - see below
     - The status file.
   * - ``--max-age SEC``
     - see below
     - Oldest ``LOTA_UPDATED`` still read as a verdict, an integer of at
       least 1.
   * - ``--once``
     -
     - Print the verdict once and exit with its code.
   * - ``-h``, ``--help``
     -
     - Print the usage and exit 0.

Without ``--status-path`` each read takes the first ``lota-status`` that
exists in ``$LOTA_HOOK_TOKEN_DIR``, ``$XDG_RUNTIME_DIR/lota-hook``
(``/run/user/<uid>/lota-hook`` when ``XDG_RUNTIME_DIR`` is unset) and
``/tmp/lota-<uid>``, the order in which the hook settles its token
directory, and reads ``OFFLINE`` when none exists. A watcher started
before the title picks the file up once the hook writes it.

``--max-age`` defaults to three times the period the hook reads from
``LOTA_HOOK_REFRESH_SEC``, 60 when that is unset or not positive, and to
15 at least. A running hook rewrites the file about
once in that period, so a ``LOTA_UPDATED`` older than ``--max-age``
means that no hook writes it any more.

The verdict is read in this order:

.. list-table::
   :header-rows: 1
   :widths: 20 80

   * - Verdict
     - Status file
   * - ``OFFLINE``
     - Missing, or ``LOTA_OFFLINE=1``.
   * - ``OFFLINE (stale)``
     - ``LOTA_UPDATED`` missing or older than ``--max-age``.
   * - ``TRUSTED``
     - ``LOTA_ATTESTED=1``.
   * - ``UNTRUSTED``
     - ``LOTA_ATTESTED=0``.
   * - ``OFFLINE``
     - ``LOTA_ATTESTED`` missing or another value.

The hook zeroes the file when it loses the agent, so ``LOTA_OFFLINE`` is
read first: a zeroed file would otherwise read as ``UNTRUSTED``. The
script prints ``polling every <n>s (Ctrl-C to stop)`` and two lines on
the refresh of the hook. It then prints ``watching <path>``, or
``watching no status file``, each time the file it reads changes, and
``<HH:MM:SS> <verdict>`` each time the verdict changes. ``--once`` prints
one verdict line.

.. list-table::
   :header-rows: 1
   :widths: 10 90

   * - Exit
     - Meaning
   * - 0
     - ``--once`` and ``TRUSTED``; ``--help``.
   * - 1
     - ``--once`` and ``UNTRUSTED``.
   * - 2
     - ``--once`` and ``OFFLINE`` or ``OFFLINE (stale)``.
   * - 64
     - An unknown option, an option without its value, or an
       ``--interval`` or ``--max-age`` that is not an integer of at
       least 1.

The hook leaves the status file in place when the title exits; the
verdict turns ``OFFLINE (stale)`` once ``--max-age`` has passed since
the last write (see
`Files <../../../Documentation/userspace-api/wine-hook.rst>`_).
