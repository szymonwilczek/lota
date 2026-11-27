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
         [--status-path PATH] [--once]

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
   * - ``--once``
     -
     - Print the verdict once and exit with its code.
   * - ``-h``, ``--help``
     -
     - Print the usage and exit 0.

Without ``--status-path`` the script takes the first of
``$XDG_RUNTIME_DIR/lota-hook/lota-status``,
``/run/user/<uid>/lota-hook/lota-status`` and
``/tmp/lota-<uid>/lota-status`` that exists when it starts, and the last
of them when none does. It does not look again later.

The verdict is read in this order:

.. list-table::
   :header-rows: 1
   :widths: 20 80

   * - Verdict
     - Status file
   * - ``OFFLINE``
     - Missing, or ``LOTA_OFFLINE=1``.
   * - ``TRUSTED``
     - ``LOTA_ATTESTED=1``.
   * - ``UNTRUSTED``
     - ``LOTA_ATTESTED=0``.
   * - ``OFFLINE``
     - ``LOTA_ATTESTED`` missing or another value.

The hook zeroes the file when it loses the agent, so ``LOTA_OFFLINE`` is
read first: a zeroed file would otherwise read as ``UNTRUSTED``. The
script prints ``watching <path>, polling every <n>s (Ctrl-C to stop)``,
two lines on the refresh of the hook, and then one line, ``<HH:MM:SS>
<verdict>``, each time the verdict changes. ``--once`` prints one such
line.

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
     - ``--once`` and ``OFFLINE``.
   * - 64
     - An unknown option, an option without its value, or an
       ``--interval`` that is not an integer of at least 1.

The hook leaves the status file in place when the title exits, so the
last verdict stays after the title is gone. ``LOTA_UPDATED`` and
``LOTA_PID`` in the file tell when, and by which process, it was written
(see `Files <../../../Documentation/userspace-api/wine-hook.rst>`_).
