.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

==========
agent-down
==========

An agent goes away under a running Counter-Strike 2. The daemon takes
the title with it. Under ``lota-agent --test-signed``, which protects
nothing, the title keeps running, the hook marks the host offline and
removes its token files, and it connects again when an agent answers on
the socket.

How the agent goes away
=======================

The daemon refuses every signal but 0 and ``SIGHUP``, from root too, so
``kill`` and ``pkill`` do not end it; ``pkill lota-agent`` ends
``lota-attest.service``, a ``lota-agent --attest`` that does not refuse
them. The daemon stops with ``sudo systemctl stop
lota-agent.socket lota-agent``, which spends the boot commitment in PCR
14: every later start of the daemon in that boot exits 78, and it attests
again after a reboot (see `the agent lifecycle
<../../../Documentation/agent/lifecycle.rst>`_).

A daemon that exits sends ``SIGKILL`` to every protected process (see
`protection <../../../Documentation/agent/protection.rst>`_), and
``lota-protect`` put the title in the protected set. The title ends with
the daemon, before its hook marks the host offline, and the status file
keeps the last verdict.

The scenario therefore runs against ``lota-agent --test-signed``, which
signs tokens with the TPM, loads no BPF and so protects nothing, reports
the host attested and stops on ``SIGINT``. It takes the sockets only
while no other agent holds them, so it runs while the daemon and its
socket unit are stopped. Like the daemon it opens the socket of each
``container_listener_uid`` and of the user its ``XDG_RUNTIME_DIR`` names:

.. code-block:: console

   $ sudo env XDG_RUNTIME_DIR=/run/user/$(id -u) lota-agent --test-signed

Running it
==========

Start ``--test-signed`` as above and launch CS2 with the launch option of
`Counter-Strike 2 under Proton <../README.rst>`_. Once the title runs,
follow the verdict in a terminal with
`verify-attested.sh <README.rst>`_. The watcher picks the status file
when it starts: started before the hook has written the file, it watches
``/tmp/lota-<uid>/lota-status`` and stays at ``OFFLINE``.

.. code-block:: console

   $ examples/cs2/scenarios/verify-attested.sh
   watching /run/user/<uid>/lota-hook/lota-status, polling every 1s
       (Ctrl-C to stop)
   <two lines on the refresh of the hook>
   <time> TRUSTED

The first line is wrapped here.

1. Stop the agent: ``Ctrl-C`` in the terminal of ``--test-signed``. The
   hook logs
   ``lota-hook: connection lost (<error>), reconnecting...``, waits one
   second and tries again. The first attempt that fails logs
   ``lota-hook: cannot reach the agent at <socket>: <error> -- <hint>``,
   once for each reason, and rewrites the status file; the watcher prints
   ``OFFLINE``. The file then reads:

   .. code-block:: console

      $ grep -E '^LOTA_(ATTESTED|OFFLINE)=' \
            $XDG_RUNTIME_DIR/lota-hook/lota-status
      LOTA_ATTESTED=0
      LOTA_OFFLINE=1
      $ ls $XDG_RUNTIME_DIR/lota-hook/
      lota-status

   ``lota-token.bin``, ``lota-attestation.bin`` and
   ``lota-boot-evidence.bin`` are removed with the connection. The title
   keeps running.

2. Start ``--test-signed``. The hook tries every
   ``LOTA_HOOK_REFRESH_SEC`` (60 by default), so within that time it logs
   ``lota-hook: connected to agent``, writes the status and the token
   files again, and the watcher prints ``TRUSTED``.

3. Quit the title. The hook leaves the status file and the token files in
   place, so the watcher keeps the last verdict.

What it shows
=============

* The hook does not end or hold the title when the agent goes away; the
  daemon ends the processes it protects.
* ``LOTA_OFFLINE`` tells a host whose agent is gone from one whose agent
  refuses: a reader of ``LOTA_ATTESTED`` alone sees both as 0.
* A hook that outlives the agent leaves no token on disk past the
  connection it was read on.
* The hook reconnects by itself, without launching the title again.

When it stays offline
=====================

The ``cannot reach the agent`` line names the socket and the cause:

* ``the agent is not running, or its per-session listener is not
  configured for this session``: the socket is missing. The agent logs
  ``IPC extra listener on <socket>`` for each per-session socket it
  opens; without that line, the user is not a ``container_listener_uid``
  and ``XDG_RUNTIME_DIR`` did not reach the agent.
* ``the session is usually missing the lota group``: the socket exists
  and the session may not open it. ``id`` shows whether the session
  carries ``lota``; Steam started from a session without it passes none to
  the title.
