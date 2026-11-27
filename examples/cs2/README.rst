.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

=============================
Counter-Strike 2 under Proton
=============================

Counter-Strike 2 runs as a Windows program under Proton, inside the
pressure-vessel container of the Steam Linux Runtime. The LOTA Wine hook,
``liblota_wine_hook.so``, is a Linux library preloaded into that process
tree. It connects to the agent on the host, keeps a token current and
writes it, with a status file, into a directory of the player's runtime
directory. This page wires it into CS2 on the player's own Steam install
and checks the result.

The hook itself, which processes it activates in, the files it writes and
its environment are described in
`the Wine hook <../../Documentation/userspace-api/wine-hook.rst>`_. The
player's version of these steps is in
`Installing LOTA on your PC <../../Documentation/player/index.rst>`_.

Requirements
============

* The agent running as the daemon, which signs tokens with the TPM; the
  installed package starts it. An agent started with ``--test-ipc`` has
  no TPM and issues no token.
* The player in the ``lota`` group, in a session started after joining
  it.
* A socket for the player's session. The agent opens
  ``$XDG_RUNTIME_DIR/lota/lota.sock`` for each ``container_listener_uid``
  of its configuration, and for the user its own ``XDG_RUNTIME_DIR``
  names, as described in `IPC <../../Documentation/agent/ipc.rst>`_.
* Both halves of the hook, 64-bit and 32-bit, under ``/usr`` or
  ``/usr/local``, as the package installs them (see
  `Builds <../../Documentation/userspace-api/wine-hook.rst>`__).

``lota-steam-setup`` configures the socket. Either command writes a file
the agent reads at its next start, and neither restarts it: a restart
spends the boot commitment in PCR 14, so the change takes effect at the
next boot.

.. code-block:: console

   $ sudo lota-steam-setup --register-uid
   $ sudo lota-steam-setup --install-systemd-dropin

``--register-uid`` writes ``container_listener_uid = <uid>`` into
``/etc/lota/lota.conf`` (``LOTA_CONF``), before its first ``[profile]``
section. It checks the result with ``lota-agent --dump-config`` and puts
the old file back when the check fails. ``--install-systemd-dropin``
writes ``10-xdg-runtime.conf`` into
``/etc/systemd/system/lota-agent.service.d/`` (``LOTA_SETUP_DROPIN_DIR``),
with ``Environment=XDG_RUNTIME_DIR=/run/user/<uid>``, and reloads
systemd. Both take the uid of the player from ``SUDO_UID``, which must
not be 0, and need root; ``--install-systemd-dropin`` with
``LOTA_SETUP_DROPIN_DIR`` set skips the root check and the reload.

Checking the host
=================

.. code-block:: console

   $ lota-steam-setup --verify

The script checks, in order, that ``XDG_RUNTIME_DIR`` is set, the agent
socket (``LOTA_AGENT_SOCKET``) exists and the player may read and write
it, the player is in the ``lota``
group, the container socket exists and the token directory can be
created. A hook that is missing, or installed as one half only, is a
warning and not an issue. Without ``--verify`` it also
creates ``$XDG_RUNTIME_DIR/lota/`` with mode ``0750`` and group ``lota``.
It prints the launch option and ends with
``[OK]   All checks passed.  LOTA Steam integration is ready.``, or with
``<n> issue(s) detected`` and exit code 1. An unknown option exits 1 as
well.

The launch option
=================

In Steam, open **Properties** of Counter-Strike 2 and set
**Launch Options** to:

.. code-block:: text

   LOTA_HOOK_LOG_LEVEL=info lota-proton-hook %command%

The next launch is hooked. ``lota-proton-hook`` runs before Proton starts
and:

* exits to the command unchanged, after one line on stderr, when
  ``LOTA_HOOK_DISABLE`` is ``1`` or ``true``;
* puts the hook into ``LD_PRELOAD``: ``LOTA_HOOK_LIB_PATH`` when it is
  set, with no search; else both halves through ``$LIB`` when both are
  installed, else the one found;
* limits the hook to the title and its compatibility tools, from
  ``STEAM_COMPAT_INSTALL_PATH`` and ``STEAM_COMPAT_TOOL_PATHS``, unless
  ``LOTA_HOOK_ACTIVATE_PATH`` and ``LOTA_HOOK_ACTIVATE_PROGRAM`` are set;
* creates the token directory and adds it, with the directory of the
  socket, to ``PRESSURE_VESSEL_FILESYSTEMS_RW``, so the container sees
  both on the paths of the host;
* runs the command through ``lota-protect``, which puts the whole process
  tree of the title in the protected set of the agent.

A missing hook prints ``lota-proton-hook: hook library not found`` and
``lota-proton-hook: continuing without the hook``, and a missing
``lota-protect`` prints
``lota-proton-hook: lota-protect not found, starting unprotected``; the
title starts in both cases. The tools are described in
`Launch tools <../../Documentation/userspace-api/wine-hook.rst>`__.

With the publishers of the agent enrolled (see
`publishers <../../Documentation/agent/publishers.rst>`_), the launch
option also names the publisher of the title, the id
``lota-agent --list-publishers`` prints:

.. code-block:: text

   LOTA_HOOK_PUBLISHER=<hex id> LOTA_HOOK_LOG_LEVEL=info \
       lota-proton-hook %command%

The line is wrapped here; Steam takes it on one line.

Why a launch option
-------------------

The hook has to be a Linux library in the process tree Steam starts: a
Windows DLL inside the Wine prefix cannot open the ``AF_UNIX`` socket of
the agent. Something has to set ``LD_PRELOAD`` before Proton starts, and
Steam offers two places for it: the launch options of a title and a
compatibility tool in ``compatibilitytools.d``. Three other ways were
examined and are not shipped:

* A compatibility tool. A tool names the one tool it runs on with
  ``require_tool_appid``, so a LOTA layer would fix the Proton version of
  the player. A tool that ran whichever Proton the player chose would
  depend on how Steam selects tools, which Steam does not document.
* Writing the launch option into ``localconfig.vdf``. Steam owns the
  file and rewrites it when it exits, so an edit made while Steam runs is
  lost.
* A preload for the whole machine, in ``/etc/ld.so.preload`` or a login
  profile. It puts the hook into every process of the machine.

A launcher shipped by a publisher starts the title itself, so it sets
``LD_PRELOAD`` and ``PRESSURE_VESSEL_FILESYSTEMS_RW`` in the environment
of the process it creates, and the player sets nothing.

The cost of protection
----------------------

``lota-protect`` puts every process of the title in the protected set.
With the agent in ``enforce`` mode and ``strict_mmap`` on, a protected
process may map executable only files that an ``allow_verity`` or a
``trust_lib`` entry covers (see
`configuration <../../Documentation/agent/configuration.rst>`_), and the
title, Proton and the runtime map many. A refused load is logged by the
hook, wrapped here:

.. code-block:: text

   lota-hook: <file> did not load while this process is in LOTA's
       protected set -- a protected process may map only objects the
       agent allows, so cover this one with an allow_verity or trust_lib
       entry in lota.conf

and recorded as ``LOTA_REFUSED_OBJECT`` in the status file. Without
``strict_mmap`` the gate refuses no file mapping of a protected process;
``block_anon_exec`` refuses anonymous executable memory.

What the hook produces
======================

The hook writes into ``$XDG_RUNTIME_DIR/lota-hook/`` by default:

``lota-status``
  ``KEY=value`` lines: ``LOTA_ATTESTED``, ``LOTA_OFFLINE``, ``LOTA_FLAGS``,
  ``LOTA_VALID_UNTIL``, ``LOTA_PROTECTED`` and others.

``lota-token.bin``, ``lota-attestation.bin``, ``lota-boot-evidence.bin``
  The token, the token with the flags it was read with, and the boot
  evidence. They exist only while the host is attested.

The keys, the formats and the order in which the hook picks the
directory are in
`Files <../../Documentation/userspace-api/wine-hook.rst>`__. The
directory of the socket, ``$XDG_RUNTIME_DIR/lota/``, belongs to the agent
and holds no file of the hook.

A hooked launch logs, at ``info``:

.. code-block:: text

   lota-hook: initializing (token_dir=<dir>, refresh=60s)
   lota-hook: hook active (pid=<pid>)
   lota-hook: connected to agent
   lota-hook: registered pid=<pid> for runtime enforcement

``LOTA_HOOK_REFRESH_SEC`` sets the refresh, and ``LOTA_HOOK_LOG_LEVEL``
takes ``debug``, ``info``, ``warn``, ``error`` or ``silent``. The lines go
to the stderr of the title.

When attestation is unavailable
===============================

The hook does not stop the title. When no agent answers, it logs the
reason, writes ``LOTA_OFFLINE=1``, removes the binary files and keeps
trying; a lost connection logs
``lota-hook: connection lost (<reason>), reconnecting...``. A missing hook
or ``LOTA_HOOK_DISABLE`` starts the title without the hook. Whether a title
runs without a token is for its anti-cheat to decide.

Troubleshooting
===============

.. list-table::
   :header-rows: 1
   :widths: 45 55

   * - Message
     - Cause
   * - ``lota-proton-hook: hook library not found``
     - ``LOTA_HOOK_LIB_PATH`` names no file, or, without it, neither
       half is under ``/usr`` or ``/usr/local`` (``LOTA_HOOK_LIB_ROOTS``).
   * - ``lota-hook: cannot reach the agent at <socket>: <error> --
       <hint>``
     - The hint names the cause: ``EACCES`` or ``EPERM``, the session is
       usually missing the ``lota`` group; ``ENOENT``, the agent is not
       running or has no listener for this session; ``ECONNREFUSED``, the
       agent is stopped or restarting; ``ETIMEDOUT``, the agent did not
       answer before the connect timeout.
   * - ``lota-hook: the agent issued no token: <error> -- <hint>``
     - The agent answered and refused. An unknown profile needs
       ``LOTA_HOOK_PUBLISHER``; the others are consent, no TPM, a locked
       TPM and the rate limit.
   * - ``lota-hook: the agent will not attest for publisher ...``
     - The publisher of ``LOTA_HOOK_PUBLISHER`` is not one the agent
       attests for.
   * - ``lota-hook: <dir> is inside this container, so the host cannot
       read the status or the token written there; launch the title
       through lota-proton-hook, which shares it``
     - The hook was preloaded without the wrapper, so the token directory
       is not shared with the host.
   * - ``... did not load while this process is in LOTA's protected
       set ...``
     - See `The cost of protection`_.

The messages are wrapped here. ``lota-steam-setup --verify`` looks for
the hook only under ``/usr`` and ``/usr/local``, whatever
``LOTA_HOOK_LIB_PATH`` and ``LOTA_HOOK_LIB_ROOTS`` say, and checks that
the socket exists and the player may read and write it: a socket no
agent listens on passes. An agent that refuses the connection or the
publisher leaves ``LOTA_ATTESTED=0`` with ``LOTA_OFFLINE=0`` in the
status file. An agent that refuses a token leaves the flags of its status
there, ``LOTA_ATTESTED=1`` on an attested host, and the hook removes the
token files: the refusal shows as a missing ``lota-token.bin`` and in the
log of the hook.

Scenarios
=========

`scenarios/ <scenarios/README.rst>`_ holds three checks against a running
CS2:

* ``verify-attested.sh`` follows ``lota-status`` and prints each change
  of state.
* `agent-down <scenarios/agent-down.rst>`_ stops ``lota-agent
  --test-signed`` under a running title and brings it back.
* `lib-block <scenarios/lib-block.rst>`_ preloads a library the agent does
  not allow into the title and shows the refusal.

Other anti-cheat
================

The hook is a library preloaded into the process of the title, and an
anti-cheat that does not expect it may treat it as an injected library.
VAC is such an anti-cheat, so the walk-through is meant for a match
against bots or a server that does not enforce VAC. The hook sends
nothing to the game server: its output stays in the files above.
