.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

=========
Wine hook
=========

A Windows title under Wine or Proton cannot link ``liblotagaming.so``.
``liblota_wine_hook.so`` is loaded into the Wine process with ``LD_PRELOAD``,
talks to the agent through its own copy of the gaming SDK and keeps a few
files in a token directory, which code on the Windows side reads through the
``Z:`` drive. The header is ``lota_wine_hook.h``
(:ghsrc:`include/lota_wine_hook.h`), the implementation
:ghsrc:`src/sdk/lota_wine_hook.c` and the pkg-config module
``lota-wine-hook``. Setting it up on a player's machine is in
:doc:`../admin-guide/lota-install`.

Lifecycle
=========

The library's constructor reads the environment, decides whether to activate
(below), picks the token directory and starts a refresh thread; it does no
agent I/O itself. The thread connects to the agent, writes the files, adds the
process to the protected set and subscribes to ``LOTA_EVENT_STATUS`` and
``LOTA_EVENT_ATTEST``, so every attestation round rewrites them. If the agent
refuses the subscription, the thread asks for the status every
``LOTA_HOOK_REFRESH_SEC`` seconds. An unreachable agent is retried at the same
interval, and a lost connection is reconnected.

The destructor stops the thread and disconnects. The files stay: the
activated processes of one launch share the directory, and a helper that
exits before the title would remove what the title's hook wrote.

A child forked from an activated process starts no thread of its own. It
keeps the protection its parent had at the fork; an ``exec`` in which the
hook activates registers again.

``LOTA_HOOK_DISABLE`` set to ``1`` or ``true`` turns the library off in any
process.

Activation
==========

``LD_PRELOAD`` reaches every program the launcher runs, and an activated
process waits for its refresh thread at exit, so the hook decides from
``/proc/self/exe`` which processes it activates in. A process whose
executable cannot be read activates. Otherwise the first rule that applies
decides:

#. When ``LOTA_HOOK_ACTIVATE_PROGRAM`` is set and the executable is Wine's
   loader (``wine``, ``wine64``, ``wine-preloader``, ``wine64-preloader``),
   the hook activates only when the Windows program in ``argv[1]`` lies in
   that directory. The directory is matched by whole components, on any
   drive, with ``/`` and ``\`` alike and ASCII case ignored.
#. When ``LOTA_HOOK_ACTIVATE_PATH`` is not empty, the hook activates only for
   an executable under one of its comma-separated prefixes. The skip lists do
   not apply.
#. An executable under a prefix of ``LOTA_HOOK_SKIP_PATH`` is skipped.
#. An executable under ``/usr/``, ``/bin/``, ``/sbin/``, ``/lib/`` or
   ``/lib64/``, or under the same prefixes below ``/run/host/``, is skipped.
#. Anything else activates.

Inside a Proton prefix the title and the prefix's services run from the same
loader binary, which is why the first rule looks at the program the loader
hosts.

Token directory
===============

The files go into the first usable of:

#. ``$LOTA_HOOK_TOKEN_DIR``, without a trailing ``/``;
#. ``$XDG_RUNTIME_DIR/lota-hook``;
#. ``/tmp/lota-<uid>``.

A missing directory is created with mode 0700. A directory that is a
symbolic link or that another user owns is reported and the next candidate
taken; one at a mode other than 0700 is set to 0700 and its old mode
reported. When no candidate is usable the hook stays inactive. It never uses
``$XDG_RUNTIME_DIR/lota``, where the agent keeps the socket for containers.
The chosen path is exported as ``LOTA_HOOK_TOKEN_DIR`` for the code that
reads the files. Inside a container the hook warns when the directory is not
a mount: the host would see none of the files.

Files
=====

Each file is written to a temporary file, synced and renamed into place, so
a reader always sees one complete version of a file.

``lota-status`` (``LOTA_HOOK_STATUS_FILE``)
  Text, one ``KEY=value`` per line:

  .. list-table::
     :header-rows: 1
     :widths: 30 70

     * - Key
       - Value
     * - ``LOTA_ATTESTED``
       - 1 when ``LOTA_FLAG_ATTESTED`` is set, else 0.
     * - ``LOTA_OFFLINE``
       - 1 when no agent answers.
     * - ``LOTA_FLAGS``
       - The ``LOTA_FLAG_*`` word, as ``0x%08x``.
     * - ``LOTA_VALID_UNTIL``
       - Unix time the current attestation expires.
     * - ``LOTA_ATTEST_COUNT``, ``LOTA_FAIL_COUNT``
       - The agent's round counters.
     * - ``LOTA_UPDATED``
       - Unix time the file was written. A running hook rewrites the file
         about once in ``LOTA_HOOK_REFRESH_SEC`` with nothing new to say
         too, so a time several periods old means that no hook writes it
         any more.
     * - ``LOTA_PID``
       - The process that wrote it.
     * - ``LOTA_PROTECTED``
       - 1 once the agent took the process into its protected set.
     * - ``LOTA_REFUSED_OBJECT``, ``LOTA_REFUSED_AT``
       - The object the runtime gate last refused to this process, and when;
         present only after a refusal.

  When the agent is gone, or refuses the publisher, the file is rewritten
  with the status fields at zero, and ``LOTA_OFFLINE`` is 1 in the first
  case.

``lota-token.bin`` (``LOTA_HOOK_TOKEN_FILE``)
  A token in the wire format of :doc:`server`, requested with no nonce. It is
  signed by the TPM and answers no server's challenge, so a relying party
  that needs freshness asks for a token through the SDK with its own nonce.

``lota-attestation.bin`` (``LOTA_HOOK_SNAPSHOT_FILE``)
  The same token behind a 16-byte header with the flags it was read with, in
  one file, so a reader does not race between the status and token files. The
  format is in :doc:`anticheat`, whose file mode reads it.

``lota-boot-evidence.bin`` (``LOTA_HOOK_BOOT_EVIDENCE_FILE``)
  The boot evidence for the token, written once and kept until the connection
  or the attestation is lost, and absent when the agent gave none.

The three binary files exist only while the host is attested. Losing the
agent or ``LOTA_FLAG_ATTESTED`` removes them.

Runtime gate refusals
=====================

The hook wraps ``dlopen()``. When the real call fails in a process the hook
registered with the agent, or a child forked from one, the wrapper asks the
agent over a connection of its own what the gate refused after the call
started. A refusal is logged on stderr, with the object's path, and written
to the status file. The handle, ``dlerror()`` and
``errno`` are those of the real call. A refusal recorded by a forked child
survives its parent's next status write.

Environment
===========

.. list-table::
   :header-rows: 1
   :widths: 34 66

   * - Variable
     - Effect
   * - ``LOTA_HOOK_DISABLE``
     - ``1`` or ``true`` turns the hook off.
   * - ``LOTA_HOOK_ACTIVATE_PATH``
     - Comma-separated executable prefixes to activate in, replacing the
       skip lists.
   * - ``LOTA_HOOK_ACTIVATE_PROGRAM``
     - The title's directory as Wine sees it; Wine's loader activates only
       for a program inside.
   * - ``LOTA_HOOK_SKIP_PATH``
     - Comma-separated prefixes to skip, on top of the system paths.
   * - ``LOTA_HOOK_SOCKET``
     - The agent socket; unset, the order of ``socket_path`` in
       :doc:`gaming`.
   * - ``LOTA_HOOK_PUBLISHER``
     - The publisher to attest for: hex SHA-256 of its CA anchor's
       SubjectPublicKeyInfo, either case. A host enrolled with more than one
       publisher issues no token without it. An invalid value is reported
       and ignored.
   * - ``LOTA_HOOK_TOKEN_DIR``
     - The token directory (above).
   * - ``LOTA_HOOK_REFRESH_SEC``
     - Seconds between retries and status polls, default 60
       (``LOTA_HOOK_DEFAULT_REFRESH_SEC``).
   * - ``LOTA_HOOK_LOG_LEVEL``
     - ``debug``, ``info``, ``warn``, ``error`` or ``silent``, default
       ``warn``. Messages go to stderr.

The hook connects with a 2000 ms timeout (``LOTA_HOOK_CONNECT_TIMEOUT_MS``)
and waits up to 20000 ms (``LOTA_HOOK_REQUEST_TIMEOUT_MS``) for an answer:
a status request may wait on a measurement. A request that times out
is asked again on the next cycle, on the same connection.

Builds
======

The hook links its own copy of the gaming SDK and is compiled with
``-fvisibility=hidden``, so its copy cannot bind in place of a
``liblotagaming.so`` the title loads; only the functions marked
``LOTA_HOOK_EXPORT`` and ``dlopen()`` are visible (:doc:`stability`).

On x86_64 a 32-bit hook is built when the compiler can link ``-m32``
programs (``LOTA_HOOK32=auto``) and installed into ``/usr/lib`` beside the
64-bit one in ``/usr/lib64``. ``lota-proton-hook`` names the hook through
the loader's ``$LIB`` token, so a 32-bit Wine process loads the 32-bit half.
``make install`` on x86_64 refuses a tree without it; the 32-bit build needs
a multilib toolchain.

Launch tools
============

``lota-proton-hook`` (:ghsrc:`scripts/lota-proton-hook`) is the Steam launch
option, ``lota-proton-hook %command%``. It:

* prepends the hook to ``LD_PRELOAD``, as a ``$LIB`` path when ``lib64/`` and
  ``lib/`` under one of ``LOTA_HOOK_LIB_ROOTS`` (default ``/usr:/usr/local``)
  both hold it, else the first copy found, or ``LOTA_HOOK_LIB_PATH``;
* sets ``LOTA_HOOK_ACTIVATE_PATH`` to ``STEAM_COMPAT_INSTALL_PATH`` and the
  directories in ``STEAM_COMPAT_TOOL_PATHS``, and
  ``LOTA_HOOK_ACTIVATE_PROGRAM`` to the install directory from
  ``steamapps/common/`` on, or to the whole host path outside a Steam
  library, each only when it is unset;
* creates the token directory and adds it, with the directory of the agent
  socket, to ``PRESSURE_VESSEL_FILESYSTEMS_RW``, so the Steam Runtime
  container shares both with the host;
* runs the command through ``lota-protect`` (``LOTA_PROTECT_PATH``, default
  from ``PATH``).

A missing hook or ``lota-protect`` is reported and the game starts without
it. With ``LOTA_HOOK_DISABLE`` set to ``1`` or ``true`` the command runs
directly, without the hook and without ``lota-protect``.

``lota-protect [--] PROGRAM [ARG]...`` (:ghsrc:`src/sdk/lota_protect.c`)
adds itself to the agent's protected set and executes the program. The
protection survives the ``exec`` and passes to every process the program
creates, so nothing in the tree runs unprotected. It reads
``LOTA_HOOK_SOCKET`` and ``LOTA_HOOK_PUBLISHER``. When the agent refuses
because a tracer holds the process, the program is not started and
``lota-protect`` exits with 125, as it does when misused; any other failure
starts the program unprotected. It exits with 126 when the program cannot be
executed and 127 when it is not found; otherwise the exit status is the
program's.

``lota-steam-setup`` (:ghsrc:`scripts/lota-steam-setup`) checks the agent,
the ``lota`` group, the hook library, the container socket and the token
directory, creates ``$XDG_RUNTIME_DIR/lota/`` and prints the launch option.
Its options are in :doc:`../admin-guide/lota-install`.

Functions
=========

.. kernel-doc:: include/lota_wine_hook.h
