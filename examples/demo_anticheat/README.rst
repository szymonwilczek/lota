.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

==============
demo_anticheat
==============

``demo_anticheat`` is the heartbeat producer of the demo. It opens a
direct-mode session of the
`anti-cheat SDK <../../Documentation/userspace-api/anticheat.rst>`_
against the local agent, builds a heartbeat with ``lota_ac_heartbeat()``
at a fixed interval and posts it to
`demo_server <../demo_server/README.rst>`_ with libcurl. The game client,
`trust_pong <../demo_game/README.rst>`_, is a separate process and learns
the verdict from the server.

Building
========

``make examples`` builds ``build/examples/demo_anticheat`` when
``pkg-config`` finds ``libcurl``; otherwise it prints
``SKIP: demo_anticheat (install libcurl-devel)``. The fragment takes its
flags from the staged SDK (see `Building <../README.rst>`__), as a
studio's build takes them from the installed one:

.. code-block:: console

   $ cc $(pkg-config --cflags lota-anticheat lota-gaming libcurl) \
         -o producer heartbeat_loop.c \
         $(pkg-config --libs lota-anticheat lota-gaming libcurl)

``lota-gaming`` is on the line because the producer calls
``lota_connect_opts()`` and ``lota_protect_self()`` itself; a producer
that calls only ``lota_ac_*`` links ``lota-anticheat`` alone.

Running
=======

.. code-block:: console

   $ build/examples/demo_anticheat --server http://127.0.0.1:7443/heartbeat

.. list-table::
   :header-rows: 1
   :widths: 30 25 45

   * - Option
     - Default
     - Meaning
   * - ``-s``, ``--server URL``
     - ``http://127.0.0.1:7443/heartbeat``
     - The full URL heartbeats are posted to.
   * - ``-g``, ``--game-id ID``
     - ``trust-pong``
     - Game id of the session.
   * - ``-S``, ``--socket PATH``
     - discovery
     - Agent socket, as in ``lota_connect_opts()`` (see
       `the gaming SDK <../../Documentation/userspace-api/gaming.rst>`_).
   * - ``-u``, ``--publisher HEX``
     - none
     - Publisher profile of the session, the id
       ``lota-agent --list-publishers`` prints (see
       `publishers <../../Documentation/agent/publishers.rst>`_).
   * - ``-p``, ``--provider NAME``
     - ``eac``
     - ``eac``, ``battleye`` or ``be``; written into every heartbeat.
   * - ``-i``, ``--interval SEC``
     - 5
     - Seconds between heartbeats, 1 to 3599.
   * - ``-1``, ``--once``
     -
     - Send one heartbeat and exit with its verdict.
   * - ``-P``, ``--protect-self``
     -
     - Put the process in the protected set of the agent first.
   * - ``-F``, ``--require-full-image``
     -
     - Add ``LOTA_FLAG_IMAGE_FULLY_MEASURED`` to ``required_flags`` of the
       session.
   * - ``-T``, ``--tamper-marker PATH``
     - none
     - Corrupt each heartbeat sent while ``PATH`` exists.
   * - ``-O``, ``--print-runtime-objects``
     -
     - Print the objects of the runtime measurement and exit.
   * - ``-A``, ``--ca-cert PATH``
     - system CAs
     - CA that verifies an ``https://`` server.
   * - ``-E``, ``--client-cert PATH``; ``-K``, ``--client-key PATH``
     - none
     - Client certificate and key, together.
   * - ``-h``, ``--help``
     -
     - Print the usage to stderr and exit 0.

``LOTA_DEMO_INTERVAL_SEC`` sets the interval when it is 1 to 3599 and is
ignored otherwise; ``LOTA_DEMO_TAMPER_MARKER`` sets the marker. Options
take precedence over both.

At start the producer prints one line to stderr, wrapped here:

.. code-block:: text

   demo_anticheat: producer up (server=<url> game=<id> provider=<name>
       interval=<n>s once=<yes|no> tamper_marker=<path|(none)>)

and then one line per heartbeat, with ``reason`` only when the server
sent one:

.. code-block:: text

   demo_anticheat: seq=<n> state=<state> latency=<ms>ms http=<code>
       reason="<reason>"

``state`` and ``reason`` are copied from the answer of the server
without decoding escapes, ``?`` when there is no ``state``. A heartbeat
that cannot be built prints
``demo_anticheat: lota_ac_heartbeat: <SDK error> (<errno text>)`` and one
that cannot be posted ``demo_anticheat: curl: <error>``; the producer
goes on with the next one. SIGINT and SIGTERM end the wait between two
heartbeats, within a second, with
``demo_anticheat: shutdown requested, exiting``.

Exit codes
----------

.. list-table::
   :header-rows: 1
   :widths: 10 90

   * - Code
     - Meaning
   * - 0
     - ``TRUSTED``; ``--help``; ``--print-runtime-objects`` done.
   * - 1
     - ``UNTRUSTED``.
   * - 2
     - ``REJECT``.
   * - 3
     - The heartbeat was not built or not posted, the answer has no known
       ``state``, or the session, libcurl, ``--protect-self`` or
       ``--print-runtime-objects`` failed.
   * - 64
     - An unknown option or a bad value: ``--provider``, ``--interval``,
       or one of ``--client-cert`` and ``--client-key`` without the
       other. The usage follows on stderr.

With ``--once`` the code is that of the one heartbeat. Without it the
producer runs until SIGINT or SIGTERM and exits with the code of the last
heartbeat.

Protection
==========

``--protect-self`` opens a second connection to the agent, with the same
socket and publisher, and calls ``lota_protect_self()`` on it before the
session starts; the session keeps its own connection. The agent then
measures the code the process maps into every token it issues, as
described in `runtime measurement
<../../Documentation/agent/runtime-measurement.rst>`_. The producer prints
one line, wrapped here:

.. code-block:: text

   demo_anticheat: protected (pid=<pid>); every token now folds this
       process's measured code

and exits 3 with ``demo_anticheat: --protect-self: cannot reach the agent
(<error>)`` or ``demo_anticheat: --protect-self refused: <error>``. The
connection stays open for the life of the process, which keeps it in the
set.

``--require-full-image`` changes only the state of the session, which
the producer does not print: its lines and exit code stay the verdict of
the server. ``demo_server -require-full-image`` makes the same demand on
the server.

The runtime manifest
====================

``--print-runtime-objects`` prints, one path per line, the main binary and
each shared library the process maps, as
``lota_ac_list_runtime_objects()`` lists them. The list is the manifest
the server computes the expected measurement from, and the one
``lota-install --verity-manifest`` enables fs-verity on (see
`lota-install <../../Documentation/admin-guide/lota-install.rst>`_):

.. code-block:: console

   $ build/examples/demo_anticheat --print-runtime-objects \
         > runtime-manifest.txt
   $ demo_server -aik-pub aik.pem \
         -anticheat-binary build/examples/demo_anticheat \
         -anticheat-runtime-manifest runtime-manifest.txt

Mutual TLS
==========

libcurl verifies the peer and the host name of an ``https://`` server, by
the CAs of the system or the one ``--ca-cert`` names. With
``--client-cert`` and ``--client-key`` the producer presents its own
certificate, which ``demo_server -client-ca`` requires.
`mtls/ <../mtls/README.rst>`_ creates the certificates.

Tamper marker
=============

When the marker path exists as a heartbeat is sent, the producer XORs the
last byte of the packet with ``0xFF`` and prints:

.. code-block:: text

   demo_anticheat: tamper marker <path> present, flipped signature byte
       at offset <n>

The last byte belongs to the signature of the token. The header and the
token still parse, so the server answers ``UNTRUSTED`` with the signature
error of ``VerifyToken()``. The marker is checked at every heartbeat;
`demo_tamper.sh <../demo/README.rst>`_ creates and removes it during the
live demo.

run.sh
======

``run.sh`` drives the producer and the server against an agent on a
software TPM, without root, and checks two verdicts. It needs ``swtpm``,
``swtpm_setup``, ``tpm2_readpublic``, ``systemd-socket-activate`` and
``make all examples``:

.. code-block:: console

   $ examples/demo_anticheat/run.sh

It works in ``/tmp/lota-anticheat.XXXXXX`` and prints one line per step:

1. ``swtpm`` on TCP port ``TPM_PORT`` (42531), its control channel on
   the next port.
2. ``lota-agent --test-signed`` under ``systemd-socket-activate`` on
   ``lota.sock`` in the run directory, with an empty configuration file
   and the AIK metadata in the run directory.
3. One heartbeat to start the agent and provision the AIK, whose public
   key ``tpm2_readpublic`` then exports from handle ``0x81010002``, and
   the runtime manifest.
4. ``demo_server`` on ``SERVER_ADDR`` (``127.0.0.1:7543``) with that AIK,
   binary and manifest; one heartbeat must exit 0.
5. One heartbeat with the tamper marker present must exit 1, print
   ``UNTRUSTED`` and leave ``signature`` in the server log.

The run ends with:

.. code-block:: text

   PASS: the reference verifies an attested host and refuses a tampered token

A missing binary or command, or a failed step, prints a line
starting ``missing`` or ``FAIL:``, plus the logs of a failed step 4, and
exits 1. A ``swtpm_setup`` that fails ends the script with its own exit
status and no such line.

``LOTA_BUILD_DIR`` (``build``), ``BIN`` (the build directory) and
``EXAMPLES_BIN`` (its ``examples/``) say where the binaries are.
``TPM_PORT`` and ``SERVER_ADDR`` move the listeners. The run directory is
removed at exit unless ``KEEP_LOGS`` is set, which prints its path.
