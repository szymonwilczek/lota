.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

=========
Live demo
=========

``setup.sh`` runs the whole heartbeat chain on one host: a software TPM,
``lota-agent --test-signed`` against it, ``demo_server``,
``demo_anticheat`` and ``trust_pong``. ``demo_tamper.sh`` makes the
heartbeats fail verification while it runs, so the game shows the
failure path. The components are described in
`demo_server <../demo_server/README.rst>`_,
`demo_anticheat <../demo_anticheat/README.rst>`_ and
`demo_game <../demo_game/README.rst>`_.

Requirements
============

``setup.sh`` checks for ``make``, ``curl``, ``swtpm``, ``swtpm_setup``,
``tpm2_getrandom`` and ``tpm2_readpublic`` on every run, ``--dry-run``
included, and exits on the first one missing. The build step needs the
project build dependencies and the optional ones of the three examples:
``sdl2`` and ``libcurl`` for ``trust_pong``, ``libcurl`` for
``demo_anticheat`` and ``go`` for ``demo_server`` (see
`Optional dependencies <../README.rst>`_).

A real run needs root, because ``lota-agent --test-signed`` binds
``/run/lota/lota.sock``, and refuses to start while that socket exists.
Stop the installed agent before the demo.

Running the demo
================

From the repository root:

.. code-block:: console

   $ sudo -E examples/demo/setup.sh

``-E`` passes the caller's environment through ``sudo``: the
``LOTA_DEMO_*`` variables and the display variables ``trust_pong`` is
started with. The runner prints each step as ``==> Step N/7: ...`` and
waits for ENTER (``press ENTER to continue:``) after each of the first
six. Before the first step it creates the sandbox
``/tmp/lota-demo.XXXXXX``, which holds the logs, the TPM state, the AIK
and the runtime directory of the run.

1. **Build.** ``make all`` and ``make examples``. ``--no-build`` skips
   them.

2. **Software TPM.** The runner initialises a TPM 2.0 state with an EK in
   ``swtpm/`` (``swtpm_setup --createek --decryption --overwrite``) and
   starts ``swtpm socket`` with its command port on
   ``127.0.0.1:<tpm-port>`` and its control port on the next one. One
   ``tpm2_getrandom`` call checks that the TPM answers.

3. **Artefacts.** ``lota-agent`` in ``$BUILD_DIR`` and ``demo_server``,
   ``demo_anticheat`` and ``trust_pong`` in ``$BUILD_DIR/examples`` must
   exist.

4. **Agent.** ``lota-agent --test-signed`` starts with ``LOTA_TCTI`` set
   to ``swtpm:host=127.0.0.1,port=<tpm-port>``, ``LOTA_AIK_META_PATH`` to
   ``aik/aik_meta.dat`` and ``XDG_RUNTIME_DIR`` to ``runtime/`` in the
   sandbox, and with ``--config lota.conf``, an empty file there, so the
   ``/etc/lota/lota.conf`` of the host does not apply. The agent takes the
   two ``LOTA_*`` variables on its one-shot commands, ``--test-signed``
   among them; the daemon and a continuous ``--attest`` ignore them.
   The runner waits up to 20 seconds for ``/run/lota/lota.sock``, then
   exports the public part of the AIK at handle ``0x81010002`` to
   ``aik/aik.pem``, retrying for up to 30 seconds.

5. **Server.** ``demo_anticheat --print-runtime-objects`` writes
   ``runtime-manifest.txt``, and ``demo_server`` starts with the exported
   AIK, the producer binary, that manifest and
   ``--expected-games <game-id>=lota-demo-CS2-clone``. The runner waits
   up to 20 seconds for ``GET /state?game_id=<game-id>`` to answer.

6. **Producer.** One ``demo_anticheat --once`` heartbeat must come back
   ``TRUSTED``; then ``demo_anticheat`` runs in the background, one
   heartbeat per ``--interval`` seconds, with the tamper marker
   ``<sandbox>/tamper.marker``. The runner prints the marker path.

7. **Game.** ``trust_pong --server <url> --game-id <game-id>`` runs in
   the foreground. Under ``sudo`` it runs as ``SUDO_USER`` with
   ``DISPLAY``, ``WAYLAND_DISPLAY``, ``XAUTHORITY``,
   ``DBUS_SESSION_BUS_ADDRESS``, every exported ``SDL_*`` variable and
   ``XDG_RUNTIME_DIR``, the last one defaulting to ``/run/user/<uid>``;
   otherwise it runs as root with the ``XDG_RUNTIME_DIR`` of the runner,
   or the sandbox ``runtime/`` when that is unset.

Each producer heartbeat prints one line to ``logs/demo_anticheat.log``,
with a ``reason="..."`` field when the server gave one:

.. code-block:: text

   demo_anticheat: seq=7 state=TRUSTED latency=0.3ms http=200

``trust_pong`` polls the server every 750 ms and names the verdict in
its banner, over a strip in green for ``TRUSTED``, amber for
``UNTRUSTED``, yellow for ``CHECKING`` and grey for ``OFFLINE``.

Esc, Q or closing the window ends ``trust_pong``, and with it the run.
On exit, including SIGINT and SIGTERM, the runner sends
``lota-agent --shutdown``, stops the background processes and
``swtpm`` and removes the sandbox; SIGINT ends the run with status 130,
SIGTERM with 143, before any later step. With ``--keep-tmp`` it prints
``kept tmp dir: <sandbox>`` and leaves the sandbox in place.

Triggering the failure path
---------------------------

The sandbox is created by root with mode 0700, so the tamper script runs
as root too. From a second terminal, while the demo runs:

.. code-block:: console

   $ sudo examples/demo/demo_tamper.sh

The script creates the marker and holds it until Ctrl-C. At each
heartbeat the producer checks whether the marker exists; while it does,
the producer flips the last byte of the packet, which ends with the
token signature, and logs
``tamper marker <path> present, flipped signature byte at offset <n>``.
The server fails the signature check and answers ``UNTRUSTED`` with the
verification error as the reason.

``trust_pong`` shows ``UNTRUSTED`` after the first such heartbeat. After
the second one in a row it freezes the play field under an
``INTEGRITY LOSS`` banner with a red strip and the overlay
``session terminated after two UNTRUSTED heartbeats``, and prints
``trust_pong: session terminated after 2 consecutive UNTRUSTED
heartbeats`` to the terminal. When the script exits it removes the
marker, and the producer stops altering its packets. The freeze stays
until ``trust_pong`` exits.

The sandbox
===========

``setup.sh`` keeps all its state under ``/tmp/lota-demo.XXXXXX``:

.. list-table::
   :header-rows: 1
   :widths: 35 65

   * - Path
     - Content
   * - ``lota.conf``
     - Empty configuration of the agent
   * - ``swtpm/``
     - TPM state and ``swtpm.pid``
   * - ``aik/aik_meta.dat``
     - AIK metadata of the agent
   * - ``aik/aik.pem``
     - AIK public key handed to ``demo_server``
   * - ``runtime/``
     - ``XDG_RUNTIME_DIR`` of the agent
   * - ``runtime-manifest.txt``
     - ``demo_anticheat --print-runtime-objects`` output
   * - ``tamper.marker``
     - Exists while ``demo_tamper.sh`` holds it
   * - ``tpm.rand``
     - Output of the ``tpm2_getrandom`` check
   * - ``logs/agent.log``
     - ``lota-agent --test-signed``
   * - ``logs/demo_server.log``
     - ``demo_server``
   * - ``logs/demo_anticheat_once.log``
     - The first ``--once`` heartbeat
   * - ``logs/demo_anticheat.log``
     - The background producer, one line per heartbeat
   * - ``logs/swtpm.log``
     - ``swtpm socket``
   * - ``logs/runtime_manifest.log``
     - Errors of ``--print-runtime-objects``
   * - ``logs/tpm2_getrandom.log``, ``logs/tpm2_readpublic.log``
     - The TPM check and the AIK export

``trust_pong`` writes to the terminal that runs ``setup.sh``.

setup.sh reference
==================

.. code-block:: text

   setup.sh [--dry-run] [--yes] [--no-build] [--keep-tmp]
            [--listen HOST:PORT] [--game-id ID] [--interval SEC]
            [--tpm-port PORT]

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Meaning
   * - ``--dry-run``
     - Print each command prefixed with ``+`` and run nothing. Needs no
       root, uses ``/tmp/lota-demo.DRYRUN`` as the sandbox name and
       prints ``expects artifact: <path>`` for the step 3 checks.
   * - ``--yes``
     - Do not wait for ENTER between steps.
   * - ``--no-build``
     - Skip ``make all`` and ``make examples``.
   * - ``--keep-tmp``
     - Leave the sandbox in place on exit.
   * - ``--listen HOST:PORT``
     - ``demo_server`` listen address, default ``127.0.0.1:7443``. Sets
       the server URL to ``http://HOST:PORT``.
   * - ``--game-id ID``
     - Game id of the producer, the server and the game, default
       ``trust-pong``.
   * - ``--interval SEC``
     - Seconds between producer heartbeats, a positive integer, default
       5.
   * - ``--tpm-port PORT``
     - ``swtpm`` command port, 1 to 65534, default 23221. The control
       port is ``PORT+1``.
   * - ``-h``, ``--help``
     - Print the usage and exit 0.

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Variable
     - Meaning
   * - ``BUILD_DIR``, ``LOTA_BUILD_DIR``
     - Build directory, in this order, default ``build/`` in the
       repository.
   * - ``LOTA_DEMO_LISTEN``
     - Default of ``--listen``.
   * - ``LOTA_DEMO_SERVER_URL``
     - URL the producer, the game and the readiness check use, default
       ``http://`` and the listen address. ``--listen`` replaces it.
   * - ``LOTA_DEMO_GAME_ID``
     - Default of ``--game-id``.
   * - ``LOTA_DEMO_INTERVAL_SEC``
     - Default of ``--interval``.
   * - ``LOTA_DEMO_TPM_PORT``
     - Default of ``--tpm-port``.
   * - ``LOTA_DEMO_TPM_CTRL_PORT``
     - Refused: the control port is always ``--tpm-port`` plus one.

``setup.sh`` exits 1 with a ``setup.sh: <reason>`` line on a missing
command or artefact, an invalid option, a missing root, an existing
``/run/lota/lota.sock``, a first heartbeat other than ``TRUSTED`` and a
process that exits or does not answer in time. For a failing process it
prints the last 40 lines of its log first. After a run it exits with the
status of ``trust_pong``.

demo_tamper.sh reference
========================

.. code-block:: text

   demo_tamper.sh [--marker PATH] [--demo-dir DIR] [--hold-sec SEC]

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Meaning
   * - ``--marker PATH``
     - Marker file to create. Takes precedence over ``--demo-dir``.
   * - ``--demo-dir DIR``
     - Sandbox of ``setup.sh``; the marker is ``DIR/tamper.marker``.
       Without both options the script takes the most recently modified
       ``/tmp/lota-demo.*``.
   * - ``--hold-sec SEC``
     - Remove the marker after ``SEC`` seconds, a positive integer.
       Without it the script holds the marker until SIGINT or SIGTERM.
   * - ``-h``, ``--help``
     - Print the usage and exit 0.

The script resolves the marker path with ``realpath -m`` and refuses one
outside ``/tmp/lota-demo.*`` or in a directory that does not exist. On
exit it removes the marker, also one that existed before it started.
A refused option or path exits 1 with a ``demo_tamper.sh: <reason>``
line.

Recording
=========

``asciinema.cast`` is an asciinema recording of one cycle: the producer
heartbeats go from ``TRUSTED`` through ``UNTRUSTED`` back to
``TRUSTED`` while ``demo_tamper.sh --hold-sec`` holds the marker.

.. code-block:: console

   $ asciinema play examples/demo/asciinema.cast

``trust_pong`` draws in its own window, and the terminal that runs
``setup.sh`` is busy with it, so a recording follows the producer log
from a second terminal. The first terminal keeps the sandbox:

.. code-block:: console

   $ sudo -E examples/demo/setup.sh --no-build --keep-tmp --yes

The second one records the log and a timed tamper:

.. code-block:: console

   $ sudo -v
   $ asciinema rec -i 2 demo.cast
   $ SANDBOX=$(ls -1dt /tmp/lota-demo.* | head -n1)
   $ sudo tail -n 2 -f "$SANDBOX/logs/demo_anticheat.log" &
   $ sleep 8
   $ sudo examples/demo/demo_tamper.sh --demo-dir "$SANDBOX" --hold-sec 12
   $ sleep 10
   $ kill %1; exit

``sudo -v`` keeps the password prompt out of the recording, and
``-i 2`` cuts idle stretches to two seconds.

The agent grants one connection 20 tokens per 60 seconds and one uid 60.
Every heartbeat takes a token over the producer's connection, so the
default interval of 5 seconds stays inside the budget. A shorter
``--interval`` can run past it, and the heartbeats past it fail with a
``lota_ac_heartbeat:`` error line in place of a verdict.
