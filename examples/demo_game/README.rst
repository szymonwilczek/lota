.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

==========
trust_pong
==========

``trust_pong`` is an SDL2 paddle game that shows the verdict
`demo_server <../demo_server/README.rst>`_ holds for its game id. It reads
the verdict and produces no heartbeats: those come from
`demo_anticheat <../demo_anticheat/README.rst>`_, a separate process.
`setup.sh <../demo/README.rst>`_ runs the three together.

Building
========

``make examples`` builds ``trust_pong`` into ``build/examples/`` when
``pkg-config`` finds ``sdl2`` and ``libcurl``; otherwise it prints
``SKIP: trust_pong (install SDL2-devel, libcurl-devel)``. The program
links against ``liblotagaming`` from the staged SDK (see
`Building <../README.rst>`__).

Running
=======

.. code-block:: console

   $ build/examples/trust_pong --server http://127.0.0.1:7443 \
         --game-id trust-pong

.. list-table::
   :header-rows: 1
   :widths: 25 30 45

   * - Option
     - Default
     - Meaning
   * - ``--server URL``
     - ``http://127.0.0.1:7443``
     - Base URL of ``demo_server``, without an endpoint path.
   * - ``--game-id ID``
     - ``trust-pong``
     - Game id sent to ``/nonce`` and ``/state``.
   * - ``--socket PATH``
     - discovery
     - Agent socket. Without it the SDK tries ``/run/lota/lota.sock``,
       then ``$XDG_RUNTIME_DIR/lota/lota.sock`` (see
       `lota_connect_opts() <../../Documentation/userspace-api/gaming.rst>`_).
   * - ``-h``, ``--help``
     -
     - Print the usage to stderr and exit 0.

``trust_pong`` exits 0 when the player quits, 64 on an unknown option or
an extra argument, and 1 when libcurl, the polling thread or SDL fails to
start.

Start-up
--------

Before the window opens, ``trust_pong`` checks the server and then the
agent, once: it posts ``{"game_id": ID}`` to ``/nonce`` and expects a
``nonce`` and a ``session_id`` back; when both come back, it connects to
the agent and asks whether the host is attested. The nonce is not used.
A failed check of the server prints its line and skips the agent; one
that passes prints ``handshake OK``, and a failed check of the agent
prints its line after it, all on stderr:

.. code-block:: text

   trust_pong: handshake OK session=<id> nonce_b64_len=<n>
   trust_pong: nonce handshake failed (server unreachable: <curl error>)
   trust_pong: nonce handshake returned no session/nonce
   trust_pong: lota_connect failed (agent down, or error <n>)
   trust_pong: agent reachable but not attested (status=<n>)

A failed check does not stop the game. The banner starts at ``OFFLINE``
with ``handshake failed - check agent + server`` after a failure and at
``CHECKING`` with ``awaiting first heartbeat verdict`` otherwise. In both
cases the window opens and the first answer from ``/state`` replaces the
banner.

Verdict
-------

A thread polls ``GET /state?game_id=ID`` every 750 ms with a 600 ms
timeout and maps the ``state`` field of the answer:

.. list-table::
   :header-rows: 1
   :widths: 20 20 15 45

   * - ``state``
     - Banner
     - Strip
     - Second row
   * - ``TRUSTED``
     - ``TRUSTED``
     - green
     - ``TRUSTED license=<license>``
   * - ``UNTRUSTED``, ``REJECT``
     - ``UNTRUSTED``
     - amber
     - ``<state>: <reason>``
   * - ``PENDING``
     - ``CHECKING``
     - yellow
     - ``PENDING``
   * - anything else, no answer
     - ``OFFLINE``
     - grey
     - the curl error, or the state received (``?`` without one)

A ``reason`` in the answer takes the place of the licence. The detail is
wrapped over two rows and cut with ``...`` past the second.

Freeze
------

``trust_pong`` counts the verdicts the server records, each one by its
``verdict_seq`` and ``updated_at_unix``, so a verdict seen by several
polls counts once, and a restarted server counting from 1 again counts
too. Each ``UNTRUSTED`` or ``REJECT`` verdict adds one to a streak and
each ``TRUSTED`` verdict clears it; ``PENDING``, other states and failed
polls leave it as it is.

At a streak of two the game freezes: the banner reads
``INTEGRITY LOSS`` over a red strip, a dark overlay with
``INTEGRITY LOSS`` and ``session terminated after two UNTRUSTED
heartbeats`` covers the play field, the ball and paddle stop, and stderr
gets:

.. code-block:: text

   trust_pong: session terminated after 2 consecutive UNTRUSTED heartbeats

The freeze lasts until the program exits. A single ``UNTRUSTED`` verdict
between ``TRUSTED`` ones leaves the game running.

Playing
=======

The window, ``LOTA trust_pong``, is 800 by 600 pixels. The ball bounces
between the paddle on the left and a wall on the right:

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Key
     - Action
   * - ``W``, Up
     - Move the paddle up.
   * - ``S``, Down
     - Move the paddle down.
   * - Esc, ``Q``
     - Quit; closing the window does the same.

The wall gives 10 points, the paddle 5, and a missed ball costs 5 down to
0 and restarts from the centre. The score and the hit count are shown in
the banner on the right. While frozen, only quitting works.

Text is drawn with a bitmap font compiled into ``ui.c``, so the game
reads no font files.
