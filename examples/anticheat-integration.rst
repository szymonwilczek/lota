.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

=========================================
Integrating LOTA into an anti-cheat stack
=========================================

The anti-cheat reference is a producer and a backend under ``examples/``,
built on the SDK libraries. This page is the map for a studio or an
anti-cheat vendor building on them: what each piece is, what a fork has to
change, what a heartbeat costs, and what a verified token says. The
functions themselves are described in
`the anti-cheat SDK <../Documentation/userspace-api/anticheat.rst>`_ and
`the gaming SDK <../Documentation/userspace-api/gaming.rst>`_.

Userspace, the SDK and every example are MIT; the BPF programs are
GPL-2.0-only and run on the host (see `Licensing <../README.rst>`_). Each
source file names its licence in its ``SPDX-License-Identifier``.

The pieces
==========

.. list-table::
   :header-rows: 1
   :widths: 30 12 58

   * - Piece
     - Use
     - Role
   * - ``liblota_anticheat.so``
     - link
     - Sessions and heartbeats on the producer, heartbeat verification
       on a C backend.
   * - ``liblotaserver.so``, ``sdk/server`` (Go)
     - link
     - Token verification for a backend, in C or Go (see
       `the server SDK <../Documentation/userspace-api/server.rst>`_ and
       `the Go SDK <../Documentation/userspace-api/go-sdk.rst>`_).
   * - `demo_anticheat/ <demo_anticheat/README.rst>`_
     - fork
     - The producer: opens a session, builds heartbeats, posts them.
   * - `demo_server/ <demo_server/README.rst>`_
     - fork
     - The backend, in Go: decodes a heartbeat, verifies its token with
       ``VerifyToken()`` and keeps a verdict.
   * - `demo_game/ <demo_game/README.rst>`_
     - read
     - A game client that learns its verdict from the backend.
   * - `cs2/ <cs2/README.rst>`_
     - read
     - A Windows title under Proton, with the Wine hook.
   * - `runtime_remeasure/ <runtime_remeasure/README.rst>`_
     - read
     - The runtime measure of the heartbeat, computed and compared.

The flow
========

1. The game host runs the agent. It holds the TPM and answers the local
   socket; the producer does not talk to the TPM.
2. The producer opens a session with ``lota_ac_init()``, naming the
   provider, the game id and the publisher, and calls
   ``lota_ac_heartbeat()`` on a timer. Each heartbeat is a header with the
   session id, sequence, timestamp, game binding hash and runtime measure,
   and a token the TPM signed over a nonce derived from that header.
3. The backend verifies the heartbeat: ``lota_ac_verify_heartbeat()`` in C,
   or, as ``demo_server`` does, a decoded header and ``VerifyToken()``
   with the nonce recomputed from it.
4. The backend decides. ``lota_ac_verify_heartbeat()`` reports a verified
   heartbeat ``TRUSTED`` when the signed flags carry
   ``LOTA_FLAG_ATTESTED`` and ``UNTRUSTED`` otherwise.
   ``VerifyToken()`` requires no flag, so ``demo_server`` calls a
   verified heartbeat ``TRUSTED`` whatever its flags, unless its
   ``-require`` options name some (see
   `demo_server <demo_server/README.rst>`__). A backend that requires
   more reads the flags of the token. What a verdict leads to in the game
   is the backend's policy and is not in this repository.

Building
========

``lota-sdk-devel`` installs the headers and the ``pkg-config`` modules
(see `the public surface <../Documentation/userspace-api/stability.rst>`_):

.. code-block:: console

   $ cc $(pkg-config --cflags lota-anticheat) -o producer producer.c \
         $(pkg-config --libs lota-anticheat)

A producer that calls only ``lota_ac_*`` links ``lota-anticheat`` alone;
one that also calls ``lota_*`` of the gaming SDK, as ``demo_anticheat``
does, adds ``lota-gaming``.

What a fork changes
===================

.. list-table::
   :header-rows: 1
   :widths: 25 75

   * - Item
     - What it becomes
   * - Game id
     - The title's identifier, 1 to 63 bytes. The game binding hash covers
       it with the SHA-256 of the executable, and the backend computes the
       hash it expects from the executable it ships.
   * - Provider
     - ``LOTA_AC_PROVIDER_EAC`` or ``LOTA_AC_PROVIDER_BATTLEYE``. The value
       goes into every heartbeat and carries no other meaning.
   * - Publisher
     - ``publisher_profile``, the id ``lota-agent --list-publishers``
       prints: the SHA-256 of the SubjectPublicKeyInfo of the CA anchor
       (see `publishers <../Documentation/agent/publishers.rst>`_). A
       host enrolled with several publishers refuses a session that names
       none, and on a host whose publishers are all session-gated a title
       that names none reads not attested. A title under the Wine hook
       sets ``LOTA_HOOK_PUBLISHER``.
   * - Transport
     - ``demo_anticheat`` posts over HTTP with libcurl. A fork uses the
       channel the client already has.
   * - Freshness
     - The backend issues no nonce for a heartbeat: the producer derives
       it from the header. ``lota_ac_verify_heartbeat()`` accepts a
       timestamp within 120 seconds of the clock of the backend and keeps
       no state, so a backend that refuses a repeated packet records the
       last ``sequence`` of each ``session_id``, as ``demo_server`` does.
   * - AIK
     - ``demo_server`` trusts one key from a file. A backend takes the AIK
       of each account from its enrolment records (see
       `enrollment/ <enrollment/README.rst>`_).
   * - Mode
     - ``direct`` 1 talks to the agent and builds heartbeats. ``direct`` 0
       reads the files of the Wine hook from ``token_dir`` and builds
       none: the token of the hook answers no nonce.
   * - Interval
     - ``demo_anticheat`` beats every 5 seconds; see below.

What a heartbeat costs
======================

Each heartbeat asks the agent for a token, and each token is a TPM quote,
a blocking operation on a device the whole machine shares. In direct mode
``lota_ac_tick()`` asks for one as well. The calls belong on a thread of
their own or the network tick, never on a frame or render loop.

The agent issues 20 tokens per connection and 60 per uid in a 60-second
window (see `tokens <../Documentation/agent/tokens.rst>`_). A session
holds one connection, so a 5-second heartbeat takes 12 of its 20. Every
title of the player runs as the same uid and shares the 60.
``LOTA_AC_ERR_RATE_LIMITED`` means the producer beats faster than the
agent issues tokens; a longer interval clears it, a retry does not.

Errors
======

``lota_ac_init()`` returns ``NULL`` and ``lota_ac_heartbeat()`` a negative
``errno``, and the errno alone does not tell the causes apart.
``lota_ac_last_error()`` names the cause on the calling thread and
``lota_ac_strerror()`` words it; the codes are listed in
`Errors <../Documentation/userspace-api/anticheat.rst>`__.

.. code-block:: c

   struct lota_ac_session *s = lota_ac_init(&cfg);

   if (!s)
           log("cannot start: %s", lota_ac_strerror(lota_ac_last_error()));

The codes split by where the cause is:

* In the producer: ``CONFIG_SIZE``, ``GAME_ID``, ``PROVIDER``,
  ``INVALID_ARG``. Nothing the player does changes them.
* On the player's machine: ``NO_AGENT``, ``CONSENT_REQUIRED``,
  ``UNKNOWN_PROFILE``, ``NOT_ATTESTED``, ``TOKEN_DIR``,
  ``TPM_LOCKOUT``. ``NOT_ATTESTED`` with ``LOTA_FLAG_REENROLLING`` in the
  status is a host enrolling again, as after a TPM clear, which completes
  without the player. ``TPM_LOCKOUT`` lasts until the dictionary-attack
  lockout of the TPM lapses or is cleared.
* In the interval: ``RATE_LIMITED``.

In direct mode a session whose connection fails is not ``NULL``: it is
returned in ``LOTA_AC_STATE_ERROR``, so the title has a state to show,
and ``lota_ac_last_error()`` names the cause, ``NO_AGENT`` when no agent
answers. It never connects later: the title opens another session once
the agent answers.

``last_attest_time`` of ``lota_get_status()`` is 0 until the host first
attests, which on a session-gated host waits for a title of the
publisher, and it does not move while nothing attests. Whether the host is
attested is ``LOTA_FLAG_ATTESTED`` with ``valid_until``.

The files of the Wine hook
==========================

A reader of ``lota-status`` reads ``LOTA_OFFLINE`` before
``LOTA_ATTESTED``. When the hook loses the agent it writes
``LOTA_OFFLINE=1`` with the other fields at zero and removes the token
files, so ``LOTA_ATTESTED`` alone reads a lost agent as a refusal. A
missing file is offline too. The files are described in
`the Wine hook <../Documentation/userspace-api/wine-hook.rst>`_, and
`verify-attested.sh <cs2/scenarios/README.rst>`_ reads them this way.

Protection
==========

``lota_ac_init()`` does not put the producer in the protected set; the
producer calls ``lota_protect_self()``, as ``demo_anticheat
--protect-self`` does, or starts under ``lota-protect``. A token then
carries the measurement the agent made of the process (see
`runtime measurement <../Documentation/agent/runtime-measurement.rst>`_).

With the agent in ``enforce`` mode and ``strict_mmap`` on, a protected
process maps executable only files that an ``allow_verity`` or a
``trust_lib`` entry covers. Anything else fails, in ``dlopen()`` as
``failed to map segment from shared object``, and the agent logs
``MMAP_BLOCKED``. A process protected by ``lota-protect`` from its first
instruction needs an entry for every object it loads, its own libraries
included; one that protects itself later needs entries only for what it
maps after. ``lota_get_refusal()`` returns the last refused object.

What a verified token says
==========================

The signature over the challenge says a TPM of the host whose AIK the
backend holds signed this status, for this nonce: a replayed token or one
from another machine fails. What the token carries is described in
`the gaming SDK <../Documentation/userspace-api/gaming.rst>`__ and
`the server SDK <../Documentation/userspace-api/server.rst>`__; for a
backend, these parts decide most:

* The flags. ``LOTA_FLAG_IMAGE_FULLY_MEASURED`` says every executable
  mapping of every protected process was measured, and is clear when
  nothing is protected; ``LOTA_FLAG_IMAGE_CONTENT_HASHED`` says an object
  without fs-verity was measured by its content.
  ``LOTA_FLAG_PROTECTED_TERMINATED``, ``LOTA_FLAG_AGENT_RESTARTED``,
  ``LOTA_FLAG_REENROLLING`` and the policy bits 14 to 19 describe the
  agent and its policy.
* The protected PIDs and a registry digest for each. ``lota_get_registry()``
  returns the list a digest covers: the objects the process mapped
  executable and the processes that reached it.
  ``lota_server_registry_digest()`` recomputes the digest, so a list that
  does not match is not the one the token describes.
* ``stopped_ms``, the time a thread of the title's instance stood
  stopped.
* The quoted boot PCRs, by digest. ``lota_ac_boot_evidence()`` fetches the
  values and the PCR 7 events behind them, and
  ``lota_ac_verify_boot_evidence()`` or ``VerifyBootEvidence()`` reads
  Secure Boot from them (see
  `boot evidence <../Documentation/agent/boot-evidence.rst>`_).

LOTA reports the state of the platform and does not judge it: which flags,
objects and actors a backend accepts is its policy. The runtime measure in
the heartbeat header is computed inside the game process, which the player
controls; what the agent measured from outside is in the token.

Trying it
=========

.. code-block:: console

   $ make all examples
   $ examples/demo_anticheat/run.sh

``run.sh`` runs the agent on a software TPM, ``demo_server`` and
``demo_anticheat`` without root, and checks a trusted heartbeat and a
tampered one refused on its signature (see
`demo_anticheat <demo_anticheat/README.rst>`_).
