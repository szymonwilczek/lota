.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

===========
demo_server
===========

``demo_server`` is the game server of the demo. It issues session ids and
nonces to game clients, verifies the heartbeats of
`demo_anticheat <../demo_anticheat/README.rst>`_ against the AIK of the
host and keeps the latest verdict of each game for
`trust_pong <../demo_game/README.rst>`_ to poll.
`setup.sh <../demo/README.rst>`_ starts it with the AIK it exports from
the software TPM.

Building
========

``make examples`` builds ``build/examples/demo_server`` with ``go build``
when ``go`` is installed, and prints
``SKIP: demo_server (go not installed or stub absent)`` otherwise. The
tests run from the module directory:

.. code-block:: console

   $ cd examples/demo_server && go test ./...

The tests sign their tokens with a key of their own, built with
``SerializeToken()``, ``ComputeRuntimeProtectDigest()`` and
``ComputeTokenQuoteNonce()`` of the Go SDK; a relying party's tests can
do the same (see `Building tokens
<../../Documentation/userspace-api/go-sdk.rst>`_).

Running
=======

.. code-block:: console

   $ demo_anticheat --print-runtime-objects > runtime-manifest.txt
   $ demo_server -aik-pub aik.pem \
         -anticheat-binary build/examples/demo_anticheat \
         -anticheat-runtime-manifest runtime-manifest.txt

Options take one dash or two:

.. list-table::
   :header-rows: 1
   :widths: 32 68

   * - Option
     - Meaning
   * - ``-listen HOST:PORT``
     - Listen address, default ``127.0.0.1:7443``.
   * - ``-aik-pub PATH``
     - AIK public key, PKIX in DER or PEM, RSA of at least 2048 bits.
       Without it every heartbeat that reaches the signature check is
       answered ``REJECT``.
   * - ``-expected-games LIST``
     - Comma-separated ``game_id=license`` entries, default
       ``trust-pong=lota-demo-CS2-clone``.
   * - ``-anticheat-binary PATH``
     - The producer binary, whose SHA-256 goes into the game binding
       hash.
   * - ``-anticheat-runtime-manifest PATH``
     - One ELF path per line, blank lines and ``#`` comments skipped,
       for the expected runtime measurement.
   * - ``-max-age SEC``
     - Oldest heartbeat timestamp accepted, in seconds, default 300. 0
       selects 300; above 86400 the server does not start.
   * - ``-require-full-image``
     - Answer ``UNTRUSTED`` to a token without
       ``LOTA_FLAG_IMAGE_FULLY_MEASURED``.
   * - ``-require-kernel-appraisal``
     - Answer ``UNTRUSTED`` to a token without
       ``LOTA_FLAG_KERNEL_APPRAISAL``.
   * - ``-tls-cert PATH``, ``-tls-key PATH``
     - PEM server certificate and key, together; the server then serves
       HTTPS with TLS 1.2 or later.
   * - ``-client-ca PATH``
     - PEM CA; every connection must present a client certificate it
       signed. Needs ``-tls-cert`` and ``-tls-key``.

The two ``-require`` options are a policy of the server over flags the
agent signs into the token; the flags are described in
`the gaming SDK <../../Documentation/userspace-api/gaming.rst>`_. On a
host where an object of a protected process could not be measured, or
nothing is protected, ``LOTA_FLAG_IMAGE_FULLY_MEASURED`` is clear and
``-require-full-image`` refuses every heartbeat. On a host whose IMA does
not appraise executables in a blocking mode,
``LOTA_FLAG_KERNEL_APPRAISAL`` is clear and ``-require-kernel-appraisal``
refuses every heartbeat.

At start the server logs
``demo_server listening on <addr> (games=<ids>, transport=<t>)`` to
stderr, with ``http``, ``https`` or ``https+mtls`` as the transport. It
exits 2 when an option or a file it names cannot be used, 1 when the
listener fails, and 0 after SIGINT or SIGTERM, giving open requests 3
seconds to finish.

Game binding
------------

Each entry of ``-expected-games`` is bound to the hash the producer puts
into every heartbeat header::

   SHA-256("lota-ac-game-binding:v1" || 0x00 || game_id || SHA-256(binary))

The binary is the one ``-anticheat-binary`` names. Without that option
the server hashes 32 zero bytes in its place, no producer matches, and
every heartbeat is answered ``UNTRUSTED`` with ``unknown game_id_hash``.

The server also computes the runtime measurement a matching producer
reports, over the objects of ``-anticheat-runtime-manifest`` or over the
producer binary alone. The producer computes the measurement in its own
process, so a heartbeat whose measurement differs is logged with
``advisory="producer runtime measurement differs from registered
baseline"`` and verified as any other. The measurement the agent signs
is described in
`runtime measurement <../../Documentation/agent/runtime-measurement.rst>`_.

Endpoints
=========

The server answers JSON, except for a wrong method (405) and the errors
of ``/nonce`` and ``/state``, which are plain text.

POST /nonce
-----------

.. code-block:: console

   $ curl -s http://127.0.0.1:7443/nonce -d '{"game_id":"trust-pong"}'
   {"session_id":"<uuid>","nonce":"<base64>","license":"lota-demo-CS2-clone"}

The body may be empty; an empty ``game_id`` selects ``trust-pong``. The
answer carries a new UUID, 32 random bytes in base64 and the licence of
the game. An unknown game is answered 403 ``unknown game_id`` and a body
that is not JSON 400 ``bad json``. The server keeps neither value: a
heartbeat is checked against a nonce computed from its own header.

POST /heartbeat
---------------

The body is one LACH packet as ``lota_ac_heartbeat()`` writes it: a
110-byte header and a token. The answer is ``{"state": ...}`` with a
``license`` on ``TRUSTED`` and a ``reason`` otherwise. The checks run in
this order and the first that fails gives the answer:

.. list-table::
   :header-rows: 1
   :widths: 40 20 40

   * - Check
     - Answer
     - ``reason``
   * - The body can be read.
     - 400 ``REJECT``
     - ``read body``
   * - The header parses: length, magic ``LACH``, version 1,
       ``total_size``, ``domain_version`` 1, ``token_size``.
     - 400 ``REJECT``
     - ``reject: `` and the field, e.g.
       ``reject: bad magic 0x00000000``
   * - The game binding hash is one of the configured games.
     - 200 ``UNTRUSTED``
     - ``unknown game_id_hash``
   * - The timestamp is at most 60 seconds ahead and at most
       ``-max-age`` behind; within a session the sequence grows and the
       timestamp does not go back.
     - 200 ``UNTRUSTED``
     - ``timestamp in the future``, ``heartbeat too old``,
       ``sequence not monotonic``, ``timestamp regressed``
   * - An AIK is configured.
     - 503 ``REJECT``
     - ``no AIK configured``
   * - The token verifies against the AIK with the nonce computed from
       the header.
     - 200 ``UNTRUSTED``
     - the error of ``VerifyToken()``
   * - The flags of the header equal those of the token.
     - 200 ``UNTRUSTED``
     - ``header flags do not match signed token``
   * - The token carries the flags the ``-require`` options demand.
     - 200 ``UNTRUSTED``
     - ``token is missing required attestation flags 0x<mask>``
   * - All of the above.
     - 200 ``TRUSTED``
     - none; ``license`` is the licence of the game

The nonce is SHA-256 over ``lota-ac-heartbeat:v1`` and a zero byte, the
session id, provider, sequence, timestamp, game binding hash,
``domain_version`` and runtime measurement of the header, as
``lota_ac_heartbeat()`` computes it. ``VerifyToken()`` and its errors are
described in `the Go SDK <../../Documentation/userspace-api/go-sdk.rst>`_.

Every answer from the game binding check onwards is recorded as the
verdict of the session and under the game binding hash of the packet.
``/state`` shows the last verdict recorded under the hash of the game it
is asked for, so the answer to a hash of no configured game shows in the
log only. A verdict from the AIK check onwards also records the sequence
and timestamp of the session, so a replayed packet fails the freshness
check. A ``REJECT`` for a body or header that does not parse is not
recorded.

GET /state
----------

.. code-block:: console

   $ curl -s 'http://127.0.0.1:7443/state?game_id=trust-pong' | \
         python3 -m json.tool
   {
       "game_id": "trust-pong",
       "state": "UNTRUSTED",
       "license": "lota-demo-CS2-clone",
       "reason": "token is missing required attestation flags 0x00000200",
       "updated_at_unix": 1750000000,
       "verdict_seq": 7
   }

The answer is the latest verdict recorded for the game, from any session:
its ``state``, ``license`` and ``reason`` when set, the time in
``updated_at_unix`` and ``verdict_seq``, which counts the verdicts of the
game from 1. Before the first verdict ``state`` is ``PENDING`` and both
numbers are 0. Without ``game_id`` the server answers for
``trust-pong``; an unknown game is answered 404 ``unknown game_id``.

All state is held in memory: a restarted server answers ``PENDING`` and
counts ``verdict_seq`` from 1 again.

Transport
=========

Without ``-tls-cert`` the server speaks plain HTTP. With ``-tls-cert``
and ``-tls-key`` it serves HTTPS on all three endpoints, and with
``-client-ca`` it refuses any connection without a client certificate
from that CA before reading a request. ``trust_pong`` has no client
certificate, so it cannot reach a server started with ``-client-ca``.
`mtls/ <../mtls/README.rst>`_ creates the certificates and runs the
producer over mutual TLS.

Log
===

Each nonce and each heartbeat verdict writes one line to stdout, prefixed
with the UTC time in RFC 3339 with nanoseconds. A body that cannot be
read is answered ``REJECT`` without a line, and a runtime measurement
that differs from the registered one adds a line with ``advisory=`` in
place of ``state=``:

.. code-block:: text

   [<time>] session=<uuid> game=trust-pong state=NONCE_ISSUED
   [<time>] session=<hex> seq=7 state=TRUSTED license=lota-demo-CS2-clone
   [<time>] session=<hex> seq=8 state=UNTRUSTED reason="heartbeat too old"
   [<time>] session=? state=REJECT reason="reject: bad magic 0x00000000"
