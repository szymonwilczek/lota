.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

demo_anticheat
==============

Reference heartbeat producer for the LOTA end-to-end demo.

The process opens an ``lota_ac_session`` in direct mode against the local LOTA
agent, mints LACH heartbeats via ``lota_ac_heartbeat()``, and POSTs them to the
demo server with ``libcurl``. It is the smallest possible C reference for an
EAC- or BattlEye-style integrator: every production-relevant decision (provider
id, game id, socket path, heartbeat interval) is a flag.

Build with ``make examples`` from the repository root. The binary lands at
``build/examples/demo_anticheat`` and links against the gaming + anticheat +
server SDKs that ``make all`` already produces under ``build/``.

Configuring the session
-----------------------

``struct lota_ac_config`` starts with ``struct_size``, which the caller sets to
its own ``sizeof``. That is what lets the structure gain members after 1.0
without a second entry point: the library reads only the members the caller's
size covers, so a game built against a newer header than the library it links
keeps working. A configuration that leaves the field zero is refused rather
than guessed at -- reading members the caller never wrote is what the field
exists to prevent -- so an integrator copying this reference should copy the
first line with it:

.. code-block:: c

   struct lota_ac_config cfg = {
           .struct_size = sizeof(cfg),
           .provider = LOTA_AC_PROVIDER_EAC,
           .game_id = "trust-pong",
           .direct = 1,
   };

``struct lota_connect_opts`` carries the same first member for the same
reason, on the rare path where a game opens the agent connection itself
instead of letting ``lota_ac_init()`` do it.

On a player's machine, which may hold enrollments with several publishers, set
``publisher_profile`` to the lowercase hex SHA-256 of your own attestation CA's
trust anchor SubjectPublicKeyInfo:

.. code-block:: sh

   openssl x509 -in ca-tls.crt -pubkey -noout \
       | openssl pkey -pubin -outform der \
       | sha256sum

The session's tokens are then signed by the AIK that machine enrolled with
*your* CA, and its attested state is your verifier's verdict rather than every
publisher on the host agreeing. Leave it NULL on a single-publisher host. A
machine that holds no enrollment for the named publisher fails the connection
rather than answering with another publisher's evidence.

Nothing enrolls with a publisher until somebody on that machine agrees to it,
so a first run there fails the connection with ``LOTA_ERR_CONSENT_REQUIRED``
(read it with ``lota_connect_last_error()``; ``lota_ac_init()`` returns NULL
and the same call answers why). That is a screen to show, not an error to
report: say what your verifier would receive, and call ``lota-agent
--allow-publisher <your hex>`` when the player accepts. Distinguish it from
``LOTA_ERR_CONNECTION_FAILED``, which means no agent is installed at all::

   struct lota_client *c = lota_connect_opts(&opts);

   if (!c) {
           switch (lota_connect_last_error()) {
           case LOTA_ERR_CONSENT_REQUIRED:  /* ask the player */
           case LOTA_ERR_UNKNOWN_PROFILE:   /* consented, not enrolled yet */
           case LOTA_ERR_CONNECTION_FAILED: /* no agent on this machine */
           default:
                   break;
           }
   }

Flags
-----

+-----------------------------+-------------------------------------+------------------------------+
| Flag                        | Default                             | Meaning                      |
+=============================+=====================================+==============================+
| ``--server URL``            | ``http://127.0.0.1:7443/heartbeat`` | demo server ``/heartbeat``   |
|                             |                                     | endpoint                     |
+-----------------------------+-------------------------------------+------------------------------+
| ``--game-id ID``            | ``trust-pong``                      | game id stamped into the     |
|                             |                                     | LACH header                  |
+-----------------------------+-------------------------------------+------------------------------+
| ``--socket PATH``           | (default agent socket)              | override the agent UNIX      |
|                             |                                     | socket path                  |
+-----------------------------+-------------------------------------+------------------------------+
| ``--provider eac/battleye`` | ``eac``                             | anti-cheat provider id       |
|                             |                                     | stamped into the LACH header |
+-----------------------------+-------------------------------------+------------------------------+
| ``--interval SEC``          | ``5``                               | seconds between heartbeats;  |
|                             |                                     | also                         |
|                             |                                     | ``$LOTA_DEMO_INTERVAL_SEC``  |
+-----------------------------+-------------------------------------+------------------------------+
| ``--once``                  | off                                 | fire a single heartbeat,     |
|                             |                                     | exit with the                |
|                             |                                     | server-reported state        |
+-----------------------------+-------------------------------------+------------------------------+
| ``--tamper-marker PATH``    | (none)                              | flip a token byte when PATH  |
|                             |                                     | exists; also                 |
|                             |                                     | ``$LOTA_DEMO_TAMPER_MARKER`` |
+-----------------------------+-------------------------------------+------------------------------+
| ``--print-runtime-objects`` | off                                 | print the runtime manifest   |
|                             |                                     | (loaded object paths) and    |
|                             |                                     | exit                         |
+-----------------------------+-------------------------------------+------------------------------+
| ``--ca-cert PATH``          | (none)                              | provisioning CA that signs   |
|                             |                                     | the server cert (mTLS,       |
|                             |                                     | ``https://`` server)         |
+-----------------------------+-------------------------------------+------------------------------+
| ``--client-cert PATH``      | (none)                              | producer mTLS certificate;   |
|                             |                                     | set with ``--client-key``    |
+-----------------------------+-------------------------------------+------------------------------+
| ``--client-key PATH``       | (none)                              | producer mTLS private key;   |
|                             |                                     | set with ``--client-cert``   |
+-----------------------------+-------------------------------------+------------------------------+
| ``--help``                  | n/a                                 | print usage and exit         |
+-----------------------------+-------------------------------------+------------------------------+

Mutual TLS
----------

When the demo server runs with TLS (``https://`` ``--server`` URL), point the
producer at the provisioning CA so it verifies the server, and present the
producer certificate so the server can require a provisioned client:

.. code:: sh

   demo_anticheat --server https://127.0.0.1:7443/heartbeat \
                  --ca-cert mtls/ca.crt \
                  --client-cert mtls/producer.crt \
                  --client-key mtls/producer.key

Peer and hostname verification stay on, so the producer refuses to ship a
heartbeat to an unauthenticated server. ``examples/mtls/gen-certs.sh``
provisions the keypairs; see
```examples/mtls/README.rst`` <../mtls/README.rst>`__.

Re-measurement runtime manifest
-------------------------------

Each heartbeat carries a runtime measurement of the producer's live image

- the main binary plus every shared library it loads. The server reproduces the
  expected value from the set of ELF files that make up that runtime. Capture
  the list once with ``--print-runtime-objects`` and hand it to the server:

.. code:: sh

   demo_anticheat --print-runtime-objects > runtime-manifest.txt
   demo_server --anticheat-runtime-manifest runtime-manifest.txt ...

Exit codes
----------

In ``--once`` mode the process return code mirrors the server verdict so
``setup.sh`` can use the call as a liveness check without parsing stderr:

==== ============================================================
Code Meaning
==== ============================================================
0    ``TRUSTED``
1    ``UNTRUSTED``
2    ``REJECT``
3    transport-level failure (no agent, no server, libcurl error)
64   usage / CLI error
==== ============================================================

In continuous mode the process loops forever and exits cleanly on SIGINT or
SIGTERM, propagating the last verdict as the exit code.

Logging
-------

Each tick writes one line to stderr:

::

   demo_anticheat: seq=<n> state=<verdict> latency=<ms> http=<status> [reason="..."]

The format is intentionally pipe-friendly so the operator can ``| awk`` it
during the live demo without an extra parser.

.. _integration-notes-vs-eac--battleye:

Integration notes vs EAC / BattlEye
-----------------------------------

- **Process model.** Real anti-cheat clients ship a long-lived helper next to
  the game. ``demo_anticheat`` reproduces that model: the process is
  independent of the SDL2 client, and the two communicate only through the demo
  server's verdict state.
- **Provider id.** EAC and BattlEye allocate different provider identifiers
  (``1`` and ``2`` here). The LACH wire stamps the value into byte 5 of the
  header so a verifier that bridges both vendors can route per-provider without
  re-deriving from the socket path.
- **Session id.** The ``lota_ac_session`` mints its own 16-byte session id at
  init time. That id is independent from the game-server session id served by
  ``POST /nonce`` -- the two are bridged on the server side through
  ``game_id_hash``, which lets multiple producers per game converge on the same
  verdict without sharing state.
- **Replay defence.** The producer's monotonic sequence is the primary replay
  defence on the wire. The demo server keeps a per-session high-water mark and
  rejects any heartbeat at or below it.

Tamper hook
-----------

``--tamper-marker PATH`` (or ``LOTA_DEMO_TAMPER_MARKER=PATH``) arms a per-tick
poll: when the file at ``PATH`` exists at heartbeat time, the producer XORs
``0xFF`` into the first byte of the signed token blob before POSTing. The LACH
header stays well-formed, so the server takes the verification branch rather
than the wire-format reject branch and answers ``UNTRUSTED`` with the
signature-verify error string surfaced from ``sdk/server.VerifyToken``. This is
the integration point that ``examples/demo/demo_tamper.sh`` uses to flip the
live demo's banner from green TRUSTED to red INTEGRITY LOSS without touching
the agent process or the swtpm sandbox.
