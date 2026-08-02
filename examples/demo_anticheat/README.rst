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
``build/examples/demo_anticheat``.

It builds the way a studio's build does: through ``pkg-config`` against the
**installed** SDK, never against the build tree. ``make examples`` first
lays the package contents out under ``build/stage`` (the ``sdk-stage``
target), so the flags come from the same ``.pc`` files ``lota-sdk-devel``
ships:

.. code:: sh

   cc $(pkg-config --cflags lota-anticheat) -o producer producer.c \
      $(pkg-config --libs lota-anticheat) $(pkg-config --libs libcurl)

``lota-anticheat`` is the only LOTA module on that line: the library
carries the gaming and server SDK inside it, so a producer that only calls
``lota_ac_*`` links one thing. Add ``lota-gaming`` or ``lota-server`` when
the same binary also calls those APIs directly.

Which half of the evidence you run
----------------------------------

A publisher adopts either half, and the choice is a real fork with a direct
privacy consequence for the player. Both work today; pick one before writing
the integration, because it decides what your backend has to be able to do.

**Light -- tokens only.** Your game backend receives the tokens titles fetch
and verifies them itself: ``lota_server_verify_token()`` in
``include/lota_server.h``, or ``VerifyToken`` in the Go server SDK. What that
buys is the TPM's signature over the attestation flags and the PCR digest,
bound to a nonce you issued, chained to the AIK certificate your attestation
CA issued that machine. You run a CA and nothing else. **Nothing is reported
from the player's machine to you** -- no attestation report, no TPM event log,
no runtime manifest -- so the machine holds no verdict of yours, and
``lota_is_attested()`` answers ``0`` with ``LOTA_FLAG_TOKEN_ONLY`` set. Read
that flag: it distinguishes "nobody verifies here, check the token yourself"
from "this machine failed verification", which look identical in the attested
bit alone. The host is configured for you with ``verifier = none`` in that
publisher's profile.

**Deep -- a verifier and a policy.** The agent sends full attestation reports
to a verifier you run, on your own cadence, and that verifier judges them
against a policy: boot PCR pins, the agent-hash allow-list, the firmware
floor, revocation, and how a kernel or firmware update is allowed to
re-anchor. Strongest judgement, and the one that can refuse a machine for a
reason no single token expresses. It costs you the verifier and its policy,
and it costs the player the report: the PCR values, the event log and the
runtime manifest reach you every interval a title of yours runs.
``lota_is_attested()`` then answers with your verifier's verdict.

Both paths use the same enrollment: a per-publisher AIK, minted on the
player's machine and certified by your CA, which no other publisher can
correlate against. Both are per publisher, so a player's machine can serve one
of each without either arrangement changing for the other. Moving from light
to deep later is a configuration change on the host and a verifier you stand
up; nothing in the title has to change except which answer it reads.

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
           case LOTA_ERR_INVALID_ARG:       /* this title's request was bad */
           default:
                   break;
           }
   }

``LOTA_ERR_INVALID_ARG`` is the one that is not about the player: the identity
was malformed, the options were not sized, or the agent refused the request
itself. It never means the publisher is unknown to that machine, so a title
that hits it should report a fault rather than send the player to a consent
screen.

End-to-end proof
----------------

``./run.sh`` verifies the whole path without root and without a real TPM: a
throwaway swTPM, ``lota-agent`` under ``systemd-socket-activate`` so it
listens in ``/tmp`` instead of ``/run/lota``, the reference server on the
AIK that TPM provisioned, and two assertions -- a heartbeat from an attested
host is ``TRUSTED``, and a heartbeat whose signature byte was flipped is
``UNTRUSTED`` with the server naming the signature as the reason.

Requires ``swtpm``, ``swtpm_setup``, ``tpm2_readpublic`` and
``systemd-socket-activate``. Set ``KEEP_LOGS=1`` to keep the run directory
for inspection.

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

When a measurement is refused
-----------------------------

The agent measures the producer's mapped objects from the kernel side, and
refuses to issue a token when one of them cannot be measured -- a missing
measurement is never handed out as a trusted one. The agent log names the
object rather than the process, so the fix is directed rather than guessed:

.. code:: text

   runtime image measurement failed for pid=2039:
     libcurl.so.4 carries no fs-verity digest
     (enable fs-verity on it, or drop the process from the protected set)

   runtime image measurement failed for pid=2039:
     libfoo.so.1 carries a 48-byte fs-verity digest;
     LOTA takes SHA-256 (32) or SHA-512 (64)

The heartbeat surfaces the same condition as ``-ENODATA``, which the producer
prints as ``lota_ac_heartbeat: No data available``. That errno also covers a
host that is simply not attested yet for the publisher in question, so read
the agent log before converting anything.

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
``0xFF`` into the **last** byte of the packet, which is the tail of the TPM
signature. Both the LACH header and the token's own header stay well-formed,
so the server parses everything and then fails the signature check: it
answers ``UNTRUSTED`` with the signature-verify error string surfaced from
``sdk/server.VerifyToken``, rather than the wire-format reject branch.

The first byte of the token is not a usable target -- it is the token magic,
and corrupting it exercises the parser instead of the integrity check. This is
the integration point that ``examples/demo/demo_tamper.sh`` uses to flip the
live demo's banner from green TRUSTED to red INTEGRITY LOSS without touching
the agent process or the swtpm sandbox.
