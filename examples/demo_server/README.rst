.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

demo_server
===========

Reference game server for the LOTA end-to-end demo. The process is a single Go
binary that:

1. mints attestation nonces and per-session ids,
2. decodes anti-cheat heartbeats off the wire (``LACH`` framing),
3. verifies the embedded LOTA token against a configured AIK public key, and
4. surfaces the most recent verdict so the SDL2 demo (``trust_pong``) can
   mirror it without owning a heartbeat channel of its own.

Build with ``make examples`` from the repository root; the binary lands at
``build/examples/demo_server``.

Flags
-----

+----------------------------------+------------------------------------+-------------------------+
| Flag                             | Default                            | Meaning                 |
+==================================+====================================+=========================+
| ``--listen``                     | ``127.0.0.1:7443``                 | host:port to listen on  |
|                                  |                                    | (loopback only by       |
|                                  |                                    | design)                 |
+----------------------------------+------------------------------------+-------------------------+
| ``--aik-pub``                    | (none)                             | path to the AIK public  |
|                                  |                                    | key (DER or PEM);       |
|                                  |                                    | required outside tests  |
+----------------------------------+------------------------------------+-------------------------+
| ``--expected-games``             | ``trust-pong=lota-demo-CS2-clone`` | comma-separated         |
|                                  |                                    | ``game_id=license``     |
|                                  |                                    | entries the server      |
|                                  |                                    | accepts                 |
+----------------------------------+------------------------------------+-------------------------+
| ``--max-age``                    | ``300``                            | maximum heartbeat age   |
|                                  |                                    | in seconds before       |
|                                  |                                    | UNTRUSTED               |
+----------------------------------+------------------------------------+-------------------------+
| ``--anticheat-binary``           | (none)                             | producer binary; its    |
|                                  |                                    | SHA-256 feeds the       |
|                                  |                                    | expected game-binding   |
|                                  |                                    | hash                    |
+----------------------------------+------------------------------------+-------------------------+
| ``--anticheat-runtime-manifest`` | (none)                             | trusted runtime         |
|                                  |                                    | manifest (one ELF path  |
|                                  |                                    | per line) for the       |
|                                  |                                    | runtime measurement     |
+----------------------------------+------------------------------------+-------------------------+
| ``--require-full-image``         | off                                | refuse a token without  |
|                                  |                                    | the full-coverage flag  |
|                                  |                                    | (see below)             |
+----------------------------------+------------------------------------+-------------------------+
| ``--tls-cert`` / ``--tls-key``   | (none)                             | PEM server keypair;     |
|                                  |                                    | enables HTTPS           |
+----------------------------------+------------------------------------+-------------------------+
| ``--client-ca``                  | (none)                             | PEM provisioning CA;    |
|                                  |                                    | require and verify an   |
|                                  |                                    | mTLS producer           |
|                                  |                                    | certificate             |
+----------------------------------+------------------------------------+-------------------------+

Runtime measurement
~~~~~~~~~~~~~~~~~~~

The heartbeat carries a runtime measurement of the producer's live image

- the main binary plus every shared library it loads. The server reproduces the
  expected value from a **trusted runtime manifest**: the set of ELF files that
  make up the producer's runtime. Capture it from the producer once and pass it
  in:

.. code:: sh

   demo_anticheat --print-runtime-objects > runtime-manifest.txt
   demo_server --aik-pub aik.der \
               --anticheat-binary ./demo_anticheat \
               --anticheat-runtime-manifest runtime-manifest.txt

A heartbeat whose live measurement does not match the manifest is answered
``UNTRUSTED`` with reason ``runtime measurement mismatch``. When the manifest
is omitted, the runtime measurement falls back to ``--anticheat-binary`` alone,
which only matches a statically linked producer.

Minting tokens in your own tests
--------------------------------

A relying party's test suite has to build tokens the way an agent would, and
the fields a token binds under its quote are computed, not guessed. The server
SDK exports each of those folds, so nothing downstream re-derives one by hand:

* ``server.ComputeRuntimeProtectDigest(pids)`` for a v1 token built with
  ``SerializeToken``,
* ``server.ComputeRuntimeProtectDigestV2(pids, imageDigests)`` for a v2 token
  built with ``SerializeTokenV2``,
* ``server.ComputeTokenQuoteNonce(...)`` for the value the quote's extra data
  has to carry.

Each is domain-separated and has to agree byte for byte with the agent's C
implementation; both sides carry the same known-answer vectors
(``TestRuntimeProtectDigest_KAT`` here, ``test_runtime_protect_digest`` there).
A second copy of one of these folds in a relying party's own tree is the drift
those domain strings exist to prevent, which is why they are exported rather
than reimplemented.

Transport security
~~~~~~~~~~~~~~~~~~

By default the demo serves plain HTTP on loopback so the operator can curl
every endpoint without bringing in a CA. Pass ``--tls-cert``/``--tls-key`` to
serve HTTPS, and add ``--client-ca`` to require the anti-cheat producer to
present a provisioned certificate (mutual TLS): a heartbeat from anything but a
provisioned producer is then refused at the TLS layer before any token is
parsed. ``examples/mtls/gen-certs.sh`` provisions the keypairs and
```examples/mtls/README.rst`` <../mtls/README.rst>`__ documents the flow.

.. code:: sh

   demo_server --aik-pub aik.der \
               --tls-cert mtls/server.crt --tls-key mtls/server.key \
               --client-ca mtls/ca.crt

The production guidance is otherwise "put the verifier behind your existing
game auth gateway"; that gateway already owns TLS termination.

Endpoints
---------

``POST /nonce``
~~~~~~~~~~~~~~~

Body: ``{"game_id": "trust-pong"}``.

Mints a per-session UUID and 32 random nonce bytes. The client uses the nonce
as input to ``lota_get_token()`` so the server can bind a given attestation to
a specific challenge.

.. code:: sh

   curl -s http://127.0.0.1:7443/nonce \
        -d '{"game_id":"trust-pong"}' | jq

Response:

.. code:: json

   {
     "session_id": "0e7e9f5b-3e3d-4f57-9d80-58dcb6c2d8d4",
     "nonce": "<base64 of 32 bytes>",
     "license": "lota-demo-CS2-clone"
   }

``POST /heartbeat``
~~~~~~~~~~~~~~~~~~~

Body: raw LACH bytes (binary, ``Content-Type: application/octet-stream``). The
handler:

1. parses the 110-byte header documented in ``include/lota_anticheat.h``,
2. rejects on bad magic / version / size / unsupported ``domain_version``
   (verdict ``REJECT``, HTTP 400),
3. fails closed on an unknown ``game_id_hash``, a runtime-measurement mismatch
   against the registered binary, a replayed / stale sequence, a future
   timestamp, or a signature/nonce mismatch (verdict ``UNTRUSTED``, HTTP 200),
4. returns ``{"state":"TRUSTED","license":"lota-demo-CS2-clone"}`` only when
   the embedded LOTA token verifies against the configured AIK and every
   freshness check passes.

.. code:: sh

   curl -s --data-binary @heartbeat.bin \
        -H 'Content-Type: application/octet-stream' \
        http://127.0.0.1:7443/heartbeat

``GET /state?game_id=trust-pong``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Returns the most recent verdict the server saw for a given game id, or
``PENDING`` when no heartbeat has arrived yet. ``trust_pong`` polls this
endpoint to drive its banner so the SDL2 client itself never has to parse LACH
packets.

Logging
-------

Every state transition writes one line to stdout in
``[RFC3339Nano] session=<uuid|hex> seq=<n> state=<verdict> reason=<...>`` form,
so the demo operator can follow the entire run by ``tail -f``-ing the server.

Tests
-----

``go test ./...`` covers each verdict branch with a fabricated heartbeat:
TRUSTED, UNTRUSTED-on-bad-signature, UNTRUSTED-on-unknown-game,
UNTRUSTED-on-tampered-header, UNTRUSTED-on-flag-mismatch, UNTRUSTED-on-replay,
REJECT-on-bad-magic, REJECT-on-unsupported-domain, REJECT-on-truncated-token,
plus ``/nonce`` and ``/state`` happy paths and failure modes.

Runtime coverage as a policy
----------------------------

A token states whether the agent's runtime measurement covered every object
the producer maps (``LOTA_FLAG_IMAGE_FULLY_MEASURED``) or only those the
kernel holds an fs-verity digest for. The bit is inside the signed token, so
it cannot be claimed by a client that did not earn it.

``--require-full-image`` makes this server demand it: a heartbeat without the
bit is ``UNTRUSTED`` with the missing flags named. On a host whose
distribution ships libraries without fs-verity that refuses every heartbeat,
which is the point -- the choice belongs to the publisher, and this is what
choosing it looks like. Left off, partial coverage is accepted and the bit is
still reported, so a backend can log or score it instead.
