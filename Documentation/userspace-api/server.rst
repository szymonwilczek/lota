.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

==========
Server SDK
==========

``liblotaserver.so`` checks, on the relying party's side, the token a game
process fetched with ``lota_get_token()`` and serialized with
``lota_token_serialize()``. It verifies the TPM signature against an AIK
public key the caller supplies, the nonce the caller issued and the expiry,
and returns the signed claims. The header is ``lota_server.h``
(:ghsrc:`include/lota_server.h`), which includes the wire formats of
``lota_token.h`` (:ghsrc:`include/lota_token.h`); the implementation is
:ghsrc:`src/sdk/lota_server.c` and the pkg-config module ``lota-server``:

.. code-block:: sh

   cc $(pkg-config --cflags lota-server) -o backend backend.c \
      $(pkg-config --libs lota-server)

The library uses OpenSSL and talks to no agent, TPM or verifier. A server
written in Go uses the ``sdk/server`` module (:doc:`go-sdk`), which verifies
tokens and boot evidence by the same rules and has no registry digest.

The AIK
=======

A token is only as good as the key it is checked against. The library takes
the AIK as a DER SubjectPublicKeyInfo and checks the signature with it, and
nothing else: it does not know which host or account the key belongs to. The
relying party keeps that record, for example from the host's enrolment, and
looks up the key by the account the token arrived on. A key the client sends
with its token proves nothing, because any key verifies the tokens it signed
itself.

The key is RSA of at least 2048 bits and at most 512 bytes of DER. The
signature is RSASSA or RSAPSS over SHA-256, SHA-384 or SHA-512, as the token
header names.

Verifying a token
=================

``lota_server_verify_token()`` takes the serialized token, the AIK and the
32-byte nonce the server issued for this attempt, and fills
``struct lota_server_claims``:

.. code-block:: c

   #include <lota/lota_gaming.h>
   #include <lota/lota_server.h>

   struct lota_server_claims claims;
   int ret;

   ret = lota_server_verify_token(buf, len, aik_der, aik_len,
                                  issued_nonce, &claims);
   if (ret != LOTA_SERVER_OK) {
           log_refusal(lota_server_strerror(ret));
           return REJECT;
   }
   if (!(claims.flags & LOTA_FLAG_ATTESTED))
           return UNTRUSTED;

``LOTA_FLAG_*`` is declared in ``lota_gaming.h``, with the meaning of each
bit in :doc:`gaming`. The checks run in this order, and the first that fails
returns:

#. The header: magic, ``LOTA_TOKEN_VERSION``, sizes, a known hash algorithm,
   ``runtime_protect_version`` 1, at most ``LOTA_TOKEN_MAX_PROTECT_PIDS``
   PIDs, in strictly increasing order.
#. ``runtime_protect_digest``, recomputed from the PID list and the registry
   digests the token carries.
#. The signature over the TPM's ``TPMS_ATTEST``.
#. The structure of ``TPMS_ATTEST``.
#. The quoted PCR mask against the header's ``pcr_mask``.
#. ``extraData`` of the quote against the hash of the header fields (below).
#. The token's nonce against ``expected_nonce``.
#. The length of the quoted PCR digest against the hash algorithm.
#. ``valid_until`` at most ``LOTA_SERVER_MAX_TOKEN_AGE_SEC`` (300) plus
   ``LOTA_SERVER_MAX_CLOCK_SKEW_SEC`` (60) seconds ahead of the server's
   clock.
#. ``valid_until`` not passed.

``claims`` is zeroed once the arguments are valid and filled once the nonce
matches, so ``LOTA_SERVER_ERR_FUTURE`` and ``LOTA_SERVER_ERR_EXPIRED`` still
report ``valid_until``. On any other failure the claims are zero or partial
and the caller ignores them.

The token has an expiry and no issue time. The window above is what bounds
its age. A relying party that wants a shorter window
compares ``claims.valid_until`` with its own clock. A ``valid_until`` of 0 is
not refused as expired. Replay is the nonce's job: the server issues one per
attempt, accepts it once, and passes it as ``expected_nonce``.

The claims
==========

.. list-table::
   :header-rows: 1
   :widths: 28 72

   * - Member
     - Content
   * - ``valid_until``
     - Unix time the token expires.
   * - ``flags``
     - The ``LOTA_FLAG_*`` word of the issuing connection at issue time.
   * - ``nonce``
     - The nonce the token answers.
   * - ``pcr_mask``
     - The PCRs the quote covers.
   * - ``policy_digest``
     - SHA-256 over the agent's enforcement policy at startup.
   * - ``runtime_protect_digest``
     - SHA-256 over the protected PIDs and the registry digest of each.
   * - ``protect_pid_count``
     - How many protected processes the token lists.
   * - ``pcr_digest``, ``pcr_digest_len``
     - The digest of the quoted PCR values, in the quote's hash.
   * - ``expired``
     - 1 when ``valid_until`` is nonzero and has passed.
   * - ``stopped_ms``
     - Milliseconds a thread of the caller's instance stood stopped,
       suspend aside.

A successful verification proves the AIK signed these fields. ``pcr_mask``
and ``pcr_digest`` come from the TPM itself; the others are what the agent
stated, and a local root can sign its own. What that leaves a relying party
is in :doc:`../security/threat-model`.

``lota_server_parse_token()`` fills the same structure without checking the
signature or the nonce, for logs and debugging. Its claims are not evidence
of anything.

The registry
============

The token carries a 32-byte digest for each protected PID, and
``runtime_protect_digest`` covers them; the list itself travels outside the
token, as ``lota_get_registry()`` returned it on the client. The server
rebuilds each entry as ``struct lota_server_registry_module`` and
``struct lota_server_registry_actor``, with every field in the order listed,
and calls ``lota_server_registry_digest()`` with the registry's flags. The
result equals the token's ``protected_registry_digests`` entry for that PID
only for the list that round measured: an entry missing, added, reordered or
changed gives another digest. A registry is at most
``LOTA_SERVER_REGISTRY_MAX_OBJECTS`` (1024) objects and
``LOTA_SERVER_REGISTRY_MAX_ACTORS`` (256) actors; more, or an unknown flag,
returns ``LOTA_SERVER_ERR_INVALID_ARG``.

Boot evidence
=============

A token quotes PCR values by their digest alone. A server with no verifier
that wants to know whether the host booted with Secure Boot takes the bytes
``lota_get_boot_evidence()`` returned with the token and calls
``lota_server_verify_boot_evidence()`` with the claims of a verified token.
The evidence is accepted only when:

* its version is ``LOTA_BOOT_EVIDENCE_VERSION`` and its PCR mask is the
  token's and includes PCR 7;
* the token's PCR digest is SHA-256;
* its PCR values hash to that digest;
* its PCR 7 events replay to the PCR 7 value.

``secure_boot`` is then 1 when at least one ``SecureBoot`` measurement comes
before the firmware's separator and every one before it holds the single byte
1, and 0 otherwise, including evidence with no separator. A failure returns
``LOTA_SERVER_ERR_BAD_EVIDENCE`` and leaves ``secure_boot`` at 0. Evidence
fetched after the PCRs changed does not match the token and fails the same
way. How the agent builds it is in :doc:`../agent/boot-evidence`.

Token wire format
=================

All integers are little-endian. The fixed part is ``struct lota_token_wire``,
``LOTA_TOKEN_HEADER_SIZE`` (144) bytes:

.. list-table::
   :header-rows: 1
   :widths: 9 7 30 54

   * - Offset
     - Size
     - Field
     - Content
   * - 0
     - 4
     - ``magic``
     - ``LOTA_TOKEN_MAGIC``, ``"LOTK"`` in memory.
   * - 4
     - 2
     - ``version``
     - ``LOTA_TOKEN_VERSION`` (1).
   * - 6
     - 2
     - ``total_size``
     - Header and variable data.
   * - 8
     - 8
     - ``valid_until``
     - Unix time.
   * - 16
     - 4
     - ``flags``
     - ``LOTA_FLAG_*``.
   * - 20
     - 32
     - ``nonce``
     - The server's nonce.
   * - 52
     - 2
     - ``sig_alg``
     - TPM signature algorithm.
   * - 54
     - 2
     - ``hash_alg``
     - TPM hash algorithm.
   * - 56
     - 4
     - ``pcr_mask``
     - Quoted PCRs.
   * - 60
     - 32
     - ``policy_digest``
     - Startup policy.
   * - 92
     - 32
     - ``runtime_protect_digest``
     - Protected PIDs and their registry digests.
   * - 124
     - 4
     - ``protect_pid_count``
     - Number of PIDs.
   * - 128
     - 2
     - ``pid_list_size``
     - ``protect_pid_count`` × 4.
   * - 130
     - 2
     - ``attest_size``
     - ``TPMS_ATTEST`` size, at most 1024.
   * - 132
     - 2
     - ``sig_size``
     - Signature size, at most 512.
   * - 134
     - 2
     - ``runtime_protect_version``
     - ``LOTA_RUNTIME_PROTECT_V1``.
   * - 136
     - 8
     - ``stopped_ms``
     - Time the instance stood stopped.

The header is followed by ``protected_pids`` (``uint32_t`` each),
``protected_registry_digests`` (32 bytes each), ``attest_data`` and
``signature``. ``LOTA_TOKEN_MAX_SIZE`` holds the largest token.

The quote signs one 32-byte value, its ``extraData``, and that value ties the
header to the signature:

.. code-block:: text

   extraData = SHA256(valid_until || flags || pcr_mask || nonce ||
                      policy_digest || runtime_protect_digest ||
                      stopped_ms)

``sig_alg``, ``hash_alg``, the sizes and the PID and digest lists are outside
it: the first two are checked by the signature they select, the lists by
``runtime_protect_digest``.

Boot evidence starts with an 8-byte header (``version``, ``event_count``,
``pcr_mask``), then 32 bytes per set bit of ``pcr_mask``, lowest first, then
the events in log order: a 32-byte SHA-256 digest, a 2-byte ``data_size`` and
the data, present only for a ``SecureBoot`` measurement. It is at most
``LOTA_BOOT_EVIDENCE_MAX_SIZE`` (8192) bytes.

Errors
======

.. list-table::
   :header-rows: 1
   :widths: 7 38 55

   * - Value
     - Code
     - Meaning
   * - 0
     - ``LOTA_SERVER_OK``
     - Verified.
   * - -1
     - ``LOTA_SERVER_ERR_INVALID_ARG``
     - A ``NULL`` pointer, an empty or oversized key, or a malformed
       registry entry.
   * - -2
     - ``LOTA_SERVER_ERR_BAD_TOKEN``
     - The header or a size does not parse, or the PID list is not in
       strictly increasing order.
   * - -3
     - ``LOTA_SERVER_ERR_BAD_VERSION``
     - Another ``LOTA_TOKEN_VERSION``.
   * - -4
     - ``LOTA_SERVER_ERR_SIG_FAIL``
     - The signature does not verify, or names an algorithm the library
       does not take.
   * - -5
     - ``LOTA_SERVER_ERR_NONCE_FAIL``
     - The PCR mask, ``extraData`` or nonce differs.
   * - -6
     - ``LOTA_SERVER_ERR_EXPIRED``
     - ``valid_until`` has passed.
   * - -7
     - ``LOTA_SERVER_ERR_ATTEST_PARSE``
     - The ``TPMS_ATTEST`` does not parse, or its PCR digest has the wrong
       length.
   * - -8
     - ``LOTA_SERVER_ERR_CRYPTO``
     - The key does not decode or is not RSA of 2048 bits or more, or
       OpenSSL failed.
   * - -9
     - ``LOTA_SERVER_ERR_BUFFER``
     - Reserved; no function of the header returns it.
   * - -10
     - ``LOTA_SERVER_ERR_FUTURE``
     - ``valid_until`` lies beyond the window.
   * - -11
     - ``LOTA_SERVER_ERR_RUNTIME_IMAGE``
     - The PID list and registry digests do not hash to the signed
       ``runtime_protect_digest``.
   * - -12
     - ``LOTA_SERVER_ERR_BAD_EVIDENCE``
     - Boot evidence that is malformed or not of the boot the token quotes.

Functions
=========

.. kernel-doc:: include/lota_server.h
