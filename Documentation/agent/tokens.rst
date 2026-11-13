.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

======
Tokens
======

A token is the daemon's answer to ``GET_TOKEN`` (:doc:`ipc`): a TPM quote
over PCRs 0, 1, 7 and 14, signed by an AIK, whose ``extraData`` binds the
token's other fields and the caller's nonce. A title asks for it through
the SDK (:doc:`../userspace-api/gaming`) and hands it to its server, which
verifies it (:doc:`../userspace-api/server`). The daemon builds it in
``handle_get_token()`` in :ghsrc:`src/agent/ipc.c`.

Contents
========

The answer is ``struct lota_ipc_token`` (:ghsrc:`include/lota_ipc.h`),
packed and in host byte order, followed by the protected PIDs
(little-endian, 32-bit), one 32-byte registry digest per PID, the
``TPMS_ATTEST`` and the signature. The SDK turns it into the
little-endian wire format of :doc:`../userspace-api/server`.

``valid_until``
  When the caller's verdict lapses: the last accepted report plus the
  attestation interval plus 60 seconds. On a connection with no publisher
  it is the host-wide window (:doc:`publishers`). Under
  ``LOTA_STATUS_TOKEN_ONLY`` it is the time of issue plus 240 seconds.

``flags``
  The status word the caller reads (:doc:`ipc`), with
  ``IMAGE_FULLY_MEASURED`` and ``IMAGE_CONTENT_HASHED`` taken from the
  processes this token lists (:doc:`runtime-measurement`).

``client_nonce``
  The 32-byte nonce of the request; zero when the request has none.

``pcr_mask``
  The PCRs of the quote, ``LOTA_TOKEN_QUOTE_PCR_MASK``: 0, 1, 7 and 14
  (:doc:`boot-evidence`).

``policy_digest``
  SHA-256 over the enforcement policy the agent started with
  (:doc:`protection`). With none set the request is answered
  ``LOTA_IPC_ERR_INTERNAL``.

``runtime_protect_digest``, ``protect_pid_count``, ``pid_list_size``
  The protected processes of the caller's own instance, in increasing PID
  order, and the digest over them and their registry digests
  (:doc:`protection`). ``runtime_protect_version`` is 1.

``stopped_ms``
  Milliseconds any thread of the caller's instance stood stopped, from the
  BPF LSM. Time the machine spent suspended is not counted. With the
  instance root gone it is 0.

``attest_size``, ``sig_size``, ``sig_alg``, ``hash_alg``
  The quote and its signature. ``sig_alg`` is ``TPM2_ALG_RSASSA`` or
  ``TPM2_ALG_RSAPSS``, ``hash_alg`` the hash of the signature (:doc:`tpm`).

The signing AIK is the publisher's on a connection bound with
``SET_PROFILE``, the only profile's on an unbound one, and the host AIK
with no profiles (:doc:`ipc`).

Quote binding
=============

The quote signs one 32-byte value, ``extraData``:

.. code-block:: text

   extraData = SHA256(valid_until || flags || pcr_mask || client_nonce ||
                      policy_digest || runtime_protect_digest ||
                      stopped_ms)

Integers are little-endian. The agent computes it with
``lota_compute_token_quote_nonce()`` in
:ghsrc:`include/lota_token_quote_nonce.h`; ``lota_server_verify_token()``
in :ghsrc:`src/sdk/lota_server.c` and ``ComputeTokenQuoteNonce`` in
:ghsrc:`sdk/server/verify.go` recompute it. The PID list and the registry
digests are bound through ``runtime_protect_digest``, which both verifiers
recompute. The remaining header fields are outside the signature.

Validity
========

The token carries an expiry and no issue time. Both verifiers refuse a
``valid_until`` more than ``LOTA_SERVER_MAX_TOKEN_AGE_SEC`` (300) plus
``LOTA_SERVER_MAX_CLOCK_SKEW_SEC`` (60) seconds ahead
(``DefaultMaxTokenAge`` and ``MaxClockSkew`` in Go).

The agent keeps inside that window: ``attest_interval`` and
``--attest-interval`` accept 30 to 240 seconds, and the interval plus the
60-second slack stays within the 300-second age, asserted at build time in
:ghsrc:`src/agent/attest.h`. The clock skew is left to the verifier's
clock. A relying party that wants a shorter window compares the verified
``valid_until`` with its own clock.

Rate limits
===========

A token costs a TPM quote, so ``GET_TOKEN`` has two limits, given in
:doc:`ipc`: a budget per connection and a ceiling per uid. A title holds
one connection, so the budget is the title's. The ceiling holds several
titles, since on a player's machine every title runs as the same uid, and
bounds a caller that opens more connections.

``_Static_assert``\ s in :ghsrc:`src/agent/ipc.h` require the connection
budget to exceed the rate of a 5-second heartbeat, the uid ceiling to cover
two connections, and the budget to stay below the ceiling.
