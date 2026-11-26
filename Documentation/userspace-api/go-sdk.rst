.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

======
Go SDK
======

``github.com/szymonwilczek/lota/sdk/server`` (:ghsrc:`sdk/server`) verifies
tokens and boot evidence for a relying party written in Go. It applies the
checks of :doc:`server`, reads the same wire formats and uses the standard
library alone; it talks to no agent, TPM or verifier. It has no registry
digest, so a server that rebuilds the registry of a protected process uses
``liblotaserver.so``.

.. code-block:: sh

   go get github.com/szymonwilczek/lota/sdk/server

The package is ``server``. Its API is the one public Go surface of the
repository (:doc:`stability`).

Verifying a token
=================

.. code-block:: go

   aik, err := server.ParseRSAPublicKey(aikDER)
   if err != nil {
           return err
   }

   claims, err := server.VerifyToken(token, aik, issuedNonce[:])
   if err != nil {
           return reject(err)
   }
   if claims.Flags&flagAttested == 0 {
           return untrusted()
   }

``aikDER`` is the host's AIK as a DER SubjectPublicKeyInfo, from the relying
party's own record of the host, never from the client (:doc:`server`).
``ParseRSAPublicKey()`` refuses a key that is not RSA or has fewer than 2048
bits. ``VerifyToken()`` takes the key as given, so a caller that builds an
``*rsa.PublicKey`` some other way checks its size itself.

The package declares no ``LOTA_FLAG_*`` constants; the bits and their meaning
are in :doc:`gaming`, and ``flagAttested`` above stands for
``LOTA_FLAG_ATTESTED``.

``VerifyToken()`` checks, and the first that fails returns:

#. a 32-byte ``expectedNonce`` and a non-nil key;
#. the header: magic, ``TokenVersion``, sizes, runtime protect version 1, at
   most ``MaxProtectPIDs`` PIDs;
#. a ``TPMS_ATTEST`` and a signature present;
#. the PID list in strictly increasing order;
#. the runtime protect digest, recomputed from the PID list and the registry
   digests the token carries;
#. the RSASSA or RSAPSS signature over the ``TPMS_ATTEST``, with SHA-256,
   SHA-384 or SHA-512 as the header names;
#. the ``TPMS_ATTEST`` itself, whose PCR selection is the SHA-256 bank only;
#. the quoted PCR mask against the header's;
#. ``extraData`` against ``ComputeTokenQuoteNonce()`` over the header;
#. the token's nonce against ``expectedNonce``;
#. the expiry: not passed, and at most ``DefaultMaxTokenAge`` (300) plus
   ``MaxClockSkew`` (60) seconds ahead of the server's clock.

An expiry of 0 is not refused as expired. The window is fixed. With
``ErrExpired`` or ``ErrFutureToken`` the verified claims come back with the
error; with any other error the claims are ``nil``. Nonces, replay and the
token's age work as in :doc:`server`.

``Claims``
==========

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Field
     - Content
   * - ``ExpiresAt``
     - The expiry as ``time.Time``; Unix time 0 when the token never
       expires.
   * - ``Flags``
     - The ``LOTA_FLAG_*`` word at issue time.
   * - ``Nonce``
     - The nonce the token answers.
   * - ``PCRMask``
     - The PCRs the quote covers.
   * - ``PolicyDigest``
     - SHA-256 over the agent's enforcement policy at startup.
   * - ``RuntimeProtectDigest``
     - SHA-256 over the protected PIDs and the registry digest of each.
   * - ``ProtectPIDCount``
     - How many protected processes the token lists.
   * - ``StoppedMS``
     - Milliseconds a thread of the caller's instance stood stopped.
   * - ``PCRDigest``
     - The digest of the quoted PCR values; empty when the attestation is no
       quote.
   * - ``SigAlg``, ``HashAlg``
     - The ``TPM_ALG_*`` signature scheme and hash, ``TPMAlg*`` in the
       package.
   * - ``Expired``
     - The expiry is nonzero and has passed.

From ``VerifyToken()`` every field but ``Expired`` is covered by the AIK
signature. Which of them the TPM vouches for and which the agent states is
the same as for the C claims (:doc:`server`).

``ParseToken()`` decodes a token without checking the signature or the
nonce, for logs and debugging, and its claims prove nothing. It fills
``PCRDigest`` when the quote parses and returns an error only for a header
that does not parse or an expiry out of range.

Boot evidence
=============

``VerifyBootEvidence(claims, evidence)`` takes the claims of a verified
token and the boot evidence the agent returned with it, and reports whether
the host booted with Secure Boot. The evidence is accepted when its version
is ``BootEvidenceVersion``, its PCR mask equals the token's and covers
PCR 7, the token's PCR digest is SHA-256, the PCR values hash to that digest
and the events replay to the PCR 7 value. Anything else returns
``ErrBadEvidence``, and ``nil`` claims ``ErrInvalidArg``; ``secureBoot`` is
false on any error.

Secure Boot is on when the separator is present, at least one
``SecureBoot`` event before it holds the value 1 and none before it holds
another value. An event without data is replayed and not read. The function
does not enforce ``BootEvidenceMaxSize``; a server that reads evidence from
the network bounds it before the call. The layout is in :doc:`server`.

Building tokens
===============

``SerializeToken()`` encodes a token from its fields, as
``lota_token_serialize()`` does in C, for tests and for tools that relay
tokens. It refuses lists and buffers over the limits, a PID list that is not
strictly increasing, and a registry digest count other than the PID count.
It does not check ``runtimeProtectDigest``, which the caller computes with
``ComputeRuntimeProtectDigest(pids, registryDigests)``.

``ComputeTokenQuoteNonce()`` returns the ``extraData`` a token's quote
carries:

.. code-block:: text

   SHA256(valid_until || flags || pcr_mask || nonce ||
          policy_digest || runtime_protect_digest || stopped_ms)

with the integers little-endian. It is another value than the binding nonce
of an attestation report to the verifier.

Constants
=========

.. list-table::
   :header-rows: 1
   :widths: 36 64

   * - Name
     - Value
   * - ``TokenMagic``, ``TokenVersion``
     - ``"LOTK"`` in memory, 1.
   * - ``TokenHeaderSize``
     - 144.
   * - ``MaxAttestSize``, ``MaxSigSize``
     - 1024, 512.
   * - ``MaxProtectPIDs``
     - 181, ``LOTA_TOKEN_MAX_PROTECT_PIDS``.
   * - ``RegistryDigestSize``
     - 32, per protected PID.
   * - ``TokenMaxSize``
     - A token with every list and buffer full.
   * - ``DefaultMaxTokenAge``, ``MaxClockSkew``
     - 300 and 60 seconds.
   * - ``MaxPCRSelectSize``, ``MaxPCRDigestSize``
     - 8 bytes of PCR selection, of which a bit past PCR 23 is refused; 64
       bytes of PCR digest.
   * - ``BootEvidenceVersion``
     - 1.
   * - ``BootEvidenceHeaderSize``, ``BootEvidenceEventSize``,
       ``BootEvidenceMaxSize``
     - 8, 34 (digest and ``data_size``), 8192.

Errors
======

The functions return the sentinels below, mostly wrapped with detail, so a
caller tests them with ``errors.Is``. ``SerializeToken()`` and
``ParseRSAPublicKey()`` return plain errors.

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Error
     - Cause
   * - ``ErrInvalidArg``
     - A ``nil`` key or claims, or a nonce of another length.
   * - ``ErrBadToken``
     - The header or a size does not parse, the PID list is not strictly
       increasing, or the expiry is out of range.
   * - ``ErrBadVersion``
     - Another ``TokenVersion``.
   * - ``ErrNoAttestData``, ``ErrNoSignature``
     - The token carries no ``TPMS_ATTEST`` or no signature.
   * - ``ErrRuntimeImage``
     - The PID list and registry digests do not hash to the signed
       runtime protect digest.
   * - ``ErrSigFail``
     - The signature does not verify, or names an algorithm the package does
       not take.
   * - ``ErrAttestParse``
     - The ``TPMS_ATTEST`` does not parse. A wrong TPM magic also matches
       ``ErrBadMagic``.
   * - ``ErrNonceFail``
     - The PCR mask, ``extraData`` or nonce differs.
   * - ``ErrExpired``
     - The expiry has passed.
   * - ``ErrFutureToken``
     - The expiry lies beyond the window.
   * - ``ErrBadEvidence``
     - Boot evidence that is malformed or not of the boot the token quotes.
