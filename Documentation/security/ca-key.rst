.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

==========================
Attestation CA signing key
==========================

Every AIK certificate ``lota-attest-ca`` issues is signed with one key, and
every verifier of the fleet trusts the certificates it pins with
``--aik-ca-cert``. Whoever signs with that key mints AIK certificates the
fleet accepts. The CA loads the key from a file or from a PKCS#11 token
(:doc:`../admin-guide/bringup/ca-enrollment`, "PKCS#11 token"); on a file
key it logs ``using on-disk CA signing key -- development-only fallback``.
This page covers the life of the key: the ceremony, rotation, compromise and
a two-tier layout.

Key ceremony
============

#. Generate the key pair inside the token, marked non-extractable, so the
   private key has no plaintext form outside the device.

#. Put the token under dual control: split security officer and user PINs,
   or the device's M-of-N authorisation, so no one person holds both the
   authorisation and physical access.

#. Issue the CA certificate for that key before the key signs anything else.
   It must carry ``CA:TRUE``; ``lota-attest-ca`` refuses to start on a
   certificate that is not a CA or whose public key differs from the key's
   (:ghsrc:`src/attestca/ca/issuer.go`).

#. Back the key up by the device's wrapped export to a second token. A lost
   key without a backup means enrolling every host against a new one.

#. Keep the device's audit log. The CA logs the module and the token it
   signs through at each start (``using PKCS#11 CA signing key``).

Rotation
========

AIK certificates live for ``-aik-cert-ttl``, 24 hours by default, and the
agent renews one in the last third of its lifetime
(:doc:`../agent/publishers`). A rotation therefore needs the verifiers to
trust both keys for one certificate lifetime:

#. Generate the new key and certificate as above.

#. Add the new certificate to every verifier. ``--aik-ca-cert`` may be
   repeated, and a verifier reads it only at start, so restart each one
   after the change.

#. Move ``lota-attest-ca`` to the new key and certificate. Renewals and
   enrollments from then on are signed by the new key.

#. Once ``-aik-cert-ttl`` has passed since the CA stopped signing with the
   old key, remove the old certificate from the verifiers and restart them.

The agent names a publisher by the public key of the certificate it trusts
the CA's TLS endpoint with (:doc:`../agent/publishers`); the signing key
plays no part in it. A rotation that keeps that certificate keeps every
host's profile. One that replaces it makes the CA a new publisher to each
host, which enrolls again with ``--enroll`` and the new ``--ca-cert``. In
:ghsrc:`examples/enrollment/gen-ca.sh` and
:ghsrc:`examples/hsm-ca/setup-token.sh` that certificate is the CA
certificate, and its key issues the listener certificate, so there a
rotation keeps the profiles only while the old key issues the listener
certificate.

Compromise
==========

A leaked signing key mints certificates for any AIK. Stop the CA, remove
its certificate from every verifier and restart them: each AIK certificate
it signed then fails the chain check. Re-enroll the fleet against a new key.

A single leaked AIK does not need a new CA key. The verifier refuses an AIK
certificate listed in a CRL given with ``--aik-crl``, reloaded on
``SIGHUP``. Each CRL must be signed by a certificate pinned with
``--aik-ca-cert``; a version 3 signer must carry ``CA:TRUE``, and a signer
with a key usage extension must allow ``cRLSign``. A CRL that fails to load
stops the verifier at start, and keeps the previous set on ``SIGHUP``
(:ghsrc:`src/verifier/store/aik.go`, :ghsrc:`src/crl/crl.go`).

Two-tier layout
===============

The online CA signs on every enrollment, so its key is the exposed one. A
root key kept offline, used only at ceremonies, can issue an intermediate
certificate to the online CA:

* ``lota-attest-ca`` runs with ``-ca-cert`` set to the intermediate
  certificate and its key in the token. The CA checks it as any CA
  certificate: ``CA:TRUE`` and a public key matching the key.

* Each verifier pins the intermediate. It verifies an AIK certificate
  against the pinned certificates alone, with no intermediate pool
  (:ghsrc:`src/verifier/store/aik.go`), so a pinned offline root without
  the intermediate verifies nothing the online CA signs. A CRL signed by the
  root needs the root pinned as well.

* To rotate the online tier, the root issues a new intermediate, and the
  rotation above applies to it.

A leaked online key then costs the intermediate, and the root issues the
next one.
