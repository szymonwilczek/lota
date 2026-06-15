.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

Privacy CA enrollment (end-to-end)
==================================

This demo shows the trust chain that closes the gap a plain EK certificate
leaves open: it proves the AIK that signs attestation quotes lives in the same
TPM as a manufacturer-certified Endorsement Key, through TPM 2.0 credential
activation.

The model
---------

Each adopter self-hosts two services with their own keys. LOTA hosts nothing.

::

   [ TPM ]  EK cert (signed by the hardware vendor root)
      |
      |  enrollment, once per host:  MakeCredential -> ActivateCredential
      v
   [ lota-attest-ca ]   you host this; you own the CA key
      - verifies the EK certificate chains to a vendor root you trust
      - proves the AIK is in that same TPM (credential activation)
      - issues a short-lived AIK certificate; subject = device pseudonym
      |
      |  the AIK cert rides in every attestation report
      v
   [ lota-verifier ] x N   trusts only the CA root (--aik-ca-cert)
      - checks the AIK cert chains to the CA; never sees the EK
      - identity = the CA-assigned pseudonym, not an agent-asserted field

The verifier never sees the EK, so attestations are unlinkable to the hardware
across relying parties. A software-only client cannot get an AIK certificate:
without a TPM holding both keys, ``TPM2_ActivateCredential`` fails and the CA
refuses to issue.

Run it
------

Requires a provisioned TPM (real or swTPM) with a readable EK certificate, and
the built binaries (``make all``).

Enrollment requires an **RSA endorsement key** (the TCG EK template H-1, which
every TPM 2.0 ships) and an RSA AIK: credential activation wraps the secret to
the EK with RSA-OAEP, and the verifier authenticates quotes with an RSA AIK. A
TPM that presents an ECC EK is refused at ``Begin`` with a clear error naming
the key type; there is no ECC activation path.

.. code:: sh

   # 1. generate the CA material you host (CA key/cert, pseudonym key, TLS)
   ./gen-ca.sh ./ca

   # 2. run the full ceremony: CA -> enroll -> verifier -> attest
   EK_ROOT=/var/lib/swtpm-localca/issuercert.pem ./run.sh

``EK_ROOT`` is the certificate the TPM's EK certificate chains to. For swTPM it
is the local swtpm CA issuer certificate; for real hardware it is your vendor's
root bundle. A ``VERIFY_OK`` at the end means the AIK was activation-bound to
the EK and the verifier trusted it through the certificate chain alone.

This demo passes a single ``-ek-root`` because swTPM mints one local CA. A
production fleet instead trusts a pin-enforced multi-vendor bundle. The bundle
ships empty: the supported hardware set is every TPM whose EK certificate
chains to a root you can verify and pin, not a fixed vendor list. Build a
bundle from the platforms you actually attest:

.. code:: sh

   # 1. draft a sources line from a host's EK certificate (walks the issuer
   #    chain to the self-signed root and fingerprints it)
   sudo tpm2_nvread 0x01c00002 -o ek.der
   cp configs/ek-roots/sources.example sources
   scripts/lota-ek-root-pin.sh ek.der >>sources

   # 2. verify each pin out of band against the vendor's published value,
   #    then materialize the bundle (re-checks every fingerprint, fails closed)
   scripts/lota-ek-roots-update.sh sources /var/lib/lota/ek-roots

   # 3. point the CA at it
   lota-attest-ca ... -ek-root-bundle /var/lib/lota/ek-roots

The CA fails closed if any pinned manufacturer root is missing, mismatched, or
unpinned, and requires at least one root source to start at all. See
`configs/ek-roots/README.rst <../../configs/ek-roots/README.rst>`__ for the
full discovery and verification flow.

The script starts ``lota-verifier`` from a writable runtime directory
(``RUN_DIR``, default: a fresh ``/tmp/lota-enrollment.*``) and points
``--aik-store`` / ``--nonce-db`` there. This keeps generated TLS material and
nonce replay state out of the repository and avoids the production
``/var/lib/lota/aiks`` default when the verifier is not running as root. The
agent verifies the verifier TLS certificate generated in ``RUN_DIR``; the
script does not use ``--no-verify-tls``.

Notes for production
--------------------

- The demo verifier loads ``policies/testing.yaml`` and runs with
  ``--allow-permissive-policy``, ``--allow-tofu-boot-baseline`` and
  ``--allow-no-initramfs-lock`` so a fresh host passes without a pinned
  production policy. A real deployment loads a signed policy that pins PCR
  0/1/7 and ships the 90lota dracut module; see `Production Bringup
  <../../Documentation/operator/production-bringup/index.rst>`_
  and `policies/ <../../policies/README.rst>`_.
- The CA holds no TPM and stores no per-host secret beyond the in-flight
  challenge. Run one per fleet (or per region); every verifier that should
  trust it gets ``--aik-ca-cert ca.crt``.
- AIK certificates are short-lived (``--aik-cert-ttl``, default 24h); a host
  refreshes before expiry. The first enrollment records the CA endpoint, so a
  refresh is a single ``lota-agent --reenroll`` with no CA arguments -- the
  same guided path the agent points operators to after an AIK rotation.
