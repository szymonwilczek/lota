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

``EK_ROOT`` is the trust material the TPM's EK certificate chains to, and the
script classes it: a directory is a pinned root bundle, passed as
``-ek-root-bundle``, and a file is a single self-signed anchor, passed as
``-ek-root``. For swTPM it is the local swtpm CA issuer certificate; for real
hardware it is the bundle built below, since a vendor chain needs the
intermediates a lone anchor cannot carry. A ``VERIFY_OK`` at the end means the
AIK was activation-bound to the EK and the verifier trusted it through the
certificate chain alone.

swTPM mints an EK one level under a root the demo itself generates, so the
request it sends carries the leaf and nothing else. Real hardware is rarely
that shallow: a firmware TPM puts its EK several levels below the vendor root
and stores the certificates nearest the leaf in its own NV. The agent presents
those with the request and reports how many it found::

   EK certificate chain: 3 manufacturer intermediate(s) from the TPM

A zero there is normal for swTPM and for a TPM whose EK is issued directly by a
published root. Where the count is not zero, it is the part of the path the
operator's bundle does not have to carry.

Pointing ``EK_ROOT`` at a single file is enough for swTPM, which mints one
local CA. Real hardware, and every production fleet, needs a pin-enforced
multi-vendor bundle instead. The bundle ships empty: the supported hardware set
is every TPM whose EK certificate chains to a root you can verify and pin, not
a fixed vendor list. Build a bundle from the platforms you actually attest:

.. code:: sh

   # 1. draft a sources line from a host's EK certificate (walks the issuer
   #    chain to the self-signed root and fingerprints it)
   sudo tpm2_nvread 0x01c00002 -o ek.der
   cp configs/ek-roots/sources.example sources
   scripts/lota-ek-root-pin.sh ek.der >>sources

   # 2. verify each pin out of band against the vendor's published value,
   #    then materialize the bundle (re-checks every fingerprint, fails closed)
   scripts/lota-ek-roots-update.sh sources /var/lib/lota/ek-roots

   # 3. point the demo at it; a directory is passed as -ek-root-bundle
   EK_ROOT=/var/lib/lota/ek-roots ./run.sh

The CA fails closed if any pinned manufacturer root is missing, mismatched, or
unpinned, and requires at least one root source to start at all. See
`configs/ek-roots/README.rst <../../configs/ek-roots/README.rst>`__ for the
full discovery and verification flow.

``CA_ADDR`` (default ``127.0.0.1:8444``, the CA's own port) and
``VERIFIER_ADDR`` (default ``127.0.0.1:9443``) are taken on a host that already
attests. The script checks both before starting anything and names the
variable to move a taken one:

.. code:: sh

   CA_ADDR=127.0.0.1:18444 VERIFIER_ADDR=127.0.0.1:19443 \
     EK_ROOT=/var/lib/swtpm-localca/issuercert.pem ./run.sh

The script starts ``lota-verifier`` from a writable runtime directory
(``RUN_DIR``, default: a fresh ``/tmp/lota-enrollment.*``) and points
``--aik-store`` / ``--state-db`` there. This keeps the verifier's durable
state -- nonce replay history and the enforcement decisions an operator makes
-- out of the repository, and avoids the production ``/var/lib/lota/aiks``
default when the verifier is not running as root. The verifier presents the listener
certificate ``gen-ca.sh`` issued, so the agent verifies the handshake against
``ca.crt`` -- the same file that names the publisher it enrolled with, which is
where the AIK certificate it presents is kept. The script does not use
``--no-verify-tls``.

The last step attests with a configuration file of its own, holding no
publisher profiles. On a host past bring-up the profile list is the target
list, and the agent refuses a ``--server`` naming one verifier beside it; a
demo configuration keeps this run pointed at the demo verifier and leaves the
host's own publishers alone.

Notes for production
--------------------

- The demo verifier loads ``policies/testing.yaml`` and runs with
  ``--allow-permissive-policy`` and ``--allow-tofu-boot-baseline`` so fresh
  host passes without a pinned production policy. The 90lota dracut module is
  required either way: the verifier has no derivation for a PCR 14 that the
  initramfs lock did not pin. A real deployment also loads a signed policy
  that pins PCR 0/1/7; see `Production Bringup
  <../../Documentation/operator/production-bringup/index.rst>`_
  and `policies/ <../../policies/README.rst>`_.
- The CA holds no TPM and stores no per-host secret beyond the in-flight
  challenge. Run one per fleet (or per region); every verifier that should
  trust it gets ``--aik-ca-cert ca.crt``.
- ``--ca-cert`` on the agent is that same ``ca.crt``, never the listener
  certificate. One file serves two roles -- the TLS trust anchor and the
  publisher's identity, which is the SHA-256 of its SubjectPublicKeyInfo -- so
  ``gen-ca.sh`` issues the listener from the CA and an operator names the CA.
  Binding the identity to the listener instead would move every enrolled host
  onto a new profile, a new AIK and a fresh consent prompt on each TLS
  rotation, with nothing reporting it; the listener is meant to rotate, and
  because it chains to the anchor, rotating it moves nobody.
- AIK certificates are short-lived (``--aik-cert-ttl``, default 24h); a host
  refreshes before expiry. The first enrollment records the CA endpoint in the
  publisher profile, so a refresh is a single ``lota-agent --reenroll
  --ca-cert ...`` naming the same trust anchor -- the same guided path the
  agent points operators to after an AIK rotation.
- The daemon's own renewal reuses that recorded **endpoint**, but presents the
  trust anchor the profile is **configured** with, falling back to the
  recorded path only for a target that has none. The two name the same
  publisher, since the profile is derived from the anchor; the difference is
  that the daemon runs sandboxed with its own ``/tmp`` and ``/var/tmp``, so an
  anchor kept in a staging directory is readable when an operator enrolls by
  hand and gone when the daemon later renews. Keep the anchor somewhere the
  daemon can read for the life of the profile -- ``/etc/lota`` is the obvious
  place -- and give ``--ca-cert`` that path rather than a build or unpack
  directory.
- Because the endpoint comes from the record, every line the agent writes
  about a renewal names the address it will dial rather than the ``ca`` and
  ``ca_port`` the profile is configured with, and a profile whose keys name
  somewhere else is reported once::

     verifier.example:8443: the enrollment records old-ca.example:8444,
     which is where renewal dials, not the CA this profile is configured
     with; run --enroll --ca-server ca.example --ca-port 8444 --ca-cert
     /etc/lota/ca.crt to move it

  ``--reenroll`` will not move it: it reuses the recorded endpoint by design,
  which is what makes it safe to run unattended. Moving a CA is an ``--enroll``
  naming the new address.
- The record also carries the enrollment token the first enrollment presented,
  and both ``--reenroll`` and the daemon's renewal replay it, so a CA that
  admits on tokens keeps admitting the host with no operator step. The token
  therefore lives at rest in the profile's ``enroll_state.dat`` (root-owned,
  ``0600``) for as long as the profile does.
