.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

HSM-backed attestation CA (PKCS#11)
===================================

The attestation CA's signing key is the root every issued AIK certificate
chains to. In production it belongs in an HSM, where the private key never
leaves the device; ``lota-attest-ca`` reaches it through PKCS#11. This example
stands the same flow up on **SoftHSM** so it can be exercised without hardware
-- the ``-ca-key-pkcs11-*`` flags are identical for a real HSM.

PKCS#11 support is **not** in the default binary (which is pure-Go); build the
CA with the ``pkcs11`` tag:

.. code:: sh

   make attest-ca GO_TAGS=pkcs11

The tag is part of what the build depends on, so this rebuilds a tree that was
already built without it. A containerised CA takes the ``-hsm`` tag of the
published image instead, which is that build on a base with a loader under it
(see `Documentation/operator/container-images.rst
<../../Documentation/operator/container-images.rst>`_).

.. _1-stand-up-the-token-and-the-ca-material:

1. Stand up the token and the CA material
-----------------------------------------

``setup-token.sh`` initialises a throwaway SoftHSM token, generates an RSA CA
key inside it, and issues everything the CA needs to start from that key. It
needs ``softhsm2-util``, ``pkcs11-tool`` (opensc) and ``openssl`` with the
pkcs11 provider:

.. code:: sh

   examples/hsm-ca/setup-token.sh ./hsm-ca     # token lota-ca, key lota-ca-key, PIN 1234

It writes into the output directory:

==================== ==========================================================
``softhsm2.conf``    token store; export it as ``SOFTHSM2_CONF``
``tokens/``          the token itself, holding the CA signing key
``ca.crt``           CA certificate whose public key is the token key
``tls.crt``/``.key`` listener keypair, issued **by** the token key
``pseudonym.key``    device-pseudonym secret
==================== ==========================================================

The script probes the common module paths (Fedora ``/usr/lib64/pkcs11``,
Debian ``/usr/lib/.../softhsm``); on an unusual layout set
``MODULE=/path/to/libsofthsm2.so``. It prints the resolved
``-ca-key-pkcs11-module`` in the command to run next.

The PIN is passed to the CA through ``LOTA_CA_PKCS11_PIN``, never a flag, so
it stays out of the process argument list.

.. _2-how-the-certificates-are-issued:

2. How the certificates are issued
----------------------------------

Both certificates are signed by the key **inside** the token, through
OpenSSL's PKCS#11 provider (``pkcs11-provider`` / ``libp11``), so the private
key never leaves it. Step 1 does this for you; the commands are here because a
real ceremony runs them against the operator's own module:

.. code:: sh

   export SOFTHSM2_CONF=./hsm-ca/softhsm2.conf
   openssl req -new -x509 -days 365 -provider pkcs11 -provider default \
       -key "pkcs11:token=lota-ca;object=lota-ca-key;type=private?pin-value=1234" \
       -subj "/CN=lota-attest-ca" -addext basicConstraints=critical,CA:TRUE \
       -addext keyUsage=critical,keyCertSign -out ca.crt

The ``pin-value`` in the URI is what makes this run unattended. Without it
OpenSSL prompts for the PIN, and a run with nothing on stdin fails with
``Could not find private key from pkcs11:...`` -- an authentication failure
reported as a missing object. A ceremony where the operator is present can
drop it and answer the prompt; ``pin-source=file:/path`` reads it from a file
the ceremony controls.

The listener certificate is issued the same way, with ``openssl x509 -req
-CA ca.crt -CAkey "pkcs11:...?pin-value=..."``. It has to be issued **from
this CA**: the agent passes one file as ``--ca-cert``, and that file both
anchors the listener's chain and is the publisher identity the host enrolls
with. A listener borrowed from another example is signed by a different root
and the agent refuses the handshake.

A real HSM follows the same steps against its own module and a key generated
or imported under the operator's key ceremony (see
`Documentation/operator/production-bringup/index.rst <../../Documentation/operator/production-bringup/index.rst>`_, "CA
signing key in an HSM").

.. _3-run-the-ca-against-the-token:

3. Run the CA against the token
-------------------------------

.. code:: sh

   export SOFTHSM2_CONF=./hsm-ca/softhsm2.conf
   export LOTA_CA_PKCS11_PIN=1234
   build/lota-attest-ca -listen :8444 \
       -ca-cert ./hsm-ca/ca.crt \
       -ca-key-pkcs11-module /usr/lib64/pkcs11/libsofthsm2.so \
       -ca-key-pkcs11-token lota-ca \
       -ca-key-pkcs11-label lota-ca-key \
       -tls-cert ./hsm-ca/tls.crt -tls-key ./hsm-ca/tls.key \
       -pseudonym-key ./hsm-ca/pseudonym.key \
       -ek-root-bundle /var/lib/lota/ek-roots

It logs ``using PKCS#11 CA signing key`` with the module and token it opened.
The CA refuses to start if the token key's public key does not match
``ca.crt``, the same check applied to an on-disk key, so a wrong token or
label cannot sign under the CA identity.

An agent enrolls against it with ``ca.crt`` as its ``--ca-cert``; the AIK
certificate that comes back is signed by the key in the token, which
``openssl verify -CAfile ca.crt`` confirms.

Continuous integration
----------------------

The ``pkcs11-softhsm`` job in ``.github/workflows/go-static-analysis.yml``
generates a key in a SoftHSM token, loads it through the production signer
path, and checks that an issued AIK certificate chains to a CA certificate
bound to that token key -- the end-to-end PKCS#11 signing path on every PR.
``tests/integration/test_hsm_ca_example.sh`` runs this example's setup script
and reads what it produced.
