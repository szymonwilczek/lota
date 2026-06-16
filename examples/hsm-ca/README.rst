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

.. _1-put-a-ca-key-in-a-token:

1. Put a CA key in a token
--------------------------

``setup-token.sh`` initialises a throwaway SoftHSM token and generates an RSA
CA key inside it, then prints the flags to use. It needs ``softhsm2-util`` and
``pkcs11-tool`` (opensc):

.. code:: sh

   examples/hsm-ca/setup-token.sh           # defaults: token lota-ca, key lota-ca-key, PIN 1234

The script probes the common module paths (Fedora ``/usr/lib64/pkcs11``, Debian
``/usr/lib/.../softhsm``); on an unusual layout set
``MODULE=/path/to/libsofthsm2.so``. It prints the resolved
``-ca-key-pkcs11-module`` to paste into step 3.

The PIN is passed to the CA through ``LOTA_CA_PKCS11_PIN``, never a flag, so it
stays out of the process argument list.

.. _2-issue-the-ca-certificate-from-the-token-key:

2. Issue the CA certificate from the token key
----------------------------------------------

The CA needs a CA *certificate* (``ca.crt``) whose public key is the token key;
``lota-attest-ca`` checks the two match at startup. The certificate is signed
by the HSM key itself, through OpenSSL's PKCS#11 provider (``pkcs11-provider``
/ ``libp11``), so the private key never leaves the token:

.. code:: sh

   export SOFTHSM2_CONF=...                  # printed by setup-token.sh
   openssl req -new -x509 -days 365 -provider pkcs11 -provider default \
       -key "pkcs11:token=lota-ca;object=lota-ca-key;type=private" \
       -subj "/CN=lota-attest-ca" -addext basicConstraints=critical,CA:TRUE \
       -addext keyUsage=critical,keyCertSign -out ca.crt

A real HSM follows the same step against its own module and a key generated or
imported under the operator's key ceremony (see
`Documentation/operator/production-bringup/index.rst <../../Documentation/operator/production-bringup/index.rst>`_, "CA
signing key in an HSM").

.. _3-run-the-ca-against-the-token:

3. Run the CA against the token
-------------------------------

.. code:: sh

   export LOTA_CA_PKCS11_PIN=1234
   lota-attest-ca -ca-cert ca.crt \
       -ca-key-pkcs11-module /usr/lib/softhsm/libsofthsm2.so \
       -ca-key-pkcs11-token lota-ca \
       -ca-key-pkcs11-label lota-ca-key \
       -tls-cert tls.crt -tls-key tls.key \
       -pseudonym-key pseudonym.key \
       -ek-root-bundle /var/lib/lota/ek-roots

The CA refuses to start if the token key's public key does not match
``ca.crt``, the same check applied to an on-disk key, so a wrong token or label
cannot sign under the CA identity.

Continuous integration
----------------------

The ``pkcs11-softhsm`` job in ``.github/workflows/go-static-analysis.yml``
generates a key in a SoftHSM token, loads it through the production signer
path, and checks that an issued AIK certificate chains to a CA certificate
bound to that token key -- the end-to-end PKCS#11 signing path on every PR.
