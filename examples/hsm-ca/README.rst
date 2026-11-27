.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

===================================
HSM-backed attestation CA (PKCS#11)
===================================

This example keeps the attestation CA's signing key in a SoftHSM token and
runs ``lota-attest-ca`` against it through PKCS#11. The ``-ca-key-pkcs11-*``
options are the same for a hardware token; they are described in
`ca-enrollment.rst
<../../Documentation/admin-guide/bringup/ca-enrollment.rst>`_, "PKCS#11
token", and the life of the key in `ca-key.rst
<../../Documentation/security/ca-key.rst>`_.

The default build has no PKCS#11 support. Build the CA with the ``pkcs11``
tag, which needs cgo:

.. code-block:: console

	$ make attest-ca GO_TAGS=pkcs11

A change of ``GO_TAGS`` rebuilds the CA. The ``-hsm`` container image is
that build (`container-images.rst
<../../Documentation/admin-guide/container-images.rst>`_).

Token and CA material
=====================

``setup-token.sh`` needs ``softhsm2-util``, ``pkcs11-tool`` from opensc, and
``openssl`` with the PKCS#11 provider. It runs without root and touches no
system token::

	examples/hsm-ca/setup-token.sh [out-dir] [token-label] [key-label] [pin]

The defaults are ``./hsm-ca``, token ``lota-ca``, key ``lota-ca-key`` and PIN
``1234``; the security officer PIN is ``12345678``. The script finds
``libsofthsm2.so`` under ``/usr/lib/softhsm``, ``/usr/lib64/softhsm``,
``/usr/lib64/pkcs11`` or ``/usr/lib/x86_64-linux-gnu/softhsm``, or takes
it from ``MODULE``. It then:

#. writes ``softhsm2.conf`` with a token store in ``tokens/`` and
   initialises a token with that label;

#. generates an RSA 2048 key pair in the token with the key label and
   ``CKA_ID`` ``01``;

#. issues ``ca.crt``, a self-signed certificate over the token key valid for
   365 days, with ``CA:TRUE`` and the ``keyCertSign`` and ``cRLSign`` key
   usages;

#. generates a P-256 listener key ``tls.key`` and issues ``tls.crt`` with the
   token key, valid for 825 days, for ``127.0.0.1`` and ``localhost``;

#. writes 32 random bytes to ``pseudonym.key``, unless the file exists.

Files are created with umask 077. Run the script on a directory without
``tokens/``: a second run adds another token with the same label, and the
later steps pick a token by its label alone. The script ends by printing the
build and run commands with the module it found and a build directory from
``BUILD_DIR``, else ``LOTA_BUILD_DIR``, else ``build/`` of the repository.

Both certificates are signed inside the token through OpenSSL's PKCS#11
provider. A ceremony against another module uses the same commands:

.. code-block:: console

	$ export SOFTHSM2_CONF=./hsm-ca/softhsm2.conf
	$ openssl req -new -x509 -days 365 -provider pkcs11 -provider default \
		-key "pkcs11:token=lota-ca;object=lota-ca-key;type=private?pin-value=1234" \
		-subj "/CN=lota-attest-ca" -addext basicConstraints=critical,CA:TRUE \
		-addext keyUsage=critical,keyCertSign,cRLSign -out ca.crt

The ``pin-value`` in the URI is what makes this run unattended. Without it
OpenSSL asks for the PIN, and a run with empty standard input fails to load
the key. A ceremony where the operator is present can
drop it and answer the prompt; ``pin-source=file:/path`` reads it from a file
the ceremony controls.

The listener certificate is issued by the CA key so that one file serves the
agent as ``--ca-cert``: it verifies the listener's certificate, and its
public key is the publisher identity the host enrolls under. A listener
certificate signed by another key fails the agent's TLS handshake.

Running the CA
==============

.. code-block:: console

	$ export SOFTHSM2_CONF=./hsm-ca/softhsm2.conf
	$ export LOTA_CA_PKCS11_PIN=1234
	$ build/lota-attest-ca -listen :8444 \
		-ca-cert ./hsm-ca/ca.crt \
		-ca-key-pkcs11-module /usr/lib64/pkcs11/libsofthsm2.so \
		-ca-key-pkcs11-token lota-ca \
		-ca-key-pkcs11-label lota-ca-key \
		-tls-cert ./hsm-ca/tls.crt -tls-key ./hsm-ca/tls.key \
		-pseudonym-key ./hsm-ca/pseudonym.key \
		-ek-root-bundle /var/lib/lota/ek-roots

The CA reads the PIN from ``LOTA_CA_PKCS11_PIN`` alone, so it stays out of
the argument list. It logs ``using PKCS#11 CA signing key`` with the module
and the token, and refuses to start when the token key does not match
``ca.crt``. An agent enrolls with ``ca.crt`` as its ``--ca-cert``.

Tests
=====

``TestPKCS11SignerIssuesAIK`` in ``src/attestca/casigner_pkcs11_test.go``
generates a key in a SoftHSM token, signs an AIK certificate through the
PKCS#11 signer and checks that it chains to a CA certificate over that key;
the ``pkcs11-softhsm`` job of ``.github/workflows/go-static-analysis.yml``
runs it. ``tests/integration/test_hsm_ca_example.sh`` runs ``setup-token.sh``
with standard input from ``/dev/null`` and checks what it wrote;
``make test-unit`` runs it when the three tools are installed.
