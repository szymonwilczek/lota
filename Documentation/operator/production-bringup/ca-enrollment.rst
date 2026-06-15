=========================
Attestation CA enrollment
=========================

The verifier authenticates an agent only through a certificate issued by the
attestation CA (``lota-attest-ca``), so each host enrolls once before it can
attest. Enrollment runs the TPM 2.0 credential-activation ceremony: the CA
verifies the EK certificate chains to a trusted manufacturer root, proves the
AIK and that EK share one TPM, and issues a short-lived AIK certificate whose
subject is the device pseudonym. The EK is presented only to the CA; verifiers
never see it.

Stand up the CA with your CA key, the trusted manufacturer EK roots and a server
TLS keypair (``examples/enrollment/gen-ca.sh`` generates the CA material).
Production fleets span several TPM manufacturers, so trust a pin-enforced
multi-vendor bundle with ``-ek-root-bundle``; the CA fails closed if any pinned
root is missing, mismatched, or unpinned (see ``configs/ek-roots/README.rst``
for how to materialize one):

.. code-block:: sh

    lota-attest-ca -listen :8444 \
        -ca-cert ca.crt -ca-key ca.key \
        -tls-cert tls.crt -tls-key tls.key \
        -pseudonym-key pseudonym.key \
        -ek-root-bundle /var/lib/lota/ek-roots

``-ek-root <file>`` is still accepted and adds operator-supplied roots (for
example a swtpm CA in the enrollment demo) on top of the bundle; pass either or
both.

Pair the bundle with the manufacturers' EK revocation feeds: ``-ek-crl <file>``
(repeatable) loads a manufacturer CRL, enrollment rejects a revoked EK, and
SIGHUP reloads a rewritten feed in place. See the "Manufacturer CRLs" section of
``configs/ek-roots/README.rst``.

CA signing key
==============

The CA signing key is the anchor every issued AIK certificate chains to, so the
CA loads it as a ``crypto.Signer`` and checks the signer's public key against
the CA certificate at startup -- a key that does not match the certificate is
refused, whether it comes from a file or an external store.

The source is selectable: an on-disk PKCS#8 PEM (``-ca-key``) for development,
or an external key store that never exposes the private key for production. The
sections below cover the production options.

``-ca-key`` is a **development-only fallback**. The key sits in the clear on the
host, so a host compromise yields the fleet's signing root. The CA logs a loud
warning at startup whenever it is used, and it is never the production default:
a production CA holds the key in an HSM (next section) and keeps ``-ca-key`` for
local bring-up and tests only.

CA signing key in an HSM (PKCS#11)
----------------------------------

A production CA holds its signing key in a PKCS#11 token (an HSM, or SoftHSM for
tests) so the private key never leaves the device. This needs a PKCS#11-enabled
build of the CA -- the default binary is pure-Go and has no PKCS#11 support:

.. code-block:: sh

    make BUILD_DIR=/var/tmp/lota-build attest-ca GO_TAGS=pkcs11   # cgo + PKCS#11

Point the CA at the token instead of ``-ca-key``. The PIN is read from the
environment, never a flag, so it stays out of the process argument list:

.. code-block:: sh

    export LOTA_CA_PKCS11_PIN=...                 # token user PIN
    lota-attest-ca -listen :8444 \
        -ca-cert ca.crt \
        -ca-key-pkcs11-module /usr/lib64/softhsm/libsofthsm2.so \
        -ca-key-pkcs11-token lota-ca \
        -ca-key-pkcs11-label lota-ca-key \
        -tls-cert tls.crt -tls-key tls.key \
        -pseudonym-key pseudonym.key \
        -ek-root-bundle /var/lib/lota/ek-roots

Select the key by ``-ca-key-pkcs11-label`` (CKA_LABEL) or ``-ca-key-pkcs11-id``
(CKA_ID, hex). The CA checks the token key's public key against ``ca.crt`` at
startup and refuses to run on a mismatch, the same check applied to an on-disk
key, so a wrong token or label cannot sign under the CA identity. ``-ca-key``
and the ``-ca-key-pkcs11-*`` flags are mutually exclusive.

The CA key ceremony, rotation, and the offline-root / online-intermediate
topology are covered in `../../security/ca-key.rst
<../../security/ca-key.rst>`_.

Materializing the EK root bundle
--------------------------------

The bundle ships empty: the supported set is every TPM whose EK certificate
chains to a root you can verify and pin, not a fixed vendor list. Build it from
the platforms you actually attest -- draft a sources line from a host's EK
certificate, verify each pin out of band against the vendor's published value,
then materialize the bundle:

.. code-block:: sh

    # walk the EK cert's issuer chain to the self-signed root and draft a line
    sudo tpm2_nvread 0x01c00002 -o ek.der
    cp configs/ek-roots/sources.example sources
    scripts/lota-ek-root-pin.sh ek.der >>sources

    # after verifying each pin out of band, fetch and pin the roots
    scripts/lota-ek-roots-update.sh sources /var/lib/lota/ek-roots

``lota-ek-root-pin.sh`` prints a fingerprint over what the network returned; it
does not vouch for it, so confirm the pin against the vendor before the line
enters ``sources``. See ``configs/ek-roots/README.rst`` for the full flow.

Enrolling a host
================

Enroll the agent once per host (the daemon then renews the certificate on its
own before the TTL, default 24h, expires):

.. code-block:: sh

    sudo lota-agent --enroll --ca-server ca.example --ca-port 8444 \
        --ca-cert tls.crt
    # stores /var/lib/lota/aik_cert.der, sent in every attestation report
    # also records the CA endpoint for guided re-enrollment

The first enrollment records the CA endpoint, so the running agent renews the
certificate on its own against that endpoint as it nears expiry (it re-enrolls
once the cert enters its final third of validity, backing off when the CA is
unreachable). The renewal is automatic whenever an endpoint is on disk, so an
enrolled host needs no scheduled ``--reenroll``. The same guided command stays
available as a manual override -- before the certificate TTL expires, or after
the agent rotates the AIK -- with no CA arguments and no manual CA steps:

.. code-block:: sh

    sudo lota-agent --reenroll

Point every verifier at the CA root:

.. code-block:: sh

    lota-verifier -aik-ca-cert ca.crt ...

A host that has not enrolled (no AIK certificate) is refused under the
production ``--require-cert`` default. See ``examples/enrollment/README.rst`` for
the full end-to-end walk-through.

Self-service re-anchor (diverse-fleet profile)
==============================================

On the diverse-fleet profile (a policy with ``require_secureboot``), a
legitimate firmware update shifts PCR 0/1 and would otherwise reject the host
until an operator clears its baseline. ``-enable-self-service-reanchor`` lets the
verifier re-pin the per-device baseline itself when the drift preserves the
Secure Boot root of trust (PK/KEK/db unchanged, ``dbx`` append-only, Secure Boot
still on, firmware version not rolled back); a hardware platform that reports no
firmware version (``ESRT``, common on DIY boards flashed with the vendor tool
rather than a UEFI capsule) takes a Low-Firmware-Assurance path. The LFA
re-anchor also applies automatically -- the player is never blocked waiting on
the operator -- but it flags the device for post-fact review: list flagged
devices with ``GET /api/v1/reanchor/review`` and clear one after inspecting it
with ``POST /api/v1/clients/{clientID}/reanchor-review-ack`` (each LFA re-anchor
is also logged at security level and counted in the ``lfa`` re-anchor metric).
If a reviewed re-anchor looks wrong, revoke or ban the device through the
existing endpoints. Leave the flag off for the enterprise profile, where
firmware drift is a feature and re-baselining stays a deliberate operator
action.

AIK rotation status over D-Bus
==============================

The agent rotates the AIK on its own schedule (``--aik-ttl``, default 30d). It
surfaces the rotation state over D-Bus so an operator -- or a fleet monitor --
can see when a rotation is due and when a re-enrollment is needed.
``GetRotationStatus`` returns the generation, the AIK creation time, the
next-rotation deadline, any open grace window, and whether the stored
certificate has been outdated by a rotation:

.. code-block:: sh

    busctl call org.lota.Agent1 /org/lota/Agent1 org.lota.Agent1 \
        GetRotationStatus
    # (tttttb) generation provisioned_at rotation_deadline ... reenroll_required

    busctl get-property org.lota.Agent1 /org/lota/Agent1 org.lota.Agent1 \
        ReenrollRequired

When ``ReenrollRequired`` is true, the host rotated its AIK and the issued
certificate is stale; clear it with the guided ``sudo lota-agent --reenroll``
above. The same properties emit ``PropertiesChanged``, so a subscriber is
notified the moment a rotation happens rather than having to poll.
