.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

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
TLS keypair (:ghsrc:`examples/enrollment/gen-ca.sh` generates the CA material).
Production fleets span several TPM manufacturers, so trust a pin-enforced
multi-vendor bundle with ``-ek-root-bundle``; the CA fails closed if any pinned
root is missing, mismatched, or unpinned (see :ghsrc:`configs/ek-roots/README.rst`
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
:ghsrc:`configs/ek-roots/README.rst`.

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
topology are covered in :doc:`../../security/ca-key <../../security/ca-key>`.

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
enters ``sources``.

See :ghsrc:`configs/ek-roots/README.rst` for the full flow.

Enrolling a host
================

Enroll the agent once per host (the daemon then renews the certificate on its
own before the TTL, default 24h, expires):

.. code-block:: sh

    sudo lota-agent --enroll --ca-server ca.example --ca-port 8444 \
        --ca-cert tls.crt
    # stores the issued certificate and the CA endpoint in the publisher
    # profile the trust anchor names, under /var/lib/lota/profiles/

``--ca-cert`` is required. Beyond verifying the TLS peer, the trust anchor is
what names the publisher: the profile directory is the SHA-256 of the anchor's
SubjectPublicKeyInfo, so a host answering to several publishers keeps one AIK,
one certificate and one enrollment record per publisher and no publisher can
correlate the host through a shared identity. The endpoint is deliberately not
the identity -- an address is mutable and two publishers can share a hostname,
while reissuing the CA certificate over the same key keeps the profile.

The first enrollment records the CA endpoint in that profile, so the running
agent renews the certificate on its own against that endpoint as it nears
expiry (it re-enrolls once the cert enters its final third of validity, backing
off when the CA is unreachable). The renewal is automatic whenever an endpoint
is on disk, so an enrolled host needs no scheduled ``--reenroll``. The same
guided command stays available as a manual override -- before the certificate
TTL expires, or after the agent rotates the AIK -- naming only the anchor that
selects the profile:

.. code-block:: sh

    sudo lota-agent --reenroll --ca-cert tls.crt

Point every verifier at the CA root:

.. code-block:: sh

    lota-verifier -aik-ca-cert ca.crt ...

A host that has not enrolled (no AIK certificate) is refused under the
production ``--require-cert`` default.

See :ghsrc:`examples/enrollment/README.rst` for the full end-to-end walk-through.

Self-service re-anchor (diverse-fleet profile)
==============================================

On the diverse-fleet profile (a policy with ``require_secureboot``), a
legitimate firmware update shifts PCR 0/1 and would otherwise reject the host
until an operator clears its baseline. ``profile: consumer`` in the policy lets
the verifier re-pin the per-device baseline itself when the drift preserves the
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
existing endpoints.

The profile lives in the policy because it describes the fleet, not the
deployment, and one verifier can serve several tenants and therefore several
fleets. ``enterprise`` (and an unset profile) leaves the path off, which is
right where firmware drift is a finding and re-baselining stays a deliberate
operator action. ``--enable-self-service-reanchor`` remains as an override in
both directions for an operator who has to contradict a policy they cannot
immediately re-sign; left unset, each policy decides for itself.

Operator-forced re-anchor and client removal
============================================

Deliberate counterpart of the self-service path works on every profile
and needs no verifier flag. When a platform change is legitimate but the
self-service re-anchor refuses it (or the profile does not enable it), drop
the device's pinned baselines through the admin API; the next attestation
re-establishes trust per the active TOFU/policy configuration:

.. code-block:: sh

    curl -X POST https://verifier:8080/api/v1/clients/{clientID}/reanchor \
        -H "Authorization: Bearer $ADMIN_KEY" \
        -d '{"actor":"ops@example.com","note":"planned firmware update"}'

``actor`` is required and lands in the audit log together with the ``note``;
the action is also logged at security level and counted in the ``forced``
re-anchor metric. The enrollment is untouched -- the host keeps attesting
with its enrolled AIK identity.

To remove a device from the fleet entirely (decommissioned host, or trust
state that must be rebuilt from scratch), delete the client. This drops the
baselines and any AIK-store registration; the optional body is audit
metadata:

.. code-block:: sh

    curl -X DELETE https://verifier:8080/api/v1/clients/{clientID} \
        -H "Authorization: Bearer $ADMIN_KEY" \
        -d '{"actor":"ops@example.com","note":"decommissioned"}'

Revocations and hardware bans are keyed separately and survive the delete,
so removing a client cannot be used to shed either -- a revoked identity
that re-enrolls is still revoked.

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

Assigning tenants at enrollment
===============================

A multi-tenant deployment gives each enrolled device a tenant, which the
verifier then uses to scope that device's bans, revocations, baselines, logs,
and PCR policy. The tenant is assigned by the CA at enrollment and written into
the issued AIK certificate as a single ``OrganizationalUnit``; the verifier
reads it only after verifying the certificate chain, so a host cannot choose
its own tenant.

The enterprise path resolves the tenant from an EK-to-tenant manifest. The
manifest is a text file, one entry per line, mapping an endorsement-key
fingerprint to a tenant name; blank lines and lines beginning with ``#`` are
ignored:

.. code-block:: text

    # <ek_sha256> <tenant>
    3b1f...c7  acme
    9a20...4e  beta

The fingerprint is the SHA-256 of the endorsement key's public modulus. For an
EK certificate in ``ek.pem`` an operator computes it with:

.. code-block:: sh

    openssl x509 -in ek.pem -noout -modulus \
      | sed 's/^Modulus=//' | xxd -r -p | sha256sum

Point the CA at the manifest with ``--tenant-manifest``:

.. code-block:: sh

    lota-attest-ca ... --tenant-manifest /etc/lota/tenants.txt

An endorsement key with no manifest entry lands in the reserved ``default``
tenant, which is encoded as the absence of an ``OrganizationalUnit`` so
single-tenant deployments keep issuing byte-identical subjects. Add
``--tenant-manifest-strict`` to refuse enrollment for any endorsement key
absent from the manifest; the manifest then doubles as an EK allowlist. A
strict rejection happens before the credential challenge is wrapped, so a
barred device never consumes an enrollment session.

The device pseudonym in the certificate ``CommonName`` mixes in a named
tenant, so one TPM enrolling into two tenants yields two distinct device IDs
and never collides in the verifier's per-tenant state. A device that moves to
a new tenant is therefore a new identity there and re-enrolls from scratch.
The ``default`` tenant keeps the pseudonym derivation used before tenant
assignment, so devices enrolled by an older CA re-enroll under the same
device ID and keep their verifier-side state.

The verifier reads this tenant from the certificate and scopes the device's
bans, revocations, PCR policy, and operator-API visibility to it. See
:doc:`../multi-tenancy <../multi-tenancy>` for how tenancy scopes verifier
state and how to configure scoped monitoring-API access.

Assigning tenants with enrollment tokens
========================================

An EK manifest presumes the operator knows every endorsement key up front,
which a consumer deployment cannot: a game title enrolls machines the operator
has never seen. Those deployments hand each tenant's install flow a shared
*enrollment token*, an opaque secret string the agent presents with its begin
request; the CA resolves the tenant from the token instead of the EK.

The CA never stores tokens, only their digests. Mint a token per tenant, hand
it to that tenant's distribution channel, and record its SHA-256 in a
token-to-tenant file with the same shape as the manifest:

.. code-block:: sh

    printf %s "$TOKEN" | sha256sum

.. code-block:: text

    # <token_sha256> <tenant>
    5e88...12  game-alpha
    a71c...09  game-beta

Point the CA at the file with ``--enrollment-tokens``:

.. code-block:: sh

    lota-attest-ca ... --enrollment-tokens /etc/lota/enroll-tokens.txt

A presented token is an explicit tenant assignment and fails closed: a token
matching no entry (or any token on a CA without ``--enrollment-tokens``) is
refused with a token rejection before the credential challenge is wrapped, and
never falls back to the EK manifest or the default tenant. Only a token-less
enrollment takes the EK-manifest path, so both mechanisms can serve one CA.
Add ``--require-enrollment-token`` to refuse token-less enrollments outright;
the token set is then the sole admission control, which is the consumer shape
where no enrolling EK is known in advance.

On the device, store the token in a root-only file (never on a command line,
where it would be visible in ``ps`` and shell history) and point ``--enroll``
at it:

.. code-block:: sh

    sudo install -m 600 /dev/null /etc/lota/enroll.token
    printf %s "$TOKEN" | sudo tee /etc/lota/enroll.token >/dev/null
    sudo lota-agent --enroll --ca-server ca.example --ca-port 8444 \
        --ca-cert /etc/lota/ca-tls.crt \
        --enroll-token-file /etc/lota/enroll.token

The token must be 1 to 128 printable, non-whitespace ASCII characters; a
trailing newline in the file is tolerated. A successful enrollment persists
the token (not the file path) in the profile's root-only enrollment record
next to the CA endpoint, so ``--reenroll`` and the daemon's automatic certificate
renewal keep presenting it without further operator input. Re-run
``--enroll`` with a new token file to replace it.

Rotate a token by minting a new one, adding its digest to the file alongside
the old entry (both then enroll into the tenant), shipping the new token to
the install flow, and deleting the old digest once the rollout completes.
Removing a digest stops future enrollments with that token but does not
revoke certificates it already produced; revoke those at the verifier.

Wire compatibility: an agent that presents no token keeps speaking protocol
version 1, so upgraded agents interoperate with an old CA, and the CA answers
each request in the version it arrived with, so old agents interoperate with
an upgraded CA. The token travels only inside the enrollment TLS channel.
