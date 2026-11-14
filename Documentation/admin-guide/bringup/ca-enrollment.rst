.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

=========================
Attestation CA enrollment
=========================

``lota-attest-ca`` is a publisher's enrollment service. It checks that a
host's endorsement key (EK) certificate chains to a TPM manufacturer the
operator trusts, proves by credential activation that the attestation key
(AIK) the host presents lives in the same TPM, and issues a certificate for
that AIK. A verifier trusts the AIK certificates of the CA certificates its
``-aik-ca-cert`` names (:ghsrc:`src/verifier/main.go`), so a host attests to
a publisher after it enrolls with that publisher's CA.

This page covers the CA. The host's side of the exchange is in
:doc:`../../agent/tpm`, profiles and renewal in
:doc:`../../agent/publishers`, and the agent's options in
:doc:`../../agent/command-line`.

Running the CA
==============

The CA needs its own certificate and signing key, a TLS key pair for its
listener, a pseudonym key and at least one trusted EK root
(:ghsrc:`src/attestca/main.go`):

.. code-block:: console

   $ lota-attest-ca -ca-cert ca.crt -ca-key ca.key \
         -tls-cert tls.crt -tls-key tls.key \
         -pseudonym-key pseudonym.key \
         -ek-root-bundle /var/lib/lota/ek-roots

:ghsrc:`examples/enrollment/gen-ca.sh` writes a CA certificate and key, a
pseudonym key and a listener certificate issued by that CA. The agent checks
the listener certificate against the certificate its ``--ca-cert`` names,
and checks that it is issued to the host name or address the agent dials
(:ghsrc:`src/agent/net.c`). A listener certificate issued from the CA key
passes the first check.

The CA logs to standard error. Once it listens it logs
``lota-attest-ca listening`` with these fields:

``address``
  The address it listens on.

``ek_roots``, ``ek_intermediates``
  The EK certificates it trusts as roots and holds as intermediates
  (`EK trust`_).

``ek_crls``
  The manufacturer CRLs loaded (`EK revocation`_).

``aik_cert_ttl``, ``session_ttl``, ``max_pending``
  The values of the options of those names.

The ``lota-attest-ca`` package installs the binary as
``/usr/bin/lota-attest-ca`` and ships no systemd unit
(:ghsrc:`packaging/nfpm/lota-attest-ca.yaml`). Container images are in
:doc:`../container-images`.

Options
=======

An option takes one dash or two. A duration is a Go duration such as
``90s`` or ``12h``. ``-h`` prints the options and exits 0.

``-listen ADDR``
  TCP address of the TLS listener. Default ``:8444``.

``-ca-cert FILE``
  PEM CA certificate that signs AIK certificates. Required. It must be a CA
  certificate (``CA:TRUE``) and match the signing key.

``-ca-key FILE``
  PKCS#8 PEM signing key of the CA: ECDSA, Ed25519 or RSA. Required when no
  ``-ca-key-pkcs11-*`` option is given, refused beside one. For development
  only (`CA signing key`_).

``-ca-key-pkcs11-module FILE``
  PKCS#11 module that holds the CA key. Required when any other
  ``-ca-key-pkcs11-*`` option is given.

``-ca-key-pkcs11-token LABEL``
  Label of the token that holds the key. Required with a module.

``-ca-key-pkcs11-label LABEL``, ``-ca-key-pkcs11-id HEX``
  The key pair, by ``CKA_LABEL`` or by ``CKA_ID`` in hex. One of them is
  required with a module; with both, the key matches both.

``-tls-cert FILE``, ``-tls-key FILE``
  PEM certificate and key of the listener. Required.

``-pseudonym-key FILE``
  Secret the device ID is derived under (`Issued certificate`_). Required;
  the file holds at least 16 bytes, all of which are used.

``-ek-root-bundle DIR``
  A pinned EK root bundle (`EK trust`_).

``-ek-root FILE``
  A PEM file of trusted EK roots. Each ``CERTIFICATE`` block is read and
  other blocks are skipped. Repeatable. At least one of ``-ek-root`` and
  ``-ek-root-bundle`` is required; both may be given.

``-ek-crl FILE``
  A manufacturer CRL, PEM or DER (`EK revocation`_). Repeatable.

``-aik-cert-ttl DURATION``
  Lifetime of an issued AIK certificate. Default ``24h``. A value of zero or
  less issues certificates of ``24h``.

``-session-ttl DURATION``
  How long a challenge stays open for its answer (`Sessions and limits`_).
  Default ``2m``; must be positive.

``-max-pending N``
  Most challenges open at one time. Default 4096; at least 1.

``-tenant-manifest FILE``
  EK-to-tenant manifest (`Tenants`_).

``-tenant-manifest-strict``
  Refuses an EK the manifest does not list. Requires ``-tenant-manifest``.

``-enrollment-tokens FILE``
  Token-to-tenant file (`Enrollment tokens`_).

``-require-enrollment-token``
  Refuses an enrollment that presents no token. Requires
  ``-enrollment-tokens``.

The CA reads every file once, at startup. Only the CRL files are read
again, on ``SIGHUP`` (`Signals`_).

Environment
===========

``LOTA_CA_PKCS11_PIN``
  User PIN of the PKCS#11 token. Required with ``-ca-key-pkcs11-module``.

CA signing key
==============

Every AIK certificate the CA issues is signed with this key, and a verifier
trusts what it signs. The CA compares the key's public half with the CA
certificate at startup and stops on
``CA private key does not match CA certificate``, for a file and for a
token alike (:ghsrc:`src/attestca/ca/issuer.go`).

``-ca-key`` reads the key from a file in the clear. The CA starts with it and
logs ``using on-disk CA signing key -- development-only fallback; hold the
CA key in an HSM in production``. The custody of the key, its rotation and a
two-tier CA are in :doc:`../../security/ca-key`.

PKCS#11 token
-------------

With ``-ca-key-pkcs11-*`` the key stays in an HSM, or in SoftHSM for
tests, and the CA signs through the module
(:ghsrc:`src/attestca/casigner_pkcs11.go`). The PIN is read from the
environment, so it stays out of the argument list:

.. code-block:: console

   # export LOTA_CA_PKCS11_PIN=1234
   # lota-attest-ca -ca-cert ca.crt \
         -ca-key-pkcs11-module /usr/lib64/softhsm/libsofthsm2.so \
         -ca-key-pkcs11-token lota-ca -ca-key-pkcs11-label lota-ca-key \
         -tls-cert tls.crt -tls-key tls.key \
         -pseudonym-key pseudonym.key \
         -ek-root-bundle /var/lib/lota/ek-roots

The CA logs ``using PKCS#11 CA signing key`` with the module and the token.
:ghsrc:`examples/hsm-ca/README.rst` sets up a SoftHSM token for this.

Token support needs cgo and is built only with the ``pkcs11`` tag:

.. code-block:: console

   $ make attest-ca GO_TAGS=pkcs11

The default build, which the packages carry, and the default container image
stop with ``this lota-attest-ca was built without PKCS#11 support`` when
they are given ``-ca-key-pkcs11-module`` and no ``-ca-key`` and the other
options pass their checks, and name both roads to one that has it
(:ghsrc:`src/attestca/casigner_nopkcs11.go`). A CA asked for a token never
falls back to ``-ca-key``.

The token refusals, each fatal at startup:

``pkcs11: -ca-key-pkcs11-module and -ca-key-pkcs11-token are required``
  The token label is missing.

``pkcs11: a key selector is required``
  Neither ``-ca-key-pkcs11-label`` nor ``-ca-key-pkcs11-id`` is given.

``pkcs11: token PIN is required in LOTA_CA_PKCS11_PIN``
  The variable is unset or empty.

``pkcs11: -ca-key-pkcs11-id is not hex:``
  The id does not decode as hex.

``pkcs11: open token %q via %s:``
  The module does not load, no token has that label, or the login with the
  PIN fails; the module's error follows.

``pkcs11: find key pair:``
  No key pair on the token matches the selector, or the search failed.

EK trust
========

The CA trusts an EK certificate that chains to a trusted root
(:ghsrc:`src/attestca/ca/issuer.go`). Roots come from ``-ek-root`` files and
from the bundle, whose manifest pins each certificate by SHA-256 and classes
it as a root or an intermediate (:ghsrc:`src/attestca/ca/ekbundle.go`). The
bundle format, its refusals and the scripts that build it are in
:ghsrc:`configs/ek-roots/README.rst`; a bundle that fails to load stops the
CA with ``load ek-root-bundle``.

An intermediate is path material: it links a leaf to a root and anchors
nothing. An ``-ek-root`` certificate whose subject differs from its issuer
is both an anchor and path material. The host sends with its EK certificate
the intermediates its TPM stores, at most 8 certificates and 8192 bytes,
and the CA uses them as path material too. A route ends at a trusted root;
a root the host sends anchors nothing. Every certificate of the route that
the host does not send has to be among the trusted roots and intermediates.

Begin checks the EK certificate in this order, and stops at the first
failure:

#. It parses.
#. The current time is inside its validity.
#. It chains to a trusted root, through trusted and sent intermediates.
   When the route breaks at an issuer that neither the CA nor the host
   holds, the error names it: ``nothing pinned or supplied issues %q, so
   the path stops there``.
#. A CRL of its issuer does not list it (`EK revocation`_).
#. It carries the TCG EK OID ``2.23.133.8.1`` as an extended key usage or a
   certificate policy.
#. Its key is RSA of at least 2048 bits.
#. The modulus does not carry the ROCA fingerprint (CVE-2017-15361)
   (:ghsrc:`src/attestca/ca/roca.go`), whether or not a CRL lists the key.

Each failure is sent as status 2 (`Status codes`_), except a stale CRL.
The CA logs which check failed (`Diagnostics`_).

EK revocation
-------------

``-ek-crl`` loads a manufacturer CRL (:ghsrc:`src/crl/crl.go`). A file holds
one DER CRL, or PEM blocks of which only ``X509 CRL`` blocks are read. Each
CRL must:

* carry ``nextUpdate``;
* be signed with RSA PKCS#1 or PSS over SHA-256, SHA-384 or SHA-512, with
  ECDSA over the same, or with Ed25519;
* be signed by a trusted root or intermediate whose subject matches its
  issuer. A version 3 signer must carry ``CA:TRUE``, and a signer with a
  key usage extension must allow ``cRLSign``.

A CRL that fails any of these stops the CA at startup with
``failed to load CRL``.

A serial a CRL of the EK's issuer lists is refused, stale CRLs included.
When every CRL of that issuer is past its ``nextUpdate``, every EK of that
issuer is refused with status 9 until a fresh CRL is loaded. An issuer with
no CRL loaded is not checked. Only the EK certificate is checked; the
intermediates above it are not.

Rewrite the file and send ``SIGHUP`` to load a fresh CRL.

AIK checks
==========

The host sends the AIK as a ``TPMT_PUBLIC``
(:ghsrc:`src/attestca/credential/credential.go`). The CA refuses it with
status 3 unless it is an RSA key with:

* name algorithm SHA-256;
* attributes ``fixedTPM``, ``fixedParent``, ``sensitiveDataOrigin``,
  ``userWithAuth``, ``restricted`` and ``sign``, and not ``decrypt``;
* a key size and a modulus of at least 2048 bits;
* the RSASSA signing scheme.

The challenge wraps a 32-byte secret to the EK, bound to the AIK's name, by
``MakeCredential``. Only a TPM that holds both the EK and a key of that name
recovers it with ``ActivateCredential``.

Issued certificate
==================

The certificate is signed by the CA key, with the CA certificate as its
issuer (:ghsrc:`src/attestca/ca/issuer.go`):

* serial: a random number below 2\ :sup:`128`;
* subject ``CommonName``: the device ID;
* subject ``OrganizationalUnit``: the tenant, absent for ``default``;
* validity: from one minute before issue to ``-aik-cert-ttl`` after it;
* key usage ``digitalSignature``, ``CA:FALSE``.

The device ID is the lowercase hex HMAC-SHA256, under the pseudonym key, of
the EK's RSA modulus. For a tenant other than ``default`` the input is the
tenant name, a zero byte and the modulus
(:ghsrc:`src/attestca/enroll/enroll.go`). The AIK is not an input, so a host
that enrolls again with a new AIK keeps its device ID. The ID changes with
another TPM or another tenant, and a new pseudonym key changes the ID of
every device.

Tenants
=======

The CA assigns each device a tenant and writes it into the certificate it
signs, so a host cannot choose its own. How a verifier scopes its state by
tenant is in :doc:`../multi-tenancy`.

``-tenant-manifest`` maps EKs to tenants
(:ghsrc:`src/attestca/enroll/tenant.go`). One entry per line, an EK
fingerprint and a tenant name; blank lines and lines starting with ``#``
are skipped:

.. code-block:: text

   # <ek_sha256> <tenant>
   3b1f...c7  acme
   9a20...4e  beta

The fingerprint is the hex SHA-256 of the EK's RSA modulus, in either case.
Read the RSA EK certificate off the TPM; the shell, not ``sudo``, creates
``ek.der``, so the next step can open it:

.. code-block:: sh

    sudo tpm2_nvread 0x01c00002 > ek.der

and print its fingerprint:

.. code-block:: sh

    modulus=$(openssl x509 -inform DER -in ek.der -noout -modulus) &&
        printf '%s' "${modulus#Modulus=}" | xxd -r -p | sha256sum

A tenant name is 1 to 64 lowercase letters, digits and dashes, with no dash
at either end. The manifest fails to load, and the CA stops with
``tenant manifest:``, on:

* ``line %d: expected "<ek_sha256> <tenant>"``
* ``line %d: ek_sha256 must be 64 hex characters``
* ``line %d: duplicate ek_sha256``
* ``line %d: invalid tenant %q``
* ``tenant manifest %s lists no devices``

An EK the manifest does not list gets the ``default`` tenant. With
``-tenant-manifest-strict`` it is refused instead, with status 2, and the
manifest is a list of the EKs allowed to enroll. With no manifest every
device gets ``default``. The CA logs ``tenant manifest loaded`` with the
path and the strict flag.

Enrollment tokens
=================

A token assigns a tenant to a device whose EK the operator does not know in
advance (:ghsrc:`src/attestca/enroll/token.go`). The host presents it with
Begin, inside the TLS session. The CA stores only token digests, in a file
of the manifest's shape:

.. code-block:: text

   # <token_sha256> <tenant>
   5e88...12  game-alpha
   a71c...09  game-beta

The digest is the hex SHA-256 of the token's bytes:

.. code-block:: console

   $ printf %s "$TOKEN" | sha256sum

The file fails to load on the same line errors with ``token_sha256``, and on
``enrollment token file %s lists no tokens``; the CA stops with
``enrollment tokens:``. It logs ``enrollment tokens loaded`` with the path
and the require flag.

The tenant comes from:

* a presented token: the tenant its digest is listed with. A token that is
  not listed, or is presented to a CA without ``-enrollment-tokens``, is
  refused with status 8. The manifest and ``default`` are not consulted.
* no token, with ``-require-enrollment-token``: refused with status 8.
* no token otherwise: the manifest, as in `Tenants`_.

The agent presents a token from ``--enroll-token-file`` and records it for
renewal (:doc:`../../agent/command-line`). To rotate a token, list the new
digest beside the old one, restart the CA, ship the new token, then remove
the old digest and restart again. Removing a digest stops further
enrollments with that token and leaves the certificates issued with it
alone.

Sessions and limits
===================

Begin checks the EK, then the AIK, then assigns the tenant, and only then
wraps the challenge and opens a session
(:ghsrc:`src/attestca/enroll/enroll.go`). A refused EK, AIK or tenant takes
no session.

A session lives ``-session-ttl``. Begin first drops the sessions older than
that, then refuses with status 7 once ``-max-pending`` remain. Complete
removes the session before it checks it, so an expired session or a wrong
secret spends the challenge, and the host starts again with Begin.

The listener (:ghsrc:`src/attestca/server/server.go`):

* serves one enrollment per connection;
* holds at most 256 connections; a connection past that is closed with no
  reply;
* allows each message 15 seconds to arrive and each reply 15 seconds to be
  written;
* counts Begin requests per source IP address in a fixed window of one
  minute; past 10 in a window, Begin gets status 7. It tracks at most 4096
  addresses; a Begin from another address while 4096 windows are open gets
  status 7.

These limits have no option. Lower ``-max-pending`` and ``-session-ttl`` on
a CA that any host can reach.

Protocol
========

The agent and the CA exchange four messages over TLS 1.2 or later; the CA
asks for no client certificate (:ghsrc:`src/attestca/wire/wire.go`,
:ghsrc:`include/lota_enroll.h`). Each message is a 32-bit big-endian length
and a body of at most 16 KiB. A body opens with the magic ``0x4C434145``
(``LCAE``) and a 16-bit version, then holds its fields in order. A byte
field is a 16-bit length and the bytes; integers are big-endian.

BeginRequest
  EK certificate (DER, ≤ 2048 bytes), AIK ``TPMT_PUBLIC`` (≤ 1024), token
  (≤ 128, empty for none), a 16-bit count of intermediates (≤ 8) and each
  intermediate (DER, ≤ 2048, ≤ 8192 in total).

ChallengeReply
  16-bit status, session ID (32 hex characters, ≤ 64), credential blob
  (≤ 1024), encrypted secret (≤ 512).

CompleteRequest
  Session ID (≤ 64), recovered secret (≤ 64).

ResultReply
  16-bit status, AIK certificate (DER, ≤ 4096), device ID (64 hex
  characters, ≤ 128).

Version 1 is the only one, and the CA answers in the version of the
request. A message longer than 16 KiB, or a body with another magic, an
unknown version, a field over its bound or trailing bytes, does not decode:
the CA logs it and closes the connection with no reply.

Status codes
------------

.. list-table::
   :header-rows: 1
   :widths: 6 22 72

   * - Code
     - Name
     - Sent when
   * - 0
     - ``OK``
     - The step succeeded.
   * - 1
     - ``BAD_REQUEST``
     - Defined; the CA does not send it.
   * - 2
     - ``EK_REJECTED``
     - The EK certificate fails a check of `EK trust`_, is revoked, holds no
       RSA key, or a strict manifest does not list it.
   * - 3
     - ``AIK_REJECTED``
     - The AIK fails `AIK checks`_.
   * - 4
     - ``ACTIVATION_FAIL``
     - The secret in CompleteRequest is not the one wrapped.
   * - 5
     - ``UNKNOWN_SESSION``
     - The session is unknown, already used, or older than
       ``-session-ttl``.
   * - 6
     - ``INTERNAL_ERROR``
     - Any other failure, such as a failed signature.
   * - 7
     - ``RATE_LIMITED``
     - The source address is over its Begin limit, or ``-max-pending``
       sessions are open.
   * - 8
     - ``TOKEN_REJECTED``
     - The token is unknown, or required and absent.
   * - 9
     - ``CRL_STALE``
     - Every CRL of the EK's issuer is past its ``nextUpdate``.

Status 7 clears once the window or a session ends, and status 9 once a
fresh CRL is loaded. After status 4 or 5 the host starts again with Begin.
The agent prints the status and its meaning
(:ghsrc:`src/agent/enroll_client.c`), and for status 8 sent to an agent that
presented no token adds ``; this CA requires --enroll-token-file``.

Signals
=======

``SIGHUP``
  Reloads the ``-ek-crl`` files. On success the CA logs
  ``SIGHUP: EK CRL feed reloaded`` with ``loaded_crls``. When any file fails,
  it logs ``SIGHUP: EK CRL reload failed; keeping previous set`` and keeps
  checking against the set it had.

``SIGINT``, ``SIGTERM``
  The CA closes the listener, waits for the open connections to end and
  exits 0.

Diagnostics
===========

A startup failure logs ``lota-attest-ca failed`` with the error and exits 1.
A malformed option exits 2. The errors on the options:

``specify either -ca-key or -ca-key-pkcs11-*, not both (given: -ca-key, %s)``
  ``-ca-key`` and a PKCS#11 option are both given; the PKCS#11 options found
  are listed.

``-ca-key-pkcs11-module is required with %s``
  A token, label or id is given without the module.

``missing required -%s``
  ``-ca-cert``, ``-tls-cert``, ``-tls-key``, ``-pseudonym-key``, or
  ``-ca-key`` without PKCS#11, is not given.

``at least one of -ek-root-bundle or -ek-root is required``
  No EK root is given.

``-session-ttl must be positive (got %s)``
  The session lifetime is zero or negative.

``-max-pending must be at least 1 (got %d)``
  The session limit is below 1.

``-tenant-manifest-strict requires -tenant-manifest``
  The strict switch is given without a manifest.

``-require-enrollment-token requires -enrollment-tokens``
  The switch is given without a token file.

The other errors name what failed to load: ``read ca-cert:``,
``read ca-key:``, ``read ek-root %s:``, ``read pseudonym-key:``,
``issuer:`` (the CA certificate, its key, an EK root or a CRL),
``enrollment service:`` (``pseudonym key too short``),
``server TLS keypair:`` and ``listen %s:``.

Each enrollment logs one line, with the peer address in ``remote``:

``enroll issued AIK certificate``
  Success, with ``device_id``, logged before the reply is written.

``enroll begin rejected``, ``enroll complete rejected``
  A refusal, with the ``status`` sent and the ``error``. For status 2 the
  error says which EK check failed.

``enroll begin rate-limited``
  Status 7 for the source address.

``enroll begin read failed``, ``enroll complete read failed``
  The message did not arrive or did not decode. No reply is sent.

``enroll challenge write failed``
  The challenge could not be written, and the CA closes the connection.

Verifier side
=============

Each verifier of the publisher names the CA certificate with
``-aik-ca-cert`` and refuses a report whose AIK certificate does not chain
to it; ``-aik-crl`` revokes single AIK certificates
(:ghsrc:`src/verifier/main.go`). The verifier's options are in
:doc:`../../verifier/index`.

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
with ``POST /api/v1/clients/{clientID}/reanchor-review-ack`` (``actor`` and
``reason`` required). Each LFA re-anchor is also logged at security level and
counted in the ``lfa`` re-anchor metric.
If a reviewed re-anchor looks wrong, revoke or ban the device through the
existing endpoints.

A change confined to the boot entries (``efibootmgr``, a second operating
system, firmware adding a disk or USB entry) moves PCR 1 without touching the
firmware. When PCR 0 and PCR 7 match the pin and the only PCR 1 events that
differ from the boot log on record are ``BootOrder`` and ``Boot####`` variables
whose data matches their digest, the verifier re-pins PCR 1 and the log in
place. This spends neither rate limit and adds nothing to the review queue: a
boot entry only selects a loader, and Secure Boot, pinned in PCR 7, still
decides which loader may start. Each re-pin is logged at security level and
counted in the ``boot_entries`` re-anchor metric. A PCR 1 change that also
moves other events (SMBIOS tables, platform configuration flags after a RAM or
CPU swap) takes the firmware path above.

The same profile follows a MOK change. Enrolling or deleting a Machine Owner
Key (``mokutil``, a DKMS or akmods signing key) moves only the ``MokList``,
``MokListX`` and ``MokListTrusted`` events shim measures into PCR 14, and so
the pinned PCR 14 itself. When every other PCR 14 event of the boot log on
record is unchanged in count, type, name and digest, and a moved ``MokList``
matches the list the agent sent, the verifier re-pins PCR 14 and the log in
place. A MOK change already needs a physical confirmation in MokManager at the
next boot, so the path has no rate limit and no review queue; each re-pin is
logged at security level and counted in the ``mok`` re-anchor metric, and the
log line names the events that moved. Any other change to PCR 14 is escalated
as before.

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
re-establishes trust per the active TOFU/policy configuration.

The commands below run from any host that reaches the verifier's monitoring
API. Off the verifier's host that API is HTTPS under the verifier's
``--cert``; ``--cacert`` names its issuing CA. ``LOTA_ADMIN_API_KEY`` holds
the verifier's admin key and ``CLIENT_ID`` the device ID: ``Device ID`` from
``lota-agent --enroll``, the AIK certificate's ``CommonName``, as
``GET /api/v1/clients`` lists it. Do not write the ID into a ``{...}``
placeholder: curl treats braces in a URL as a pattern.

.. code-block:: sh

    curl --cacert verifier-ca.crt -X POST \
        "https://verifier.example:8080/api/v1/clients/$CLIENT_ID/reanchor" \
        -H "Authorization: Bearer $LOTA_ADMIN_API_KEY" \
        -d '{"actor":"ops@example.com","reason":"planned firmware update"}'

The verifier answers:

.. code-block:: json

    {"status": "reanchored", "client_id": "<client-id>"}

``actor`` and ``reason`` are required and land in the audit log with the
optional ``note``; a request missing either gets **400** and changes nothing.
The action is also logged at security level and counted in the ``forced``
re-anchor metric. The enrollment is untouched -- the host keeps attesting with
its enrolled AIK identity.

To remove a device from the fleet entirely (decommissioned host, or trust
state that must be rebuilt from scratch), delete the client. This drops the
baselines and any AIK-store registration only; a running host keeps its
certificate and is re-baselined at its next heartbeat. Revoke it first to keep
it out. ``actor`` and ``reason`` are required, ``note`` is optional:

.. code-block:: sh

    curl --cacert verifier-ca.crt -X DELETE \
        "https://verifier.example:8080/api/v1/clients/$CLIENT_ID" \
        -H "Authorization: Bearer $LOTA_ADMIN_API_KEY" \
        -d '{"actor":"ops@example.com","reason":"decommissioned"}'

The verifier answers:

.. code-block:: json

    {"status": "deleted", "client_id": "<client-id>"}

Revocations and hardware bans are keyed separately and survive the delete,
so removing a client cannot be used to shed either -- a revoked identity
that re-enrolls is still revoked.

