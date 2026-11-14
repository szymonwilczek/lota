.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

=============
Multi-tenancy
=============

One verifier serves several tenants: separate fleets, or the titles behind
one anti-cheat backend. A tenant has its own policy, its own bans and its own
operators, and a key scoped to it sees none of another tenant's records. The
reasoning is in :doc:`../security/threat-model`.

The tenant
==========

The attestation CA assigns a device its tenant at enrollment, from an
enrollment token or from the EK manifest ("Tenants" in
:doc:`bringup/ca-enrollment`). It writes the tenant into the AIK certificate
as the subject's one ``OrganizationalUnit``, and leaves it out for
``default``. The host has no say in it.

The verifier reads it once the certificate chain is checked
(:ghsrc:`src/verifier/verify/tenant.go`):

* no ``OrganizationalUnit``: the tenant is ``default``;
* one, a valid name: that tenant;
* two or more, or an invalid name: the round is refused with
  ``identity_fail`` and logged at security level as ``AIK certificate
  carries an invalid tenant``.

A tenant name is 1 to 64 lowercase letters, digits and dashes, with no dash
first or last. The CA, the policy ``tenant:`` key and the key file accept the
same names.

The CA derives the device pseudonym, the client ID, from the tenant and the
EK, so one TPM enrolled in two tenants is two clients with unrelated IDs. A
revocation of one, a ban of one, or a baseline of one leaves the other
untouched.

What a tenant holds
===================

Policy
  The policy bound to the tenant (`Policies`_), else the active policy.

Bans
  A ban names a tenant and a pseudonym, and refuses ``banned`` in that tenant
  alone. There is no ban across tenants.

Records
  The client's baseline, its revocation, the audit rows about it and its
  decision log rows carry its tenant, and each listing of the monitoring API
  filters on it.

A client's baseline takes its tenant on its first passing round, and reads
``default`` until then. The trust roots, the CRLs, the nonce history and
the verifier's limits are shared by every tenant.

Policies
========

A policy binds itself to a tenant with a ``tenant:`` key:

.. code-block:: yaml

   name: acme-strict
   tenant: acme
   require_secureboot: true
   require_lockdown: true

Each ``--policy`` loads one file (:doc:`../verifier/command-line`):

.. code-block:: sh

   lota-verifier --policy fleet-base.yaml \
                 --policy acme-strict.yaml \
                 --policy beta-relaxed.yaml

The first file is the active policy. It verifies every client whose tenant
binds no policy, and may itself bind one. Every file is checked the same way
wherever it stands. The verifier refuses to start on two files with one
``name:``, two bound to one tenant, or a ``tenant:`` that is not a valid
name. At startup it logs each binding as ``tenant bound to policy`` and
warns about a file past the first that binds no tenant, since no client
reaches it.

With ``--policy-pubkey`` each file carries its own signature, which covers
its ``tenant:`` key (:ghsrc:`policies/README.rst`).

Scoped keys
===========

``--api-keys-file`` holds the monitoring API keys scoped to tenants:

.. code-block:: yaml

   keys:
     - key_sha256: 2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae
       role: admin
       tenants: ["acme"]
     - key_sha256: fcde2b2edba56bf408601fb721fe9b5c338d10ee429ea04fae5511b68fbf8fb9
       role: reader
       tenants: ["acme", "beta"]
     - key_sha256: baa5a0964d3320fbc0c6a922140453c8513ea24ab8fd0577034804a967248096
       role: reader
       tenants: ["*"]

``key_sha256``
  The SHA-256 of the bearer token, 64 hex digits. The token itself is not in
  the file; ``printf %s "$KEY" | sha256sum`` gives the digest.

``role``
  ``reader`` for the ``GET`` routes, ``admin`` for every route.

``tenants``
  The tenants the key sees and acts in; ``"*"`` for all of them.

The file loads whole or not at all (:ghsrc:`src/verifier/server/apikeys.go`).
A file with no key, an unknown key, a second YAML document, a digest of the
wrong length, a digest listed twice, an unknown role, an empty tenant list or
an invalid tenant name stops the verifier at startup. On ``SIGHUP`` it is
read again; a file that fails keeps the previous keys in force.

The keys from ``LOTA_READER_API_KEY`` and ``LOTA_ADMIN_API_KEY`` cover every
tenant. A key for one tenant goes in the file, and the file alone satisfies
the key a non-loopback monitoring API needs.

A key scoped to tenants (:doc:`../verifier/monitoring-api`):

* lists the clients, revocations, bans, re-anchor reviews, audit rows and
  decision rows of its tenants;
* gets 404 ``client not found`` for a client of another tenant, as for an
  unknown one;
* gets 403 ``tenant not permitted for this key`` for a ban or an unban in
  another tenant;
* reads ``/api/v1/stats`` with the counts of its tenants and without the
  counters that hold no tenant;
* gets 403 on ``/metrics``, which holds no tenant.

``tenant`` in a ban or an unban goes in the body, ``default`` when left out.
