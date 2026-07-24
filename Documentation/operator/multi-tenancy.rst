.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

=============
Multi-tenancy
=============

Single verifier can serve several isolated tenants -- separate enterprise
fleets, or individual game titles behind one anti-cheat backend -- so that one
tenant never sees or affects another. This page describes how a tenant is
assigned, what it scopes, and how an operator configures scoped access to the
monitoring API.

The security rationale is in the
:doc:`threat model <../../security/threat-model>`; this page is the operator
configuration reference.

How a tenant is assigned
========================

The tenant is **not** chosen by the host. The attestation CA assigns it at
enrollment and writes it into the AIK certificate subject as a single
``OrganizationalUnit`` (OU). The verifier reads the tenant only after it has
verified the certificate chain, so a host cannot forge or change its own
tenancy.

* A certificate with **no OU** maps to the reserved ``default`` tenant.
* A certificate with **one valid OU** maps to that tenant.
* A certificate with a **malformed or ambiguous** OU (an invalid name, or more
  than one OU) is rejected fail-closed, before any state is written.

A tenant name is 1 to 64 characters of lowercase letters, digits, and
inner dashes (``[a-z0-9-]``, no leading or trailing dash). The reserved name
``default`` is the tenant of every client that predates multi-tenancy and every
client enrolled without a tenant OU.

What the tenant scopes
======================

Tenancy scopes stored state and enforcement decisions. It does **not** change
the cryptographic root of trust, which is per device regardless of tenant.

Hardware bans
-------------

Hardware bans are **strictly per tenant**. A hardware identity banned in one
tenant is untouched in every other tenant; there is no cross-tenant or global
ban. A ban issued through the API names its tenant explicitly (defaulting to
``default``), and attestation rejects a client only for a ban recorded in that
client's own tenant.

Per-tenant PCR policy
---------------------

A PCR policy may bind itself to a tenant by adding a ``tenant:`` key to the
policy document:

.. code-block:: yaml

   name: acme-strict
   tenant: acme
   require_secureboot: true
   require_lockdown: true
   # ... pcrs, agent_hashes, ...

A client whose certificate carries the ``acme`` tenant is then verified against
``acme-strict``; clients in tenants with no bound policy fall back to the
verifier's active policy. A tenant binds to at most one policy. Because the
binding lives inside the signed policy document, a signed policy authenticates
its own scope: an operator cannot silently re-point a tenant by editing an
unsigned side file.

Scoped state
------------

Revocations, PCR14/boot baselines, the audit log, the attestation log, and
session tokens all carry the tenant, so every operator listing and every
mutation can be scoped to the caller's tenant set.

Scoped monitoring-API keys
==========================

The monitoring API supports per-operator keys, each with a role and a tenant
set, loaded from a file named by ``--api-keys-file``:

.. code-block:: yaml

   keys:
     - key_sha256: 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8
       role: admin
       tenants: ["acme"]
     - key_sha256: 6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b
       role: reader
       tenants: ["acme", "beta"]
     - key_sha256: d4735e3a265e16eee03f59718b9b5d03019c07d8b6c51f90da3a666eec13ab35
       role: reader
       tenants: ["*"]

Each entry carries:

* ``key_sha256`` -- the SHA-256 of the bearer token, as 64 lowercase
  hex characters. The plaintext key is never written to the file. Compute it
  with, for example, ``printf %s "$KEY" | sha256sum``.
* ``role`` -- ``reader`` (read-only endpoints) or ``admin`` (mutating
  endpoints too). Admin implies reader.
* ``tenants`` -- the tenants the key may see and act on, or ``["*"]`` for every
  tenant.

The whole file is validated on load: a single bad entry -- a malformed hash, an
unknown role, an empty or invalid tenant list, a duplicate hash -- fails the
load. Sending the verifier ``SIGHUP`` reloads the file; if the reload fails the
previous key set stays in place, so a bad edit cannot lock operators out.

Scoping behavior
----------------

A scoped key sees only its tenants' resources:

* listings (clients, revocations, bans, audit, attestations, re-anchor review)
  are filtered to the key's tenant set;
* a request naming a client or resource outside the key's tenant set is
  answered as **404**, not 403, so the key cannot probe another tenant's
  namespace or even confirm that a foreign client exists;
* a ban or unban into a tenant outside the key's set is refused;
* ``/api/v1/stats`` returns tenant-narrowed counts and flags itself
  ``tenant_scoped``; the fleet-wide attestation counters, which are not
  attributable per tenant, are omitted from a scoped response;
* ``/metrics`` is refused (403) for a tenant-scoped key: the Prometheus
  exposition is fleet-wide and carries no tenant dimension, so only a
  global-scope key (environment key or ``tenants: ["*"]``) can scrape it.

The environment keys ``LOTA_ADMIN_API_KEY`` and ``LOTA_READER_API_KEY`` keep
working and are **global-scope**: they see every tenant. A scoped key file may
be used alone, without either environment key, and is sufficient to satisfy the
authentication requirement that a non-loopback API bind enforces.

Enrollment
==========

Assigning tenants at enrollment is a property of the attestation CA: the
enterprise path adds a tenant column to the EK pin manifest, and the gaming
path issues a per-tenant enrollment token. See
:doc:`production-bringup/ca-enrollment <production-bringup/ca-enrollment>` for
the enrollment ceremony these hook into.
