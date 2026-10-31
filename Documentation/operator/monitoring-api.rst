.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

========================
Monitoring API reference
========================

The verifier exposes a REST monitoring and fleet-management API on the
listener configured with ``--http-addr``. This page is the wire contract:
paths, methods, authentication tiers, request payloads, response shapes
and status codes. For task-oriented usage prefer the
:doc:`lota-fleet CLI <fleet-cli>`, which wraps every endpoint below; the
operational semantics of enrollment, re-anchoring and revocation are
covered in :doc:`production-bringup/ca-enrollment`.

Conventions
===========

Transport
---------

The transport follows the bind. On ``127.0.0.1`` the API is plain HTTP and
requires no key, but enforces any key the verifier is configured with. On any
other address it is **HTTPS** with the verifier's ``--cert``/``--key`` pair,
and the verifier refuses to start without a reader or admin key. Remote
clients use ``https://`` and the issuing CA, as in
``deploy/observability/prometheus.yml``.

Authentication
--------------

Two Bearer-token tiers, configured through the verifier's environment:

* **reader** (``LOTA_READER_API_KEY``) -- read-only endpoints: statistics,
  listings, logs, metrics.
* **admin** (``LOTA_ADMIN_API_KEY``) -- mutating endpoints. The admin key
  also satisfies every reader endpoint.

Clients authenticate with ``Authorization: Bearer <key>``. A missing
header on a protected endpoint yields **401** with a ``WWW-Authenticate``
challenge; a wrong key yields **403**. Admin endpoints answer **403**
with ``admin API key not configured`` when no admin key is set. When
neither key is configured the reader endpoints are public, and the
verifier refuses to bind the API to a non-loopback address.

Requests and responses
----------------------

Every response body is JSON except ``GET /metrics``. Errors use one
envelope on every endpoint::

   {"error": "<message>"}

That includes the two refusals that belong to no endpoint: a path this
listener does not serve is a **404**, and a method the path does not take is
a **405** naming the ones it does in ``Allow``. Neither answer echoes the
request back. A client can parse the envelope on every non-2xx.

Request bodies are limited to 1 MiB, 64 levels of nesting and 32768 JSON
tokens; a violated limit, an empty body where one is required, or
trailing data after the JSON value is a **400**. A field the endpoint
does not read is a **400** naming it: a request that carries a field the
handler ignores did not do what its author wrote, and a caller has to hear
that instead of reading a success for an action taken with something else.
Timestamps are RFC 3339 UTC. Unexpected server failures are **500** with
a generic message; details go to the verifier log, not the client.

Mutation payloads share three fields: ``reason`` (one of ``cheating``,
``compromised``, ``hardware_change``, ``admin``), ``actor`` (the
administrator identity recorded in the audit log; required where noted)
and ``note`` (free-form justification, optional).

Every record that belongs to a device -- client details, revocations,
bans, audit entries, attestation records, and the results of the ban and
unban verbs -- carries a ``tenant``. A deployment that assigns no tenants
reads ``default`` there on every record, which is the tenant an
unassigned device belongs to, not a missing value. See
:doc:`multi-tenancy`.

State an instance does not hold
-------------------------------

Revocations, hardware bans, the audit log and the attestation decision log
are one group: they are what an operator decided, and they answer **503**
with the store named when this instance holds none of them. That is the
answer to act on -- it says the instance cannot keep the decision, before
one is made against it.

A verifier holds them whenever it has somewhere durable to keep them, which
is every ordinary deployment: ``--pg-dsn`` puts them in the shared database
the fleet serves from, ``--db`` in that SQLite file, and an instance given
neither keeps them beside its AIK store in ``--state-db`` (default
``<aik-store>/verifier-state.sqlite``), which is the same file its used-nonce
history lives in. Only ``--allow-insecure-memory-state`` leaves the group
absent, and that flag says what it does: the instance keeps nothing across a
restart, so it refuses to take a decision it would forget.

Pagination
----------

``GET /api/v1/clients`` uses ``limit``/``offset`` (limit default 100,
maximum 1000; offset above 10000 is a **400**). ``GET /api/v1/bans`` is
keyset-paged: ``limit`` plus a ``next_id`` cursor returned by the
previous page; passing ``offset`` there is a **400**. The log endpoints
take only ``limit``.

Endpoint summary
================

=========================================================  ======  ===========================================
Endpoint                                                   Tier    Purpose
=========================================================  ======  ===========================================
``GET /health``                                            none    liveness for load balancers
``GET /api/v1/stats``                                      reader  verification statistics
``GET /metrics``                                           reader  Prometheus metrics
``GET /api/v1/clients``                                    reader  list client IDs
``GET /api/v1/clients/{id}``                               reader  per-client details
``POST /api/v1/clients/{id}/revoke``                       admin   revoke a client's AIK
``DELETE /api/v1/clients/{id}/revoke``                     admin   lift a revocation
``GET /api/v1/revocations``                                reader  list active revocations
``POST /api/v1/bans``                                      admin   ban a hardware identity
``DELETE /api/v1/bans/{hwid}``                             admin   lift a hardware ban
``GET /api/v1/bans``                                       reader  list active bans
``POST /api/v1/clients/{id}/reanchor``                     admin   operator-forced baseline re-anchor
``DELETE /api/v1/clients/{id}``                            admin   remove a client's trust state
``GET /api/v1/reanchor/review``                            reader  LFA re-anchors awaiting review
``POST /api/v1/clients/{id}/reanchor-review-ack``          admin   acknowledge an LFA re-anchor
``GET /api/v1/audit``                                      reader  operator audit log
``GET /api/v1/attestations``                               reader  attestation decision log
=========================================================  ======  ===========================================

Every ``admin`` row above changes fleet state and is refused with **503** on a
reporting instance, before the key is weighed, naming the read-only database
and sending the caller to an instance on the primary. The ``reader`` rows
answer there exactly as they do on the primary.

Health and statistics
=====================

GET /health
-----------

No authentication. **200** when the attestation TLS listener is up,
**503** with the same body shape when it is not::

   {
     "status": "ok",
     "uptime": "1m30s",
     "uptime_sec": 90,
     "tls": {"listening": true, "address": ":8443"}
   }

``status`` is ``ok`` or ``degraded``. ``degraded`` means this instance is
not accepting attestations: it is shutting down, or its listener died under
it. Both are answers to route away from, and neither is visible any other
way -- a process that has already gone answers nothing at all, which a
health check reads as a network fault.

On shutdown the attestation listener closes first and the monitoring API
answers through ``--shutdown-drain`` before going itself, so a load balancer
polling ``/health`` sees ``degraded`` and takes the instance out of rotation
while the process is still there. The window defaults to zero -- the API
goes as soon as it is idle -- and behind a load balancer it belongs at one
health-check interval or more.

A reporting instance (``--report-only``, :doc:`ha-deployment`) answers **200**
with ``"mode": "reporting"`` and ``"listening": false``: it binds no
attestation listener by design, so the missing listener is the shape of the
deployment and not a fault. ``mode`` is absent on an instance that attests, so
a caller that reached the wrong one can tell which it got.

GET /api/v1/stats
-----------------

Reader. **200**::

   {
     "pending_challenges": 0,
     "used_nonces": 12,
     "registered_clients": 3,
     "active_policy": "prod",
     "loaded_policies": ["prod"],
     "total_attestations": 42,
     "successful_attestations": 40,
     "failed_attestations": 2,
     "revoked_attestations": 0,
     "banned_attestations": 0,
     "active_revocations": 1,
     "active_bans": 0,
     "uptime": "2h0m0s",
     "uptime_sec": 7200
   }

A tenant-scoped key gets a narrower body: ``registered_clients``,
``active_revocations`` and ``active_bans`` count the key's tenants only,
``tenant_scoped`` is ``true`` beside a ``tenants`` list, and the counters
that cannot be attributed to a tenant -- ``total_attestations``,
``successful_attestations``, ``failed_attestations``,
``revoked_attestations``, ``banned_attestations``, ``used_nonces`` and
``pending_challenges`` -- are absent from the object.

GET /metrics
------------

Reader. Prometheus text exposition format (version 0.0.4), not JSON.

``lota_rejections_total{reason}`` carries one series per reason a round can be
refused for, and each exists at zero before it has ever fired: the reasons are
the verdict vocabulary above plus ``baseline_error``, which the verifier counts
when it cannot read or pin a baseline of its own and which reaches the host as
``internal_error``. An alert expression naming a reason therefore matches on a
verifier that has refused nothing yet.

``lota_connection_errors_total`` counts peers that spoke the attestation
protocol and got it wrong. A peer that connects and leaves without speaking is
a liveness question -- a load-balancer health check, or a port scan -- so it
raises no error and the challenge it was issued is released, which is what lets
``lota_pending_challenges`` read zero on an idle fleet.

Device inventory
================

GET /api/v1/clients
-------------------

Reader. Query: ``limit``, ``offset`` (see Pagination). **200**::

   {
     "clients": ["host-0001", "host-0002"],
     "count": 2,
     "total": 2,
     "limit": 100,
     "offset": 0
   }

The list is the durable per-client record -- the baseline every instance of a
deployment shares -- so behind a load balancer every instance answers it the
same way, and the answer survives a restart. ``total`` counts that record plus
the sessions this instance is holding that have no baseline pinned yet; those
are appended after the record, so a client mid-handshake is listed once and
only until its first baseline is written.

GET /api/v1/clients/{id}
------------------------

Reader. **200** with per-client details, **404** for an unknown client.
A client exists server-side when the verifier holds a baseline row or
recent attestation state for it; enrollment alone (Privacy CA) does not
register anything with the verifier. ::

   {
     "client_id": "host-0001",
     "tenant": "default",
     "hardware_id": "ab12...",
     "revoked": false,
     "revocation_reason": "",
     "last_attestation": "2026-07-02T10:00:00Z",
     "last_attestation_unix": 1782986400,
     "attestation_count": 7,
     "monotonic_counter": 7,
     "pending_challenges": 0,
     "pcr14_baseline": "cafe...",
     "first_seen": "2026-06-30T08:00:00Z",
     "first_seen_unix": 1782806400
   }

String fields are omitted when empty.

``hardware_id`` is the 32-byte hardware identity as 64 hex characters -- the
value ``POST /api/v1/bans`` takes, unedited. Under the Privacy CA flow it is
the device pseudonym the attestation CA put in the certificate subject, so it
reads the same as ``client_id``; a deployment that provisions its clients
out of band carries the registered identity there instead, beside whatever
client id it chose.

Everything above is read from the state the deployment shares -- the durable
per-client record -- except two fields, which are this instance's own:

``monotonic_counter``
   the nonce sequence this process has seen from the client. It is not
   compared against anything, so it gates nothing; it resets when the instance
   restarts and differs between instances at the same moment. It is not a
   replay or reordering indicator for a fleet.

``pending_challenges``
   the challenges this instance is holding for the client right now. A
   challenge lives where the connection is, so an instance the client is not
   talking to reports none.

Behind a load balancer, read either of those from one pinned instance or not
at all. ``last_attestation``, ``attestation_count``, ``first_seen``,
``tenant``, ``revoked`` and ``pcr14_baseline`` are the fleet's answer and are
the same on every instance.

Revocations
===========

POST /api/v1/clients/{id}/revoke
--------------------------------

Admin. Body: ``reason`` and ``actor`` required, ``note`` optional.
**201**::

   {"status": "revoked", "client_id": "host-0001", "reason": "cheating"}

**400** invalid reason or missing actor, **409** already revoked,
**503** revocation not configured.

DELETE /api/v1/clients/{id}/revoke
----------------------------------

Admin. Body: ``reason`` and ``actor`` required, ``note`` optional --
lifting a restriction is attributed on the same terms as imposing one.
The reason is free text rather than the revocation vocabulary. **200**
``{"status": "unrevoked", "client_id": ...}``; **400** missing actor or
reason, **404** when the client is not revoked.

GET /api/v1/revocations
-----------------------

Reader. **200**::

   {
     "revocations": [
       {
         "client_id": "host-0001",
         "tenant": "default",
         "reason": "cheating",
         "revoked_at": "2026-07-02T10:00:00Z",
         "revoked_by": "alice@ops",
         "note": "IR ticket 8841"
       }
     ],
     "count": 1
   }

Hardware bans
=============

POST /api/v1/bans
-----------------

Admin. Body: ``hardware_id`` (64 hex characters, the 32-byte hardware
identity), ``reason`` and ``actor`` required, ``tenant`` and ``note``
optional. ``tenant`` is the scope the ban is imposed in and defaults to
``default``; it must be within the calling key's tenant set. **201**::

   {"status": "banned", "hardware_id": "ab12...", "tenant": "default",
    "reason": "cheating"}

**400** malformed hardware ID, invalid reason, invalid tenant or missing
actor, **403** tenant outside the key's set, **409** already banned,
**503** bans not configured. The identity may be given in either case;
the returned ``hardware_id`` is the canonical lower-case form, and it is
the form a ban is recorded, listed and matched in -- so the same identity
in upper case answers **409** against its own ban.

DELETE /api/v1/bans/{hwid}
--------------------------

Admin. Body: ``reason`` and ``actor`` required, ``tenant`` and ``note``
optional -- lifting a ban is attributed on the same terms as imposing
one, and names the tenant the same way, because a ban is identified by
``(tenant, hardware_id)``. **200**::

   {"status": "unbanned", "hardware_id": "ab12...", "tenant": "default"}

The identity in the path is canonicalised the same way, so a ban lifts
in whichever case it is named. **400** malformed hardware ID, missing
actor or reason, invalid tenant, or ``tenant`` passed as a query
parameter instead of a body field; **403** tenant outside the key's set,
**404** not banned in that tenant.

GET /api/v1/bans
----------------

Reader. Query: ``limit`` and ``next_id`` (see Pagination). **200**::

   {
     "bans": [
       {
         "hardware_id": "ab12...",
         "tenant": "default",
         "reason": "cheating",
         "banned_at": "2026-07-02T10:00:00Z",
         "banned_by": "alice@ops",
         "note": ""
       }
     ],
     "count": 1,
     "total": 5,
     "limit": 1,
     "next_id": "<cursor>"
   }

``next_id`` is present only when another page exists; a ban store
without cursor support answers **400** to a ``next_id`` request.

Client lifecycle
================

POST /api/v1/clients/{id}/reanchor
----------------------------------

Admin. The operator-forced re-baseline: drops the client's stored PCR14
and boot baselines so the next attestation re-establishes trust. The
AIK registration is untouched. Body: ``reason`` and ``actor`` required,
``note`` optional. **200**::

   {"status": "reanchored", "client_id": "host-0001"}

**400** missing actor or reason, **404** unknown client. Writes an audit entry
with action ``reanchor`` and counts toward the forced re-anchor metric.

DELETE /api/v1/clients/{id}
---------------------------

Admin. Removes the client's verifier-side trust state: the baselines and
the AIK registration, on every storage backend. The device keeps its
certificate, so its next attestation is a first sight and becomes the new
baseline; revoke or ban it first to keep it out. The per-identity attestation
state (counter, last-attestation time, rate-limit window) goes too, so the
client leaves ``GET /api/v1/clients`` at once; the used-nonce history stays.
Revocations and hardware bans survive the delete. Body: ``reason`` and
``actor`` required, ``note`` optional. **200**::

   {"status": "deleted", "client_id": "host-0001"}

**400** invalid client ID or missing actor or reason, **404** unknown
client. Writes an audit entry with action ``delete_client``.

GET /api/v1/reanchor/review
---------------------------

Reader. Clients that re-anchored on the Low-Firmware-Assurance path and
await operator review (see :doc:`production-bringup/ca-enrollment`).
**200**::

   {"pending_review": ["host-0001"], "count": 1}

POST /api/v1/clients/{id}/reanchor-review-ack
---------------------------------------------

Admin. Clears the client's pending-review flag and writes a
``reanchor_review_ack`` audit row. Body: ``actor`` and ``reason`` required,
``note`` optional. **200** ``{"status": "reviewed", "client_id": ...}``;
**400** when ``actor`` or ``reason`` is missing; **404** for an unknown
client; **409** when no re-anchor awaits review::

   curl -X POST -H "Authorization: Bearer $LOTA_ADMIN_API_KEY" \
        -H 'Content-Type: application/json' \
        -d '{"actor":"alice@ops","reason":"inspected the firmware update"}' \
        https://verifier.internal:8080/api/v1/clients/host-0001/reanchor-review-ack

Logs
====

GET /api/v1/audit
-----------------

Reader. Query: ``limit`` (default 100, maximum 10000). Most recent
first. **200**::

   {
     "entries": [
       {
         "id": 17,
         "timestamp": "2026-07-02T10:00:00Z",
         "tenant": "default",
         "action": "revoke",
         "target_id": "host-0001",
         "reason": "cheating",
         "actor": "alice@ops",
         "note": "IR ticket 8841"
       }
     ],
     "count": 1
   }

Actions include ``revoke``, ``unrevoke``, ``ban``, ``unban``,
``reanchor`` and ``delete_client``. **503** when no audit log is
configured.

GET /api/v1/attestations
------------------------

Reader. Query: ``limit`` (default 100, maximum 10000), ``since`` and
``until`` (RFC 3339), ``result`` (one verdict), ``events=true`` (every round
that was not trusted) and ``client_id`` (one host). **200**::

   {
     "attestations": [
       {
         "id": 9,
         "timestamp": "2026-07-02T10:00:00Z",
         "last_seen": "2026-07-02T10:55:00Z",
         "rounds": 12,
         "tenant": "default",
         "client_id": "host-0001",
         "hardware_id": "ab12...",
         "result": "ok",
         "duration_ms": 12.5,
         "pcr14": "cafe...",
         "kernel_hash": "5b97...",
         "remote_addr": "192.0.2.10:39412"
       }
     ],
     "count": 1
   }

Identical trusted rounds of one host share a row: ``timestamp`` is the
first, ``last_seen`` the last, ``rounds`` their count. The record above is
twelve such rounds over an hour. A refusal, a verdict change and a
host's first round always open a new row. ``--attestation-log-window``
bounds how long a trusted row extends; zero writes a row per round.

``since`` and ``until`` return the rows that overlap the window, including
one opened before ``since``. A bound that does not parse is ignored.
``events=true`` drops trusted rows and is ignored when ``result`` is set.

``result`` is the verdict the verifier reached, and an accepted round reads
``ok``. The refusals are ``nonce_fail``, ``sig_fail``, ``identity_fail``,
``certificate_validity``, ``certificate_missing``, ``pcr_fail``,
``iommu_fail``, ``secureboot_required``, ``lockdown_required``,
``module_sig_required``, ``enforce_required``, ``ima_appraisal_required``,
``kernel_image_required``, ``cmdline_required``, ``policy_requirement``,
``integrity_mismatch``, ``old_version``, ``report_malformed``, ``revoked``,
``banned`` and ``internal_error`` -- the same vocabulary the agent is
answered with. Each policy requirement has its own verdict (a host refused
for Secure Boot reads ``secureboot_required`` on both sides);
``policy_requirement`` covers a refusal none of them names. ``old_version``
means the version field alone; any other unreadable report (truncated, wrong
magic) is ``report_malformed``.

``kernel_hash`` is the kernel image hash the agent reported. It is covered by
the quote, so it is attested, and it is advisory: nothing is gated on it,
and it is what an operator reads to answer whether a device's kernel changed.

The record above is an accepted round, which has nothing to explain, so it
carries no ``details``. A refused one does::

   {
     "id": 10,
     "result": "pcr_fail",
     "details": "PCR 0 mismatch: got 6b90c371..., expected 000...001",
     "remote_addr": "192.0.2.10:39412",
     ...
   }

``details`` is the reason the round ended as it did -- which register drifted,
which check refused it -- written by the verifier and bounded to 2048
characters where it is recorded. It is HTML-escaped on the way out, and a
value that met the bound ends in ``...[truncated]``. The key is absent when
there is no reason, so a reader can tell "nothing went wrong".
``remote_addr`` is the address the report arrived from: it answers
*which host*, where ``client_id`` answers which key. **503** when no
attestation log is configured.

``hardware_id`` is the same 64-hex hardware identity as on the client record,
and it is the field this endpoint exists to hand an operator: the hardware
behind a refused round is banned by pasting it into ``POST /api/v1/bans``. It
is present once the round authenticated its AIK certificate, which is where
the identity comes from; a report refused before that names no hardware.

The decision log is written asynchronously in batches so a busy fleet does
not pay one database commit per report. Records become durable within
about one second; this endpoint forces a flush first, so it always returns
the records it has accepted, but an ungraceful verifier crash can lose up
to the last second of *audit* entries. No attestation verdict or
replay-protection state is affected -- those writes are synchronous.
