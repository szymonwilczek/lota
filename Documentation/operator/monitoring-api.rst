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

Authentication
--------------

Two Bearer-token tiers, configured through the verifier's environment:

* **reader** (``LOTA_READER_API_KEY``) -- read-only endpoints: statistics,
  listings, logs, metrics, session-token validation.
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

Request bodies are limited to 1 MiB, 64 levels of nesting and 32768 JSON
tokens; a violated limit, an empty body where one is required, or
trailing data after the JSON value is a **400**. Timestamps are RFC 3339
UTC. Endpoints backed by an optional subsystem (revocations, bans, the
audit and attestation logs) answer **503** when that store is not
configured. Unexpected server failures are **500** with a generic
message; details go to the verifier log, not the client.

Mutation payloads share three fields: ``reason`` (one of ``cheating``,
``compromised``, ``hardware_change``, ``admin``), ``actor`` (the
administrator identity recorded in the audit log; required where noted)
and ``note`` (free-form justification, optional).

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
``POST /api/v1/session/validate``                          reader  validate a session token
=========================================================  ======  ===========================================

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

``status`` is ``ok`` or ``degraded``.

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

GET /metrics
------------

Reader. Prometheus text exposition format (version 0.0.4), not JSON.

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

``total`` counts durable clients plus active in-memory sessions not yet
persisted.

GET /api/v1/clients/{id}
------------------------

Reader. **200** with per-client details, **404** for an unknown client.
A client exists server-side when the verifier holds a baseline row or
recent attestation state for it; enrollment alone (Privacy CA) does not
register anything with the verifier. ::

   {
     "client_id": "host-0001",
     "hardware_id": "ab12...",
     "revoked": false,
     "revocation_reason": "",
     "last_attestation": "2026-07-02T10:00:00Z",
     "last_attestation_unix": 1782727200,
     "attestation_count": 7,
     "monotonic_counter": 7,
     "pending_challenges": 0,
     "pcr14_baseline": "cafe...",
     "first_seen": "2026-06-30T08:00:00Z",
     "first_seen_unix": 1782547200
   }

String fields are omitted when empty.

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

Admin. No body. **200**
``{"status": "unrevoked", "client_id": ...}``; **404** when the client
is not revoked.

GET /api/v1/revocations
-----------------------

Reader. **200**::

   {
     "revocations": [
       {
         "client_id": "host-0001",
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
identity), ``reason`` and ``actor`` required, ``note`` optional.
**201**::

   {"status": "banned", "hardware_id": "ab12...", "reason": "cheating"}

**400** malformed hardware ID, invalid reason or missing actor,
**409** already banned, **503** bans not configured. The returned
``hardware_id`` is the canonical lower-case form.

DELETE /api/v1/bans/{hwid}
--------------------------

Admin. No body. **200**
``{"status": "unbanned", "hardware_id": ...}``; **400** malformed
hardware ID, **404** not banned.

GET /api/v1/bans
----------------

Reader. Query: ``limit`` and ``next_id`` (see Pagination). **200**::

   {
     "bans": [
       {
         "hardware_id": "ab12...",
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
AIK registration is untouched. Body: ``actor`` required, ``note``
optional. **200**::

   {"status": "reanchored", "client_id": "host-0001"}

**400** missing actor, **404** unknown client. Writes an audit entry
with action ``reanchor`` and counts toward the forced re-anchor metric.

DELETE /api/v1/clients/{id}
---------------------------

Admin. Removes the client's verifier-side trust state (baselines and,
where the store carries one, the AIK registration), forcing a fresh
enrollment. Revocations and hardware bans are keyed separately and
survive the delete. Body optional: ``actor`` and ``note`` as audit
metadata. **200**::

   {"status": "deleted", "client_id": "host-0001"}

**400** invalid client ID, **404** unknown client. Writes an audit
entry with action ``delete_client``.

GET /api/v1/reanchor/review
---------------------------

Reader. Clients that re-anchored on the Low-Firmware-Assurance path and
await operator review (see :doc:`production-bringup/ca-enrollment`).
**200**::

   {"pending_review": ["host-0001"], "count": 1}

POST /api/v1/clients/{id}/reanchor-review-ack
---------------------------------------------

Admin. Clears the client's pending-review flag. No body. **200**
``{"status": "reviewed", "client_id": ...}``.

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

Reader. Query: ``limit`` (default 100, maximum 10000). **200**::

   {
     "attestations": [
       {
         "id": 9,
         "timestamp": "2026-07-02T10:00:00Z",
         "client_id": "host-0001",
         "hardware_id": "ab12...",
         "result": "success",
         "duration_ms": 12.5,
         "pcr14": "cafe...",
         "details": "",
         "remote_addr": "192.0.2.10:39412"
       }
     ],
     "count": 1
   }

``details`` is HTML-escaped and truncated to 2048 characters. **503**
when no attestation log is configured.

Session tokens
==============

POST /api/v1/session/validate
-----------------------------

Reader. Checks a session token issued to an attested client (game or
service back ends validating a client-presented token). Body::

   {"session_token": "<64 hex characters>", "consume": false}

``consume: true`` additionally marks the token used, so it cannot
validate again. **400** when the token is not 64 hex characters.
**200** always for a well-formed request; an unknown token is
``{"valid": false}`` with every other field omitted::

   {
     "valid": true,
     "consumed": false,
     "client_id": "host-0001",
     "hardware_id": "ab12...",
     "result_code": 1,
     "flags": 7,
     "pcr_mask": 16787,
     "valid_until": 1782730800
   }

``valid`` is false for an expired token even though it still resolves;
``valid_until`` is a Unix timestamp.
