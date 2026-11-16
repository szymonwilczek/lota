.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

==============
Monitoring API
==============

The verifier serves an HTTP API on ``--http-addr`` (:doc:`command-line`):
health, metrics, the client inventory, the audit and decision logs, and the
operator actions on a client. The routes are in
:ghsrc:`src/verifier/server/api.go`. :doc:`../admin-guide/fleet-cli` calls
them from the command line.

Transport
=========

A loopback IP address serves plain HTTP. Any other address serves HTTPS with
the ``--cert`` pair and needs at least one API key; without either the
verifier does not start. A client names the CA that issued the certificate,
as ``curl --cacert`` does.

Authentication
==============

A key is sent as ``Authorization: Bearer <key>``. A key has a role and a
tenant scope:

``reader``
  The ``GET`` routes.

``admin``
  Every route.

Two keys of global scope come from the environment, ``LOTA_READER_API_KEY``
and ``LOTA_ADMIN_API_KEY``; ``--api-keys-file`` adds keys scoped to tenants
and is reloaded on ``SIGHUP`` (:doc:`command-line`). A token is matched
against the admin key, the reader key, then the file, by comparing SHA-256
digests in constant time.

========================================= ====================================
Request                                   Answer
========================================= ====================================
Reader route, no key configured anywhere  Served, to anyone.
Reader route, no token                    401, ``WWW-Authenticate: Bearer
                                          realm="lota"``.
Reader route, unknown token               403 ``invalid API key``.
Admin route, no admin key and no file     403 ``admin API key not
                                          configured``.
Admin route, no token                     401, ``WWW-Authenticate: Bearer
                                          realm="lota-admin"``.
Admin route, token without the admin role 403 ``invalid API key``.
========================================= ====================================

A refused token is logged at security level as ``reader auth failed`` or
``admin auth failed``.

A key scoped to tenants sees and acts on the records of its tenants alone. A
client outside them answers 404 ``client not found``, as an unknown one does;
a ban in another tenant answers 403 ``tenant not permitted for this key``.
``/metrics`` has no tenant dimension and answers such a key 403 ``metrics are
global-scope; use a key with tenants ["*"]``.

Requests and responses
======================

Every body is JSON but that of ``/metrics``, and every error is one object::

   {"error": "<message>"}

.. list-table::
   :header-rows: 1
   :widths: 40 60

   * - Answer
     - Cause
   * - 400 ``invalid JSON: ...``
     - The body is missing or over 1 MiB, nests over 64 levels, holds over
       32768 tokens, carries a field the route does not read, or a second
       value. Unrevoke, unban, the acknowledgement and the delete read a
       missing body as empty, and answer ``actor is required``.
   * - 404 ``no such endpoint``
     - No route takes the path.
   * - 404 ``unknown action``
     - The client route names no action it takes.
   * - 405 ``method not allowed on this endpoint; see the Allow header``
     - The path takes other methods, named in ``Allow``.
   * - 500 ``database unavailable``
     - A store read failed. The cause is logged, not answered.
   * - 500 ``internal error``
     - A store write failed. The cause is logged.
   * - 503 ``... not configured``
     - The instance has no revocation, ban, audit or decision store, which is
       the case on ``--allow-insecure-memory-state`` (:doc:`store`).
   * - 503 ``this instance serves reports from a read-only database; send
       state changes to an instance on the primary``
     - An admin route on a ``--report-only`` instance, before the key is
       read.

Times are RFC 3339 in UTC. A record of a client carries its ``tenant``,
``default`` for a client with none (:doc:`../admin-guide/multi-tenancy`). A
decision row refused before the pseudonym and tenant in its certificate
were read holds no tenant, and leaves the field out.

The admin routes take these body fields:

``actor``
  Who acts, recorded in the audit log. Required.

``reason``
  Required. On a revoke or a ban, one of ``cheating``, ``compromised``,
  ``hardware_change`` and ``admin``; elsewhere free text.

``note``
  Free text. Optional.

Routes
======

================================================= ====== ======================
Route                                             Role   Action
================================================= ====== ======================
``GET /health``                                   none   Health
``GET /api/v1/stats``                             reader Counters
``GET /metrics``                                  reader Prometheus metrics
``GET /api/v1/clients``                           reader List clients
``GET /api/v1/clients/{id}``                      reader Read a client
``POST /api/v1/clients/{id}/revoke``              admin  Revoke a client
``DELETE /api/v1/clients/{id}/revoke``            admin  Lift a revocation
``GET /api/v1/revocations``                       reader List revocations
``POST /api/v1/bans``                             admin  Ban a pseudonym
``DELETE /api/v1/bans/{id}``                      admin  Lift a ban
``GET /api/v1/bans``                              reader List bans
``POST /api/v1/clients/{id}/reanchor``            admin  Force a re-anchor
``DELETE /api/v1/clients/{id}``                   admin  Delete a client
``GET /api/v1/reanchor/review``                   reader List pending reviews
``POST /api/v1/clients/{id}/reanchor-review-ack`` admin  Acknowledge a review
``GET /api/v1/audit``                             reader Read the audit log
``GET /api/v1/attestations``                      reader Read the decision log
================================================= ====== ======================

The verifier logs the route list as ``endpoints`` when the API opens. Every
admin action logs one line at security level, but for an acknowledgement,
and writes one audit row on an instance with an audit log, which
``--allow-insecure-memory-state`` leaves out. A re-anchor, a delete or an
acknowledgement whose audit write fails stands, and the failure is logged.

Health and counters
===================

``GET /health``
---------------

::

   {
     "status": "ok",
     "uptime": "1h0m0s",
     "uptime_sec": 3600,
     "tls": {"listening": true, "address": ":8443"}
   }

``tls`` is the attestation listener. While it is closed, on shutdown or
after a failure, the answer is 503 with ``status`` ``degraded``; the API
keeps answering for ``--shutdown-drain``, so a load balancer polling here
stops routing first. A ``--report-only`` instance answers 200 with ``mode``
``reporting``, ``listening`` false and no address.

``GET /api/v1/stats``
---------------------

::

   {
     "pending_challenges": 0,
     "used_nonces": 120,
     "registered_clients": 3,
     "active_policy": "default",
     "loaded_policies": ["default"],
     "total_attestations": 42,
     "successful_attestations": 40,
     "failed_attestations": 2,
     "revoked_attestations": 0,
     "banned_attestations": 0,
     "active_revocations": 1,
     "active_bans": 0,
     "uptime": "1h0m0s",
     "uptime_sec": 3600
   }

For a key scoped to tenants, ``registered_clients``, ``active_revocations``
and ``active_bans`` count its tenants, ``tenant_scoped`` is true beside the
``tenants`` list, and the counters that hold no tenant are left out:
``pending_challenges``, ``used_nonces`` and the five attestation counters.

``GET /metrics``
----------------

The Prometheus text format, version 0.0.4. The series are in
:doc:`../admin-guide/observability`.

Clients
=======

A client is a 64-digit hex client ID (:doc:`index`).

``GET /api/v1/clients``
-----------------------

::

   {"clients": ["<client ID>", "..."], "count": 100, "next": "<client ID>"}

The IDs come in order, after the ``after`` query value. ``limit`` is 100 by
default and at most 1000; a value that is not a positive number is ignored.
A full page carries ``next``, the ``after`` of the following page. ``offset``
is refused with 400.

The list is the clients with a baseline, which every instance on the store
reads alike. A key of global scope also gets the clients this instance has
challenged that hold no baseline yet. A key scoped to tenants gets the
clients with a baseline in its tenants.

``GET /api/v1/clients/{id}``
----------------------------

::

   {
     "client_id": "<client ID>",
     "tenant": "default",
     "hardware_id": "<client ID>",
     "revoked": false,
     "last_attestation": "2026-01-01T10:00:00Z",
     "last_attestation_unix": 1767261600,
     "attestation_count": 7,
     "monotonic_counter": 7,
     "pcr14_baseline": "<64 hex digits>",
     "first_seen": "2026-01-01T08:00:00Z",
     "first_seen_unix": 1767254400,
     "machine_keys": {
       "db": [{"type": "x509", "sha256": "<64 hex digits>",
               "subject": "CN=Example DB Key"}],
       "mok": [],
       "mok_state": "not_measured"
     }
   }

``client_id``, ``tenant``, ``revoked``, ``attestation_count`` and
``monotonic_counter`` are always present; another field is left out when
empty. A client is found when it has a baseline or this
instance has challenged it; else the answer is 404 ``client not found``.

``hardware_id``
  The device pseudonym, as ``POST /api/v1/bans`` takes it. It is the client
  ID in lower case.

``revocation_reason``
  The reason of a revocation, present while ``revoked`` is true.

``monotonic_counter``
  The rounds this instance has seen from the client. It resets on restart,
  differs between instances, and gates nothing. Every other field comes from
  the store and reads alike on every instance.

``machine_keys``
  The keys the host trusted at boot in its last passing round: ``db`` from
  the PCR 7 log, ``mok`` from the MOK list the agent sent. ``mok_state`` is
  ``listed`` when that list matches the ``MokList`` event of PCR 14,
  ``not_measured`` when PCR 14 has no event, and ``unproven`` otherwise,
  with ``mok`` empty. Nothing is gated on them.

Revocations
===========

A revocation refuses the client ID with ``revoked`` (:doc:`index`).

``POST /api/v1/clients/{id}/revoke``
------------------------------------

Body ``actor``, ``reason``, ``note``. 201::

   {"status": "revoked", "client_id": "<client ID>", "reason": "cheating"}

409 ``client is already revoked``. A client the verifier has not seen is
revoked under the tenant ``default``, so only a key that covers it may do
so. Audit action ``revoke``; log line ``client revoked``.

``DELETE /api/v1/clients/{id}/revoke``
--------------------------------------

Body ``actor``, ``reason``, ``note``. 200::

   {"status": "unrevoked", "client_id": "<client ID>"}

404 ``client is not revoked``. Audit action ``unrevoke``; log line ``client
unrevoked``.

``GET /api/v1/revocations``
---------------------------

::

   {
     "revocations": [
       {
         "client_id": "<client ID>",
         "tenant": "default",
         "reason": "cheating",
         "revoked_at": "2026-01-01T10:00:00Z",
         "revoked_by": "ops@example.com",
         "note": ""
       }
     ],
     "count": 1
   }

Every revocation, unpaged.

Bans
====

A ban refuses a device pseudonym in one tenant with ``banned``. It is kept by
tenant and pseudonym, outlives a client delete, and holds for every
certificate that names the pseudonym.

``POST /api/v1/bans``
---------------------

Body ``hardware_id``, 64 hex digits in either case, ``tenant``, ``default``
when empty, ``actor``, ``reason``, ``note``. 201::

   {"status": "banned", "hardware_id": "<lower-case hex>",
    "tenant": "default", "reason": "cheating"}

400 ``invalid hardware_id: ...`` or ``invalid tenant``, 403 ``tenant not
permitted for this key``, 409 ``hardware ID is already banned``. The
pseudonym is kept in lower case. Audit action ``ban``; log line ``hardware
banned``.

``DELETE /api/v1/bans/{id}``
----------------------------

Body ``tenant``, ``actor``, ``reason``, ``note``. 200::

   {"status": "unbanned", "hardware_id": "<lower-case hex>",
    "tenant": "default"}

The pseudonym in the path is read in either case. ``tenant`` in the query is
refused with 400. 404 ``hardware ID is not banned``, 403 as for a ban. Audit
action ``unban``; log line ``hardware unbanned``.

``GET /api/v1/bans``
--------------------

::

   {
     "bans": [
       {
         "hardware_id": "<lower-case hex>",
         "tenant": "default",
         "reason": "cheating",
         "banned_at": "2026-01-01T10:00:00Z",
         "banned_by": "ops@example.com",
         "note": ""
       }
     ],
     "count": 1,
     "total": 1,
     "limit": 100
   }

``limit`` is 100 by default and at most 1000; one that is not a positive
number is refused with 400 ``invalid limit``. A page followed by another
carries ``next_id``, passed back as the ``next_id`` query value; one that
does not decode is refused with 400 ``invalid next_id``. ``offset`` is
refused with 400. ``total`` counts every ban the key may see.

Baselines
=========

The effect on the next round is in "Operator actions" of :doc:`index`.

``POST /api/v1/clients/{id}/reanchor``
--------------------------------------

Body ``actor``, ``reason``, ``note``. 200::

   {"status": "reanchored", "client_id": "<client ID>"}

Drops the client's baselines and records consent for one first-use boot
baseline. 404 ``client not found`` for a client with no baseline. Audit
action ``reanchor``; log line ``client baseline force re-anchored``.

``DELETE /api/v1/clients/{id}``
-------------------------------

Body ``actor``, ``reason``, ``note``. 200::

   {"status": "deleted", "client_id": "<client ID>"}

Drops the baselines, a pending forced re-anchor and this instance's
challenge state; the replaced baselines stay in the archive (:doc:`store`).
404 ``client not found`` for a client with no baseline. Audit action
``delete_client``; log line ``client deleted``.

``GET /api/v1/reanchor/review``
-------------------------------

::

   {"pending_review": ["<client ID>"], "count": 1}

The clients re-pinned on the low-firmware-assurance path and not yet
acknowledged.

``POST /api/v1/clients/{id}/reanchor-review-ack``
-------------------------------------------------

Body ``actor``, ``reason``, ``note``. 200::

   {"status": "reviewed", "client_id": "<client ID>"}

404 ``client not found``, 409 ``no re-anchor review pending for this
client``. Audit action ``reanchor_review_ack``.

Logs
====

``GET /api/v1/audit``
---------------------

::

   {
     "entries": [
       {
         "id": 17,
         "timestamp": "2026-01-01T10:00:00Z",
         "tenant": "default",
         "action": "revoke",
         "target_id": "<client ID>",
         "reason": "cheating",
         "actor": "ops@example.com"
       }
     ],
     "count": 1
   }

Newest first. ``limit`` is 100 by default and at most 10000. ``action`` is
``revoke``, ``unrevoke``, ``ban``, ``unban``, ``reanchor``,
``delete_client`` or ``reanchor_review_ack``.

``GET /api/v1/attestations``
----------------------------

::

   {
     "attestations": [
       {
         "id": 9,
         "timestamp": "2026-01-01T10:00:00Z",
         "last_seen": "2026-01-01T10:55:00Z",
         "rounds": 12,
         "tenant": "default",
         "client_id": "<client ID>",
         "hardware_id": "<client ID>",
         "result": "ok",
         "duration_ms": 12.5,
         "pcr14": "<64 hex digits>",
         "kernel_hash": "<64 hex digits>",
         "remote_addr": "192.0.2.10:39412"
       }
     ],
     "count": 1
   }

One row stands for a run of rounds ("Decision log" in :doc:`store`). Newest
first. The query values:

``limit``
  100 by default, at most 10000.

``since``, ``until``
  RFC 3339. The rows that overlap the window, one opened before ``since``
  included. A value that does not parse is ignored.

``result``
  One verdict name ("Verdicts" in :doc:`index`).

``events=true``
  The rows that did not pass. Ignored beside ``result``.

``client_id``
  One client.

``details`` is the verifier's reason for the verdict, absent on a pass. The
verifier records at most 2048 bytes of it: a longer one is cut on a character
boundary and ends in ``...[truncated]``, and a byte that is not UTF-8 reads
U+FFFD. Control characters below U+0020 but the tab, and DEL, are turned to
spaces, and the text is HTML escaped. On a round refused before the pseudonym
and tenant in its certificate were read, ``hardware_id`` is absent and
``client_id`` holds the challenge ID, not the client's. A read writes the
buffered rounds first.

For a key scoped to tenants, the audit and decision logs are read up to
``limit`` and then filtered, so a page may come back short.

Example
=======

The client ID goes into the URL from a variable: ``curl`` reads braces in a
URL as a pattern.

.. code-block:: sh

   curl --cacert verifier-ca.crt -X POST \
       "https://verifier.example:8080/api/v1/clients/$CLIENT_ID/reanchor" \
       -H "Authorization: Bearer $LOTA_ADMIN_API_KEY" \
       -d '{"actor":"ops@example.com","reason":"planned firmware update"}'
