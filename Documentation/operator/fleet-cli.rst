.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

======================
Fleet CLI (lota-fleet)
======================

``lota-fleet`` is the operator command-line front end for the verifier's
REST monitoring API. It covers the fleet lifecycle that otherwise requires
hand-written ``curl``: device inventory, AIK revocations, hardware bans,
operator-forced re-anchor, client removal, review of Low-Firmware-Assurance
re-anchors, the audit and attestation logs, and session-token validation.

The CLI is a pure API client. It shares no code with the verifier, so any
``lota-fleet`` build works against any verifier that speaks the documented
endpoint contract (:doc:`monitoring-api`), and it can run from an operator
workstation that has network access to the monitoring API only.

Building
========

::

   make fleet-cli

produces ``build/lota-fleet``. The binary is static pure-Go with no
dependencies outside the standard library.

Connecting and authenticating
=============================

The monitoring API is the verifier's ``--http-addr`` listener. The CLI
takes the base URL from ``--server`` or the ``LOTA_FLEET_SERVER``
environment variable (default ``http://127.0.0.1:8080``).

The API has two Bearer-token tiers, matching the verifier's
``LOTA_READER_API_KEY`` and ``LOTA_ADMIN_API_KEY``: a reader key covers
the read-only endpoints (stats, listings, logs, session validation), the
admin key additionally unlocks the mutating ones (revoke, ban, re-anchor,
delete, review acknowledgement). Give the CLI whichever tier the task
needs:

* ``LOTA_FLEET_API_KEY`` environment variable, or
* ``--key-file PATH`` pointing at a file that holds the key (trailing
  whitespace is trimmed); the file takes precedence.

There is deliberately no ``--key <value>`` flag: a key in ``argv`` is
visible to every user on the machine through the process list.

For an https ``--server`` (the API behind a TLS-terminating proxy),
``--tls-ca PATH`` adds PEM roots to trust. Plain HTTP is fine on loopback;
the verifier itself refuses a non-loopback HTTP bind without a configured
API key.

Commands
========

::

   lota-fleet [global flags] <command> [command flags] [args]

===================================================  =====================
Command                                              API tier
===================================================  =====================
``health``                                           none
``stats``                                            reader
``devices list [-limit N] [-offset N]``              reader
``devices show <client-id>``                         reader
``revoke <client-id> -reason R -actor A [-note S]``  admin
``unrevoke <client-id>``                             admin
``revocations``                                      reader
``ban <hardware-id> -reason R -actor A [-note S]``   admin
``unban <hardware-id>``                              admin
``bans [-limit N] [-next-id CURSOR]``                reader
``reanchor <client-id> -actor A [-note S]``          admin
``delete <client-id> [-actor A] [-note S]``          admin
``reanchor-review list``                             reader
``reanchor-review ack <client-id>``                  admin
``audit [-limit N]``                                 reader
``attests [-limit N]``                               reader
``session validate <token> [-consume]``              reader
===================================================  =====================

``-reason`` must be one of the server's revocation reasons: ``cheating``,
``compromised``, ``hardware_change`` or ``admin``. ``-actor`` is the
administrator identity recorded in the audit log and is required for every
mutating action except ``delete``, where it is optional audit metadata.

Global ``--json`` prints the raw API response instead of the human
rendering, for scripting against the full field set.

Exit codes: 0 on success, 1 when the operation fails **or reports a
negative result** (a degraded ``health``, an invalid ``session validate``
token), 2 on a usage error. ``devices list`` and ``reanchor-review list``
print bare IDs on stdout (page summaries go to stderr), so their output
pipes cleanly into further tooling.

Lifecycle actions
=================

``reanchor`` is the operator-forced re-baseline: it drops the client's
stored PCR14 and boot baselines so the next attestation re-establishes
trust. Use it after a legitimate platform change (board swap, firmware
update) that the self-service re-anchor refuses or is not enabled for.
The action is audited (``reanchor``) and counted in the forced re-anchor
metric.

``delete`` removes the client's verifier-side trust state (baselines and,
where the store carries one, the AIK registration), forcing a fresh
enrollment. Revocations and hardware bans are keyed separately and
**survive the delete**: removing a device cannot shed a ban. The action
is audited (``delete_client``).

``reanchor-review`` is the post-fact review queue for self-service
re-anchors taken on the Low-Firmware-Assurance path; see the enrollment
document (:doc:`production-bringup/ca-enrollment`) for when the verifier
puts a client in that queue.

Examples
========

Revoke a compromised host and confirm::

   export LOTA_FLEET_SERVER=http://verifier.internal:8080
   lota-fleet --key-file /etc/lota/fleet-admin.key \
       revoke host-0142 -reason compromised -actor alice@ops \
       -note "IR ticket 8841"
   lota-fleet --key-file /etc/lota/fleet-reader.key revocations

Re-baseline a host after a planned firmware update::

   lota-fleet --key-file /etc/lota/fleet-admin.key \
       reanchor host-0142 -actor alice@ops -note "BIOS 2.4 rollout"

Decommission a host::

   lota-fleet --key-file /etc/lota/fleet-admin.key \
       delete host-0142 -actor alice@ops -note "decommissioned"

Check the fleet from a script::

   lota-fleet health || alert "verifier degraded"
   lota-fleet --json stats | jq .failed_attestations

Multi-tenancy
=============

When the verifier serves several tenants, the CLI is tenant-aware.

Hardware bans are per tenant. ``ban`` and ``unban`` take a ``-tenant`` flag
naming the tenant the ban lives in; omitting it uses the server's ``default``
tenant. A ban in one tenant never affects another, so the tenant is part of
the ban's identity::

   lota-fleet --key-file /etc/lota/fleet-admin.key \
       ban <hardware-id> -tenant acme -reason cheating -actor alice@ops
   lota-fleet --key-file /etc/lota/fleet-admin.key \
       unban <hardware-id> -tenant acme

The listing commands (``revocations``, ``bans``, ``audit``, ``attests``) print
a ``TENANT`` column, and ``devices show``, ``session validate`` and ``stats``
report the tenant. Those listings also accept a ``-tenant`` flag that filters
the displayed rows to one tenant, in the table and the ``--json`` rendering
alike. This filter is applied client-side, for an
operator holding a broad key who wants to narrow the view: the verifier
already scopes every response to the tenants the API key is allowed to see, so
a tenant-scoped key needs no ``-tenant`` flag to stay within its bounds. A
request that names a client, ban, or session outside the key's tenant set is
answered as not found.

``stats`` from a tenant-scoped key reports ``tenant scoped: true`` and the
tenant list, and narrows the client, revocation, and ban counts to those
tenants; the fleet-wide attestation counters, which are not attributable per
tenant, are omitted.

Tenants are assigned by the attestation CA at enrollment and written into the
device certificate; see :doc:`production-bringup/ca-enrollment` for the
assignment mechanism.
