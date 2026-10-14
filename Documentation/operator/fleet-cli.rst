.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

======================
Fleet CLI (lota-fleet)
======================

``lota-fleet`` is the operator command-line front end for the verifier's
REST monitoring API. It covers the fleet lifecycle that otherwise requires
hand-written ``curl``: device inventory, AIK revocations, hardware bans,
operator-forced re-anchor, client removal, review of Low-Firmware-Assurance
re-anchors, and the audit and attestation logs.

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
the read-only endpoints (stats, listings, logs), the
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

=====================================================  ========
Command                                                API tier
=====================================================  ========
``health``                                             none
``stats``                                              reader
``devices list [-limit N] [-offset N]``                reader
``devices show <client-id>``                           reader
``revoke <client-id> -reason R -actor A [-note S]``    admin
``unrevoke <client-id> -reason R -actor A [-note S]``  admin
``revocations``                                        reader
``ban <hardware-id> -reason R -actor A [-note S]``     admin
``unban <hardware-id> -reason R -actor A [-note S]``   admin
``bans [-limit N] [-next-id CURSOR]``                  reader
``reanchor <client-id> -reason R -actor A [-note S]``  admin
``delete <client-id> -reason R -actor A [-note S]``    admin
``reanchor-review list``                               reader
``reanchor-review ack <client-id>``                    admin
``audit [-limit N]``                                   reader
``attests [-limit N]``                                 reader
=====================================================  ========

``-reason`` on ``revoke`` must be one of the server's revocation reasons:
``cheating``, ``compromised``, ``hardware_change`` or ``admin``. ``-actor`` is
the administrator identity recorded in the audit log.

**Every command that changes a client's trust state requires ``-actor`` and
``-reason``**, and the audit row carries both. There is one rule rather than
one per verb.

Lifting a restriction is attributed on the same terms as imposing one:
restoring a machine that was banned for cheating is the act a fleet most wants
signed -- banning one is the reversible, conservative direction -- so a trail
that names who imposed a restriction must also name who lifted it. And
``delete``, which removes a client's trust state entirely, is the last action
to leave unattributed.

Only ``revoke`` takes a fixed vocabulary. Everywhere else ``-reason`` is free
text, because "why was this machine let back in" and "why was this one
removed" have no enumerable answer.

Global ``--json`` prints the raw API response instead of the human
rendering, for scripting against the full field set.

Exit codes: 0 on success, 1 when the operation fails **or reports a
negative result** (a degraded ``health``), 2 on a usage error. ``devices list`` and ``reanchor-review list``
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

The revoked host says so itself. Its next round fails at the verifier's
verdict, and ``journalctl -u lota-attest`` on the machine reads::

   Attestation round failed at the verifier's verdict: FAIL - This host's
   attestation key was revoked by the publisher's administrator;
   re-enrollment is their decision, not this machine's

A banned hardware ID reads the same way, naming the ban. Both are worth
knowing before a support call: the machine is obeying an administrative
decision, and nothing done locally to it changes the answer.
The reason recorded with the revocation (``compromised`` above)
stays on the verifier -- the host is told the state, not the case for it.

Re-baseline a host after a planned firmware update::

   lota-fleet --key-file /etc/lota/fleet-admin.key \
       reanchor host-0142 -reason "BIOS 2.4 rollout" -actor alice@ops \
             -note "fleet-wide firmware update"

Decommission a host::

   lota-fleet --key-file /etc/lota/fleet-admin.key \
       delete host-0142 -reason decommissioned -actor alice@ops \
             -note "returned to vendor"

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
       unban <hardware-id> -tenant acme -reason "appeal upheld" \
             -actor alice@ops

The listing commands (``revocations``, ``bans``, ``audit``, ``attests``) print
a ``TENANT`` column, and ``devices show`` and ``stats`` report the tenant. Those listings also accept a ``-tenant`` flag that filters
the displayed rows to one tenant, in the table and the ``--json`` rendering
alike. This filter is applied client-side, for an
operator holding a broad key who wants to narrow the view: the verifier
already scopes every response to the tenants the API key is allowed to see, so
a tenant-scoped key needs no ``-tenant`` flag to stay within its bounds. A
request that names a client or ban outside the key's tenant set is answered as
not found.

``stats`` from a tenant-scoped key reports ``tenant scoped: true`` and the
tenant list, and narrows the client, revocation, and ban counts to those
tenants; the fleet-wide attestation counters, which are not attributable per
tenant, are omitted.

Tenants are assigned by the attestation CA at enrollment and written into the
device certificate; see :doc:`production-bringup/ca-enrollment` for the
assignment mechanism.
