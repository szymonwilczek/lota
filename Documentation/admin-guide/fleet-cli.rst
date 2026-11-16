.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

======================
Fleet CLI (lota-fleet)
======================

``lota-fleet`` calls the verifier's monitoring API
(:doc:`../verifier/monitoring-api`) from the command line: the client
inventory, revocations, hardware bans, forced re-anchors, client deletes, the
low-firmware-assurance review list, and the audit and decision logs. It
talks HTTP to the API alone and needs no access to the verifier's host or
store. The commands are in :ghsrc:`src/fleetctl/main.go`, the requests in
:ghsrc:`src/fleetctl/client/client.go`.

``make fleet-cli`` builds ``build/lota-fleet``, a static binary with no
module dependencies. ``make all`` and the packages leave it out.

Usage
=====

::

   lota-fleet [global options] <command> [subcommand] [<id>] [command options]

The options take one or two leading dashes. A command that names a client or
a hardware ID takes it first, before its options: ``revoke <client-id>
-reason R -actor A``.

.. code-block:: console

   $ export LOTA_FLEET_SERVER=https://verifier.example:8080
   $ lota-fleet -tls-ca verifier-ca.crt -key-file fleet-reader.key stats

Global options
==============

``-server URL``
  The API base URL, ``http`` or ``https`` with a host. Without the option,
  ``LOTA_FLEET_SERVER``; without either, ``http://127.0.0.1:8080``. A path in
  the URL prefixes every route, and a trailing ``/`` is dropped.

``-key-file PATH``
  A file holding the API key, sent as ``Authorization: Bearer <key>``.
  Whitespace around the key in the file is trimmed. Without the option the
  key is ``LOTA_FLEET_API_KEY``, taken as it is; with neither, no
  ``Authorization`` header is sent. There is no option that takes the key
  itself: an argument shows in the process list, which other users of the
  machine read unless ``/proc`` is mounted with ``hidepid``.

``-tls-ca PATH``
  PEM certificates that replace the system roots for an ``https`` server.
  The verifier serves HTTPS on any address other than a loopback IP
  (:doc:`../verifier/command-line`), so this names the CA that issued its
  ``--cert``. Without the option, or with an empty file, the system roots
  apply.

``-timeout DURATION``
  The time allowed for each request, as a Go duration such as ``10s``.
  Default ``30s``; ``0`` means the default, and a negative value sets no
  limit.

``-json``
  Prints the response as JSON in place of the text below (`Output`_). The
  action commands print text either way.

``-h`` before the command prints the usage, and among the options of a
command that takes options, those options; both exit 2. In the place of a
client or hardware ID, ``-h`` is taken as the ID: ``ban -h`` asks for
``-reason``, and ``revoke -h -reason admin -actor A`` revokes a client named
``-h``. ``ban x -h`` prints the options of ``ban``.

The key a command needs is the role of its route: a reader key for the
listings, an admin key for the actions ("Authentication" in
:doc:`../verifier/monitoring-api`).

Commands
========

.. list-table::
   :header-rows: 1
   :widths: 50 10 40

   * - Command
     - Role
     - Route
   * - ``health``
     - none
     - ``GET /health``
   * - ``stats``
     - reader
     - ``GET /api/v1/stats``
   * - ``devices list [-limit N] [-after ID]``
     - reader
     - ``GET /api/v1/clients``
   * - ``devices show <client-id>``
     - reader
     - ``GET /api/v1/clients/{id}``
   * - ``revoke <client-id> -reason R -actor A [-note S]``
     - admin
     - ``POST /api/v1/clients/{id}/revoke``
   * - ``unrevoke <client-id> -reason R -actor A [-note S]``
     - admin
     - ``DELETE /api/v1/clients/{id}/revoke``
   * - ``revocations [-tenant T]``
     - reader
     - ``GET /api/v1/revocations``
   * - ``ban <hardware-id> -reason R -actor A [-tenant T] [-note S]``
     - admin
     - ``POST /api/v1/bans``
   * - ``unban <hardware-id> -reason R -actor A [-tenant T] [-note S]``
     - admin
     - ``DELETE /api/v1/bans/{id}``
   * - ``bans [-limit N] [-next-id CURSOR] [-tenant T]``
     - reader
     - ``GET /api/v1/bans``
   * - ``reanchor <client-id> -reason R -actor A [-note S]``
     - admin
     - ``POST /api/v1/clients/{id}/reanchor``
   * - ``delete <client-id> -reason R -actor A [-note S]``
     - admin
     - ``DELETE /api/v1/clients/{id}``
   * - ``reanchor-review list``
     - reader
     - ``GET /api/v1/reanchor/review``
   * - ``reanchor-review ack <client-id> -reason R -actor A [-note S]``
     - admin
     - ``POST /api/v1/clients/{id}/reanchor-review-ack``
   * - ``audit [-limit N] [-tenant T]``
     - reader
     - ``GET /api/v1/audit``
   * - ``attests [-limit N] [-tenant T]``
     - reader
     - ``GET /api/v1/attestations``

What each route does, the answers it gives and the audit row it writes are
in :doc:`../verifier/monitoring-api`; the effect of a re-anchor, a delete, a
revocation and a ban on the client's next round is in "Operator actions" of
:doc:`../verifier/index`.

Actions
-------

``-reason``, ``-actor`` and ``-note`` fill the fields of the same names in
the request body. ``lota-fleet`` refuses an action without ``-reason`` or
``-actor``. The verifier takes one of ``cheating``, ``compromised``,
``hardware_change`` and ``admin`` as the reason of a revoke or a ban, and
free text elsewhere.

``ban`` and ``unban`` send ``-tenant`` in the body; without it the verifier
uses the tenant ``default`` (:doc:`multi-tenancy`). A hardware ID is the
device pseudonym that ``devices show`` prints as ``hardware id`` and the
decision log holds as ``hardware_id``.

On success each action prints one line:

``revoke``, ``unrevoke``
  ``revoked <client-id> (<reason>)``, ``unrevoked <client-id> (<reason>)``

``ban``, ``unban``
  ``banned <hardware-id> in tenant <tenant> (<reason>)``, ``unbanned
  <hardware-id> in tenant <tenant> (<reason>)``

``reanchor``
  ``reanchored <client-id>: baselines cleared, next attestation
  re-establishes trust``

``delete``
  ``deleted <client-id>: trust state removed, revocations and bans kept``

``reanchor-review ack``
  ``reviewed <client-id>``

``ban`` and ``unban`` print ``in the default tenant`` when ``-tenant`` is not
given.

Listings
--------

``-limit``
  The ``limit`` query value; a value of 0 or less is not sent, and the
  verifier uses its default. ``audit`` and ``attests`` send no other query
  value, so they read the newest rows.

``-after``, ``-next-id``
  The cursor of the next page, which ``devices list`` and ``bans`` print on
  standard error as ``next page: -after <id>`` and ``more results: -next-id
  <cursor>``. Under ``-json`` it is the ``next`` and ``next_id`` field of the
  page, and standard error stays empty.

``-tenant``
  Keeps the rows of one tenant, in the table and under ``-json``. The filter
  runs in ``lota-fleet`` over the rows the verifier sent, so a page can come
  back short or empty while more rows exist. The verifier answers a key
  scoped to tenants with the rows of its tenants alone; the filter narrows
  the view of a key that sees more.

Output
======

``health``
  ``status``, ``mode`` when the verifier sends one, ``uptime``, and ``tls
  listening: <true|false> (<address>)``.

``stats``
  ``name: value`` lines: ``registered clients``, ``active policy``,
  ``loaded policies``, the attestation counters, ``active revocations``,
  ``active bans``, ``pending challenges``, ``used nonces`` and ``uptime``
  (``GET /api/v1/stats``). A key scoped to tenants gets ``tenant scoped:
  true`` and ``tenants`` first, and no line for a counter the verifier left
  out.

``devices list``, ``reanchor-review list``
  One client ID per line on standard output. The count goes to standard
  error, as ``<n> clients`` and ``<n> client(s) awaiting re-anchor review``,
  so standard output holds the IDs alone.

``devices show``
  ``client``, ``tenant``, ``hardware id``, ``revoked``, ``revocation reason``,
  ``first seen``, ``last attestation``, ``attestation count``, ``monotonic
  counter`` and ``pcr14 baseline``, a field the verifier left empty
  omitted. With machine keys on record, ``mok state`` and one ``mok key`` and
  ``db key`` line per key: its type, SHA-256 and subject.

``revocations``, ``bans``, ``audit``, ``attests``
  A table with the columns below. ``attests`` gives the duration in
  milliseconds with one decimal.

  ================ ===============================================================
  Command          Columns
  ================ ===============================================================
  ``revocations``  ``CLIENT TENANT REASON REVOKED AT BY NOTE``
  ``bans``         ``HARDWARE ID TENANT REASON BANNED AT BY NOTE``
  ``audit``        ``TIME TENANT ACTION TARGET ACTOR REASON NOTE``
  ``attests``      ``TIME TENANT CLIENT RESULT MS DETAILS``
  ================ ===============================================================

``-json`` prints the response as ``lota-fleet`` decoded it, indented. A field
it does not read is left out: ``kernel_hash``, ``last_seen`` and ``rounds``
of a decision row. ``revocations``, ``reanchor-review list``, ``audit`` and
``attests`` print the array of rows without the ``count`` beside it;
``bans`` prints the page with ``count`` set to the rows kept by ``-tenant``.

Exit status
===========

``0``
  Success.

``1``
  The request failed or the verifier refused it, or ``health`` read a
  status other than ``ok``. A refusal prints ``lota-fleet: API error: HTTP
  <code>: <message>``, with the message of the verifier's error object, or
  ``lota-fleet: API error: HTTP <code>`` alone when the body holds none, as
  from a server other than the verifier or plain HTTP sent to its HTTPS
  port. A key file or ``-tls-ca`` file that cannot be read, a server URL
  that is not ``http`` or ``https`` or has no host, a non-empty ``-tls-ca``
  file with an ``http`` server, and a CA file with no certificate also exit
  1. These are checked after the global options and before the command, so
  they win over a usage error in the command, and a missing command or an
  unknown global option wins over them.

``2``
  A usage error: no command, an unknown command or subcommand, an unknown
  option or a value it cannot parse, a missing ``-reason`` or ``-actor``, a
  missing or extra argument, and ``-h``.

``health`` prints its answer before exiting 1, so a script can test the
status alone:

.. code-block:: sh

   lota-fleet health >/dev/null || echo "verifier degraded" >&2

Examples
========

Revoke a client and list the revocations:

.. code-block:: console

   $ lota-fleet -key-file fleet-admin.key revoke "$CLIENT_ID" \
         -reason compromised -actor ops@example.com -note "incident 42"
   $ lota-fleet -key-file fleet-reader.key revocations

Ban the hardware behind the failed rounds of one tenant:

.. code-block:: console

   $ lota-fleet -key-file fleet-reader.key -json attests -limit 50 -tenant acme \
         | jq -r '.[] | select(.result != "ok") | .hardware_id // empty'
   $ lota-fleet -key-file fleet-admin.key ban "$HARDWARE_ID" -tenant acme \
         -reason cheating -actor ops@example.com

Re-anchor a client after a planned firmware update:

.. code-block:: console

   $ lota-fleet -key-file fleet-admin.key reanchor "$CLIENT_ID" \
         -reason "firmware update" -actor ops@example.com

Walk every client ID:

.. code-block:: sh

   after=
   while :; do
       lota-fleet -key-file fleet-reader.key devices list -limit 1000 \
           ${after:+-after "$after"} 2>page.err
       after=$(sed -n 's/^next page: -after //p' page.err)
       [ -n "$after" ] || break
   done
