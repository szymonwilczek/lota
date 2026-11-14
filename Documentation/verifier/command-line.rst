.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

============
Command line
============

``lota-verifier`` takes options only. The options are declared in
:ghsrc:`src/verifier/main.go`, and ``lota-verifier -h`` prints the same list.
Each option takes one or two leading dashes, and a boolean option takes
``=false`` to turn it off.

.. code-block:: console

   $ lota-verifier --cert verifier.crt --key verifier.key \
         --aik-ca-cert ca.crt --policy fleet.yaml --db /var/lib/lota/verifier.db

``-h`` prints the usage and exits with status 0; an unknown option, or one
whose value does not parse, prints it and exits with status 2. A refusal at
startup is logged and exits with status 1 (`Startup refusals`_).

Listeners
=========

``--addr ADDR``
  The attestation listener (:doc:`index`). Default ``:8443``.

``--cert PATH``, ``--key PATH``
  The TLS certificate and key, PEM. Both listeners serve them, at TLS 1.3 or
  higher. Required, except with ``--report-only``.

``--generate-cert``
  Writes a self-signed certificate and key to ``lota-verifier.crt`` and
  ``lota-verifier.key`` in the working directory, replacing files of those
  names, and uses them when ``--cert`` is not given. The key is ECDSA P-256,
  the certificate is valid for 365 days and names ``localhost``,
  ``lota-verifier``, ``127.0.0.1`` and ``::1``. For testing.

``--max-connections N``
  The most attestation connections open at once. Default 256; 0 means the
  default, and a negative value removes the cap. A connection past the cap is
  closed at accept.

``--http-addr ADDR``
  The monitoring API (:doc:`monitoring-api`). Empty, the default, opens none.
  A loopback IP address serves plain HTTP. Any other address, a host name,
  ``0.0.0.0`` and ``::`` included, serves HTTPS with ``--cert`` and needs at
  least one API key (`Monitoring API keys`_); without either the verifier
  does not start. The server allows 5 seconds for the request headers, 10 for
  the request and the response each, and closes an idle connection after 60.

``--shutdown-drain DURATION``
  How long the monitoring API keeps answering after the attestation listener
  closes on shutdown (`Signals`_). ``/health`` answers ``degraded`` in that
  window, which tells a load balancer to stop routing here. Default 0. Takes
  a Go duration, such as ``10s``.

``--report-only``
  Serves the monitoring API alone, from a Postgres database it never writes:
  a hot standby or the primary. No attestation listener opens, the schema is
  checked but never applied, ``--policy`` is ignored with a warning, and every
  endpoint that changes state is refused (:doc:`../admin-guide/ha-deployment`).
  Needs ``--http-addr`` and ``--pg-dsn`` or ``--pg-shard-dsn``; the
  certificate becomes optional, and without it the API takes a loopback
  address only.

Storage
=======

One backend holds the verifier state (:doc:`store`):

``--pg-dsn DSN``
  A Postgres database shared by every instance. ``LOTA_PG_DSN`` is read when
  the option is not given. The verifier applies the schema at startup, so the
  database must be writable, and a hot standby is refused.

``--pg-shard-dsn DSN``
  One shard of a sharded Postgres store; repeat it for each. With no option
  given, ``LOTA_PG_SHARD_DSNS`` is read as a comma-separated list. Every
  instance must name the same shards in the same order: the verifier pins the
  set in each shard and refuses to start on another. Per-client baselines
  and nonces are spread over the shards; revocations, bans, the audit log
  and the decision log live on the first.

``--db PATH``
  A SQLite database holding all of the state.

``--state-db PATH``
  Used when none of the above is given. A SQLite database holding the used
  nonces, revocations, bans, the audit log and the decision log, but no boot
  baselines: those stay in memory and are lost on restart. Default
  ``/var/lib/lota/verifier-state.sqlite``.

``--allow-insecure-memory-state``
  INSECURE. With no database option, opens no ``--state-db`` and keeps all
  state in memory. A restart re-opens a replay window for the nonces, and the
  instance holds no revocations, bans, audit log or decision log; their
  endpoints answer 503.

``--pg-dsn`` and ``--pg-shard-dsn`` exclude each other, from the options or
the environment, and either excludes ``--db``.

``--pg-max-open-conns N``
  The most Postgres connections one instance opens, per shard. Default 20,
  at least 1. The verifier warns when the pool exceeds the database's
  ``max_connections``, or half of it, which leaves no room for a second
  instance.

``--attestation-log-window DURATION``
  How long one decision-log row may stand for. A passing round that repeats
  what the host's current row says updates that row; refusals, verdict
  changes and a host's first round always get a row of their own. Default
  ``1h``; 0 writes a row per round.

Policy
======

``--policy PATH``
  A PCR policy file, YAML, at most 64 KiB (:ghsrc:`policies/README.rst`).
  Repeatable. The first file is the active policy, which verifies every
  client whose tenant binds none; a further file reaches clients through its
  ``tenant:`` key (:doc:`../admin-guide/multi-tenancy`), and one with no
  tenant is logged as reaching no client. Two files with one ``name:``, or
  two bound to one tenant, are refused.

``--policy-pubkey PATH``
  An Ed25519 public key, PEM. Each ``--policy`` file must then carry a
  detached signature over its bytes in ``PATH.sig`` next to it.

``--allow-permissive-policy``
  INSECURE. Loads a policy that pins no PCR and lists no kernel or agent
  hash. Without ``--policy`` it loads the built-in ``default`` policy, which
  sets only ``require_iommu``, ``require_enforce`` and
  ``require_module_sig``.

``--allow-unpinned-agent``
  INSECURE. Loads a policy that sets ``require_secureboot``, pins no PCR and
  lists no agent hash. The agent hash is then pinned on first use, so a
  modified agent that enforces nothing can pin its own hash.

``--allow-tofu-boot-baseline``
  INSECURE. Pins the PCR 0, 1 and 7 a client reports on its first round
  without any enrollment road (:doc:`index`).

``--enable-self-service-reanchor``
  Turns self-service re-anchor on, or off with ``=false``, for every policy.
  Not given, each policy's ``profile:`` decides (:doc:`index`).

Attestation CA
==============

``--aik-ca-cert PATH``
  An attestation-CA root, PEM, that the AIK certificate in a report must
  chain to (:doc:`../admin-guide/bringup/ca-enrollment`). Repeatable.

``--aik-crl PATH``
  A CRL, PEM or DER, revoking AIK certificates. Repeatable. Each must be
  signed by an ``--aik-ca-cert`` root, and the option needs one.

``--require-cert``
  Refuses to start without ``--aik-ca-cert``. Default on. Off, the verifier
  starts, warns, and refuses every report.

Monitoring API keys
===================

Two keys of global scope come from the environment: ``LOTA_READER_API_KEY``
for the read endpoints and ``LOTA_ADMIN_API_KEY`` for all of them
(:doc:`monitoring-api`). With neither key and no file, the admin endpoints are
off and the read endpoints are open, on a loopback address only.

``--api-keys-file PATH``
  Keys scoped to tenants, YAML. Each entry names the key by the SHA-256 of
  its value in hex, a role, and the tenants it may see, or ``*`` for all:

  .. code-block:: yaml

     keys:
       - key_sha256: 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
         role: reader
         tenants: [acme]
       - key_sha256: 60303ae22b998861bce3b28f33eec1be758a213c86c93c076dbe9f558c11c752
         role: admin
         tenants: ["*"]

  A file with no entry, or one invalid entry, is refused whole: a bad digest,
  a repeated digest, a role other than ``reader`` or ``admin``, an empty or
  invalid tenant list. The environment keys keep working beside it.

Logging
=======

The log goes to standard error.

``--log-format FORMAT``
  ``json``, or ``text`` for any other value. Default ``text``.

``--log-level LEVEL``
  The lowest level logged: ``debug``, ``info``, ``warn`` (or ``warning``),
  ``error`` or ``security``. Any other value means ``info``. ``security``
  lies above ``error``, and its records show the level ``SECURITY``.

``--print-versions``
  Prints the attestation report wire version, the schema version each
  backend is built to and the minimum TLS version, then exits with status 0
  (:doc:`../admin-guide/protocol-versions`).

Signals
=======

``SIGHUP``
  Reads ``--api-keys-file`` again, then the ``--aik-crl`` files. A file that
  fails keeps the previous set in force, logged as ``SIGHUP: API key reload
  failed; keeping previous set`` or ``SIGHUP: CRL reload failed; keeping
  previous set``. The CA roots are not read again. With neither a CA root nor
  a key file the verifier logs ``SIGHUP: no CRL feed configured; nothing to
  reload``.

``SIGINT``, ``SIGTERM``
  Stops the verifier: the attestation listener closes, the monitoring API
  answers for ``--shutdown-drain``, then gets 5 seconds to finish its
  requests, and open rounds run to their end. The buffered decision log is
  flushed; rows it lost in the run are logged as ``decision log incomplete
  for this run``. The verifier logs ``LOTA Verifier stopped`` and exits with
  status 0.

Startup refusals
================

Each of these is logged at error level and exits with status 1:

* ``TLS certificate and key required (use --generate-cert for testing)``:
  ``--cert`` or ``--key`` is missing.
* ``failed to generate certificate``: ``--generate-cert`` could not make or
  write the certificate or key.
* ``choose one Postgres form: --pg-dsn (single database) or --pg-shard-dsn
  (sharded), not both``: both Postgres forms are given.
* ``choose one storage backend: Postgres or --db (SQLite), not both``:
  Postgres and ``--db`` are given.
* ``--report-only reads a Postgres database`` and ``--report-only serves only
  the monitoring API``: ``--report-only`` lacks a Postgres DSN or
  ``--http-addr``.
* ``--pg-max-open-conns must be at least 1``: the pool is below 1.
* ``failed to initialize AIK certificate verification``: no ``--aik-ca-cert``
  with ``--require-cert``, an ``--aik-crl`` without a root, or a root or CRL
  that does not load.
* ``failed to open Postgres database``, ``failed to read shard identity`` and
  ``shard set check failed``: a database does not open or its schema does not
  fit, or the shard list differs from the one pinned (:doc:`store`).
* ``failed to open database`` and ``failed to open the state database
  (required for anti-replay and enforcement persistence)``: the ``--db`` or
  ``--state-db`` file does not open.
* ``failed to load policy public key``, ``failed to load policy`` and ``policy
  file reuses the name of one already loaded, which would replace it``: a
  key, a policy or its signature does not load, a policy binds a tenant
  another one holds, or two policies share a name.
* ``no PCR policy configured``: no ``--policy`` and no
  ``--allow-permissive-policy``.
* ``refusing to start with measurement-empty PCR policy``: the active policy
  pins nothing, without ``--allow-permissive-policy``.
* ``failed to create server`` and ``failed to start server``: the
  certificate, the key or ``--api-keys-file`` does not load, or a listener
  does not open, including a refused monitoring API address.

Files
=====

``/usr/bin/lota-verifier``
  The binary, from the verifier package.

``/var/lib/lota``
  The state directory, mode 0700, from the same package. The default
  ``--state-db`` lives in it.

``lota-verifier.crt``, ``lota-verifier.key``
  Written by ``--generate-cert`` in the working directory, mode 0644 and
  0600.

``PATH.sig``
  The detached signature of policy file ``PATH``, read with
  ``--policy-pubkey``.
