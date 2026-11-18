.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

============
Load testing
============

``lota-loadgen`` (:ghsrc:`src/verifier/loadgen`) drives a live verifier with
a fleet of synthetic agents over the attestation protocol. An agent needs a
TPM and a measured boot, so one host is one identity; the synthetic fleet is
thousands of identities from one process, with software keys in place of a
TPM.

What a run measures
===================

Each synthetic round goes through the verifier's whole check: the AIK
certificate chain, the quote signature, the nonce binding, the PCR digest,
the event log and the PCR 14 boot commitment, then the policy, the
baseline and the nonce store. A run measures the verifier and the database
behind it. The TPM quote, the agent and the network between a host and the
verifier are not part of it.

The generator spends more CPU building and signing reports than the
verifier spends checking them, so a generator and a verifier on one host
saturate the generator first. Read both processes' CPU across a run, for
instance with ``top``; when ``lota-loadgen`` is the one at its
limit, the rate describes the load host. Drive the verifier from more
hosts, each with a rig of its own, until the verifier is the process at
its limit.

Building
========

.. code-block:: console

   $ make loadgen

The binary is ``build/lota-loadgen``. No package ships it.

The rig
=======

``setup`` writes a rig directory once, and prints the flags a verifier
needs for it on standard error:

.. code-block:: console

   $ lota-loadgen setup -dir rig -agents 10000
   rig ready in ...: 10000 agents
   verifier flags: --aik-ca-cert rig/ca.crt --policy rig/policy.yaml

``-dir DIR``
  The rig directory, created with mode 0700. Required.

``-agents N``
  The fleet size, default 1000.

``-key-pool N``
  How many RSA keys the fleet's AIKs share, default the smaller of the
  fleet size and 256. Agent ``i`` takes key ``i`` modulo the pool.

``-tenant NAME``
  Issues the AIK certificates into the tenant NAME and binds the generated
  policy to it. Left out, the fleet is in the default tenant.

The rig holds:

.. list-table::
   :header-rows: 1
   :widths: 25 10 65

   * - File
     - Mode
     - Contents
   * - ``ca.crt``
     - 0644
     - The rig's attestation CA, RSA-2048.
   * - ``ca.key``
     - 0600
     - Its private key.
   * - ``aik-keys.pem``
     - 0600
     - The key pool.
   * - ``policy.yaml``
     - 0644
     - The verifier policy the fleet passes.
   * - ``rig.json``
     - 0644
     - The fleet size, the pool size and the tenant.

``setup`` creates the directory and the files with these modes, less the
umask; a directory or file that already exists keeps its own.

A verifier for the rig, with a self-signed TLS certificate and a state
file:

.. code-block:: console

   $ lota-verifier -addr :8443 -generate-cert \
         -aik-ca-cert rig/ca.crt -policy rig/policy.yaml \
         -state-db /var/tmp/loadtest-state.sqlite

``-generate-cert`` writes a self-signed ``lota-verifier.crt`` and its key to
the verifier's working directory, which ``run -tls-ca`` takes. The
attestation flags are in :doc:`../verifier/command-line`.

.. warning::

   ``rig/ca.crt`` is an attestation trust anchor, and ``rig/ca.key`` mints
   identities under it with no TPM behind them. A verifier given that root
   accepts every identity the rig makes. Give it only to verifiers kept for
   load tests, and keep the rig directory off shared hosts.

The CA is valid for 30 days from ``setup``
(:ghsrc:`src/verifier/loadgen/synth/synth.go`). ``run`` issues the AIK
certificates again from the stored CA every time it loads the rig, each
valid for 30 days from then, so a rig older than 30 days fails the chain
at its CA; run ``setup`` again.

What the fleet reports
----------------------

Every agent reports the same boot: a UEFI boot without shim, with the
firmware's ``SecureBoot`` variable event and a separator on PCR 7, the
bootloader's ``EV_IPL`` event for the kernel image on PCR 9, and no PCR 14
event, so PCR 14 is the boot commitment over the fleet's agent hash from a
zero baseline. The report is built at the agent's wire version, with the
ESRT and MOK list sections.

``policy.yaml`` pins PCRs 0, 1 and 7, the kernel hash and the agent hash
of that boot, and requires enforce mode and module signatures. A verifier
with PCR 0, 1 and 7 pins in its policy passes a client's first round
without an enrolled boot baseline (:ghsrc:`src/verifier/verify/verify.go`),
so the rig needs no opt-out flag.

The boot measurements are fixed in the source, so two rigs built from the
same tree write the same policy. The identities are not: each agent is
named ``loadgen-NNNNNN``, and its pseudonym is a hash of that name and the
rig's CA certificate. A rig keeps its identities across runs, and two rigs
never share one, so several rigs can drive one verifier backend side by
side when every instance trusts every rig's ``ca.crt`` (``--aik-ca-cert``
repeats). A new ``setup`` in the same directory makes a new CA, and with it
a new fleet whose clients have no baseline; run again against the same rig
or a fresh database.

Running
=======

.. code-block:: console

   $ lota-loadgen run -dir rig -server 127.0.0.1:8443 \
         -tls-ca lota-verifier.crt -mode steady -interval 60s \
         -duration 15m -out steady.json

``-dir DIR``, ``-server HOST:PORT``
  The rig and the verifier's attestation address. Both required.

``-tls-ca FILE``
  The verifier's TLS certificate or its CA, in PEM.

``-insecure``
  Skips the verifier's certificate check. One of ``-tls-ca`` and
  ``-insecure`` is required; without either, ``run`` exits with 1.

``-agents N``
  Drives the first N agents of the rig; 0, the default, drives the whole
  rig. More than the rig holds is refused.

``-mode steady|storm``
  The traffic shape, default ``steady``.

``-interval D``, ``-duration D``
  Steady mode's interval, default 60s, and run length, default 5m.

``-in-flight N``
  Storm mode's cap on concurrent rounds, default 128.

``-timeout D``
  One deadline for a round from the dial to the result, default 15s.

``-progress D``
  The period of the progress line, default 10s; 0 prints none.

``-out FILE``
  Writes the JSON summary to FILE, or to standard output for ``-``.

``-attest-log FILE``
  Appends one JSON line per passed round, with the agent, the time and the
  token's ``valid_until``. The file is created with mode 0600, and a
  failed write ends the run.

The connection uses TLS 1.3 at least. ``SIGINT`` or ``SIGTERM`` stops the
run and prints what it has.

Modes
-----

``steady``
  Every agent attests once per interval, the start of agent ``i`` delayed
  by ``i`` intervals over the fleet size, so the verifier sees a flat rate
  of fleet size over interval: 10 000 agents at 60 seconds is about 167
  rounds a second.

``storm``
  Every agent attests once, as fast as ``-in-flight`` allows. Against a
  fresh database every round is a first round and inserts a baseline; run
  again and every round updates one.

The verifier closes a connection past ``--max-connections``, default 256,
right after accept (:doc:`../verifier/command-line`,
:ghsrc:`src/verifier/server/server.go`), and the generator counts it as a
``dial`` error. A storm with ``-in-flight`` above the cap loses rounds as
``dial`` errors.

Exit status
-----------

``lota-loadgen`` exits with 0 after a run, whatever the verifier answered,
with 2 for a missing command, an unknown command, a bad flag or a missing
``-dir`` or ``-server``, and with 1 for any other error. ``help``, ``-h``,
``-help`` and ``--help`` print the usage and exit with 0; ``setup -h`` and
``run -h`` print the command's flags and exit with 0.

Reading a run
=============

The summary goes to standard error:

``attempts``, ``verify_ok``
  The rounds started, and the ones the verifier passed.

``rejected NAME=N``
  The rounds the verifier refused, by result code. A healthy rig has none;
  a verifier restarted with another policy shows here.

``transport_err KIND=N``
  The rounds that failed outside a verdict, by the step that failed:
  ``dial``, ``deadline``, ``build report``, ``read challenge``, ``write
  report``, ``read result``, or ``timeout`` for any step past the deadline.
  ``dial`` covers the TCP connection and the TLS handshake, so a stopped
  instance and a verifier at its connection cap both show there; timeouts
  under steady load mean the verifier or the generator is saturated, and
  the CPU of both says which.

``rate``
  The rounds passed per second, then the rounds started per second. The
  first is the throughput. When some rounds did not pass,
  the line says how many did and that the rate is not a throughput
  ceiling; a figure to quote comes from a run whose line says nothing of
  the kind.

``latency ms``
  p50, p90, p99, max and mean, from the dial to the result, over the
  passed and refused rounds.

``agents_never_ok``
  The agents that never passed, printed when there are any.

The progress line counts the same way while the run goes on.

The JSON summary carries the same figures as ``attempts``, ``ok``,
``rejected``, ``transport_errors``, ``latency``, ``achieved_rate_per_sec``,
``attempted_rate_per_sec`` and ``agents_never_ok``, with ``mode``,
``server``, ``agents``, ``started``, ``finished`` and, in steady mode,
``interval_sec``. ``timeline`` holds one entry for each second in which a
round ended, with the rounds passed, refused and failed in it. A second in
which no round ended has no entry.

The measured runs are in :doc:`evaluation`, and what they mean for a
deployment is in :doc:`../admin-guide/sizing`.
