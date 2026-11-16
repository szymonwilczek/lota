.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

=============
Observability
=============

The verifier serves Prometheus metrics on its monitoring API. A reference
scrape configuration, dashboard and alert rules are under
:ghsrc:`deploy/observability`, and ``make observability-lint`` checks them
with ``promtool`` and ``jq``. Each alert has a runbook below; the rules link
to it.

Scraping
========

``GET /metrics`` is a reader route of the monitoring API, open once the
verifier runs with ``--http-addr`` (:doc:`../verifier/monitoring-api`). On a
loopback address it is plain HTTP; elsewhere it is HTTPS and needs a key,
which the scraper sends as a bearer token. A key scoped to tenants is
refused: the metrics hold no tenant.

:ghsrc:`deploy/observability/prometheus.yml` scrapes a remote verifier over
HTTPS with a reader key from ``credentials_file`` and the CA in
``tls_config``, every 30 seconds, and loads the alert rules. A commented job
scrapes a verifier on the same host over HTTP. On Kubernetes the Helm chart
opens the API with ``httpApi.enabled`` (:doc:`helm-chart`).

Metrics
=======

The counters count from the instance's start, and each instance has its own.
The gauges are read when ``/metrics`` is scraped.

.. list-table::
   :header-rows: 1
   :widths: 40 10 50

   * - Metric
     - Type
     - Value
   * - ``lota_attestations_total``
     - counter
     - Reports checked. A report refused for its magic or size before it is
       read is not one (``lota_connection_errors_total``).
   * - ``lota_attestations_success_total``
     - counter
     - Reports answered ``ok``.
   * - ``lota_attestations_failed_total``
     - counter
     - Reports answered with any other verdict.
   * - ``lota_rejections_total{reason}``
     - counter
     - Refusals by verdict name ("Verdicts" in :doc:`../verifier/index`),
       and ``baseline_error`` (`Baseline errors`_).
   * - ``lota_reanchors_total{outcome}``
     - counter
     - Baseline moves by outcome (`Re-anchor outcomes`_).
   * - ``lota_connection_errors_total``
     - counter
     - Attestation connections that failed outside a verdict: an accept
       error, a connection past ``--max-connections``, a failed TLS
       handshake, a frame with a foreign magic or size, a report cut off, a
       failed write. A peer that hangs up before it sends a byte is not
       counted, and its challenge is dropped.
   * - ``lota_attestation_log_dropped_total``
     - counter
     - Decision-log rounds shed from a full buffer (:doc:`../verifier/store`).
   * - ``lota_attestation_log_failed_total``
     - counter
     - Decision-log rounds lost to a failed write.
   * - ``lota_attestation_log_events_lost_total``
     - counter
     - The refusals among the two above.
   * - ``lota_verification_duration_seconds``
     - histogram
     - Time to check a report, buckets from 1 ms to 10 s.
   * - ``lota_pending_challenges``
     - gauge
     - Challenges this instance sent and has not seen answered. A challenge
       lapses after five minutes.
   * - ``lota_registered_clients``
     - gauge
     - Clients with a baseline in the store.
   * - ``lota_active_revocations``
     - gauge
     - Revoked client IDs.
   * - ``lota_active_bans``
     - gauge
     - Banned device pseudonyms, every tenant.
   * - ``lota_used_nonces``
     - gauge
     - Rows of the used-nonce history.
   * - ``lota_loaded_policies``
     - gauge
     - Policies loaded.
   * - ``lota_uptime_seconds``
     - gauge
     - Seconds since the instance started.

On a shared store the gauges ``lota_registered_clients``,
``lota_active_revocations``, ``lota_active_bans`` and ``lota_used_nonces``
read the whole store, so every instance reports the same value. Sum the
counters and ``lota_pending_challenges`` across instances, and take any one
of those four.

Each ``reason`` and each ``outcome`` is exported at 0 before it first counts,
so an alert on one has a series to match from the first scrape.

Baseline errors
---------------

``baseline_error`` counts a round the baseline store failed, answered
``internal_error``. A first-use boot baseline refused for having no
enrollment road counts under ``policy_requirement``
(:doc:`../verifier/index`).

Re-anchor outcomes
------------------

``strong``, ``lfa``
  PCR 0, 1 and 7 re-pinned on the strong or the low-firmware-assurance path.
  An ``lfa`` client joins the review list.

``boot_entries``
  PCR 1 re-pinned after a boot-entry change.

``mok``
  PCR 14 re-pinned after a Machine Owner Key change.

``agent_hash``
  The agent pin moved to a listed build.

``forced``
  An operator forced a re-anchor through the API, counted at the call.

``escalate``, ``agent_hash_escalate``
  A boot or agent move refused; the round is ``integrity_mismatch``.

The paths are in "Re-anchor" of :doc:`../verifier/index`.

Dashboard
=========

:ghsrc:`deploy/observability/grafana/lota-verifier-dashboard.json` imports
into Grafana with a Prometheus data source picked at import. Its stat panels
show the success ratio over 5 minutes, the clients, revocations, bans,
pending challenges and uptime; its time series show the attestation rate,
the rejections by reason, the latency at the 50th, 95th and 99th percentile,
the re-anchor outcomes, the connection errors and the used-nonce history.

Alerts
======

:ghsrc:`deploy/observability/alerts/lota-verifier-alerts.yaml` holds 12
rules in three groups. ``critical`` asks for action at once: the verifier
gives no verdicts, or a host failed an integrity check. ``warning`` asks for
triage.

======================================= ======== ===========================
Alert                                   Severity Condition
======================================= ======== ===========================
`LotaVerifierDown`_                     critical ``up`` is 0 for 2 minutes.
`LotaAttestationStall`_                 warning  No report in 15 minutes,
                                                 with clients, for 15
                                                 minutes.
`LotaIntegrityLoss`_                    critical A ``pcr_fail`` or
                                                 ``integrity_mismatch`` in 5
                                                 minutes.
`LotaRevokedDeviceActivity`_            warning  A ``revoked`` or ``banned``
                                                 in 15 minutes.
`LotaReplayBurst`_                      warning  Over 3 ``nonce_fail`` in 5
                                                 minutes.
`LotaReanchorEscalation`_               warning  An ``escalate`` in 15
                                                 minutes.
`LotaBaselineStoreErrors`_              critical A ``baseline_error`` in 5
                                                 minutes.
`LotaAttestationFailureRatioHigh`_      warning  Over 10% failed over 10
                                                 minutes, for 10 minutes.
`LotaVerifyLatencyP99High`_             warning  99th percentile over 1 s,
                                                 for 10 minutes.
`LotaPendingChallengesHigh`_            warning  Over 1000 pending, for 5
                                                 minutes.
`LotaConnectionErrorBurst`_             warning  Over 1 error per second,
                                                 for 5 minutes.
`LotaDecisionLogLoss`_                  warning  A dropped or failed round
                                                 in 10 minutes, for 5
                                                 minutes.
======================================= ======== ===========================

The runbooks read the monitoring API on ``127.0.0.1:8080``; with keys
configured, add ``-H "Authorization: Bearer $KEY"``, a reader key to read
and an admin key to act.

.. _alert-lotaverifierdown:

LotaVerifierDown
----------------

Prometheus cannot scrape the verifier, and no verdict is given there.

#. ``systemctl status lota-verifier`` and ``journalctl -u lota-verifier``,
   or the pod log. A start that fails logs its reason at error level
   ("Startup refusals" in :doc:`../verifier/command-line`).
#. With the process up, check the scrape path: the address, the firewall,
   the key in ``credentials_file``.

.. _alert-lotaattestationstall:

LotaAttestationStall
--------------------

Clients are on record and no report came for 30 minutes: the agents are
down, or the attestation port is unreachable.

#. Open a TLS connection to the attestation port from the hosts' network:
   ``openssl s_client -connect verifier.example:8443 </dev/null`` prints the
   certificate.
#. On one host, ``systemctl status lota-attest.service``.
#. ``GET /api/v1/attestations?limit=10`` dates the last rounds.

.. _alert-lotaintegrityloss:

LotaIntegrityLoss
-----------------

A host's quoted PCRs, event log, PCR 14 derivation, agent hash or pinned
baseline did not match.

#. ``GET /api/v1/attestations?events=true&limit=50`` names the client and
   the cause in ``details``. A PCR refusal names each PCR that differs, with
   both values.
#. ``GET /api/v1/clients/{id}`` shows the baseline and the machine keys.
#. Match the change against a known one: a firmware or boot chain update, an
   agent update off the policy's ``agent_hashes``, a changed kernel command
   line. Several PCRs at once point at a different boot chain.
#. A known change: let the host re-pin ("Re-anchor" in
   :doc:`../verifier/index`), or force a re-anchor
   (``POST /api/v1/clients/{id}/reanchor``). An unknown change: revoke the
   client ID or ban the pseudonym, and keep the host for inspection.

A host that misses a ``require_*`` key is refused under that key's verdict,
not here.

.. _alert-lotarevokeddeviceactivity:

LotaRevokedDeviceActivity
-------------------------

A revoked or banned host keeps attesting. The agent retries on its interval,
so a short run after a revocation is expected.

#. ``GET /api/v1/revocations``, ``GET /api/v1/bans`` and ``GET
   /api/v1/audit`` show who listed the host and why.
#. A host meant to come back needs a new client ID; its old one stays
   revoked. A ban covers every certificate with the pseudonym.

.. _alert-lotareplayburst:

LotaReplayBurst
---------------

More than three ``nonce_fail`` in 5 minutes: a nonce unknown, used, expired,
answered on another connection or missing from the quote, or a client over
30 rounds a minute.

#. ``GET /api/v1/attestations?result=nonce_fail`` shows whether one client
   or many fail. One client: its rate, its link, the time a round takes.
#. Many clients: the store, through ``lota_verification_duration_seconds``
   and the database.

.. _alert-lotareanchorescalation:

LotaReanchorEscalation
----------------------

A boot baseline move was refused and the host fails with
``integrity_mismatch`` until an operator acts. The rule watches
``escalate``; ``agent_hash_escalate`` counts an agent move refused for the
per-client interval or for a baseline with no pinned hash, or lost to a
concurrent round.

#. The verifier log has the refusal at security level, with the client ID
   and the reason.
#. Many hosts with the same change point at a rollout; one host with its own
   change belongs to `LotaIntegrityLoss`_.
#. For a known change, ``POST /api/v1/clients/{id}/reanchor``. Otherwise
   revoke or ban.

.. _alert-lotabaselinestoreerrors:

LotaBaselineStoreErrors
-----------------------

``baseline_error`` counted: the baseline store failed (`Baseline errors`_).

#. Check the database: the connection, the disk, whether it takes writes.
   The verifier log names the failed operation. Refused hosts pass on their
   next round once the store answers.

.. _alert-lotaattestationfailureratiohigh:

LotaAttestationFailureRatioHigh
-------------------------------

More than one report in ten fails, for 10 minutes. One host does not move
this ratio.

#. The *Rejections by reason* panel names the verdict that dominates.
   ``sig_fail`` or ``certificate_validity`` point at the attestation CA,
   ``pcr_fail`` at the policy pins, ``integrity_mismatch`` after an agent
   update at ``agent_hashes``, a ``*_required`` verdict at a requirement the
   hosts miss, ``internal_error`` at the store.
#. Match the onset with the last policy or infrastructure change.

.. _alert-lotaverifylatencyp99high:

LotaVerifyLatencyP99High
------------------------

One check in a hundred takes over a second, for 10 minutes. The verifier
reads a report in 30 seconds and writes the result in 10.

#. Check the database latency and the verifier's CPU.
#. With load grown with the fleet, add instances
   (:doc:`ha-deployment`, :doc:`sizing`).

.. _alert-lotapendingchallengeshigh:

LotaPendingChallengesHigh
-------------------------

Over 1000 challenges unanswered: hosts drop the connection after the
challenge, or a source opens connections and sends nothing.

#. Compare with ``lota_registered_clients``. Near the fleet size points at
   the network; far above it at a flood.
#. Challenges lapse after five minutes. A gauge that keeps climbing needs
   the sources from the verifier log filtered upstream, or a lower
   ``--max-connections``.

.. _alert-lotaconnectionerrorburst:

LotaConnectionErrorBurst
------------------------

Over one failed connection a second: a scanner, a load balancer probing the
port with plain HTTP, connections past ``--max-connections``, or a frame
the verifier does not read.

#. The verifier log names the source and the failure: ``TLS handshake
   failed``, ``invalid report magic``, ``invalid report size``,
   ``connection limit reached, rejecting``.
#. An onset with a rollout points at mismatched versions
   (:doc:`protocol-versions`).

.. _alert-lotadecisionlogloss:

LotaDecisionLogLoss
-------------------

Decision-log rounds were lost. Verdicts are unaffected, and the rounds lost
are not recoverable (:doc:`../verifier/store`).

#. ``lota_attestation_log_dropped_total`` moves when the buffer is full,
   ``lota_attestation_log_failed_total`` when a write fails, and
   ``lota_attestation_log_events_lost_total`` when refusals are among them.
   The log says ``attestation-log buffer full; decision records shed`` or
   ``attestation-log flush failed; records dropped``.
#. Check the database latency, its connections, and locks on
   ``attestation_log``.
#. Note the window: for it, ``GET /api/v1/attestations`` misses rounds and
   ``rounds`` can count low.

Reading the decision log
========================

``GET /api/v1/attestations`` selects rows by window, verdict and client
(:doc:`../verifier/monitoring-api`):

.. code-block:: sh

   # every refusal in one day
   curl -H "Authorization: Bearer $KEY" \
       "http://127.0.0.1:8080/api/v1/attestations?events=true&since=2026-01-01T00:00:00Z&until=2026-01-02T00:00:00Z"

   # one client
   curl -H "Authorization: Bearer $KEY" \
       "http://127.0.0.1:8080/api/v1/attestations?client_id=$CLIENT_ID&limit=50"

   # one verdict
   curl -H "Authorization: Bearer $KEY" \
       "http://127.0.0.1:8080/api/v1/attestations?result=pcr_fail"

A row covers a run of passing rounds, up to ``--attestation-log-window``; the
time of each round in it is not kept.

Integrity drill
===============

The drill checks the chain from a refusal to a page, on a staging verifier:

#. Change one hex digit of the host's build in the policy's
   ``agent_hashes`` and restart the verifier.
#. Let one host attest. It is refused with ``integrity_mismatch``, and
   ``lota_rejections_total{reason="integrity_mismatch"}`` steps.
#. Within a scrape and an evaluation interval, the *Rejections by reason*
   panel shows the step and `LotaIntegrityLoss`_ fires.
#. Check the page arrives, restore the policy, restart, and see the host's
   next round pass.

The drill reads as a real refusal, so it runs under a change record.
