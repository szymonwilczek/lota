.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

=============
Observability
=============

Verifier emits Prometheus metrics; this page covers shipping them into a
working monitoring stack: scraping, the reference Grafana dashboard, the
alert rules, and a runbook for every alert. The reference configs live in
the tree under :ghsrc:`deploy/observability` and are validated by
``make observability-lint`` in CI.

Scraping the verifier
=====================

Metrics are served at ``GET /metrics`` on the HTTP monitoring API, which is
disabled until the verifier is started with ``--http-addr``:

.. code-block:: sh

    lota-verifier ... --http-addr 127.0.0.1:8080

The endpoint sits on the *reader* tier of the monitoring API:

* On a **loopback** bind no key is required; a co-located Prometheus can
  scrape ``127.0.0.1:8080`` directly.
* On a **non-loopback** bind the API fails closed: the verifier refuses to
  start unless a reader or admin key is configured, and every scrape must
  present the reader key as a Bearer token
  (``LOTA_READER_API_KEY``; see the deployment page for the key tiers).
* The monitoring API speaks plain HTTP. Scrape over loopback or a trusted
  network, or terminate TLS in front of it; never expose the port to an
  untrusted network.

:ghsrc:`deploy/observability/prometheus.yml` is a complete reference
configuration: it scrapes ``/metrics`` with the reader key read from a
root-only credentials file and loads the alert rules from the ``alerts``
directory next to it. On Kubernetes, the Helm chart exposes the same API
through the ``httpApi`` values (off by default).

Metrics reference
=================

Every labeled series is zero-filled with its known label values, so alert
expressions match from the first scrape and never miss the first event
after a verifier restart.

=============================================== ========= =======================================================
Metric                                          Type      Meaning
=============================================== ========= =======================================================
``lota_attestations_total``                     counter   Attestation attempts.
``lota_attestations_success_total``             counter   Attestations that verified successfully.
``lota_attestations_failed_total``              counter   Failed attestations (parse errors + rejections).
``lota_rejections_total{reason}``               counter   Rejections by reason: ``pcr_fail``,
                                                          ``integrity_mismatch`` (tamper signals),
                                                          ``sig_fail``, ``nonce_fail``, ``revoked``,
                                                          ``banned``, ``baseline_error`` (verifier store
                                                          failure).
``lota_reanchors_total{outcome}``               counter   Boot-baseline re-anchors by outcome:
                                                          ``strong`` and ``lfa`` (self-service,
                                                          auto-applied; ``lfa`` also lands in the
                                                          operator review queue), ``escalate``
                                                          (refused, device blocked until an operator
                                                          acts), ``forced`` (operator-forced via the
                                                          monitoring API).
``lota_connection_errors_total``                counter   Protocol-level errors on the attestation port.
``lota_verification_duration_seconds``          histogram Attestation verification latency.
``lota_pending_challenges``                     gauge     Outstanding attestation challenges.
``lota_registered_clients``                     gauge     Registered attestation clients.
``lota_active_revocations``                     gauge     Currently revoked client AIKs.
``lota_active_bans``                            gauge     Currently banned hardware IDs.
``lota_used_nonces``                            gauge     Consumed nonces retained for replay protection.
``lota_loaded_policies``                        gauge     Loaded PCR policies.
``lota_uptime_seconds``                         gauge     Verifier uptime.
=============================================== ========= =======================================================

Grafana dashboard
=================

:ghsrc:`deploy/observability/grafana/lota-verifier-dashboard.json` is a
reference dashboard importable into a stock Grafana: *Dashboards -> New ->
Import*, upload the JSON, and select the Prometheus datasource that scrapes
the verifier. It shows the fleet at a glance (success ratio, clients,
revocations, bans, challenge backlog, uptime) over time series for
attestation rates, rejections stacked by reason, verification-latency
quantiles, re-anchor outcomes, protocol errors, and the replay history.
Panel thresholds mirror the alert rules, so a red stat on the dashboard and
a firing alert say the same thing.

Alerts and runbooks
===================

:ghsrc:`deploy/observability/alerts/lota-verifier-alerts.yaml` ships 11
rules. Severity encodes the escalation tier:

* **warning = L2**: operator triage. The fleet's integrity verdicts are
  still sound; investigate during working hours.
* **critical = L3**: integrity or service impact. Act immediately: either a
  device failed integrity or the verifier cannot render verdicts.

The runbooks below assume shell access to the verifier host and the
monitoring API on ``127.0.0.1:8080``; on an authenticated deployment add
``-H "Authorization: Bearer $(cat /path/to/key)"`` (reader key for reads,
admin key for mutations).

.. _alert-lotaverifierdown:

LotaVerifierDown (critical)
---------------------------

Prometheus cannot scrape the verifier. While it is down no verdicts are
rendered and relying parties see stale or missing attestation state.

1. Check the service and its last words:
   ``systemctl status lota-verifier`` / ``journalctl -u lota-verifier -n 100``
   (or the pod logs on Kubernetes).
2. A crash loop after a configuration change: roll the change back first,
   ask questions later.
3. If the process is healthy, the path Prometheus uses is broken: firewall,
   reader key rotated without updating the credentials file, or the
   monitoring bind address changed.
4. Escalate to L3 if the verifier does not come back within one restart:
   collect the journal and the database state before further restarts.

.. _alert-lotaattestationstall:

LotaAttestationStall (warning)
------------------------------

Registered clients exist but no attestation arrived for 30 minutes. The
fleet went silent: agents down, network path broken, or the attestation
port unreachable. A silent fleet is indistinguishable from a compromised
one, so do not let this linger.

1. Confirm the attestation listener is up and reachable from a fleet
   subnet: ``curl -sk https://VERIFIER:8443/`` should at least open a TLS
   connection.
2. Pick a known host and check its attest unit:
   ``systemctl status lota-attest.service`` on the device.
3. Check ``GET /api/v1/attestations?limit=10`` for the last records and
   their timestamps to bound when the fleet went quiet.
4. Escalate if the outage window exceeds the fleet's attestation interval
   several times over - decide whether stale sessions must be invalidated.

.. _alert-lotaintegrityloss:

LotaIntegrityLoss (critical)
----------------------------

Device presented PCR or runtime state that does not match its policy or
recorded baseline (``pcr_fail`` or ``integrity_mismatch``). This is the
product's primary tamper signal and the alert the forced drill below
exercises.

1. Identify the device: ``GET /api/v1/attestations?limit=50`` and filter
   the failed records; each carries the client ID and failure detail.
2. Read that client's state: ``GET /api/v1/clients/{id}``.
3. Decide benign versus hostile. Benign causes leave a paper trail: a
   kernel or bootloader update changes PCRs after a reboot (the re-anchor
   flow handles it), an agent binary update changes the agent hash pin, an
   operator changed the kernel command line. No matching change record =
   treat as hostile.
4. Hostile: revoke the AIK
   (``POST /api/v1/clients/{id}/revoke`` with an actor and a reason) and,
   on the gaming deployment, consider a hardware ban
   (``POST /api/v1/bans``). Preserve the device for forensics; do not
   *fix* it back into the fleet.
5. Benign: follow the re-anchor procedure in the bring-up documentation
   and clear the finding through the review queue, not by loosening
   policy.

.. _alert-lotarevokeddeviceactivity:

LotaRevokedDeviceActivity (warning)
-----------------------------------

Revoked or banned device keeps attesting. Expected for a short window
right after a revocation (the agent retries on its interval); persistent
activity means the remediation never reached the host or someone is
replaying its identity.

1. ``GET /api/v1/revocations`` / ``GET /api/v1/bans`` - confirm the device
   is intentionally listed and by whom (``GET /api/v1/audit``).
2. If the device should have been reprovisioned, verify the host was
   actually re-enrolled (a re-enrollment issues a fresh AIK certificate;
   the old identity keeps knocking until the agent state is cleared).
3. Sustained activity from a banned gaming device is an expected nuisance;
   sustained activity from a revoked enterprise host is a process failure -
   chase the owner.

.. _alert-lotareplayburst:

LotaReplayBurst (warning)
-------------------------

More than a handful of nonce failures in 5 minutes. Isolated failures are
benign retries after timeouts; a burst is either a replay attempt or a
client whose clock is far enough off to keep missing the nonce window.

1. ``GET /api/v1/attestations`` - if the failures concentrate on one
   client, check that host's clock and network latency first.
2. Failures spread across many clients usually mean a verifier-side
   problem (nonce store latency); correlate with
   ``lota_verification_duration_seconds`` and the database.
3. A concentrated burst from one source that is *not* a registered client
   is an attack signature: capture the source address from the verifier
   log and treat it as hostile traffic.

.. _alert-lotareanchorescalation:

LotaReanchorEscalation (warning)
--------------------------------

Device's boot baseline changed in a way the self-service re-anchor
policy would not accept automatically. The re-anchor was refused and the
device keeps failing attestation until an operator acts; this is not the
post-fact review queue (that queue holds ``lfa`` re-anchors, which apply
automatically).

1. Identify the device from the verifier's security log (the escalation
   is logged with the client ID and the refusal reason).
2. Corroborate the change: a fleet-wide firmware or kernel rollout
   produces a wave of escalations with the same measurement delta; a
   single device with a unique delta deserves the LotaIntegrityLoss
   treatment.
3. For a legitimate platform change, force the re-baseline with
   ``POST /api/v1/clients/{clientID}/reanchor`` (admin key, actor
   recorded in the audit log); the next attestation re-establishes
   trust. For anything suspect, revoke or ban instead.

.. _alert-lotabaselinestoreerrors:

LotaBaselineStoreErrors (critical)
----------------------------------

Attestations are being rejected because the verifier cannot read or write
its baseline store. The verifier fails closed, so healthy devices are
refused while the backend is broken - this is a service outage, not a
security event.

1. Check the database: connectivity, disk space, and (Postgres) whether
   the instance accepts writes.
2. The verifier log names the failing operation; a migration mismatch
   after a partial upgrade also lands here.
3. Once the store recovers, rejected devices re-attest on their next
   interval with no operator action.

.. _alert-lotaattestationfailureratiohigh:

LotaAttestationFailureRatioHigh (warning)
-----------------------------------------

More than 10% of all attestations failing for 10 minutes. One tampered
device cannot move this needle - fleet-wide ratios point at policy,
certificate, or infrastructure problems.

1. The rejections-by-reason dashboard panel says which failure dominates:
   ``sig_fail`` after a CA change means certificates (did the AIK CA
   rotate without redistributing?), ``pcr_fail`` across the fleet means a
   policy pushed with wrong pins, ``baseline_error`` means the store.
2. Correlate the onset with the last policy or infrastructure change and
   roll it back.

.. _alert-lotaverifylatencyp99high:

LotaVerifyLatencyP99High (warning)
----------------------------------

Verification p99 above one second, sustained. Agents tolerate this but
their timeouts are finite; at several seconds the failure ratio starts
climbing as a side effect.

1. Database pressure is the usual cause: check the backend's latency and
   the verifier host's CPU.
2. If load grew with the fleet, scale per the deployment page
   (:doc:`ha-deployment`) rather than raising timeouts.

.. _alert-lotapendingchallengeshigh:

LotaPendingChallengesHigh (warning)
-----------------------------------

More than 1000 challenges issued but never answered. Either a fleet
segment stalls mid-handshake (network drops the second leg) or an
unauthenticated source is farming challenges.

1. Compare with ``lota_registered_clients``: a backlog near the fleet size
   is a fleet-wide network problem; a backlog far above it is a flood.
2. Challenges expire on their own; the gauge should drain once the cause
   stops. If it climbs unbounded, capture the source addresses from the
   verifier log and filter upstream.

.. _alert-lotaconnectionerrorburst:

LotaConnectionErrorBurst (warning)
----------------------------------

Sustained protocol-level errors on the attestation port: a scanner, a
protocol-version mismatch after a partial upgrade, or a load balancer
health-checking the TLS port with plain HTTP.

1. The verifier log records the offending source and the parse error.
2. If the onset matches an agent or verifier rollout, suspect a version
   mismatch and finish or roll back the rollout.

Forced integrity-loss drill
===========================

Run this drill after standing up the stack (and periodically after) to
prove the pipeline end to end: a tampered measurement must light the
dashboard and page within one scrape interval. It satisfies the "alerts
fire on a forced integrity-loss event" acceptance test.

The safe variant injects the mismatch on the verifier side, so no device
is modified: edit a **staging** verifier's policy to pin an agent hash
that cannot match (for example, flip one hex digit of the pinned value in
``agent_hashes``), reload, and let one healthy device attest:

1. The attestation is rejected; ``lota_rejections_total`` increments with
   the corresponding reason.
2. Within one scrape interval the *Rejections by reason* panel shows the
   series step, and *LotaIntegrityLoss* enters pending/firing.
3. Confirm the page arrives through the deployed notification channel,
   then restore the correct policy and verify the device's next
   attestation succeeds.

The full-fidelity variant tampers with a scrap test device instead (edit
its kernel command line and reboot, or strip the agent binary's integrity
metadata): the device itself fails verification, exercising the same path
an attacker would trip. Never run either variant against production
policy state without a change record: the drill is indistinguishable from
a real event by design, and the on-call rotation should treat it as one
until the change record says otherwise.
