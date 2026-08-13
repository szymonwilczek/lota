.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

==========================================
Load testing with the synthetic fleet
==========================================

``lota-loadgen`` (:ghsrc:`src/verifier/loadgen`) drives thousands of
synthetic agents against a live verifier over the real TLS attestation
protocol. It exists to answer the scale questions a real agent cannot:
a genuine ``lota-agent`` needs a TPM and a measured boot, so one host
yields one identity, while a load test needs a fleet.

The synthetic agents are software-only but are **not** mocks of the
verifier: each attestation walks the production verification path --
AIK certificate chain to a rig CA, RSA quote signature over a
``TPMS_ATTEST`` blob, the report binding nonce, PCR digest, event-log
parsing, and the PCR14 boot-commitment derivation (initramfs lock +
boot commitment). The synthetic event log carries the firmware's
``SecureBoot`` variable measurement on PCR 7, which is what proves a
UEFI boot, and no PCR 14 event, so the chain anchors on a zero
baseline -- the shape of a UEFI host that boots without shim. The
verifier under test runs its strict production configuration; no TOFU
opt-out flags are involved.

The synthetic report is built to the same wire version the agent emits
(``ReportVersion``), including the mandatory trailing ESRT section, so a wire
change breaks the harness in the build rather than showing up as a fleet of
rejected attestations mid-run.

What a run measures and what it cannot
======================================

The harness measures the **verifier tier**: connection handling, the
cryptographic verification path, policy evaluation, baseline/nonce/
session state commits, and the store backend behind them. Client-side
work (TPM quote latency, agent scheduling) is out of scope -- the
numbers here bound how many agents a verifier deployment sustains, not
how long one agent's attestation takes end to end on real hardware.

Rig setup
=========

Generate a rig directory once. It persists the throwaway attestation
CA, the AIK key pool and the generated verifier policy, so runs are
repeatable and re-attesting clients keep their server-side baselines::

   lota-loadgen setup -dir rig -agents 10000

Point the verifier under test at the rig's trust material. The
generated ``policy.yaml`` pins the fleet's PCR 0/1/7 values and its
kernel/agent hashes, so the strict first-attestation boot-enrollment
gate passes without any TOFU opt-out::

   lota-verifier -addr :8443 -generate-cert \
     -aik-ca-cert rig/ca.crt -policy rig/policy.yaml \
     -aik-store /var/tmp/loadtest-aiks

.. warning::

   ``rig/ca.crt`` is a real attestation trust anchor and ``rig/ca.key``
   is sitting next to it. Any verifier given that root accepts every
   identity the rig can mint, with no TPM behind them, so the rig
   belongs only on verifiers dedicated to load testing. Never add it to
   a production ``--aik-ca-cert`` set, and keep the rig directory off
   shared hosts.

.. note::

   ``--db`` (single-file SQLite backend) runs the rig, but one process
   serializing writes to one file is not the write tier the numbers
   describe. Use the default file-backed stores as above, or
   ``--pg-dsn`` for the shared Postgres backend -- the Postgres rig is
   the configuration the scale and failover numbers are recorded
   against.

Run modes
=========

``steady`` is the production traffic shape: every agent attests on the
interval, with start offsets spread across one interval so the
verifier sees a flat arrival rate (10 000 agents at 60 s = ~167
attestations/second)::

   lota-loadgen run -dir rig -server 127.0.0.1:8443 -tls-ca lota-verifier.crt \
     -mode steady -interval 60s -duration 15m -out steady.json

``storm`` pushes every agent through exactly one attestation as fast
as the in-flight cap allows. Against a fresh verifier store every
attestation is a first one, so this is the registration-commit burst:
it bounds enrollment waves and disaster-recovery re-registration::

   lota-loadgen run -dir rig -server 127.0.0.1:8443 -tls-ca lota-verifier.crt \
     -mode storm -in-flight 128 -out storm.json

Useful flags:

``-agents N``
   Drive a subset of the rig (defaults to the setup size).
``-timeout D``
   Per-attestation deadline covering dial through result (default 15s).
``-session-log FILE``
   Append one JSONL record per ``VERIFY_OK`` (agent, unix time, session
   token, ``valid_until``). The soak's zero-loss check replays these
   tokens against ``POST /api/v1/session/validate`` after a failover.
``-insecure``
   Skip verifier TLS certificate verification. Load rigs only.

Reading the output
==================

The human summary prints attempts, ``VERIFY_OK`` count, rejections by
verifier result code, transport errors by phase (``dial``, ``read
challenge``, ``write report``, ``read result``, ``timeout``), the
achieved rate and latency percentiles (p50/p90/p99/max/mean, measured
from dial to result). The ``-out`` JSON adds a per-second timeline of
ok/rejected/error counts -- failover drills read the outage dip and
recovery window straight off that series -- plus ``agents_never_ok``,
which must be zero in a healthy run.

Interpreting failures:

* ``rejected`` counts are verifier verdicts (policy, baseline, nonce);
  in a healthy rig they stay zero. A restart of the verifier with a
  changed policy shows up here, not as transport errors.
* ``transport_errors`` are connection-level: a ``dial`` burst during a
  failover drill is the expected signature of the drained instance;
  ``timeout`` under steady load means the verifier is saturated (check
  the connection limit before blaming crypto -- the attestation
  listener refuses connections past ``--max-connections``, 256 by
  default, so a storm run with ``-in-flight`` above that measures the
  cap rather than the verifier).

Repeatability
=============

The fleet's measurement profile (PCR bank, agent/kernel hashes) is
deterministic: two rigs built by the same release produce the same
policy, so recorded numbers are comparable across hosts and runs.
Agent identities (pseudonyms, hardware IDs) are the opposite -- salted
with the rig's CA certificate, unique per rig but stable across
reloads of one rig directory. Multiple rigs can therefore drive one
shared verifier backend side by side (the multi-instance failover
drill splits the fleet across rigs, one per verifier instance) without
colliding on client IDs; give every verifier instance every rig's
``ca.crt`` (``--aik-ca-cert`` repeats). Regenerating a rig directory
mints a new CA and with it a new fleet identity, so server-side
baselines from the old rig become garbage -- point re-runs at the same
rig directory, or start from a fresh database. RSA keys are random per
rig, which changes nothing the verifier measures.

The scale acceptance numbers recorded for a release, the soak/failover
runbook and the sizing derivation live in
:doc:`the performance evaluation <evaluation>` (L2/L3 sections).
