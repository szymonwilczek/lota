# Verifier deployment topologies

LOTA verifier persists two kinds of state: durable identity and enforcement
records (AIK registrations, per-client baselines, revocations, hardware bans,
the audit and attestation logs, used nonces) and short-lived session tokens
issued after a successful attestation. Where that state lives decides how many
verifier instances a deployment can run.

This document describes the supported topologies and the shared-state
requirement of each. It is written for operators standing up a verifier tier
and for contributors changing the store layer.

## Single node (default)

One verifier process owns its state. Two equivalent storage layouts exist:

- **File + SQLite (production default).** The certificate-backed AIK store
  lives under `--aik-store`; used nonces persist to a SQLite database
  (`--nonce-db`); revocation, ban, audit and attestation state are in-memory.
  This is what a `--require-cert` deployment runs today without `--db` or
  `--pg-dsn`.
- **SQLite (`--db`).** All of the above persist to one SQLite file. This path
  does not verify AIK certificate chains (`--require-cert` is refused), so it
  suits TOFU-only test fleets, not production.

Single node is the simplest topology and needs no external database. Its
ceiling is one process: there is no failover, and the in-memory enforcement
state of the production default is lost on restart.

## N instances behind a load balancer (Postgres)

Several stateless verifier instances point at one shared Postgres database,
selected with `--pg-dsn` (or `LOTA_PG_DSN`, which keeps the connection string
out of the process argument list). A load balancer fans attestation and
validation traffic across them; the `GET /health` endpoint is the health
check.

```
client --> load balancer --> verifier (1) --|
                         --> verifier (1) --|-->  Postgres (2)
                         --> verifier (1) --|

(1) - stateless, identical config
(2) - shared enforcement + session-token state
```

With `--pg-dsn` the shared database holds the baseline, used-nonce,
revocation, ban, audit, attestation and session-token state. The consequences:

- A baseline pinned, a client revoked, or hardware banned on one instance is
  enforced by every instance. The per-client baseline pin is committed under a
  transaction-scoped advisory lock, so the firmware/agent_hash TOFU contract
  holds across instances exactly as it does within one SQLite process.
- A used nonce recorded on one instance is rejected as replayed on all
  instances.
- A session token issued by one instance validates on every instance, and a
  single-use token (`consume=true`) is consumed exactly once across the fleet.

Unlike the SQLite `--db` path, the Postgres path supports the
certificate-backed AIK store, so a production `--require-cert` fleet can run
multiple instances. Run each instance with identical policy, CA roots and
storage configuration.

### Shared-state requirements

- **One Postgres database, reachable from every instance.** Use TLS to the
  database (`sslmode=verify-full` in the DSN) and a dedicated least-privilege
  role. Each instance opens its own connection pool; size Postgres
  `max_connections` for the instance count times the per-instance pool.
- **Schema migrations are safe to race.** Every instance runs migrations at
  startup under a Postgres advisory lock, so the schema is created exactly
  once regardless of start order.
- **AIK certificate roots and PCR policy are configuration, not shared
  state.** Distribute the same `--aik-ca-cert`, `--aik-crl`, `--policy` and
  `--policy-pubkey` material to every instance through the usual configuration
  channel; they are not stored in the database.
- **CA signing key.** The attestation CA is a separate service; its key
  handling (HSM/PKCS#11 or the dev-only PEM) is covered in
  [`CA-KEY.md`](CA-KEY.md).

### Scaling the read path

Session-token validation and other reads are single indexed lookups. At
session granularity their volume is far below the attestation path, so a
single Postgres node serves them comfortably. If a deployment ever needs more
read throughput, route reads to Postgres read replicas; because tokens are
opaque records in the shared store rather than self-describing blobs, this
needs no change to the token wire format or the SDK.

## Choosing a topology

| Need | Topology |
| ---- | -------- |
| Test fleet, single host, no external DB | Single node (file + SQLite) |
| Production, single verifier host | Single node (file + SQLite, `--require-cert`) |
| Production, failover or horizontal scale | N instances + Postgres (`--pg-dsn`, `--require-cert`) |
