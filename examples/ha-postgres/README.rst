.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

Multi-instance verifier on a shared Postgres backend
====================================================

Single verifier process keeps its enforcement and session-token state to
itself, so it cannot sit behind a load balancer. Pointing several verifier
instances at one Postgres database with ``--pg-dsn`` makes them share that
state: a token issued by one instance validates on another, and a revocation or
ban on one is enforced by all. This example stands two instances up against one
Postgres so the shared-state behaviour can be observed without a full fleet.

See `Documentation/operator/ha-deployment.rst <../../Documentation/operator/ha-deployment.rst>`_ for the
topology and the shared-state requirements, and
`examples/enrollment/ <../enrollment>`__ for the CA + attestation ceremony
this example reuses.

.. _1-start-a-shared-postgres:

1. Start a shared Postgres
--------------------------

.. code:: sh

   podman run -d --name lota-pg \
     -e POSTGRES_USER=lota -e POSTGRES_PASSWORD=lota -e POSTGRES_DB=lota \
     -p 5432:5432 docker.io/library/postgres:16-alpine

The DSN both instances use (the password is in the DSN here for brevity; in
production pass it through ``LOTA_PG_DSN`` and use ``sslmode=verify-full``):

.. code:: sh

   export LOTA_PG_DSN="postgres://lota:lota@127.0.0.1:5432/lota?sslmode=disable"

.. _2-build-the-verifier-and-a-ca-trust-root:

2. Build the verifier and a CA trust root
-----------------------------------------

.. code:: sh

   make verifier attest-ca
   # reuse the enrollment example's CA so both verifiers trust one root
   examples/enrollment/gen-ca.sh        # writes ca.crt / ca.key

.. _3-run-two-instances-against-the-same-database:

3. Run two instances against the same database
----------------------------------------------

Each instance is stateless and identical apart from its listen ports. Both take
``--pg-dsn`` (here via ``LOTA_PG_DSN``), the same CA root, and the same policy,
so they enforce the same rules over the same shared state.

.. code:: sh

   # instance A
   build/lota-verifier --generate-cert \
     --addr :8443 --http-addr 127.0.0.1:8080 \
     --aik-ca-cert ca.crt \
     --policy policies/production.yaml &

   # instance B (same DSN, different ports)
   build/lota-verifier --generate-cert \
     --addr :8444 --http-addr 127.0.0.1:8081 \
     --aik-ca-cert ca.crt \
     --policy policies/production.yaml &

Both log ``Postgres store initialized schema_version=1``. The first to start
runs the schema migration under an advisory lock, the second finds the schema
already present.

.. _4-observe-the-shared-state:

4. Observe the shared state
---------------------------

Drive one full attestation through **instance A** (port 8443) using the
enrollment example, then read the result back through **instance B** (port
8081). Because the client registration, baseline and session token live in
Postgres, instance B reports the client it never spoke to:

.. code:: sh

   # the client enrolled + attested via instance A shows up on instance B
   curl -s -H "X-API-Key: $LOTA_READER_API_KEY" \
     http://127.0.0.1:8081/api/v1/clients

   # a session token issued by instance A validates on instance B
   curl -s -H "X-API-Key: $LOTA_READER_API_KEY" \
     -X POST http://127.0.0.1:8081/api/v1/session/validate \
     -d '{"session_token":"<token-from-instance-A>","consume":true}'

``consume:true`` call marks the token used in Postgres, so a second validation
of the same token on **either** instance reports ``consumed:true`` --
single-use is enforced across the fleet, not per process.

Production deltas
-----------------

This example uses ``--generate-cert`` self-signed TLS and a plaintext database
connection so it runs on one host. A production tier additionally:

- terminates client traffic at a load balancer whose health check is
  ``GET /health``, fanning out to the instances;
- uses real TLS material and ``sslmode=verify-full`` to a least-privilege
  Postgres role;
- keeps the CA signing key in an HSM (see
  `Documentation/security/ca-key.rst <../../Documentation/security/ca-key.rst>`_).
