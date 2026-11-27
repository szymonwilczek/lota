.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

Two verifiers on one Postgres
=============================

Two verifier instances share one Postgres database with ``--pg-dsn``: a host
that attests to one is listed by the other, and a revocation taken on one is
enforced by both. The topology is in `ha-deployment.rst
<../../Documentation/admin-guide/ha-deployment.rst>`_; the host is enrolled
by `examples/enrollment/ <../enrollment>`__.

1. Postgres
-----------

.. code:: sh

   podman run -d --name lota-pg \
     -e POSTGRES_USER=lota -e POSTGRES_PASSWORD=lota -e POSTGRES_DB=lota \
     -p 5432:5432 docker.io/library/postgres:16-alpine

   export LOTA_PG_DSN="postgres://lota:lota@127.0.0.1:5432/lota?sslmode=disable"

The verifier reads ``LOTA_PG_DSN`` when ``--pg-dsn`` is not given, which keeps
the password off the command line.

2. Enroll the host
------------------

.. code:: sh

   make verifier attest-ca agent
   examples/enrollment/run.sh

The script makes the CA material in ``examples/enrollment/ca``, enrolls the
host's AIK with ``lota-attest-ca``, and attests once to a verifier of its own.
It prints ``Done.`` when the round passes, and keeps the configuration it
wrote, ``demo.conf`` with no publisher profiles, in the ``lota-enrollment.*``
directory it names.

3. Two instances
----------------

.. code:: sh

   CA=examples/enrollment/ca
   export LOTA_READER_API_KEY="$(openssl rand -hex 32)"
   export LOTA_ADMIN_API_KEY="$(openssl rand -hex 32)"

   for i in 0 1; do
       build/lota-verifier --addr 127.0.0.1:944$i \
           --http-addr 127.0.0.1:808$i \
           --cert $CA/tls.crt --key $CA/tls.key \
           --aik-ca-cert $CA/ca.crt \
           --policy policies/testing.yaml \
           --allow-permissive-policy --allow-tofu-boot-baseline &
   done

Instance A listens on 9440 with its API on 8080, instance B on 9441 and 8081.
Both take the same DSN, CA root, policy and keys. Both log ``Postgres store
initialized`` with ``schema_version``; the first to start applies the schema
under a lock and the second finds it applied. With the state in Postgres,
nothing is written under ``/var/lib/lota`` and both run as an ordinary user.

``--allow-permissive-policy`` and ``--allow-tofu-boot-baseline`` let a test
host with no pinned measurements pass, as in the enrollment example.

4. Shared state
---------------

Attest to instance A, with the configuration from step 2:

.. code:: sh

   sudo build/lota-agent --attest --config /tmp/lota-enrollment.XXXX/demo.conf \
       --server 127.0.0.1 --port 9440 --ca-cert $CA/ca.crt

Read the host through instance B:

.. code:: sh

   curl -s -H "Authorization: Bearer $LOTA_READER_API_KEY" \
       http://127.0.0.1:8081/api/v1/clients

   CLIENT_ID=...   # a client ID from the list
   curl -s -H "Authorization: Bearer $LOTA_READER_API_KEY" \
       "http://127.0.0.1:8081/api/v1/clients/$CLIENT_ID"

The record comes from Postgres, and outlives a restart of both instances.
``monotonic_counter`` is the answering instance's own: B, which never saw a
round from the host, answers 0 (`monitoring-api.rst
<../../Documentation/verifier/monitoring-api.rst>`_).

Revoke the host through instance B:

.. code:: sh

   curl -s -H "Authorization: Bearer $LOTA_ADMIN_API_KEY" \
       -X POST "http://127.0.0.1:8081/api/v1/clients/$CLIENT_ID/revoke" \
       -d '{"reason": "compromised", "actor": "ops"}'

and attest to instance A again: the round is refused with ``revoked``.

Production
----------

This example runs on one host. A production tier also:

- puts a load balancer in front, with ``GET /health`` as its check and
  ``--shutdown-drain`` on the instances;
- reaches Postgres over ``sslmode=verify-full`` with a role of its own;
- runs a policy that pins the fleet's measurements, without the two
  ``--allow-*`` options;
- keeps the CA key in an HSM (`ca-key.rst
  <../../Documentation/security/ca-key.rst>`_).
