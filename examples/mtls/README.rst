.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

Producer and server over mutual TLS
===================================

The heartbeat producer, ``demo_anticheat``, and the game server,
``demo_server``, can authenticate each other with mutual TLS: each end
presents a certificate signed by one provisioning CA and verifies the other's
against it. The heartbeat's token is verified against the AIK either way; TLS
authenticates the channel that carries it.

Two CAs
-------

The provisioning CA is not the attestation CA:

::

   attestation CA   -> AIK certificates      -> "this quote is from this TPM"
   provisioning CA  -> service certificates  -> "this is the producer or server"

A service key never stands in for a device's AIK, and the attestation CA's
key signs nothing here.

Provision
---------

.. code:: sh

   cd examples/mtls
   ./gen-certs.sh

The script writes into ``OUT_DIR``, ``./mtls`` by default, every file mode
0600:

=============================== =============================================
File                            Use
=============================== =============================================
``ca.crt``, ``ca.key``          The provisioning CA, P-256, ``CA:TRUE``,
                                ``pathlen:0``, ``CA_DAYS`` days, default 1825.
``server.crt``, ``server.key``  The server, ``serverAuth``, with the subject
                                alternative names in ``SERVER_SAN``, default
                                ``IP:127.0.0.1,DNS:localhost``.
``producer.crt``,               The producer, ``clientAuth``.
``producer.key``
=============================== =============================================

The leaves are P-256 and valid for ``LEAF_DAYS`` days, default 365. A
``ca.key`` already in ``OUT_DIR`` is reused, and a missing ``ca.crt`` is
issued again from it.

Run
---

.. code:: sh

   demo_server -tls-cert mtls/server.crt -tls-key mtls/server.key \
               -client-ca mtls/ca.crt ...

   demo_anticheat --server https://127.0.0.1:7443/heartbeat \
                  --ca-cert mtls/ca.crt \
                  --client-cert mtls/producer.crt \
                  --client-key mtls/producer.key ...

The other options are in
`examples/demo_server/README.rst <../demo_server/README.rst>`__ and
`examples/demo_anticheat/README.rst <../demo_anticheat/README.rst>`__.

The server (``examples/demo_server/main.go``):

* ``-tls-cert`` and ``-tls-key`` serve HTTPS, TLS 1.2 or later, and go
  together. Without them it serves plain HTTP.
* ``-client-ca`` requires a client certificate on every connection, signed by
  that CA and carrying ``clientAuth``. A connection without one is refused in
  the handshake, before any request is read. ``-client-ca`` without the
  keypair stops the server at startup.
* It logs ``transport=https+mtls``, ``https`` or ``http`` at startup.
* Any certificate the CA signed for ``clientAuth`` is accepted; the server
  does not check the subject.

The producer (``examples/demo_anticheat/heartbeat_loop.c``):

* An ``https://`` URL verifies the server's certificate and that its subject
  alternative names cover the host in the URL, against ``--ca-cert``, or the
  system's trust store without it. A server that fails either is not sent the
  heartbeat.
* ``--client-cert`` and ``--client-key`` present the producer's certificate,
  and go together.
* An ``http://`` URL, the default, sends the heartbeat in clear, whatever the
  certificate options.

With ``-client-ca`` set, ``/nonce`` and ``/state`` require a client
certificate as well. ``trust_pong`` presents none, so it runs against a
server without ``-client-ca``.

Rotate
------

A leaf is issued again against the same CA, and its end restarted to load
it:

.. code:: sh

   ./gen-certs.sh -producer    # producer.crt and producer.key
   ./gen-certs.sh -server      # server.crt and server.key

The other end keeps trusting the CA, so it needs nothing. ``-server`` and
``-producer`` need a ``ca.key`` in ``OUT_DIR``.

A new CA is issued when ``ca.key`` and ``ca.crt`` are removed before
``./gen-certs.sh``, which then issues both leaves under it. Both ends trust
one CA file, so to roll one over without a break, give each end a file
holding the old and the new CA, move the leaves to the new one, then drop
the old.

Production
----------

The example issues from a CA key on disk. A deployment keeps the CA key
offline, or issues the two leaves from its own service PKI, and distributes
them with its own secret management. The contract stays: a CA of its own,
a ``clientAuth`` producer, a ``serverAuth`` server, and both ends verifying
against the CA.
