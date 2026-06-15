SDK <-> server mutual TLS
=========================

The anti-cheat heartbeat producer and the game server authenticate each other
with mutual TLS. The producer proves it is the registered anti-cheat service;
the server proves it is the real backend and not an interceptor that would
otherwise collect signed heartbeats. Both ends pin one provisioning CA and
present a certificate it signed.

Two PKIs, two jobs
------------------

LOTA already runs an *attestation* CA that certifies a device's AIK -- the
hardware identity behind a quote. mTLS is a different question: which two
*services* are talking. Conflating them would let a service-transport key stand
in for a hardware-attestation anchor, so the provisioning CA here is
deliberately separate:

::

   attestation CA   -> signs AIK certs      -> "this quote came from a real TPM"
   provisioning CA  -> signs service certs  -> "this is the producer / the server"

The token inside each heartbeat is still verified against the AIK exactly as
before; mTLS only secures and authenticates the channel that carries it.

Provision
---------

.. code:: sh

   ./gen-certs.sh            # writes ./mtls/{ca,server,producer}.{crt,key}

``gen-certs.sh`` stands up the provisioning CA and issues two leaves:

- ``server.crt`` -- ``serverAuth``, bound to the server's address via SAN
  (``SERVER_SAN``, default ``IP:127.0.0.1,DNS:localhost``).
- ``producer.crt`` -- ``clientAuth``, the identity the server requires on every
  heartbeat connection.

Wire them in:

.. code:: sh

   demo_server -tls-cert mtls/server.crt -tls-key mtls/server.key \
               -client-ca mtls/ca.crt ...

   demo_anticheat --server https://127.0.0.1:7443/heartbeat \
                  --ca-cert mtls/ca.crt \
                  --client-cert mtls/producer.crt \
                  --client-key mtls/producer.key ...

With ``-client-ca`` set the server requires and verifies a client certificate,
so a heartbeat from anything but a provisioned producer is refused at the TLS
layer before any token is parsed. The producer verifies the server certificate
against the same CA and refuses to ship a heartbeat to an unauthenticated
endpoint.

Rotate
------

Leaves are short-lived (``LEAF_DAYS``, default 365). Rotation reissues one leaf
against the unchanged CA and restarts that side:

.. code:: sh

   ./gen-certs.sh -producer    # new producer.crt/key, same CA
   # restart demo_anticheat with the new leaf

   ./gen-certs.sh -server      # new server.crt/key, same CA
   # restart demo_server with the new leaf

Because the CA is untouched, the peer keeps trusting the new leaf with no
coordination. Rotating the CA itself is rarer: reissue both leaves
(``./gen-certs.sh`` after removing ``ca.key``/``ca.crt``) and redistribute
``ca.crt`` to both ends, ideally adding the new CA to each trust store before
removing the old one so connections never break mid-rollout.

Scope
-----

This is plumbing plus a reference wiring, not a transport library: the server
uses Go's ``crypto/tls`` and the producer uses libcurl's native TLS directly. A
real deployment keeps the CA key offline, issues leaves from an existing
service PKI, and distributes them with its own secret-management, but the
contract -- separate provisioning CA, ``clientAuth`` producer, ``serverAuth``
server, both pinning the CA -- is the same.
