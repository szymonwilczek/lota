.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

==================================
Privacy CA enrollment (end-to-end)
==================================

This example runs the whole enrollment path on one host: it starts
``lota-attest-ca``, enrolls the host's AIK with it, starts a
``lota-verifier`` that trusts only the CA certificate, and attests once.

::

	TPM  --- EK certificate, credential activation --->  lota-attest-ca
	                                                          |
	                                     AIK certificate, subject = device ID
	                                                          v
	lota-agent --- report with the AIK certificate --->  lota-verifier
	                                                     (--aik-ca-cert ca.crt)

The CA checks that the EK certificate chains to a trusted manufacturer root
and that the AIK sits in the same TPM, by credential activation, and signs
an AIK certificate whose subject is the device ID. The verifier checks that
certificate against ``ca.crt`` and never receives the EK. A client without
a TPM holding both keys fails ``TPM2_ActivateCredential`` and gets no
certificate. The CA side is described in `ca-enrollment.rst
<../../Documentation/admin-guide/bringup/ca-enrollment.rst>`_.

Requirements
============

* A TPM, hardware or swtpm, with a readable RSA EK certificate. The CA
  refuses an EK certificate without an RSA key with ``EK certificate public
  key is not RSA``, and an AIK that is not a restricted RSA signing key.

* The binaries from ``make all`` in ``build/``, or another directory given
  in ``BIN``.

* ``sudo``, as the agent enrolls and attests as root, and ``openssl``.

CA material
===========

.. code-block:: console

	$ examples/enrollment/gen-ca.sh examples/enrollment/ca

``gen-ca.sh`` writes into its argument, ``./ca`` by default, with umask 077:

``ca.key``, ``ca.crt``
  A P-256 CA key and a self-signed certificate for 1825 days with
  ``CA:TRUE`` and the ``keyCertSign`` and ``cRLSign`` key usages. The agent
  takes ``ca.crt`` as ``--ca-cert`` and every verifier as
  ``--aik-ca-cert``.

``pseudonym.key``
  32 random bytes, the key the CA derives device IDs with.

``tls.key``, ``tls.crt``
  A P-256 listener key and a certificate issued by ``ca.key`` for 825 days,
  for ``127.0.0.1`` and ``localhost``. The CA and the demo verifier both
  present it.

An existing file is kept. A missing ``ca.key`` is generated with a new
``ca.crt`` and ``tls.crt``, a missing ``ca.crt`` is issued again over the
existing ``ca.key``, a missing ``tls.key`` is generated with a new
``tls.crt``, and a ``tls.crt`` that ``ca.crt`` does not verify is issued
again. The script does not check that a key it finds matches its
certificate; the CA refuses such a pair at start with ``CA private key does
not match CA certificate`` or ``server TLS keypair:``.

The agent names the publisher by the SHA-256 of the ``--ca-cert``
certificate's SubjectPublicKeyInfo, and verifies the TLS endpoint against
that certificate (`publishers.rst
<../../Documentation/agent/publishers.rst>`_). A listener issued by the CA
key can therefore be replaced without moving any host to another profile;
a certificate over another CA key makes the CA another publisher, and
``ca.crt`` issued again over the same ``ca.key`` keeps it.

Running the demo
================

.. code-block:: console

	$ EK_ROOT=/var/lib/swtpm-localca/issuercert.pem examples/enrollment/run.sh

``run.sh`` reads its settings from the environment:

``EK_ROOT``
  Required. A directory is passed to the CA as ``-ek-root-bundle``, a file
  as ``-ek-root``. For swtpm it is the issuer certificate of swtpm's local
  CA. For hardware it is a bundle built as in `configs/ek-roots/README.rst
  <../../configs/ek-roots/README.rst>`_.

``CA_ADDR``, ``VERIFIER_ADDR``
  The CA and verifier listen addresses, ``127.0.0.1:8444`` and
  ``127.0.0.1:9443`` by default. The script checks both before it starts
  anything; a taken one makes it exit 1 with the variable to set, and with
  a free port to try when one of the next 100 on that host, other than
  the port of the other address, is free.

``BIN``, ``CA_DIR``
  The binaries, by default ``LOTA_BUILD_DIR``, else ``build/`` of the
  repository, and the CA material, by default
  ``examples/enrollment/ca``.

``RUN_DIR``, ``STATE_DB``, ``POLICY``
  The verifier's working directory, a new ``lota-enrollment.*`` under
  ``$TMPDIR`` or ``/tmp`` by default; its state database, by default
  ``verifier-state.sqlite`` there; and its policy, by default
  ``policies/testing.yaml``.

The script then runs four steps:

#. ``lota-attest-ca`` with ``ca.key``, ``ca.crt``, the listener pair, the
   pseudonym key and ``EK_ROOT``.

#. ``sudo lota-agent --enroll`` against ``CA_ADDR`` with ``ca.crt`` as
   ``--ca-cert``. The AIK certificate is stored in the publisher's profile
   under ``/var/lib/lota/profiles/``.

#. ``lota-verifier`` on ``VERIFIER_ADDR`` with ``-aik-ca-cert ca.crt``, the
   listener pair, ``-allow-permissive-policy`` and
   ``-allow-tofu-boot-baseline``.

#. ``sudo lota-agent --attest`` against that verifier, with a root-owned
   configuration in ``RUN_DIR`` that holds no publisher profiles, as
   ``--attest`` refuses ``--server`` beside configured profiles.

The CA and the verifier run in the background. A failing enrollment or
attestation stops the script, and on any exit it stops both services.
``Done.`` at the end means the attestation round passed.

A swtpm EK certificate comes without intermediates. A TPM that stores the
certificates above its EK sends them with the request, and the agent prints
their count::

	EK certificate chain: 3 manufacturer intermediate(s) from the TPM

What the run leaves
===================

The enrollment adds a publisher profile for ``ca.crt`` to the host, and the
host answers to at most eight publishers (`publishers.rst
<../../Documentation/agent/publishers.rst>`_). Consent is recorded before the
CA is reached, so a failed run holds the slot too. Rerunning with the same
``CA_DIR`` reuses that slot; another ``ca.key`` takes another. On exit the
script prints the publisher ID and the command that releases it:

.. code-block:: console

	# lota-agent --forget-publisher <id>

The script releases nothing itself.

The demo verifier runs with a test policy and a trust-on-first-use boot
baseline. A deployment loads a signed policy; see `bringup/index.rst
<../../Documentation/admin-guide/bringup/index.rst>`_ and
`policies/README.rst <../../policies/README.rst>`_. Renewal, re-enrollment
and the enrollment record are described in `publishers.rst
<../../Documentation/agent/publishers.rst>`_.
