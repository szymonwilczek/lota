.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

=================================
EK manufacturer root trust bundle
=================================

``lota-attest-ca`` accepts an endorsement key certificate only when it
chains to a TPM manufacturer root the operator trusts. A fleet with several
manufacturers trusts a bundle of their roots: a directory the CA loads with
``-ek-root-bundle DIR``, in which a manifest pins every certificate by its
SHA-256. How the CA uses the bundle is in `ca-enrollment.rst
<../../Documentation/admin-guide/bringup/ca-enrollment.rst>`_.

This directory holds no certificates. It holds ``sources.example``, the
template of the file the bundle is built from, and this description. Two
scripts do the work:

``scripts/lota-ek-root-pin.sh``
  Walks an EK certificate up to its self-signed root and drafts a sources
  line for each certificate the bundle has to pin.

``scripts/lota-ek-roots-update.sh``
  Fetches each certificate of a sources file, refuses one whose SHA-256
  differs from its pin, and writes the bundle.

A pin is worth what its source is. The project ships none, because a
fingerprint taken over a download proves only that the download matches
itself. Check each pin against a value the manufacturer publishes apart
from the certificate.

Bundle
======

The bundle directory holds ``ek-roots.manifest`` and one PEM file per
certificate. Each manifest line that is not blank and does not start with
``#`` reads::

	<sha256>  <filename>  <class>  [label...]

``sha256``
  The SHA-256 of the certificate's DER, 64 hex characters in either case.

``filename``
  A bare file name in the directory. The file must hold exactly one PEM
  ``CERTIFICATE`` block; blocks of other types are skipped.

``class``
  ``root`` for a self-signed certificate, which anchors a chain, or
  ``intermediate`` for one that is not self-signed, which the CA builds a
  path through and never anchors at.

``label``
  Free text.

The CA refuses to start on a bundle with a missing or empty manifest, a
malformed line, a pin or file name on two lines, a missing file, a file that
does not hold exactly one certificate, a certificate whose SHA-256 is not its
pin, a ``root`` that is not self-signed or an ``intermediate`` that is, no
``root`` line, or a ``.pem`` file, in any letter case, that no line names
(``src/attestca/ca/ekbundle.go``). Files with other extensions and
subdirectories are not checked. An extra certificate therefore cannot widen
the trusted set without a manifest line.

Sources file
============

``scripts/lota-ek-roots-update.sh`` reads lines of the form::

	<sha256>  <filename>  <class>  <url>  [label...]

The URL is where the script fetches the certificate. The script refuses the
file when a line has fewer than four fields, a pin is ``REPLACE_ME`` or not
64 hex characters, a file name is not bare, is ``ek-roots.manifest``, or
appears twice, a class is neither ``root`` nor ``intermediate``, no line is
``root``, or no line is given at all. Copy ``sources.example`` and add the
lines; an unedited copy has none.

Finding the certificates to pin
===============================

Read the EK certificate from the TPM first. The RSA EK certificate is at NV
index ``0x01c00002``, the ECC one at ``0x01c0000a``. A TPM that also stores
the certificates above its EK keeps them at ``0x01c00100`` as concatenated
DER:

.. code-block:: console

	# tpm2_nvread 0x01c00002 -o ek.der
	# tpm2_nvread 0x01c00100 -o nvchain.bin

The agent sends the certificates at ``0x01c00100`` with its enrollment
request and prints their count (``EK certificate chain: %zu manufacturer
intermediate(s) from the TPM``). Then run the pin script::

	scripts/lota-ek-root-pin.sh [--nv-chain FILE] <ek-cert | -> [output-dir]

It reads the EK certificate in DER or PEM, or from standard input for ``-``.
``--nv-chain`` takes the certificates the TPM stores, as concatenated DER or
a PEM bundle. From the EK the script climbs to each issuer: first one from
the chain file whose signature verifies the certificate, otherwise the
certificate at the first ``CA Issuers`` URL of its Authority Information
Access extension, over HTTP or HTTPS. It stops at a self-signed
certificate, and fails after 10 hops, at a certificate with no issuer in the
chain file and no ``CA Issuers`` URL, or at a URL of another scheme:

.. code-block:: console

	$ scripts/lota-ek-root-pin.sh --nv-chain nvchain.bin ek.der >>sources

Standard output carries one line per certificate to pin: the root, and each
certificate the walk fetched. Another certificate from the chain file gets no
line, as the host sends it. The file name is derived from the subject. A
line for a certificate taken from the chain file or fetched over HTTP gets
``REPLACE_WITH_VENDOR_PUBLISHED_URL`` for its URL, as the update script
fetches over HTTPS alone. Comments go to standard
error, and with ``output-dir`` each certificate that gets a line is written
there as PEM.

The pins are computed over what the network returned. Check each against
the manufacturer's published value before the line goes into a sources
file.

Building the bundle
===================

.. code-block:: console

	$ scripts/lota-ek-roots-update.sh sources /var/lib/lota/ek-roots
	# lota-attest-ca -ek-root-bundle /var/lib/lota/ek-roots ...

For each line the script fetches the URL with ``curl`` over HTTPS and TLS 1.2
or later, converts the certificate from DER or PEM to PEM, and compares the
SHA-256 of its DER with the pin. Any refusal exits 1 before anything is
written into the output directory. On success it installs the manifest and every
certificate with mode 0644 and prints ``wrote %d pinned certificate(s)``.

The script writes the files it builds and removes none. A certificate
whose line was dropped stays in the directory, and when its name ends in
``.pem`` the CA refuses the bundle as unpinned; remove the file by hand.

Path material
=============

A route from an EK certificate to a root uses two sources of path
material: the certificates the host sends from ``0x01c00100``, at most 8,
and the bundle's intermediates. Neither anchors a route, so a self-signed
certificate the host sends counts for nothing. Every certificate of the route
that the host does not send needs an ``intermediate`` line. When one is
missing, enrollment fails with ``EK certificate does not chain to a trusted
manufacturer root``, and the error names the issuer the route stops at.

An ``intermediate`` line does not narrow the trust to its branch, since the
route still has to reach a ``root``. A bundled intermediate is not checked
against a CRL: the CA checks the EK certificate alone
(``src/crl/crl.go``). To stop trusting an intermediate, remove its line
and its file.

Manufacturer CRLs
=================

``-ek-crl FILE`` gives the CA a manufacturer CRL, and may be repeated. A
file holds one DER CRL or PEM blocks, of which only ``X509 CRL`` blocks are
read:

.. code-block:: console

	# lota-attest-ca -ek-root-bundle /var/lib/lota/ek-roots \
		-ek-crl /var/lib/lota/ek-crls/vendor.crl ...

Each CRL must be signed by a root or intermediate of the trust set whose
subject matches its issuer, carry ``NextUpdate``, and use RSA, RSA-PSS or
ECDSA with SHA-256, SHA-384 or SHA-512, or Ed25519. A CRL signed by an
intermediate loads only when that intermediate is bundled or given with
``-ek-root``. A CRL that fails
any of these stops the CA at start. On ``SIGHUP`` the CA reloads every CRL
and, when one fails, keeps the previous set.

Enrollment refuses an EK certificate listed in a loaded CRL with status 2,
and one whose issuer has only CRLs past ``NextUpdate`` with status 9. An
issuer with no CRL is not checked. The CRL distribution point is usually in
the EK certificate:

.. code-block:: console

	$ openssl x509 -in ek.der -inform DER -noout -ext crlDistributionPoints

The CA also refuses an EK whose RSA modulus carries the ROCA fingerprint,
with or without a CRL (``src/attestca/ca/roca.go``).
