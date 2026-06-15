.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

EK manufacturer root trust bundle
=================================

The attestation CA accepts an Endorsement Key certificate only if it chains to
a TPM manufacturer root the operator trusts. Production fleets span several
manufacturers, so the trust set is a *bundle* of vendor roots.

What this directory ships is **not** vendor certificates -- it is the machinery
that turns operator-verified roots into a pin-enforced bundle:

- ``sources.example`` -- the per-vendor template: one line per root, carrying
  the SHA-256 fingerprint you verified out of band, the file it is written
  under, and where it was fetched.
- ``lota-ek-roots-update.sh`` (in ``scripts/``) -- fetches each root, refuses
  any download whose fingerprint does not match the pin you recorded, and
  writes the populated bundle directory.

The CA loads the populated bundle with ``-ek-root-bundle <dir>`` and is
**fail-closed**: every pin in the bundle manifest must resolve to a present
certificate whose SHA-256 matches, and any unpinned certificate dropped into
the directory is rejected. A swapped or injected root therefore cannot widen
the trusted manufacturer set without the change showing up as a pin edit in
version control.

Why no roots ship here
----------------------

The bundle ships empty by design. A pin is only worth anything if it was
verified **out of band** against a source the vendor controls -- a signed
advisory, a release note, a fingerprint the manufacturer publishes separately
from the download. That verification is an act the operator performs against
their own platforms; the project cannot stand in for it, and a fingerprint
computed over a blob the project happened to download is worth nothing (a man
in the middle hands you a matching pair).

Two manufacturers publish a root over a channel an operator can verify and pin
directly: **Infineon** (OPTIGA TPM root via its PKI host) and
**STMicroelectronics** (ST TPM EK root via GlobalSign, ST app note TN1330). The
others do not reduce to a single shippable anchor:

- **Intel** runs two PKIs -- the legacy discrete / early-PTT roots
  (historically at ``upgrades.intel.com``) and the `Intel OnDie
  CA <https://software.intel.com/sites/manageability/AMT_Implementation_and_Reference_Guide/default.htm?turl=WordDocuments%2FODCA.htm>`__
  used by modern CSME firmware TPM (PTT) on Tiger Lake and later. A CSME PTT EK
  cert (issuer ``CSME <SoC> PTT``) chains through the OnDie CA root
  (``https://tsci.intel.com/content/OnDieCA/certs/OnDie_CA_RootCA_Certificate.cer``),
  not the legacy root, so which root to pin depends on the platform -- walk the
  EK cert's chain to be sure.
- **AMD fTPM** and AMD-based **vTPM** EK certificates chain under Microsoft's
  TPM PKI on most platforms, not an AMD root, and many AMD fTPMs ship with no
  EK certificate in NV at all -- there is nothing to pin until you have an EK
  cert whose chain you can walk.

So the supported hardware set is not a fixed vendor list. It is **every TPM
whose EK certificate chains to a root you can verify and pin** -- which on real
platforms is determined by walking an actual EK certificate up to its
self-signed root, not by trusting a name in a table.

Finding the root for a platform
-------------------------------

Take an EK certificate from a host you mean to attest and walk its issuer chain
to the self-signed root:

.. code:: sh

   # discrete TPM / Intel PTT: the EK cert lives in TPM NV
   sudo tpm2_nvreadpublic                    # find the 0x01c0xxxx EK cert index
   sudo tpm2_nvread 0x01c00002 -o ek.der     # RSA EK (0x01c0000a = ECC)
   openssl x509 -in ek.der -inform DER -noout -issuer -ext authorityInfoAccess
   # follow each "CA Issuers" URL up until issuer == subject (the root),
   # then: openssl x509 -in root.der -inform DER -outform DER | sha256sum  # the pin

On a Windows host the chain comes from PowerShell (admin):
``Get-TpmEndorsementKeyInfo -HashAlgorithm Sha256`` exposes
``ManufacturerCertificates`` and ``AdditionalCertificates``; export each
(``[IO.File]::WriteAllBytes(...,$c.RawData)``) and walk the same way.

``scripts/lota-ek-root-pin.sh`` automates the walk: hand it the EK certificate
and it follows the AIA chain to the self-signed root, then prints the root PEM
and a ready sources line carrying the root's SHA-256:

.. code:: sh

   sudo tpm2_nvread 0x01c00002 -o ek.der
   scripts/lota-ek-root-pin.sh ek.der
   # de0e...99b  acme-tpm-root-ca.pem  https://...  Acme TPM Root CA

The pin it prints is over what the network returned -- it does **not** vouch
for it. The pin you record is the SHA-256 over the root's DER **after** you
have confirmed that root against the vendor's published value -- never the
value the download alone hands you.

Provisioning a bundle
---------------------

1. Copy the template and add one line per root your fleet's EK certificates
   chain to -- ``lota-ek-root-pin.sh`` drafts a line from a platform's EK
   certificate. Fill each ``pin`` with the SHA-256 you verified out of band (a
   vendor advisory, a signed release note -- never the download itself):

   .. code:: sh

      cp sources.example sources
      scripts/lota-ek-root-pin.sh ek.der >>sources   # draft a line, then verify its pin
      $EDITOR sources

2. Materialize the bundle. The tool downloads each root, re-checks its
   fingerprint against your pin, and fails closed on any mismatch:

   .. code:: sh

      scripts/lota-ek-roots-update.sh sources /var/lib/lota/ek-roots

3. Point the CA at it:

   .. code:: sh

      lota-attest-ca -ek-root-bundle /var/lib/lota/ek-roots ...

Intermediate CAs
----------------

Real manufacturer EK PKIs are commonly three-level: the EK leaf is issued by an
intermediate CA which in turn chains to the self-signed root. The enroll wire
carries only the leaf (a TPM NV index holds a single certificate, so the agent
has nothing else to send), which means the CA can only build that chain from
material the operator loaded: **the bundle must include every intermediate that
issues your fleet's EK certificates**, pinned in the manifest exactly like a
root. Loaded intermediates serve both as path material (a leaf issued by a
bundled intermediate verifies up to the bundled root) and as trust anchors in
their own right -- pinning only the intermediate is a deliberate narrowing that
trusts one manufacturer branch instead of everything under the root.

The AIA walk that finds the root passes through each intermediate on the way
(``lota-ek-root-pin.sh`` follows the same chain); record a manifest line for
every CA certificate on the path, not just the final self-signed one. A missing
intermediate surfaces as an ``ErrEKChain`` rejection on genuine hardware. The
manufacturer CRL feed (below) has the same dependency: CRLs covering EK leaves
are signed by the issuing intermediate, so the feed loads only when that
intermediate is bundled.

Updating
--------

Adding, removing, or rotating a vendor root is a manifest edit: change the
relevant line in ``sources``, re-run ``lota-ek-roots-update.sh``, and commit
the resulting fingerprint change. Because the CA pins every root, the diff in
the manifest is the audit trail for any change to the trusted set.

A vendor that rotates its root publishes the new fingerprint; record it as a
new line (keep the old one until every host with the older EK is retired so
both chains keep verifying through the overlap).

Manufacturer CRLs
-----------------

Root bundle without the matching revocation feed is half a trust anchor:
manufacturers revoke EK certificates in bulk (the ROCA / CVE-2017-15361
advisory revoked millions of Infineon EKs whose private key is recoverable from
the public modulus), and an EK with a recoverable key lets a software attacker
complete credential activation without any TPM. Pass each manufacturer CRL to
the CA with ``-ek-crl <file>`` (repeatable; PEM or DER, a file may bundle
several PEM blocks):

.. code:: sh

   lota-attest-ca -ek-root-bundle /var/lib/lota/ek-roots \
       -ek-crl /var/lib/lota/ek-crls/infineon.crl ...

Each CRL must be signed by a certificate present in the loaded EK trust set;
manufacturers that issue EK certificates through an intermediate CA sign their
CRLs with that intermediate, so the intermediate must be part of the bundle for
the feed to load.

The CA fails closed at startup on a CRL that does not verify, omits
``NextUpdate``, or uses a weak signature algorithm, and an issuer whose every
loaded CRL is past ``NextUpdate`` is refused at enrollment time.

An issuer with no configured CRL is accepted (standard RFC 5280 semantics) --
ship the feed for every manufacturer that publishes one.

Independently of any CRL, the CA rejects an EK whose RSA modulus carries the
ROCA fingerprint itself -- the weakness is intrinsic to the key, so a lagging
or unconfigured feed does not reopen that hole.

Refresh a feed by rewriting the file atomically and sending the daemon SIGHUP;
a refresh that fails validation keeps the previous set active. The CRL
distribution point is usually listed in the EK certificate's
``crlDistributionPoints`` extension
(``openssl x509 -in ek.der -inform DER -noout -ext crlDistributionPoints``).
