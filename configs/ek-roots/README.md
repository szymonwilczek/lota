# EK manufacturer root trust bundle

The attestation CA accepts an Endorsement Key certificate only if it chains
to a TPM manufacturer root the operator trusts. Production fleets span
several manufacturers, so the trust set is a *bundle* of vendor roots.

What this directory ships is **not** vendor certificates -- it is the
machinery that turns operator-verified roots into a pin-enforced bundle:

- `sources.example` -- the per-vendor template: one line per root, carrying
  the SHA-256 fingerprint you verified out of band, the file it is written
  under, and where it was fetched.
- `lota-ek-roots-update.sh` (in `scripts/`) -- fetches each root, refuses
  any download whose fingerprint does not match the pin you recorded, and
  writes the populated bundle directory.

The CA loads the populated bundle with `-ek-root-bundle <dir>` and is
**fail-closed**: every pin in the bundle manifest must resolve to a present
certificate whose SHA-256 matches, and any unpinned certificate dropped
into the directory is rejected. A swapped or injected root therefore cannot
widen the trusted manufacturer set without the change showing up as a pin
edit in version control.

## Why no roots ship here

The bundle ships empty by design. A pin is only worth anything if it was
verified **out of band** against a source the vendor controls -- a signed
advisory, a release note, a fingerprint the manufacturer publishes
separately from the download. That verification is an act the operator
performs against their own platforms; the project cannot stand in for it,
and a fingerprint computed over a blob the project happened to download is
worth nothing (a man in the middle hands you a matching pair).

Two manufacturers publish a root over a channel an operator can verify and
pin directly: **Infineon** (OPTIGA TPM root via its PKI host) and
**STMicroelectronics** (ST TPM EK root via GlobalSign, ST app note TN1330).
The others do not reduce to a single shippable anchor:

- **Intel** runs two PKIs -- the legacy discrete / early-PTT roots
  (historically at `upgrades.intel.com`) and the
  [Intel OnDie CA](https://software.intel.com/sites/manageability/AMT_Implementation_and_Reference_Guide/default.htm?turl=WordDocuments%2FODCA.htm)
  used by modern CSME firmware TPM (PTT) on Tiger Lake and later. A CSME PTT
  EK cert (issuer `CSME <SoC> PTT`) chains through the OnDie CA root
  (`https://tsci.intel.com/content/OnDieCA/certs/OnDie_CA_RootCA_Certificate.cer`),
  not the legacy root, so which root to pin depends on the platform -- walk
  the EK cert's chain to be sure.
- **AMD fTPM** and AMD-based **vTPM** EK certificates chain under
  Microsoft's TPM PKI on most platforms, not an AMD root, and many AMD
  fTPMs ship with no EK certificate in NV at all -- there is nothing to pin
  until you have an EK cert whose chain you can walk.

So the supported hardware set is not a fixed vendor list. It is **every TPM
whose EK certificate chains to a root you can verify and pin** -- which on
real platforms is determined by walking an actual EK certificate up to its
self-signed root, not by trusting a name in a table.

## Finding the root for a platform

Take an EK certificate from a host you mean to attest and walk its issuer
chain to the self-signed root:

```sh
# discrete TPM / Intel PTT: the EK cert lives in TPM NV
sudo tpm2_nvreadpublic                    # find the 0x01c0xxxx EK cert index
sudo tpm2_nvread 0x01c00002 -o ek.der     # RSA EK (0x01c0000a = ECC)
openssl x509 -in ek.der -inform DER -noout -issuer -ext authorityInfoAccess
# follow each "CA Issuers" URL up until issuer == subject (the root),
# then: openssl x509 -in root.der -inform DER -outform DER | sha256sum  # the pin
```

On a Windows host the chain comes from PowerShell (admin):
`Get-TpmEndorsementKeyInfo -HashAlgorithm Sha256` exposes
`ManufacturerCertificates` and `AdditionalCertificates`; export each
(`[IO.File]::WriteAllBytes(...,$c.RawData)`) and walk the same way.

The pin you record is the SHA-256 over the root's DER **after** you have
confirmed that root against the vendor's published value -- never the value
the download alone hands you.

## Provisioning a bundle

1. Copy the template and add one line per root your fleet's EK certificates
   chain to. Fill each `pin` with the SHA-256 you verified out of band (a
   vendor advisory, a signed release note -- never the download itself):

   ```sh
   cp sources.example sources
   $EDITOR sources
   ```

2. Materialize the bundle. The tool downloads each root, re-checks its
   fingerprint against your pin, and fails closed on any mismatch:

   ```sh
   scripts/lota-ek-roots-update.sh sources /var/lib/lota/ek-roots
   ```

3. Point the CA at it:

   ```sh
   lota-attest-ca -ek-root-bundle /var/lib/lota/ek-roots ...
   ```

## Updating

Adding, removing, or rotating a vendor root is a manifest edit: change the
relevant line in `sources`, re-run `lota-ek-roots-update.sh`, and commit the
resulting fingerprint change. Because the CA pins every root, the diff in
the manifest is the audit trail for any change to the trusted set.

A vendor that rotates its root publishes the new fingerprint; record it as a
new line (keep the old one until every host with the older EK is retired so
both chains keep verifying through the overlap).
