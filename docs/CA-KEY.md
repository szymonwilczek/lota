# Attestation CA signing key: ceremony, rotation, topology

Attestation CA's signing key is the trust anchor every issued AIK
certificate chains to, and every verifier pins it (`--aik-ca-cert`). It is
the highest-value secret in a LOTA deployment: whoever can sign with it can
mint an AIK certificate the whole fleet trusts. Treat it accordingly --
keep it in an HSM (see [`PRODUCTION_BRINGUP.md`](PRODUCTION_BRINGUP.md), "CA
signing key in an HSM"), never on a daily-driver host, and gate access to
it.

How `lota-attest-ca` loads the key is covered in the bring-up guide; this
document is the key-lifecycle reference: the generation ceremony, rotation,
and the offline-root / online-intermediate topology.

## Key ceremony

The goal of the ceremony is a CA key that no single person can exfiltrate
and that is bound to a certificate before it ever signs.

1. **Generate in the HSM, non-exportable.** Create the key pair inside the
   HSM so the private key has no plaintext form outside the device. Do not
   import a software-generated key unless an offline ceremony requires it
   (then generate on an air-gapped host and import under wrap). Record the
   public key.
2. **Dual control.** Initialise the token and generate the key under at
   least two-person control (split SO/user PINs or the HSM's quorum/M-of-N
   authorisation). No one person should hold both the token authorisation
   and physical access.
3. **Bind a certificate.** Issue the CA certificate from the key (the HSM
   signs its own certificate request) before the key signs anything else.
   `lota-attest-ca` checks the token key against this certificate at startup
   and refuses to run on a mismatch.
4. **Back up under wrap.** Follow the HSM's backup procedure (wrapped-key
   export to a backup HSM, or a quorum-encrypted blob). A CA key with no
   backup is a single hardware failure away from re-enrolling the fleet.
5. **Audit.** Keep the HSM audit log: every use of the key, every
   authorisation. The CA itself logs each start and the key source.

## Rotation

Issued AIK certificates are short-lived (`-aik-cert-ttl`, default 24h) and
hosts re-enroll before expiry, so rotating the CA key does **not** require
touching every host at once -- it requires the fleet's verifiers to trust
the new CA key, then a re-enrollment pass within one certificate lifetime.

1. Stand up the new CA key and certificate (a fresh ceremony as above).
2. Distribute the new CA certificate to every verifier. `--aik-ca-cert` is
   repeatable, so during the overlap a verifier trusts **both** the old and
   the new CA certificate and accepts AIK certificates from either.
3. Re-enroll hosts against the new CA (the agent's guided `--reenroll`).
   Within one `-aik-cert-ttl` window every live host holds an AIK certificate
   signed by the new key.
4. Drop the old CA certificate from the verifiers once no unexpired AIK
   certificate was issued by the old key.

A *compromised* CA key is a faster path: stop the CA, drop the old CA
certificate from verifiers immediately (every AIK it signed is now
untrusted), and re-enroll the fleet against a new key. Individual
compromised AIK certificates are revoked out of band with `--ek-crl`
without a full CA rotation.

## Offline root, online intermediate

The online `lota-attest-ca` is reachable and signs continuously, so its key
is the more exposed one. A two-tier PKI bounds that exposure: keep a **root
CA key offline** (an air-gapped HSM, used only at ceremonies) and have it
issue an **intermediate CA certificate** to the online CA.

- The intermediate key lives in the online CA's HSM; `lota-attest-ca` runs
  with `-ca-cert` set to the intermediate certificate and signs AIK leaves
  with the intermediate key. `NewIssuer` accepts any `CA:TRUE` certificate,
  so an intermediate works as the CA certificate without code changes.
- Verifiers pin the **intermediate** certificate with `--aik-ca-cert`. The
  verifier trusts each pinned certificate directly (it does not chain an AIK
  through an unpinned root), so the certificate the online CA signs with is
  the one to pin, not the offline root.
- To rotate the online tier, the offline root issues a **new** intermediate;
  deploy its certificate to the verifiers (pin both during the overlap, as
  in rotation above) and move the online CA to the new intermediate key. The
  offline root key never goes online, so compromising the online host costs
  an intermediate, not the fleet's root of trust.

A single-tier deployment (the online CA holds a self-signed root) is simpler
and fine for a small fleet; the two-tier topology is the option to reach for
when the online CA's exposure is the concern an enterprise PKI review raises.
