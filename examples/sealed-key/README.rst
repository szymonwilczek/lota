.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

Sealed keys - offline local attestation
=======================================

Remote attestation proves a host's state to a verifier over the network.
**Sealing** is the local counterpart: the TPM releases a secret only when the
host booted into the expected state, with no verifier round-trip. It is the
building block for single-player / offline DRM and for hardening key storage at
rest.

A sealed blob is inert: it is useless on a different machine, and useless on
the same machine booted into a different (tampered) state. The TPM enforces
this - it is a local boundary, **not** a replacement for remote attestation in
competitive multiplayer, where the attacker owns the box and can simply read
the unsealed secret out of the running game.

How it works
------------

``lota-agent --seal`` wraps a secret (≤ 128 bytes, read from stdin) as a TPM
keyed-hash object whose authorization policy is a PolicyPCR digest over the
selected PCRs. ``lota-agent --unseal`` recreates the same deterministic storage
primary, loads the object, and unseals it over a salted, response-encrypted
policy session. If the current PCRs differ from the seal-time values, the
policy no longer matches and the unseal fails closed.

Large payloads (envelope mode)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

``TPM2_Seal`` bounds the sensitive data it can wrap, so a direct seal caps at
128 bytes. For a larger payload (<= 64 KiB) - an asset blob, a bundle of
per-title keys, a small save file - ``--seal`` automatically switches to an
**envelope**: it seals a fresh random AES-256 key (the KEK) to the PCR state
through the same PolicyPCR path, then encrypts the payload under the KEK with
AES-256-GCM. The TPM still gates release of the KEK, so the envelope inherits
the exact same boot/PCR binding. The header and the sealed-KEK blob are bound
in as additional authenticated data, so a tampered envelope fails the GCM tag
instead of returning corrupt data. ``--unseal`` detects the envelope from its
magic; no extra flag is needed.

The default PCR set is the firmware/kernel boot PCRs 0–7 plus LOTA's PCR14
boot-commitment, so a firmware, kernel, or agent change invalidates the seal.
Override it with ``--seal-pcrs MASK``.

.. code:: sh

   # Seal a per-title key to the current boot state (root; TPM-backed).
   printf '%s' "$PER_TITLE_KEY" | sudo lota-agent --seal > title.sealed

   # Later, in the same boot state, recover it:
   sudo lota-agent --unseal < title.sealed

Run the demo
------------

``seal-demo.sh`` runs the full round-trip and proves the fail-closed property
by sealing to a PCR it then extends. It needs a working TPM, ``tpm2-tools``,
and root. Point ``AGENT`` at your built binary:

.. code:: sh

   sudo AGENT=/var/tmp/lota-build/lota-agent examples/sealed-key/seal-demo.sh

Expected output ends with:

::

   ==> 2. Unseal it back (same boot state -> succeeds)
       RESULT: OK - recovered the key
   ==> 3. Bind to a single PCR, then change it -> unseal must fail
       RESULT: SEALED SHUT - unseal failed closed after the state changed
   ==> 4. Seal a large payload (> 128 B) via the AES-256-GCM envelope
       RESULT: OK - large payload round-trips through the envelope
       RESULT: AUTHENTICATED - tampered envelope rejected (GCM tag)

The script seals step 3 to PCR 16 (the resettable debug PCR) only so it can
move the state without a reboot; production seals to the default 0–7 + PCR14
set, where the equivalent "state change" is a firmware, kernel, or agent
update.

Performance: persisting the storage primary
-------------------------------------------

By default each ``--seal`` / ``--unseal`` derives its TPM storage primary on
the fly with ``CreatePrimary``. That is stateless and consumes no persistent
slot, but it costs one key derivation per call. A host that seals or unseals
often can persist the primary once:

.. code:: sh

   sudo lota-agent --seal-persist-primary

and set ``seal_persistent_primary = true`` in ``lota.conf``. The seal path then
reuses the persistent object at handle ``0x81010003`` and skips the per-op
``CreatePrimary``. The derived and the persisted primaries are byte-identical
(same owner hierarchy, same fixed template), so **blobs sealed either way stay
interchangeable** - persisting or evicting never invalidates existing sealed
data. Remove it with:

.. code:: sh

   sudo lota-agent --seal-evict-primary

If you leave ``seal_persistent_primary = false`` (the default), seal/unseal
ignore any persisted object and keep deriving per op — the intended behaviour
for hosts that seal rarely.

Anti-rollback: the binding contract
-----------------------------------

A sealed blob is bound to a boot/PCR **state**, not to a version. This is the
intended contract, and it has a deliberate edge:

- Booting the same expected state always releases the key - replaying a
  recurring *good* state is by design (your offline key must work every boot),
  **not** a rollback hole.
- A different / tampered state fails closed.
- PCR binding has no notion of "newer than", so it does **not** stop a
  *downgrade*: revoking an old secret version while the host can still
  reproduce the PCR state it was sealed against.

LOTA core does not version or revoke sealed secrets, so it ships no
monotonic-counter machinery - NV counters are a scarce global TPM resource and
add a compound-policy path with no consumer in the core. If your use case
genuinely needs downgrade protection, bind the secret to a TPM NV monotonic
counter *in addition* to the PCRs and bump the counter to revoke.
```anti-rollback-recipe.sh`` <anti-rollback-recipe.sh>`__ is a complete, tested
tpm2-tools recipe that seals under ``PolicyPCR AND PolicyNV(counter <= now)``
and shows the secret failing closed after the counter advances:

.. code:: sh

   sudo anti-rollback-recipe.sh      # or, on swtpm, with TPM2TOOLS_TCTI set

It ends with:

::

   ==> Unseal while the counter is unchanged (must recover)
       RESULT: OK - recovered the secret in-policy
   ==> Unseal after the bump (must fail closed)
       RESULT: REVOKED - unseal failed closed after the counter advanced

Hardening the agent's AIK auth
------------------------------

The same primitive backs an opt-in at-rest hardening of the agent's own AIK
userAuth. Enabling ``seal_aik_auth_strict`` in ``lota.conf`` stores the auth
only sealed to the boot state, so a captured disk no longer yields it even to
an attacker holding the same TPM. See the "Sealed keys" section of
```Documentation/operator/production-bringup/index.rst`` <../../Documentation/operator/production-bringup/index.rst>`__.
