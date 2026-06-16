.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

=======================================
Sealed keys (offline local attestation)
=======================================

Remote attestation proves state to a verifier over the network. Sealing is the
local counterpart: the TPM releases a secret only when the host booted into the
expected state, with no verifier round-trip. It is a local boundary the TPM
enforces -- useful for single-player / offline DRM and for at-rest key storage
-- but it does **not** replace remote attestation for competitive multiplayer,
where the attacker owns the box.

Seal a secret to the current boot state and recover it later:

.. code-block:: sh

    # Seal: secret in on stdin, sealed blob out on stdout (root only).
    printf '%s' "$PER_TITLE_KEY" | sudo lota-agent --seal > title.sealed

    # Unseal: only succeeds when the host is in the sealed PCR state.
    sudo lota-agent --unseal < title.sealed

The default PCR set is firmware/kernel PCRs 0-7 plus LOTA's PCR14
boot-commitment, so a firmware, kernel, or agent change makes the unseal fail
closed. Pick a different set with ``--seal-pcrs MASK`` (for example
``--seal-pcrs 0xC1`` for PCRs 0, 6, 7) when you want the secret to survive agent
upgrades.

To harden the agent's own AIK userAuth at rest, enable sealing in ``lota.conf``:

.. code-block:: ini

    seal_aik_auth = true          # keep a sealed copy, prefer it on load
    seal_aik_auth_strict = true   # store ONLY sealed; no plaintext on disk

``strict`` removes the plaintext sidecar, so a captured disk no longer yields
the AIK auth even to an attacker with the same TPM in a different boot state.
Leave both keys at their default ``false`` to keep the existing
plaintext-sidecar behaviour.

An already-enrolled host adopts sealing without re-enrolling:

.. code-block:: sh

    # Set the keys in lota.conf, then seal the current auth in place:
    sudo lota-agent --seal-aik-auth

The trade-off of ``strict``: a legitimate firmware/kernel/agent change makes the
sealed auth unrecoverable. The agent will then **not** silently rotate the
enrolled AIK; it reports the PolicyPCR mismatch and waits for an explicit
recovery. Rotate and re-seal deliberately, then re-enroll:

.. code-block:: sh

    sudo lota-agent --reprovision-aik
    sudo lota-agent --enroll --ca-server ca.example --ca-port 8444 --ca-cert tls.crt

Anti-rollback: what sealing binds, and what it does not
=======================================================

LOTA sealing binds a secret to a boot/PCR **state**, and that is the intended
contract. A few consequences worth stating plainly:

* **Replaying a recurring good state is by design.** Rebooting into the same
  expected state releases the key every time. For offline DRM and at-rest
  storage that is the whole point.
* **A different (tampered) state fails closed.** A firmware, kernel, or agent
  change moves the bound PCRs and the unseal is denied.
* **What PCR binding does** *not* **cover:** revoking an *old* secret version
  while the host can still reproduce the PCR state it was sealed against -- i.e.
  a key/version *downgrade*. PCR binding has no notion of "newer than".

LOTA core does not version or revoke sealed secrets, so it deliberately ships no
monotonic-counter machinery (NV counters are a scarce, global TPM resource, and
a compound PolicyPCR+PolicyNV path cannot be validated on the target hardware
until the hardware bring-up above). If your use case *does* need downgrade
protection, bind the secret to a TPM NV monotonic counter in addition to the
PCRs and bump the counter to revoke.

Complete, tested tpm2-tools recipe is in `examples/sealed-key/anti-rollback-recipe.sh <https://github.com/szymonwilczek/lota/blob/main/examples/sealed-key/anti-rollback-recipe.sh>`__.
