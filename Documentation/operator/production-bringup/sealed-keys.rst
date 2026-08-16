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

The default PCR set is the platform: firmware and Secure Boot PCRs 0-7. Those
describe the machine rather than the software on it, so they cannot be
reproduced on other hardware or under other firmware -- which is the binding
at-rest sealing wants, since the threat it answers is a powered-off disk in
someone else's hands. A firmware or Secure Boot change still makes the unseal
fail closed.

**PCR 14 is deliberately not in the default set.** It is LOTA's boot
commitment, and its value is a function of the agent binary: it is stable from
boot to boot, and it moves when the agent is updated. Binding it would make
every agent upgrade destroy every sealed secret on the host, while adding
nothing against a stolen disk.

Ask for it explicitly with ``--seal-pcrs 0x40FF`` when you want a secret a
swapped agent cannot read and you accept losing it at each upgrade; pick any
other set the same way (for example ``--seal-pcrs 0xC1`` for PCRs 0, 6 and 7).

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

The sealed AIK auth is bound to the platform set, so a reboot and an agent
upgrade both recover it. That is what makes ``strict`` usable at all: were the
agent binary in the policy, a routine update would leave every host without an
AIK authorization and force a re-enrollment with every publisher.

The trade-off of ``strict``: a legitimate firmware or Secure Boot change makes
the sealed auth unrecoverable. The agent will then **not** silently rotate the
enrolled AIK; it reports the PolicyPCR mismatch and waits for an explicit
recovery. Rotate and re-seal deliberately, then re-enroll:

.. code-block:: sh

    sudo lota-agent --reprovision-aik
    sudo lota-agent --enroll --ca-server ca.example --ca-port 8444 --ca-cert ca.crt

Anti-rollback: what sealing binds, and what it does not
=======================================================

LOTA sealing binds a secret to a boot/PCR **state**, and that is the intended
contract. A few consequences worth stating plainly:

* **Replaying a recurring good state is by design.** Rebooting into the same
  expected state releases the key every time. For offline DRM and at-rest
  storage that is the whole point.
* **A different (tampered) state fails closed.** A firmware or Secure Boot
  change moves the bound PCRs and the unseal is denied. An agent change does
  not, unless the secret was sealed with the agent-bound mask above.
* **What PCR binding does** *not* **cover:** revoking an *old* secret version
  while the host can still reproduce the PCR state it was sealed against -- i.e.
  a key/version *downgrade*. PCR binding has no notion of "newer than".

LOTA core does not version or revoke sealed secrets, so it deliberately ships no
monotonic-counter machinery (NV counters are a scarce, global TPM resource, and
a compound PolicyPCR+PolicyNV path cannot be validated on the target hardware
until the hardware bring-up above). If your use case *does* need downgrade
protection, bind the secret to a TPM NV monotonic counter in addition to the
PCRs and bump the counter to revoke.

Complete, tested tpm2-tools recipe is in :ghsrc:`examples/sealed-key/anti-rollback-recipe.sh`.
