.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

===========
Sealed keys
===========

A sealed secret is one the TPM releases only while chosen PCRs hold the
values they held when it was sealed. The check runs on the host, with no
verifier. ``lota-agent`` seals two kinds of secret: one an operator hands it
with ``--seal``, and the authorization of its own attestation keys. The
objects and blob formats are described in :doc:`../../agent/tpm`.

Sealing a secret
================

``--seal`` reads the secret from standard input and writes the blob to
standard output; ``--unseal`` does the reverse:

.. code-block:: sh

   printf '%s' "$TITLE_KEY" | sudo lota-agent --seal > title.sealed
   sudo lota-agent --unseal < title.sealed

A secret of up to 128 bytes is sealed whole. One of up to 64 KiB is
encrypted with AES-256-GCM under a random key, and that key is sealed; the
blob is then an envelope. An empty secret is refused. On success the
command reports the sizes on standard error, with ``(envelope)`` after an
envelope::

   Sealed <N>-byte secret to a <M>-byte blob.

The blob opens only on the TPM that sealed it. Another TPM refuses to load
it, whatever its PCRs hold, and the unseal fails as for a damaged blob
(`A refused unseal`_).

Choosing the PCRs
=================

``--seal-pcrs MASK`` selects the PCRs, bit *n* for PCR *n*, in C notation.
The mask is not empty and names no PCR above 23
(:doc:`../../agent/command-line`).

``0x83``, the default
  PCRs 0, 1 and 7: the firmware, its configuration and the Secure Boot
  state. A firmware update or a Secure Boot change makes the secret
  unreadable. A kernel update does not, as PCR 4 is left out.

``0x4083``
  Adds PCR 14, the agent's boot commitment. An agent update then makes the
  secret unreadable too. The mask binds a boot state, not a process: any
  process with access to the TPM unseals while the registers match.

A secret sealed to a PCR that changes from boot to boot opens only in the
boot that sealed it.

A refused unseal
================

``--unseal`` checks the blob's framing before it opens the TPM, and names
the field it refuses::

   Not a sealed blob this build can read: the declared bodies do not fill
   the file exactly (1300, expected 1301).

The other reasons are a file shorter than the header, a foreign magic, an
unknown version, a set reserved byte, an empty or out-of-range PCR
selection, a digest algorithm other than SHA-256, and a body length out of
range. Each is a fault of the file: a cut transfer, a truncated copy, or a
blob from a build with another format.

When the TPM refuses to load the blob, or refuses to unseal it while the
PCRs still hold their seal-time values, the blob itself is at fault::

   Unseal failed: Bad message
   (the blob is damaged, or was sealed on another TPM)

Any other refusal is followed by a line pointing at the boot state. A PCR
that moved since the seal reads::

   Unseal failed: TPM policy not satisfied
   (the host may not be in the sealed boot state)

The secret comes back once the host boots into the sealed state again. A
firmware or Secure Boot change that stays has no way back; seal the secret
anew from its source.

Attestation key authorization
=============================

Each attestation key has a 32-byte authorization value, kept in plaintext in
``aik_auth.dat`` beside the key's record (:doc:`../../agent/tpm`). Two
configuration keys seal it to PCRs 0, 1 and 7
(:doc:`../../agent/configuration`):

``seal_aik_auth = true``
  Writes ``aik_auth.sealed`` beside the plaintext file and reads the sealed
  copy first. When the sealed copy does not open, the agent reads the
  plaintext file, so a firmware update leaves the host attesting.

``seal_aik_auth_strict = true``
  Writes the sealed copy and removes the plaintext file. The agent reads
  only the sealed copy, so a captured disk does not yield the value.

Both default to false. With both off, writing an authorization removes an
``aik_auth.sealed`` left from an earlier setting, so turning sealing back on
does not seal an old value. The mask leaves PCR 14 out, so an agent update
keeps the authorization readable. Sealing protects the value, not the key: the
authorization is no input to the key's derivation, so a local root can
create the same key with an authorization of its own.

Adopting sealing
----------------

The keys take effect for authorizations written afterwards. To seal the
ones a host already holds, set them and run:

.. code-block:: sh

   sudo lota-agent --seal-aik-auth

It seals the authorization of every publisher's key, or of the host key on
a host with no publishers, and reports the count, then reads the disk back
to count the plaintext copies left::

   Sealed the authorization of 3 attestation keys to the platform state.
   3 still keep a plaintext copy beside the sealed one; set
   seal_aik_auth_strict to drop them.

A key whose sealed copy opens is sealed again and counted, so a second run
on a strict host reports the count followed by::

   No plaintext copy remains on disk.

A key that could not be sealed, the host key included, is named with the
error and the state its authorization is in, and the command exits 1. When
that state is sealed with no plaintext copy and the TPM refused the sealed
copy, a second line says the sealed copy did not open and names
``--reprovision-aik`` (`After a boot-state change`_).

Auditing
--------

``--list-publishers`` prints a ``key auth`` line per publisher, read from the
two files without the TPM:

``sealed to the platform state, no plaintext copy``
  Strict: the only state a captured disk does not give away.

``sealed, and a plaintext copy is kept beside it``
  ``seal_aik_auth`` without strict, or sealing adopted before strict was set.

``plaintext on disk, not sealed``
  Sealing is off, or was turned on after the value was written and
  ``--seal-aik-auth`` was not run.

``none stored``
  No authorization on disk.

After a boot-state change
-------------------------

Without strict, a firmware or Secure Boot change leaves the sealed copy
unreadable and the agent reads the plaintext file. Run ``--seal-aik-auth``
to seal the value to the new state.

With strict there is no other copy, and the agent refuses the key at start
with ``SECURITY:`` lines naming the cause and the sealed file. Draw a new
authorization:

.. code-block:: sh

   sudo lota-agent --reprovision-aik

It replaces the authorization of every key the host attests with and
writes each one sealed. It then compares each enrolled publisher's key with
the certificate stored for it, and the host key's TPM Name with the one
before. The key derives from the TPM's seed and the publisher's template,
so it is normally the same key, and the command ends::

   No certificate is stale: each still names the key it was issued over.

The certificates stay valid and no re-enrollment is needed. Then start
``lota-agent.service`` again. Only when a certificate names another key
does the command print ``Their certificates are now stale -- re-enroll
each:`` followed by a ``lota-agent --reenroll --publisher`` command for
each such publisher, and ``lota-agent --enroll`` when the host key's Name
changed. An enrolled publisher whose certificate is missing or cannot be
read is listed under ``could not be checked:`` with the reason, and the
``No certificate is stale`` line is not printed.

An unreadable authorization
===========================

The agent creates a new authorization at start only when the key exists and
no record of its authorization does: neither ``aik_auth.dat`` nor
``aik_auth.sealed``. A record that exists and does not load, at a version
this build does not read, too short, or sealed and not opening, leaves the
key as it is and stops with::

   SECURITY: the attestation key's authorization could not be read
   (<cause>). The key is left as it is.

The next lines give the magic and version the plaintext record holds
beside the ones this build reads, and whether the sealed copy is present.
Restore the record from a backup, or run ``--reprovision-aik``
(`After a boot-state change`_). It does not read the old authorization: it
gives the same key a new one, and the key's certificate stays valid.

When sealing is on and the plaintext record has no sealed copy beside it,
the last line names ``--seal-aik-auth`` instead, to seal the record the host
already has.

What sealing does not cover
===========================

A secret opens every time the host boots into the state it was sealed to.
Sealing has no notion of a newer secret, so an old blob still opens while
the host can reproduce its PCR state; the agent neither versions nor
revokes sealed secrets. A secret that must be revocable needs a TPM NV
monotonic counter in its policy beside the PCRs, bumped to revoke.
:ghsrc:`examples/sealed-key/anti-rollback-recipe.sh` builds one with
``tpm2-tools`` (:ghsrc:`examples/sealed-key/README.rst`).
