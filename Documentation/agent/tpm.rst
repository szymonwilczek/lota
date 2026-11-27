.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

===
TPM
===

The agent requires a TPM 2.0. It reaches the chip through the kernel's
resource manager, ``/dev/tpmrm0``, with the TSS2 ESYS library; the code is
:ghsrc:`src/agent/tpm.c` and :ghsrc:`src/agent/tpm.h`.

.. list-table::
   :header-rows: 1
   :widths: 24 20 56

   * - Device
     - Use
     - Notes
   * - Firmware TPM
     - Supported
     - Shares its persistent-object space with everything else on the
       machine that persists keys.
   * - Discrete TPM
     - Supported
     - The same interface over a separate chip; the agent does not tell the
       two apart.
   * - swTPM
     - Development
     - Fresh state on every start and no lockout, so it says nothing about
       capacity or lockout on a real chip (:doc:`../dev-tools/vm-testing`).

``LOTA_TCTI`` names another TCTI and ``LOTA_AIK_META_PATH`` another host AIK
record. The one-shot verbs and an ``--attest`` that sends one report read
them; the daemon and the ``--attest`` loop do not (:doc:`command-line`).

Handles
=======

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Handle
     - Content
   * - ``0x01c00002``
     - NV index: the EK certificate. Required for enrollment.
   * - ``0x01c00100``
     - NV index: the chain of manufacturer intermediates. Optional.
   * - ``0x81010001``
     - The EK, when the platform persists it. Without it the agent creates
       the EK from the TCG default template for each use.
   * - ``0x81010002``
     - The host AIK, or the handle ``aik_handle`` names
       (:doc:`configuration`). It signs when no publisher profile binds.
   * - ``0x81010003``
     - The seal storage primary, when ``--seal-persist-primary`` stored it.
   * - ``0x81010010`` to ``0x81010017``
     - The AIKs of the publishers, one per publisher (:doc:`publishers`).

NV indices are read in chunks of ``TPM2_PT_NV_BUFFER_MAX`` with owner
authorization.

Attestation keys
================

An AIK is an RSA 2048 primary key of the owner hierarchy: restricted,
signing, ``fixedTPM``, ``fixedParent``, ``sensitiveDataOrigin``,
``userWithAuth``, scheme RSASSA with SHA-256. A publisher's AIK carries the
publisher's identity in the ``unique`` field of its template; the host AIK
carries none. The TPM derives a primary key from its owner seed and the
template, so the same publisher gets the same key back until the owner
hierarchy is cleared, and the keys of two publishers differ. The
authorization value does not enter the derivation.

The agent stores each key with ``EvictControl`` at its handle. A publisher's
handle is the first one in the range that no profile records and the TPM
holds no object at; it is written to the profile's ``aik_handle`` file and
read from there afterwards. An object at a handle in the range that no
profile records is never evicted.

Authorization
-------------

Every AIK has a random 32-byte authorization value, kept beside the key's
``aik_meta.dat``:

``aik_auth.dat``
  The value in plaintext, mode 0600, written to a temporary file, synced and
  renamed into place.

``aik_auth.sealed``
  The value sealed to PCRs 0, 1 and 7 (`Sealing`_). Written when
  ``seal_aik_auth`` or ``seal_aik_auth_strict`` is set.

``seal_aik_auth`` keeps both files and reads the sealed one first.
``seal_aik_auth_strict`` removes the plaintext file and reads the sealed one
alone, so a change of boot state locks the key until ``--reprovision-aik``.
``--list-publishers`` prints which of the states holds for each key: sealed
with no plaintext copy, sealed with a plaintext copy, plaintext only, or none
stored.

Provisioning
------------

At startup and at enrollment the agent provisions the key of the bound
profile:

* No object at the handle: it creates the key with a fresh authorization.
* An object and an authorization that loads: it uses them.
* An object and no authorization record: it evicts the object, creates the
  key again with a fresh authorization and stores both.
* An object and an authorization record that does not load, or fails for a
  reason other than its absence: it reports ``SECURITY:`` with the cause and
  refuses, and leaves the key in place. The message names
  ``--seal-aik-auth``, or restoring the record or ``--reprovision-aik``,
  which gives the same key a new authorization.

A publisher whose record says its key is the shared host key is refused
until it gets a key of its own: the daemon logs once that the key matches
the other publishers' byte for byte and names
``lota-agent --reenroll --publisher ID``, and no round runs for it.
``--enroll`` replaces such a key.

When the TPM rejects an authorization value for a quote, the agent
remembers the value with the key's name. The next quote reads the stored
value again and presents it only when it is another one, so a wrong value
costs one dictionary-attack attempt and no more; a key created again at the
handle is a key of its own.

Rotating the authorization
--------------------------

``--seal-aik-auth`` seals the authorization of every publisher's key to the
current boot state, and the host AIK's when no publisher is configured. It
reports how many keys still keep a plaintext copy beside the sealed one and
any key it could not seal. With sealing off, writing an authorization
removes a sealed copy left from before, so turning sealing back on does not
seal an old value. Copies that already hold different values stay so, and
the key fails its authorization; ``--reprovision-aik`` replaces both with
a new value.

``--reprovision-aik`` replaces the authorization of every key: it draws a
value, evicts the object, creates the key again and stores it with the
value. As the value does not enter the derivation, the key is the same, and
the command says so. It compares each enrolled publisher's key with the
certificate stored for it and lists ``--reenroll --publisher`` for each
publisher whose certificate names another key; the host key, which has no
stored certificate, gets ``--enroll`` when its name changed across the
rotation. A missing or unreadable certificate is listed as not checked,
with the reason. A key created where none was is counted as an
authorization rotated, not as a key moved.

Enrollment
==========

Enrollment proves to a publisher's CA that the AIK lives in the same TPM as
an EK the manufacturer certified (:ghsrc:`src/agent/enroll_client.c`). The
agent opens the session with the CA before it touches the TPM, so a CA that
cannot be reached leaves no key created or replaced and no certificate
written.

#. It reads the EK certificate; without one the CA cannot anchor the TPM and
   the agent stops. It reads the intermediate chain when present.
#. It binds the profile's handle and provisions the AIK.
#. It sends the EK certificate, the chain and the AIK's ``TPMT_PUBLIC``.
#. The CA answers with a credential bound to the AIK's name and encrypted to
   the EK. A CA that refuses the enrollment token, or demands one the agent
   does not present, ends the enrollment here.
#. ``ActivateCredential`` recovers the secret: the AIK under its
   authorization, the EK in a policy session satisfied with
   ``PolicySecret(TPM_RH_ENDORSEMENT)``. Only the TPM that holds both keys
   can do this.
#. The agent returns the secret and receives the AIK certificate.

The certificate's subject is a device pseudonym the CA derives from the EK
under its own secret. The EK survives a clear of the owner hierarchy, so a
host enrolled again after a clear carries the same pseudonym.

Room for keys
-------------

Two limits refuse a key, with different messages:

* All eight handles of the range are taken. The message counts them.
* The TPM has no persistent space left (``TPM_RC_NV_SPACE``). The message
  prints the objects the TPM holds (``TPM2_PT_HR_PERSISTENT``) and the room
  it reports (``TPM2_PT_HR_PERSISTENT_AVAIL``), and names
  ``--list-publishers`` and ``--forget-publisher``.

Sealing
=======

``--seal`` reads a secret from standard input and writes a blob that only
this TPM, in the same PCR state, opens with ``--unseal``
(:doc:`command-line`).

A secret of up to 128 bytes is sealed directly: a ``KEYEDHASH`` object,
``fixedTPM`` and ``fixedParent``, with no user authorization and a
``PolicyPCR`` over the selected PCRs as its policy. A secret of up to 65536
bytes goes into an envelope: a random 256-bit key, sealed as above, encrypts
it with AES-256-GCM. An empty secret is refused.

The parent is the seal storage primary, an RSA 2048 restricted decryption
key of the owner hierarchy with AES-128-CFB and an empty ``unique``. The
agent derives it for each operation, or uses the object at ``0x81010003``
when ``seal_persistent_primary`` is set and the object's Name matches the one
``--seal-persist-primary`` recorded in ``/var/lib/lota/seal_primary.name``.
With no record, or another Name, it derives the primary. Both are the same
key, so a blob opens either way. ``--unseal`` runs in a session
salted with that primary and with parameter encryption, so the secret does
not cross the bus in the clear.

``--seal-persist-primary`` stores the primary at ``0x81010003`` and records
its Name, and reports when the primary is already there. Seal and unseal use
it only with ``seal_persistent_primary``. ``--seal-evict-primary`` removes it
and the record; blobs stay valid, as the derived key is the same. Both
commands compare the object at the handle with the derived primary and leave
another object alone, exiting 1. With no object at the handle
``--seal-evict-primary`` exits 1. When the TPM step succeeds but the record
cannot be written or removed, the command says the TPM step is done, names
the record, and exits 1.

PCR masks
---------

The default mask is ``0x83``: PCRs 0, 1 and 7, the firmware, its
configuration and the Secure Boot state. PCR 4 is left out, so a kernel
update keeps the secret readable; a disk moved to another machine opens
nothing.

``0x4083`` adds PCR 14, which holds the agent's boot commitment. It binds a
boot state, not a process: any process with access to the TPM unseals while
the registers match, and an upgrade of the agent makes the secret
unreadable (:ghsrc:`include/lota_seal.h`).

Blob formats
------------

Both formats are little-endian and defined in :ghsrc:`include/lota_seal.h`
and :ghsrc:`include/lota_envelope.h`, which are not installed. ``--unseal``
checks the framing before it opens the TPM and names the field it refuses.
A blob the TPM refuses to load, or refuses to unseal while its PCRs match,
is reported as a damaged blob or one sealed on another TPM (``EBADMSG``),
not as another boot state.

.. list-table:: Sealed blob, 52-byte header
   :header-rows: 1
   :widths: 14 14 72

   * - Offset
     - Size
     - Field
   * - 0
     - 4
     - Magic, ``LSEL``.
   * - 4
     - 2
     - Version, 1.
   * - 8
     - 4
     - PCR mask, nonzero, no PCR above 23.
   * - 12
     - 1
     - PCR bank, 0 for SHA-256.
   * - 16
     - 32
     - Digest of the PCR values sealed to.
   * - 48
     - 2
     - Length of the ``TPM2B_PUBLIC`` that follows, at most 1024.
   * - 50
     - 2
     - Length of the ``TPM2B_PRIVATE`` after it, at most 1024.

.. list-table:: Envelope, 48-byte header
   :header-rows: 1
   :widths: 14 14 72

   * - Offset
     - Size
     - Field
   * - 0
     - 4
     - Magic, ``LENV``.
   * - 4
     - 2
     - Version, 1.
   * - 8
     - 2
     - Length of the sealed key blob that follows.
   * - 12
     - 4
     - Length of the ciphertext after it, at most 65536.
   * - 16
     - 12
     - GCM nonce.
   * - 28
     - 16
     - GCM tag.

Bytes the tables do not list are zero. The envelope's additional
authenticated data is its header with the tag zeroed, followed by the sealed
key blob. The bodies fill the file exactly.

Diagnostics
===========

``--test-tpm`` runs these steps and prints each result
(:ghsrc:`src/agent/selftest.c`):

#. Open the TPM and run ``TPM2_SelfTest``.
#. Read PCRs 0, 1 and 10.
#. Hash the kernel image and the agent binary.
#. Read PCR 14 and check it against this binary's commitment without
   extending it: a daemon started later in the same boot still makes the
   extend.
#. Quote PCRs 0, 1 and 14 with each publisher's key, or with the host AIK
   when no publisher holds a key. A handle with no object is skipped.

It ends with how many steps passed, failed and were skipped, and exits 1
when one failed. It says before a quote that a rejected authorization costs
one dictionary-attack attempt. It creates no key at an empty handle and
replaces none: a key with no authorization record is skipped. The daemon
gives a publisher's key a fresh value when it binds a ``lota.conf`` profile
of that publisher, and the host key one when it runs with no publisher
bound. It gives none to a key in the profile store that no profile
names.

``--test-signed`` serves the IPC socket with tokens signed by the TPM, in a
simulated attested state. It claims the socket before it opens the TPM, so
a run refused because the daemon holds the socket costs nothing. With no
key at the handle it says that it creates one, and that the key stays after
it exits.

Transient errors
================

A TPM answer that asks to be tried again (``TPM_RC_RETRY``, ``YIELDED``,
``TESTING``, ``NV_RATE``, ``NV_UNAVAILABLE``, the memory codes, or a TCTI
that asks to try again) is retried up to six times, starting at 25 ms and
doubling, with at most 2 seconds of sleep in all, well inside the daemon's
watchdog. Lockout is not retried.

Other codes map to an errno: a missing handle to ``ENOENT``, no NV space to
``ENOSPC``, a bad value or size to ``EINVAL``, and a lost TPM to
``ENODEV``. Three codes are the agent's own: lockout, a rejected
authorization (the authorization failures and ``NV_AUTHORIZATION``) and an
unsatisfied policy (``POLICY_FAIL``, ``PCR_CHANGED``).

Dictionary-attack lockout
=========================

The TPM counts failed authorizations and refuses every authorized command
once the count reaches its limit. Three properties of the chip decide what
that costs; ``tpm2_getcap properties-fixed`` and
``tpm2_getcap properties-variable`` read them:

``TPM2_PT_MAX_AUTH_FAIL``
  The number of failures that engages lockout.

``TPM2_PT_LOCKOUT_INTERVAL``
  The seconds after which the TPM forgets one failure.

``TPM2_PT_LOCKOUT_RECOVERY``
  The seconds the lockout hierarchy stays barred after a failed
  ``lockoutAuth``.

The agent logs ``TPM2_RC_LOCKOUT`` with the count of events and the time of
the first, and sets ``LOTA_STATUS_TPM_LOCKOUT``. The daemon refuses
``GET_TOKEN`` with ``LOTA_IPC_ERR_TPM_LOCKOUT`` before it reads a verdict
(:doc:`ipc`). After a successful TPM command the agent reads
``TPM2_PT_PERMANENT`` and clears the flag when the TPM is out of lockout;
tokens resume with no restart.

With ``lockoutAuth`` known, ``tpm2_dictionarylockout --clear-lockout`` ends
the lockout at once. Without it the host waits for the interval to drain
the count, or the TPM is cleared. Whoever provisions the host decides which
applies; a TPM another operating system has owned may hold a
``lockoutAuth`` the fleet does not know.

Clearing the TPM
================

``TPM2_Clear`` replaces the owner seed and deletes every persistent object
and every NV index the owner hierarchy created. The platform-created indices
stay, the EK certificate among them, and the PCRs keep their values.
``resetCount`` starts again.

For the agent this means:

* Every AIK is gone, and the key derived again at a handle is another one.
  Blobs sealed before the clear open no more.
* For each publisher whose certificate names another key, the daemon logs
  that no round is attempted until the publisher issues a certificate for
  the key that is there, and names the publisher. It quotes nothing for that
  publisher, so no dictionary-attack attempt is spent.
* The ``--attest`` loop enrolls again each such publisher that has consent,
  with the recorded endpoint and token. The others wait for
  ``lota-agent --reenroll``.
* The verifier receives no round from the host meanwhile, so nothing on the
  fleet side reports the state; the host's journal does.
* After the next cold boot PCR 14 waits for its commitment again, and the
  agent records the ``resetCount`` of that boot with it (:doc:`lifecycle`).

Where the firmware offers the physical presence interface,
``/sys/class/tpm/tpm0/ppi/`` shows its version and the operations it
accepts; an operation written to ``request`` runs at the next reboot, and
``response`` holds the result.

Suspend and resume
==================

A suspend that keeps the TPM powered, such as ``s2idle``, leaves it
untouched. A suspend to RAM saves the TPM state and restores it on resume:
the PCRs come back, ``resetCount`` stays and ``restartCount`` grows. The
boot commitment depends on neither, so a resumed host attests as before.

A cold boot resets PCR 14. The initramfs helper writes its lock value, and
the agent extends the commitment; a commitment already present at that
point comes from something that ran before the agent, and the agent refuses
it (:doc:`lifecycle`).
