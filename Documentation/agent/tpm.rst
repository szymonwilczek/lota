.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

===
TPM
===

The agent requires a **TPM 2.0**.

.. list-table::
   :header-rows: 1
   :widths: 22 22 56

   * - Device
     - Tier
     - What it means for a deployment
   * - Firmware TPM (fTPM / Intel PTT)
     - Supported
     - The reference hardware device: the full path -- enrollment against a
       manufacturer EK certificate, boot commitment, quoting under load,
       suspend and resume, dictionary-attack lockout and recovery -- runs on
       one. Its limits are the ones a deployment meets first: a small
       persistent-object pool shared with whatever else on the machine
       persists keys, small command and NV buffers, and quote latency
       measured in tens of milliseconds.
   * - Discrete TPM (dTPM)
     - Supported
     - The same interfaces over a separate chip. Nothing in the agent
       distinguishes the two; a dTPM is typically more generous with
       persistent objects and is **not** automatically faster at quoting.
   * - swTPM (KVM guest, TIS)
     - Development only
     - The documented development environment. It is fast, permissive,
       always freshly initialised and never locked out, so it cannot stand
       in for a hardware device when the question is capacity, latency or
       lockout behaviour. Its divergences and the operator workarounds are
       under :doc:`../dev-tools/vm-testing`.

The measurements and limits below were taken on an Intel PTT (CSME Tiger Lake)
firmware TPM. Read them as the order of magnitude for that class of device and
measure the hardware a deployment ships on.

How many publishers a TPM has room for
======================================

Each publisher this host answers to holds its own attestation key, and each
key occupies one TPM persistent object. That capacity, not any LOTA constant,
is the real ceiling on publishers: a discrete TPM is generous with it, a
firmware TPM is not, and any other software on the machine that persists keys
takes from the same pool.

The agent reports both halves. ``lota-agent --list-publishers`` prints the keys
this machine holds, what the TPM answers for persistent objects
(``TPM2_PT_HR_PERSISTENT`` and its ``_AVAIL`` estimate) and the maximum this
build will hand out. Provisioning a key into a full TPM is refused with the
count and the two verbs that free a slot -- ``--list-publishers`` and
``--forget-publisher`` -- rather than an I/O error, because the machine is full,
not broken and the space is reclaimable.

Two different things take a slot, and the listing separates them. This build
hands out eight handles, ``0x81010010`` to ``0x81010017``, and prints how many
of them are free next to how many the profiles here record. A handle in that
range that holds an object no profile records is the second kind: it is left
behind by a wiped profile, a failed eviction, an earlier build or another
program, and the allocator steps over it rather than evicting what it did not
put there. The listing names each one::

    Handle range 0x81010010-0x81010017: 0 of 8 free, 5 recorded here.
    3 handles in that range hold a key no publisher here records:
      0x81010012 0x81010013 0x81010014
    Each costs a publisher slot. LOTA will not evict what it did not put there;
    remove one with tpm2_evictcontrol -c <handle> once you know what it is.

Without that line, a host with five keys and eight handles reads as having
three slots left while having none, and the first symptom is the next
publisher failing to bind.

A title that names a publisher with no slot left is refused at connect:
``LOTA_ERR_NO_KEY_SLOT`` through ``lota_connect_last_error()``. That is a screen
for the player -- the machine answers to as many publishers as it has room for
and this one is over the line.

The diagnostic verbs take from the same pool, so they say what they cost
before they cost it. ``--test-tpm`` reports state and never creates a key: it
says when the handle is empty and tells the operator which command provisions
one. It quotes with each publisher's own key and names the publisher and its
handle. The records that predate publishers name a handle whose stored
authorization no longer opens what sits there, so quoting from them would
fail on a healthy host and spend a dictionary-attack attempt; they are used
only where nobody holds a publisher key.

``--test-signed`` cannot decline, since signing is what it is for, so it
names the key it is about to use, and when there is none at the handle it says
that it is creating one that stays after the server exits. Both claim their
socket before touching the TPM, so a run refused by a daemon that already
holds it spends nothing at all.

``--test-tpm`` is safe to gate a script on: it exits non-zero when any
operation it performed failed, and ends with how many passed, failed and were
skipped. A section it could not reach -- the quote, on a host with no
attestation key -- is skipped, since nothing was learned about it.
An authorization the TPM refuses spends one dictionary-attack attempt,
which the verb says before it makes the attempt.

A measured example: an Intel PTT firmware TPM holds 21 persistent objects in total,
of which five are resident on an installed host before any publisher enrolls.
16 publisher keys fit, which is above the eight this build hands out, so on that
platform the build's own maximum is what a host meets first. A firmware TPM with
a smaller pool, or one shared with other software, meets the TPM's limit instead.

What a token costs on a firmware TPM
====================================

Every token is a fresh ``TPM2_Quote``, and a quote is a blocking operation on a
device the whole machine shares. Measured on the validation host -- an Intel
PTT (CSME Tiger Lake) firmware TPM, agent running with three publishers
enrolled, CPU governor ``powersave``, on AC:

.. list-table::
   :header-rows: 1

   * - What
     - Cost
     - How
   * - ``lota_get_token()`` end to end
     - **48 ms median** (45 min, 49 max)
     - 12 requests a second apart through the gaming SDK against the running
       daemon, with a session open; includes the IPC round trip, the runtime
       measurement of the calling process, the quote and serialisation
   * - Bare ``tpm2_quote`` over 4 PCRs
     - **26 ms** per invocation
     - 20 and 30 repetitions in one root shell; adding ``sudo`` per invocation
       costs about 16 ms more
   * - Four concurrent quote streams
     - 60 quotes in **884 ms**
     - four workers of 15 ``tpm2_quote`` invocations each, run at once

Take that as the order of magnitude for this class of device, not as a
guarantee: the same host has also measured ~171 ms of TPM work per quote, with
a flat ceiling of about 6 quotes per second regardless of concurrency, and the
difference is unexplained. Size against the slower figure if a design depends
on throughput, and measure your own hardware before committing to a cadence.

Two consequences hold under either figure:

* **A token request is a blocking TPM operation of tens of milliseconds.** It
  does not belong on a frame loop or any latency-sensitive path. Fetch tokens
  on a heartbeat -- the reference integration uses 5 seconds -- and reuse the
  one you hold until it nears expiry.
* **The per-uid token limit is a meaningful share of the device.** The limit is
  60 requests per 60 seconds, which is one quote a second: between 3% and 17%
  of this TPM's throughput depending on which figure above applies. The
  per-session limit of 20 per 60 seconds exists so one title cannot spend the
  whole uid allowance; both are documented under the IPC rate limits.

A discrete TPM is not automatically faster. Nothing here is a floor: measure
the hardware a deployment actually ships on.

Dictionary-attack lockout
=========================

A TPM counts failed authorization attempts and stops answering when the count
reaches its threshold. The three properties that decide what that costs a fleet
are per-device and are read from the chip, not assumed:

.. list-table::
   :header-rows: 1
   :widths: 34 18 48

   * - Property
     - Example
     - What it governs
   * - ``TPM2_PT_MAX_AUTH_FAIL``
     - 32
     - How many failures reach lockout. The example device enters lockout on
       exactly the 32nd.
   * - ``TPM2_PT_LOCKOUT_INTERVAL``
     - 7200 s
     - How fast the counter drains on its own: one attempt forgiven per
       interval, so a host walks out of lockout in its own time.
   * - ``TPM2_PT_LOCKOUT_RECOVERY``
     - 86400 s
     - How long the **lockout hierarchy** stays barred after a failed
       ``lockoutAuth``. It is not the wait for an object lockout, which is
       what the interval above governs.

Read them with ``tpm2_getcap properties-variable`` and
``tpm2_getcap properties-fixed``. The agent reports the state it sees rather
than an errno: a round that fails on a locked-out device says
``TPM dictionary-attack lockout engaged``.

**Whether recovery is a command or a wait is decided by who holds
``lockoutAuth``, and that is a property of the deployment, not of LOTA.** With
the value in hand, recovery is ``tpm2_dictionarylockout --clear-lockout`` and
the next attestation round succeeds. Without it, the fleet either waits out the
drain or clears the TPM and re-enrolls. Check ``lockoutAuthSet`` before
assuming: a machine that has run another operating system may have had the
value set by it, and an OS that derives the authorization instead of storing it
leaves nothing to recover. Provision hosts so the fleet owns ``lockoutAuth``,
or plan for the wait.

A failed authorization against the **platform** hierarchy does not move the
counter, so probing platform-owned state costs nothing in lockout terms.

What clearing a TPM costs
=========================

Clearing is the last resort behind an unrecoverable ``lockoutAuth``, and it is
survivable but not free. It destroys **every persistent object**: each
publisher's attestation key and any persisted EK. It does not touch the PCRs --
every register the boot chain measures comes back byte for byte, and only
PCR 10 differs, because IMA re-extends it each boot.

NV storage is **not** left alone, and which half of it survives is what decides
whether the host can be recovered. ``TPM2_Clear`` deletes every index created
under the **owner** hierarchy and keeps the **platform-created** ones. The
manufacturer EK certificates are platform-created, so they stay on the chip:
the endorsement key still chains to the vendor root, and ``--reenroll`` issues
a certificate over the same device pseudonym the host had before. Every
owner-hierarchy index goes with the hierarchy -- another TPM consumer's state,
a firmware feature's, a sealed blob keyed to an index -- and none of it is
LOTA's to restore. Inventory them before clearing (``tpm2_nvreadpublic``
prints each index and whether it carries ``platformcreate``).

A clear also rebases the TPM's own counters: ``resetCount`` restarts at 1 and
the TPM clock restarts near zero. Nothing in LOTA breaks because of it -- the
PCR 14 classification reads both, and a cleared host reaches its
``AWAITING_EXTEND`` state before the counters are consulted -- but a counter
that has gone backwards is exactly what the agent's rollback verdict exists
for, so a clear leaves a host one step from a verdict that means something
else. Any fleet tooling that treats ``resetCount`` as monotonic reads a cleared
host as a rolled-back one.

For LOTA that means every publisher's attestation key on the host is gone. The
attestation loop enrolls each publisher consent is recorded for again on its
own, with the endpoint, anchor and token its first enrollment recorded; the
rest wait for ``lota-agent --reenroll``, which re-enrolls every publisher whose
certificate no longer names the key at its handle. The next round after a
re-enrollment verifies.

**The agent refuses this state, and it does so before any quote.** The key at
each publisher's handle is no longer the key their certificate was issued over,
so the agent says once per publisher that ``No round is attempted until they
issue a certificate for the key that is here now``, names that publisher, and
sleeps. Quoting anyway would be refused by the TPM and would spend a
dictionary-attack attempt on every interval, which is what the check exists to
avoid.

**Nothing reaches the verifier.** No round is opened, so there is no failed
attestation, no connection and no metric to alert on: a cleared host is silent
on the fleet side and loud in its own journal. A fleet-side signal for this
state does not exist today; the place to watch is the agent's log on the host.

Where the authorization to clear comes from is firmware-dependent. Both
hierarchy-authorized routes need a value the fleet may not hold, and the
platform's own physical-presence interface is the way through when they do not:
read ``/sys/class/tpm/tpm0/ppi/`` for the version, the transition action and
whether the firmware marks the clear operation as requiring a user at the
keyboard. Where it does not, writing the operation to ``request`` and rebooting
performs it, and ``response`` reports the result afterwards. **Write 0 to
``request`` before writing an operation**: firmware has been observed returning
junk from that file when nothing is pending, so a stale-looking value is not
evidence of a queued request, and an unexecuted one can sit there across many
reboots.

Suspend and resume
==================

A host may suspend and resume without losing its attestation. A suspend
shallow enough to keep the TPM powered (``s2idle``) leaves the TPM
untouched. A deeper suspend (``deep`` / S3) restarts the TPM, which saves
and restores its state: every PCR comes back byte for byte, ``resetCount``
does not move, and ``restartCount`` is incremented to record the restart.

The agent's boot commitment binds the agent binary and the platform baseline,
neither of which a suspend touches, so a resume needs no special handling on
either side: the register still holds what the running binary derives, and
the verifier still matches it. There is no skew window to configure and no
candidate scan to bound.

A cold boot is the case that does move it. The hardware reset clears PCR 14,
the initramfs helper leaves the lock value, and the agent extends next; a
commitment already present at that point was written by something that ran
before the agent, which the agent refuses by name. A register another writer
extended is refused after a resume exactly as it is before one.
