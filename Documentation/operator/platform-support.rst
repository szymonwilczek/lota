.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

================
Platform support
================

LOTA has two halves with different platform coupling. The **verifier** and
**attestation CA** are distro-independent Go services: they run from the native
RPMs or the distroless container images on any Linux the container or binary
targets, and platform support does not constrain them. The **agent** is coupled
to the host: it drives the TPM, loads a BPF LSM program, and installs an
initramfs module, so its support is defined per distribution family, firmware
and TPM. The tables below describe the agent.

Support tiers
=============

.. list-table::
   :header-rows: 1
   :widths: 20 80

   * - Tier
     - Meaning
   * - Supported
     - The full bring-up and attestation path runs on the platform, and it is
       the reference environment the packaging and documentation describe.
   * - Experimental
     - The packages build and install from the same nfpm configs and dracut
       module as the supported platform, and the packaging is exercised there
       in CI. Parts of the bring-up path may be verified on the platform, but
       it is not the reference environment and a capability the supported
       platform has may be missing -- the row says which.
   * - Unsupported
     - The platform needs packaging or a boot-integration model LOTA does not
       carry. The agent has no path there.

Distributions
=============

.. list-table::
   :header-rows: 1
   :widths: 26 30 16 28

   * - Distribution family
     - Packaging
     - Tier
     - Notes
   * - Fedora
     - RPM + dracut ``90lota``
     - Supported
     - The reference agent platform. Fedora 44 ships ``module.sig_enforce=1``
       and the kernel lockdown the startup gates require.
   * - RHEL / Rocky / AlmaLinux (el9+)
     - RPM + dracut ``90lota`` (same nfpm configs)
     - Experimental
     - The RPM/dracut family the agent targets beyond Fedora. The RPMs build
       and install on el9 and el10 userspaces, and on el10 the agent enrolls,
       commits the boot state to PCR 14 and passes its TPM attestation. On el9
       the agent's ``fsverity-utils`` dependency is served by EPEL rather than
       the distribution, so that repository has to be enabled first. The
       BPF LSM does not arm on the el-family kernels, however -- see the
       Kernel section below -- so runtime enforcement stays a Fedora-class
       capability there.
   * - Debian / Ubuntu
     - separate ``initramfs-tools`` packaging
     - Unsupported
     - A different initramfs generator than dracut; the ``90lota`` module does
       not apply.
   * - Arch / SteamOS / immutable (A/B) distributions
     - none
     - Unsupported
     - A different update and root-filesystem model than the packaged
       bring-up assumes.

Kernel
======

The agent's BPF LSM enforcement needs a kernel new enough for its
``file_mprotect`` gate. That gate reads the mapped file through
``vm_area_struct::vm_file`` and hands it to the fs-verity digest kfunc, which
the verifier only accepts when the pointer is trusted. The kernel began marking
that field access trusted around **6.18**; measured with ``veristat`` against
live kernels, 6.17 rejects the program and 6.19 accepts it. The RHEL-family
kernels are below that floor -- el9 ships 5.14 (which additionally lacks the
fs-verity kfunc entirely) and el10 ships 6.12, where 12 of the 13 programs
verify and only ``file_mprotect`` is rejected. Because one rejected program
fails the whole object, the LSM does not load. The agent still enrolls,
commits PCR 14 and completes its TPM attestation on those kernels; only the
runtime BPF-LSM layer is unavailable. Lowering that layer to make the object
load on an older kernel is not offered: runtime enforcement requires a
Fedora-class kernel, not a reduced program set.

Firmware and boot
=================

.. list-table::
   :header-rows: 1
   :widths: 26 74

   * - Boot path
     - Behaviour
   * - UEFI + Secure Boot
     - The reference target. shim measures the MOK state into PCR 14 before the
       initramfs, and the boot commitment is baseline-aware over it (see
       :doc:`production-bringup/ca-enrollment`). The verifier replays the TPM
       event log and establishes Secure Boot from the log rather than the
       self-report. A boot chain without shim (own PK/KEK/db, a directly signed
       systemd-boot or UKI) measures nothing into PCR 14; the boot commitment
       then chains onto a zero baseline, which is supported.
   * - UEFI without Secure Boot
     - The agent runs, but the firmware root of trust is weaker. Pass
       ``lockdown=integrity`` on the kernel command line so the BPF-load gate is
       satisfied (see :doc:`production-bringup/gate-matrix`).
   * - Legacy BIOS / CSM
     - **Unsupported.** BIOS measures neither the firmware and Secure Boot
       state the verifier pins nor an EFI variable the event log can carry, so
       a BIOS host cannot produce the evidence an attestation is built from.
       The installer refuses such a host, the initramfs helper refuses to lock
       PCR 14 on it, the agent refuses to form a boot commitment, and the
       verifier rejects the report. Switch the firmware out of legacy/CSM mode
       and reinstall.

Which registers a policy can pin
--------------------------------

A policy that pins a PCR is asking that register to hold still. Not all of them
do, and which ones move is a property of the boot path.

.. list-table::
   :header-rows: 1
   :widths: 20 80

   * - Register
     - Stability
   * - PCR 0, 1, 7
     - Stable across kernel upgrades and across a machine-owner key change.
       These are what a boot-state pin is built from.
   * - PCR 14
     - The LOTA commitment, derived over the platform baseline. On a shim host
       the baseline carries the MOK state, so enrolling a machine-owner key
       moves it while PCR 7 does not -- an enrolled host then reports an
       integrity mismatch until an operator re-anchors it. That is the review
       gate a boot-chain change is meant to pass through, not a fault.
   * - PCR 4, 8, 9, 10
     - Move with a kernel upgrade, and on a GRUB host **also move with boot
       history**. ``grubenv`` is measured into PCR 9 and GRUB rewrites it every
       boot; GRUB's menu logic branches on ``boot_success``, so PCR 8 records a
       different command sequence after an interrupted boot. Two boots of one
       kernel, with the kernel and initramfs digests byte-identical, differ in
       both. A pin on either re-pins after every unclean shutdown.

A consumer fleet pins none of these and is unaffected by a kernel upgrade: the
upgrade touches neither the boot baseline nor the PCR 14 commitment, so the
host keeps attesting with nothing to re-anchor. An enterprise fleet that pins
PCR 4, 8, 9 or 10 refuses the host after the upgrade, correctly by its own
rules, and the operator updates the pins.

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
       under :doc:`production-bringup/post-bringup`.

The measurements and limits below were taken on an Intel PTT (CSME Tiger Lake)
firmware TPM. Read them as the order of magnitude for that class of device and
measure the hardware a deployment ships on.

How many publishers a TPM has room for
--------------------------------------

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

The diagnostic verbs take from the same pool, so they say what they cost
before they cost it. ``--test-tpm`` reports state and never creates a key: it
says when the handle is empty and tells the operator which command provisions
one. ``--test-signed`` cannot decline, since signing is what it is for, so it
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
------------------------------------

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
-------------------------

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
-------------------------

Clearing is the last resort behind an unrecoverable ``lockoutAuth``, and it is
survivable but not free. It destroys **every persistent object**: each
publisher's attestation key and any persisted EK. It leaves **NV storage
alone**, so the manufacturer EK certificates stay on the chip, and it does not
touch the PCRs.

For LOTA that means every publisher enrollment on the host is gone and each has
to be re-established with ``lota-agent --reenroll --ca-cert <their anchor>``.
The agent mints fresh keys on its next round, so a verifier holding the old
certificate sees a host whose key no longer matches what it was issued and
refuses it by name until the re-enrollment lands.

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
------------------

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

Runtime measurement coverage
============================

Every token folds a kernel-anchored measurement of the live code of each
protected process, and that measurement can cover an object only when the
kernel holds an fs-verity digest for it. What a platform provides therefore
decides how much of a process's code the measurement can account for.

.. list-table::
   :header-rows: 1
   :widths: 28 72

   * - Platform
     - Coverage
   * - A title's own binaries
     - Full, on any verity-capable filesystem. Whoever ships the title
       enables it, with ``lota-install --verity-manifest`` or the
       equivalent in their own packaging. The agent refuses a token when
       **the requesting process's own** executable carries no digest, and
       says so with ``LOTA_ERR_UNMEASURABLE_SELF``. Another protected
       process being unmeasurable never refuses this caller: any local
       program may ask to be protected, so one program's packaging would
       otherwise stop token issuance for every title on the machine. It is
       reported through the coverage flag instead.
   * - Distribution libraries on a package-managed host
     - **None, today.** Fedora ships ``libc``, ``libcurl`` and the rest
       without fs-verity, so those objects are absent from the fold and the
       token reports partial coverage
       (``LOTA_FLAG_IMAGE_FULLY_MEASURED`` clear). Enabling verity on them
       by hand lasts until the next update of the owning package, which
       replaces the inode and the digest with it. Whether partial coverage
       is acceptable is the relying party's policy.
   * - Image-based and composed filesystems
     - Not consumed yet. An image-based host (composefs, an OSTree
       deployment, a dm-verity root) already carries per-file or
       whole-image integrity, and consuming that as measurement evidence
       would give full coverage without per-file enablement. LOTA does not
       read those sources today; a protected process on such a host reports
       coverage over whatever fs-verity digests are present.

A relying party that requires full coverage asks for
``LOTA_FLAG_IMAGE_FULLY_MEASURED`` and, on a package-managed host, will not
get it. That is a statement about the platform, not about the machine
concealing anything: an unmeasurable object is reported as unmeasured and is
never folded in as though it had been measured.
