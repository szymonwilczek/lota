.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

======================================
LOTA guided install (``lota-install``)
======================================

``lota-install`` is the single-machine path onto a LOTA-attested host: one guided,
reboot-resumable command instead of the operator checklist in
:doc:`production-bringup/index`. It drives the
same hard requirements the agent enforces at startup, but it explains every
change before making it, asks for consent, and survives the reboot the install
inherently needs.

The three install surfaces and their audiences:

.. list-table::
   :header-rows: 1
   :widths: 28 32 40

   * - Tool
     - Audience
     - Scope
   * - ``lota-install``
     - Somebody installing one machine by hand
     - Guided stages, consent prompts, reboot resume
   * - :doc:`production bring-up <production-bringup/index>`
     - Operator bringing up fleet hosts, CA and verifier
     - Full manual reference
   * - ``scripts/lota-dev-bringup.sh``
     - Contributor iterating on a dev host
     - Generates a throwaway signing key. Never for production.

This page is the reference: it states what each stage does and why, and
assumes the reader knows what a TPM and an initramfs are. Somebody installing
LOTA on their own PC to play a game wants
:doc:`../player/index` instead, which walks the same tool
end to end and explains the terms as it goes.

Running it
==========

.. code-block:: sh

    sudo lota-install \
        --ca-server ca.example --ca-port 8444 --ca-cert /path/to/ca.crt \
        --verifier verifier.example

CA/verifier endpoints and the trust material paths come from the operator's
install instructions (see "What the operator must ship" below).

``lota-install --status`` prints a read-only report of every step without
changing anything, and its step numbers are the ones the guided install shows.
A stage the installer can satisfy reads ``pending``; one that needs an action
the installer must not take -- Secure Boot enabled in firmware, an operator's
SELinux module, IMA signatures -- reads ``BLOCKED``, because a report that
calls both "pending" reads as work about to happen.

The last step is the self-check, which is where an install answers "did this
work". The report says what it can see without acting -- the kernel integrity
floor, the agent binary's immutability, the service, and the AIK certificate
-- and stops there: the attestation round-trip is an action and belongs to an
install, so no report sends one.

* ``--yes`` skips the per-stage prompts,
* ``--plain`` disables the TUI for logs and scripting,
* ``--unattended`` is the mode a package post-install hook runs in. It implies
  ``--yes --plain``, does nothing at all inside a container or image build (the
  host that eventually boots the image is the one bring-up belongs to), and
  **leaves the two boot-path stages alone** -- the initramfs PCR 14 lock and
  the kernel integrity floor -- stopping at the reboot checkpoint, where it
  names each boot-path stage still to run and the one command that runs them.
  A host that wants them unattended too opts in before installing, with
  ``/etc/lota/auto-bringup`` or ``LOTA_AUTO_BRINGUP=1``; exactly ``1``, since
  a hook inherits whatever environment the transaction had and reading ``0``
  as consent is how a machine ends up with a boot path nobody chose.

On an interactive terminal ``lota-install`` is a full-screen application
(alternate screen): a stage list on the left, a details pane explaining the selected
stage, and an output pane streaming what every command actually does.
The initial system probe runs before the screen takeover and its
per-stage results stay in the scrollback. Nothing scrolls away and the layout
follows terminal resizes. Keys:

.. list-table::
   :header-rows: 1
   :widths: 40 60

   * - Key
     - Action
   * - ``up``/``down`` or ``j``/``k``
     - Select a stage
   * - ``Enter``
     - Run the selected stage (dialog explains the change and asks first)
   * - ``a``
     - Run every pending stage in order
   * - ``y`` / ``n``
     - Answer the confirmation dialog
   * - ``r``
     - Re-probe all stages
   * - ``PgUp``/``PgDn`` or ``Ctrl-U``/``Ctrl-D``
     - Scroll the output pane
   * - ``q``, ``Ctrl-C``
     - Quit (``Ctrl-C`` first aborts a running command)

The original scrollback is restored on exit and a one-line result is printed
to the normal screen: complete (exit ``0``), reboot required (``10``) or
re-run to continue (``1``). Without a TTY, or with ``--plain``, the same stages
run as a sequential prompted flow suitable for logs and scripts. There a stage
with work to do prints what it found after ``Before this stage:`` and ends
``applied``; a stage with nothing to do reports ``already satisfied``. An
upgrade that brings a binary without fs-verity thus shows that stage as
``applied``. Prompts take ``y`` or ``n`` (``q`` quits) and the bracket shows
what Enter means: yes for a stage, no for ``--pause`` and ``--resume``, whose
yes cannot be undone in the same boot. An unrecognised answer is asked again
and never proceeds.

Exit codes:

* ``0`` -- complete: every stage is satisfied, the same answer ``--status``
  gives with exit ``0``;
* ``1`` -- failed, blocked on missing input, or stopped before the end;
* ``2`` -- usage;
* ``10`` -- reboot required: reboot and re-run the same command, the installer
  detects the finished stages from live system state and continues at the
  first unmet one;
* ``11`` -- ``--unattended`` only: host-local setup is done and the boot-path
  stages it names are left to a person, so the host is not finished. Run
  ``sudo lota-install`` to complete it.

There is no state file to corrupt: every done-condition is probed from the
system itself (installed files, the fs-verity bit, the initramfs content,
``/proc/cmdline``, PCR 14 via sysfs, the certificate's validity window), and the
probes mirror the agent's own startup gates, so the installer cannot report
green on a host the agent would refuse.

What the stages do
==================

#. **Preflight** -- TPM 2.0 device present, UEFI Secure Boot enabled, required
   tooling installed. Secure Boot off is a hard stop: the verifier proves it
   from the TPM event log and rejects hosts without it (MOK-signed custom
   kernels keep working). It is also the one requirement nobody but the person
   at the keyboard can satisfy, so the blocked stage prints a route instead of
   a rule: the machine as DMI names it, ``systemctl reboot --firmware-setup``
   where the firmware honours that request, then the startup screen's key for
   when it is refused (the request is an EFI variable write, which a full store
   answers with ``Cannot allocate memory``), the "restore the factory keys"
   step in setup mode, and that enabling Secure Boot leaves distribution
   kernels bootable. A guest is sent to its VM definition instead, since a
   virtual machine has no firmware menu of its own -- ``systemd-detect-virt``
   decides that, so the installer keeps no list of hypervisors. Everything in
   that message is read off the machine; the installer names no per-vendor
   menu path or setup key, because those differ between firmware revisions of
   a single model and a confidently wrong instruction costs more than a
   general one.
#. **Package artifacts** -- agent binary, BPF object, systemd units, udev rule
   and dracut module are installed. The installer does not build or download
   anything. Missing artifacts mean the LOTA package has not been installed yet.
#. **Operator trust material** -- the BPF object's signature verifies against
   the operator's public key, and ``/etc/lota/lota.conf`` points the agent at
   that key. Fail-closed: the installer never generates a signing key on this
   host -- a locally generated key would let local malware re-sign a tampered
   enforcement object.
#. **Binary immutability** -- enables fs-verity on the agent binary
   (ext4/btrfs/f2fs). On filesystems without verity (XFS, ZFS) it instead
   accepts a signed ``security.ima`` xattr enforced by IMA appraisal, which
   gives the same guarantee.
#. **Initramfs PCR14 lock** -- regenerates the initramfs of every installed
   kernel so the PCR14 lock helper runs before any regular userspace, whichever
   kernel is selected at boot. It reports work to do while any installed kernel
   is missing the helper. Requires a reboot.
#. **Kernel integrity floor** -- appends the missing ones of
   ``ima_appraise=fix``, ``module.sig_enforce=1`` and ``lockdown=integrity`` to
   the boot entries via grubby. It reports those parameters and nothing more:
   the appraisal *mode* is not the floor on its own, and the rules it applies
   to are the next stage. On a Secure Boot host the appraisal parameter is left
   out, because the kernel discards ``ima_appraise=`` there and appraises in
   its own built-in blocking mode -- writing it would describe a mode that is
   not the machine's. Signature content stays distribution or
   operator-supplied (see the production bring-up guide). Requires a reboot.
#. **IMA appraisal scope** -- the previous stage sets the appraisal *mode*, and
   the kernel applies that mode only to the rules its loaded policy carries. A
   policy whose ``appraise`` rules reach no executable appraises nothing, so
   this stage reads ``/sys/kernel/security/ima/policy`` and reports what the
   kernel covers. It loads no rules of its own. An IMA rule cannot name a path,
   so the rule that appraises the agent appraises every executable it matches,
   and on a Secure Boot host that happens in ``enforce`` -- the kernel discards
   ``ima_appraise=`` there whatever the cmdline asks for -- which on a root
   filesystem without IMA signatures means refusing every executable at the
   next boot. What such a host is missing is the signatures, not a rule set:
   IMA-signed distribution packages with the distribution's certificate on the
   ``.ima`` keyring, or an operator image pipeline that signs the executable
   closure and enrols its certificate.

   **A host that appraises nothing still finishes the install**, as long as the
   agent binary carries fs-verity: the kernel refuses a modified read of it and
   PCR 14 commits the running build, so the agent's own footing does not rest
   on IMA. The stage says what the machine gives up, and every token it hands
   out carries ``LOTA_FLAG_KERNEL_APPRAISAL`` clear, which is what a publisher
   or a verifier policy (``require_ima_appraisal``) reads. On a filesystem
   without verity, where the agent's only claim is a signed ``security.ima``
   xattr, appraisal is what makes that claim real: there the agent refuses to
   start and the stage is blocked. A kernel built without
   ``CONFIG_IMA_READ_POLICY`` publishes no policy at all, so the scope cannot
   be read and both the stage and the agent say it went unverified.
#. **SELinux fence** -- loads the LOTA policy module if needed and re-triggers
   udev so ``/dev/tpm*`` carries the LOTA-only label.
#. **Reboot checkpoint** -- stops with exit 10 until the boot-chain changes are
   live and PCR 14 carries this boot's initramfs lock. A host whose agent has
   already run and refused to start this boot is told that instead: the
   register carries the extend of that attempt, and the next boot meets the
   same refusal, so the checkpoint names ``journalctl -u lota-agent -b``.
   A pause is the exception: an agent stopped with ``lota-install --pause`` or
   ``lota-agent --shutdown`` spent the register on purpose and refuses to start
   until the next boot, so the checkpoint asks for that reboot, as
   ``--resume`` does. It reads the pause from the flag the agent records in
   ``/var/lib/lota/clock_state.dat``, while PCR 14 still holds the value the
   agent left.
   PCR 14 only resets on a hardware reset, so this cannot be skipped. On a
   Secure Boot machine PCR 14 is already non-zero before any of this -- shim
   measures the MOK variables into it -- and the checkpoint says.
#. **Agent service** -- enables and starts ``lota-agent.service`` and its
   socket.
#. **Enrollment** -- the TPM proves itself to a publisher's attestation CA
   (credential activation) and receives a short-lived AIK certificate, one per
   publisher. Naming a CA here (``--ca-server`` with ``--ca-cert``) enrolls
   with it during the install, which is what an operator provisioning a fleet
   wants. Naming none is the normal single-machine case and is not a blocked
   stage: the publisher is whoever they buy a title from, so the agent enrolls
   with each publisher the first time a title asks for one. Either way the
   running agent renews the certificate on its own against the endpoint
   recorded in the profile, and ``lota-agent --reenroll --ca-cert ...`` stays
   as a manual fallback.

   Each publisher's key is derived from that publisher's identity, so the
   certificates they hold carry different public keys and no two of them can
   name this machine from what their own CA issued. That is the whole of the
   guarantee, and it is worth being precise about the rest: a publisher who
   runs a **verifier** also receives this host's boot evidence -- the firmware
   and Secure Boot measurements, and the event log, which names the disk the
   host boots from. Two publishers who both run verifiers can compare what
   they each legitimately received and conclude it is one machine. A publisher
   whose titles only check tokens receives none of that, and for them the
   separation is complete. Choosing between the two is the privacy decision
   in this design; ``lota-agent --list-publishers`` says which of them this
   machine answers to and ``--forget-publisher`` takes one back.

Run ends with a self-check (integrity floor, fs-verity, service, certificate,
and an attestation round-trip) and a plain-language summary of exactly what
telemetry leaves the machine.

Who performs that round-trip depends on whether the host answers to
publishers. On a machine with no publisher profiles, ``--verifier`` names the
one verifier and the self-check runs a round against it; with no
``--verifier``, the first title launch performs it. **On a machine that has
publisher profiles, the publishers are the agent's target list** -- each with
its own trust anchor, verifier and cadence -- so no single verifier stands for
them and the self-check says so instead of naming one. That is not a host
failing to attest: a ``--verifier`` passed alongside profiles is reported as
unused, and a publisher whose titles gate on a session is reported to when one
of their titles runs.

What the operator must ship
===========================

A guided install needs these inputs, all fail-closed:

* nothing for **enforcement**: the agent package ships the BPF object, its
  ``.sig`` and the public key at ``/usr/lib/lota/enforcement.pub``, because
  enforcement is host-owned and signed by whoever built the package. All three
  are replaced together by an upgrade. A fleet that signs it with its own key
  re-signs the object and puts its key at ``/etc/lota/policy.pub``, which no
  package owns and the agent prefers whenever it is there;
* optionally an **attestation CA endpoint** (``--ca-server``, ``--ca-port``)
  and its **trust anchor** (``--ca-cert``), to enroll during the install. Both
  or neither: an anchor without an endpoint has nothing to enroll against. A
  guided install normally passes neither and lets the agent enroll with each
  publisher when a title first asks;
* optionally the **verifier endpoint** (``--verifier``) for the final
  round-trip check;
* compiled **SELinux module** (``lota.pp``, default
  ``/usr/share/lota/selinux/lota.pp``, override with ``--selinux-module``) on
  SELinux-enforcing distributions.

Every one of those options names a file, and a path reaches the installer only
by being typed. One that cannot be read is refused before any stage runs,
naming the option, the path and the reason::

    lota-install: Cannot read --policy-pubkey /etc/lota/ploicy.pub (No such file or directory)

The refusal is the same for ``--ca-cert``, ``--policy-pubkey``,
``--selinux-module`` and ``--verity-manifest``, in ``--status`` as well as in a
real run, so a typo never turns into a report about the host. It applies to
what the operator typed and not to the built-in defaults: a packaged SELinux
module that is not installed is a fact about the machine, and the stage that
wants it says so.

A run that finds the SELinux labels already in place says that the module named
on the command line was not loaded.

The RPM and DEB post-install hook drives this same stage engine
(``lota-install --unattended``), so installing the package leaves the
host-local half of bring-up already done and this command finishes the boot
path. Building from a release tree instead (``sudo make install``) does none of
it, and every stage below is then this command's work.

Titles that run under Proton or Wine
====================================

A Windows title reaches the agent through a Linux-side bridge
(``liblota_wine_hook.so``), because a DLL inside the Wine prefix cannot open a
host socket. Steam has to be told to preload it, which is one line pasted into
that title's launch options -- ``lota-steam-setup`` prints the exact string.
Container mounts are not pasted: ``lota-proton-hook`` adds the socket and
token directories to ``PRESSURE_VESSEL_FILESYSTEMS_RW`` itself.

The bridge is installed once per word size on x86_64: Steam's launch chain
mixes 64- and 32-bit processes that all inherit ``LD_PRELOAD``, so
``lota-proton-hook`` names it through ld.so's ``$LIB`` token. With only one
half installed, Steam logs a loader error on every launch.
``lota-steam-setup`` reports which halves it found.

A title running inside a Proton container reaches the agent through a
per-user socket, and ``lota-steam-setup --register-uid`` records the account
that needs one. The agent reads that setting when it starts, so it takes
effect at the **next boot**: the command says so before it edits anything.
Nothing stops the running agent to force it -- stopping the agent spends this
boot's attestation and would cost a reboot regardless.

After that boot the socket follows the login rather than the agent: it is
created when the registered account logs in and released when its last
session ends. ``lota-steam-setup --verify``, run from that account, is the
check -- it reports the socket as ready only when this account can open it,
and prints the ownership when it cannot, which is the case an account
outside the ``lota`` group lands in. Nor can that account look into the
group's directory holding the socket; the check names the group.

An account with no login session (a service account, ``sudo -u``, cron) has
no ``$XDG_RUNTIME_DIR``. Each check that needs it reports that, and the run
still reaches its verdict.

It is the only step in this document that asks anyone to type something, and
it stays until Steam supports a compatibility-tool layer that composes with
the player's Proton choice rather than replacing it. A publisher shipping
their own launcher avoids it entirely by setting the same variables on the
process they spawn. The reasoning, and the three alternatives that were
examined and rejected, are in :ghsrc:`examples/cs2/README.rst`.

When a title will not close
===========================

A game that asks to be protected (``lota_protect_self()``) gets a signal that
could end or stop it only from itself, the agent or the kernel. That stops a
cheat from killing the measured process, and also means a hung title survives
a terminal, a task manager and a root shell alike.

A signal the game handles itself runs the game's own code and is delivered;
Wine drives the program it hosts that way. ``SIGTERM``, ``SIGINT`` and
``SIGHUP`` stay refused even when handled: a game handles them to exit.

The agent holds the identity the kernel accepts, so it delivers the signal on
request::

    lota-agent --terminate-protected <pid>
    lota-agent --terminate-protected <pid> --force   # SIGKILL

It answers for whoever ``kill(2)`` would already have allowed -- the owner of
the process, or root -- so a player ends their own game as themselves, with no
``sudo``. It reports how many other processes are still protected, not
counting the one it signalled. Nothing else widens: only ``SIGTERM`` and
``SIGKILL`` are relayed, a process nobody protected is refused because an
ordinary ``kill`` reaches it, and the agent will not end itself this way.

The exchange is that the host says so. Every relayed termination is journalled
with the target, its owner and the caller, and the host reports
``PROTECTED_TERMINATED`` in its status and in every token until it reboots.
A publisher then sees a session that was ended on the machine rather than a
process that silently disappeared -- closing a hung game is the ordinary reason
for it, and what says *which* process left is the protected set the token
already carries.

Pausing and removing
====================

* **Pause:** ``sudo lota-install --pause`` (a wrapper over
  ``lota-agent --shutdown``). The agent deliberately cannot be killed (the
  kill-block is the anti-tamper surface), and the graceful shutdown poisons PCR
  14 before unloading -- so **resume requires a reboot**. That is the security
  contract, not a bug: same-boot re-attestation after a shutdown would let a
  tampered session pose as the original one.
* **Resume:** ``sudo lota-install --resume`` explains that resuming is a reboot
  and offers to reboot now (default no); the socket-activated agent then
  starts on its own and re-measures into a fresh PCR 14.
* **Remove:** take the host off the kernel floor (drop the cmdline parameters)
  and disable the service. The agent then refuses to run and the host simply
  stops attesting. The design degrades gracefully: ``disabled`` means
  ``fails attestation``, never ``agent runs without its guarantees``.

What leaves this machine
========================

Shown by the installer at the end of every run, repeated here. Each attestation
report to the operator's verifier carries:

* TPM PCR values and a TPM-signed quote,
* Boot event log (which includes the kernel command line and therefore disk
  UUIDs),
* Agent and kernel image hashes,
* IOMMU status,
* Recent process-execution telemetry from the BPF layer (binary paths, hashes,
  PIDs, UIDs),
* Stable device identifier derived by hashing the TPM endorsement key's public
  name,
* AIK certificate whose subject is a CA-issued pseudonym.

During enrollment only, the attestation CA additionally receives the TPM's EK
certificate. No file contents, browsing data or account identity are read or
transmitted.
