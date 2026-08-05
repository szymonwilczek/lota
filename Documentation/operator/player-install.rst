.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

======================================
LOTA player install (``lota-install``)
======================================

``lota-install`` is the player-side path onto a LOTA-attested host: one guided,
reboot-resumable command instead of the operator checklist in
:doc:`production-bringup/index <production-bringup/index>`. It drives the
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
     - Player on a single machine
     - Guided stages, consent prompts, reboot resume
   * - :doc:`production bring-up <production-bringup/index>`
     - Operator bringing up fleet hosts, CA and verifier
     - Full manual reference
   * - ``scripts/lota-dev-bringup.sh``
     - Contributor iterating on a dev host
     - Generates a throwaway signing key. Never for production.

Running it
==========

.. code-block:: sh

    sudo lota-install \
        --ca-server ca.example --ca-port 8444 --ca-cert /path/to/ca-tls.crt \
        --verifier verifier.example

CA/verifier endpoints and the trust material paths come from the operator's
install instructions (see "What the operator must ship" below).

``lota-install --status`` prints a read-only report of every stage without
changing anything.

* ``--yes`` skips the per-stage prompts,
* ``--plain`` disables the TUI for logs and scripting.

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

The original scrollback is restored on exit and a one-line result (complete /
reboot required / re-run to continue) is printed to the normal screen. Without a
TTY, or with ``--plain``, the same stages run as a sequential prompted flow
suitable for logs and scripts.

Exit codes: ``0`` complete, ``1`` failed or blocked on missing input, ``2``
usage, ``10`` reboot required -- reboot and re-run the same command, the
installer detects the finished stages from live system state and continues at
the first unmet one.

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
   where the firmware advertises that it honours the request, the extra
   "restore the factory keys" step when the firmware is in setup mode, and
   that enabling Secure Boot leaves distribution kernels bootable. A guest is
   sent to its VM definition instead, since a virtual machine has no firmware
   menu of its own -- ``systemd-detect-virt`` decides that, so the installer
   keeps no list of hypervisors. Everything in that message is read off the
   machine; the installer names no per-vendor menu path or setup key, because
   those differ between firmware revisions of a single model and a confidently
   wrong instruction costs more than a general one.
#. **Package artifacts** -- agent binary, BPF object, systemd units, udev rule
   and dracut module are installed. The installer does not build or download
   anything. Missing artifacts mean the LOTA package has not been installed yet.
#. **Operator trust material** -- the BPF object's signature verifies against
   the operator's public key, and ``/etc/lota/lota.conf`` points the agent at
   that key. Fail-closed: the installer never generates a signing key on the
   player machine -- a locally generated key would let local malware re-sign a
   tampered enforcement object.
#. **Binary immutability** -- enables fs-verity on the agent binary
   (ext4/btrfs/f2fs). On filesystems without verity (XFS, ZFS) it instead
   accepts a signed ``security.ima`` xattr enforced by IMA appraisal, which
   gives the same guarantee.
#. **Initramfs PCR14 lock** -- regenerates the initramfs so the PCR14 lock
   helper runs before any regular userspace. Requires a reboot.
#. **Kernel integrity floor** -- appends ``ima=on ima_appraise=fix`` (plus
   ``module.sig_enforce=1`` / ``lockdown=integrity`` where the running kernel
   lacks them) to the boot entries via grubby. The floor pins the appraisal
   *mode*. Signature content stays distribution or operator-supplied (see the
   production bring-up guide). Requires a reboot.
#. **SELinux fence** -- loads the LOTA policy module if needed and re-triggers
   udev so ``/dev/tpm*`` carries the LOTA-only label.
#. **Reboot checkpoint** -- stops with exit 10 until the boot-chain changes are
   live and PCR 14 carries this boot's initramfs lock. PCR 14 only resets on a
   hardware reset, so this cannot be skipped.
#. **Agent service** -- enables and starts ``lota-agent.service`` and its
   socket.
#. **Enrollment** -- the TPM proves itself to a publisher's attestation CA
   (credential activation) and receives a short-lived AIK certificate, one per
   publisher. Naming a CA here (``--ca-server`` with ``--ca-cert``) enrolls
   with it during the install, which is what an operator provisioning a fleet
   wants. Naming none is the normal player case and is not a blocked stage:
   the publisher is whoever they buy a title from, so the agent enrolls with
   each publisher the first time a title asks for one. Either way the running
   agent renews the certificate on its own against the endpoint recorded in
   the profile, and ``lota-agent --reenroll --ca-cert ...`` stays as a manual
   fallback.

Run ends with a self-check (integrity floor, fs-verity, service, certificate,
and -- when ``--verifier`` is given -- a full attestation round-trip) and a
plain-language summary of exactly what telemetry leaves the machine.

What the operator must ship
===========================

A player install needs these inputs, all fail-closed:

* nothing for **enforcement**: the agent package ships the BPF object, its
  ``.sig`` and the public key at ``/usr/lib/lota/enforcement.pub``, because
  enforcement is host-owned and signed by whoever built the package. All three
  are replaced together by an upgrade. A fleet that signs it with its own key
  re-signs the object and puts its key at ``/etc/lota/policy.pub``, which no
  package owns and the agent prefers whenever it is there;
* optionally an **attestation CA endpoint** (``--ca-server``, ``--ca-port``)
  and its **trust anchor** (``--ca-cert``), to enroll during the install. Both
  or neither: an anchor without an endpoint has nothing to enroll against. A
  player install normally passes neither and lets the agent enroll with each
  publisher when a title first asks;
* optionally the **verifier endpoint** (``--verifier``) for the final
  round-trip check;
* compiled **SELinux module** (``lota.pp``, default
  ``/usr/share/lota/selinux/lota.pp``, override with ``--selinux-module``) on
  SELinux-enforcing distributions.

Distro-native packaging (RPM/DEB whose post-install hooks drive the same stage
engine) is the planned follow-up. Until then the package step is
``sudo make install`` from a release tree plus the operator's bundle.

Pausing and removing
====================

* **Pause:** ``sudo lota-install --pause`` (a wrapper over
  ``lota-agent --shutdown``). The agent deliberately cannot be killed (the
  kill-block is the anti-tamper surface), and the graceful shutdown poisons PCR
  14 before unloading -- so **resume requires a reboot**. That is the security
  contract, not a bug: same-boot re-attestation after a shutdown would let a
  tampered session pose as the original one.
* **Resume:** ``sudo lota-install --resume`` explains that resuming is a reboot
  and offers to reboot now; after it the socket-activated agent starts on its
  own and re-measures into a fresh PCR 14.
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
