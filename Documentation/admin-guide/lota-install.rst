.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

=============================
Guided install (lota-install)
=============================

``lota-install`` brings one machine up as a LOTA-attested host. It runs a
fixed list of stages; each stage probes the live state of the machine, and a
stage that is not satisfied explains the change it makes and asks before it
makes it. A run stops for the reboot the boot-path stages need, and the same
command run again after it starts over from the probes, so it continues at the
first stage still unmet. The stages are in :ghsrc:`installer/stages.c`, the
probes in :ghsrc:`installer/probe.c` and the options in
:ghsrc:`installer/main.c`.

The installer ships in the agent package as ``/usr/bin/lota-install``, and the
package's post-install script runs it (`Package installs`_). The same
requirements by hand, for fleet hosts, are in :doc:`bringup/index`; the walk
through for a player is :doc:`../player/index`.

Usage
=====

::

   lota-install [options]

.. code-block:: console

   $ sudo lota-install --ca-server ca.example --ca-port 8443 \
         --ca-cert publisher-ca.pem --verifier verifier.example
   $ sudo lota-install --status

A run that changes the machine needs root; without it the installer prints
``lota-install changes system state and must run as root`` and exits 2.
``--status`` runs as any user.

Options
=======

Operator inputs
---------------

``--ca-server HOST``, ``--ca-port PORT``
  The attestation CA the enrollment stage enrolls with. Without
  ``--ca-port`` the agent's default, 8444, applies
  (:doc:`../agent/command-line`).

``--ca-cert FILE``
  The CA's certificate, PEM or DER. It names the publisher the host enrolls
  with: the profile under ``/var/lib/lota/profiles/`` is derived from it
  (:doc:`../agent/publishers`). Without it the enrollment stage has nothing to
  do.

``--verifier HOST``, ``--verifier-port PORT``
  The verifier the publisher reports to, and the verifier of the self-check.

``--policy-pubkey FILE``
  The key the enforcement object's signature is verified against
  (`Enforcement trust material`_). Without it the key is the one the agent
  resolves on its own.

``--selinux-module FILE``
  The compiled LOTA SELinux module. Default
  ``/usr/share/lota/selinux/lota.pp``, which the agent package ships.

Each file named by ``--ca-cert``, ``--policy-pubkey``, ``--selinux-module``
and ``--verity-manifest`` must be readable before anything runs; otherwise
the run names the option, the path and the error, and exits 2. The default
SELinux module is not checked there.

Behaviour
---------

``--status``
  Probes every stage and the self-check, prints each verdict and changes
  nothing. It ends with the count of stages that need work. Exit status 0
  when every stage and the self-check are satisfied or not applicable, 1
  otherwise. Without root some probes
  cannot read what they need, and the run says so first.

``--yes``
  Applies each pending stage without asking.

``--plain``
  Line output in place of the interactive view (`Interactive view`_).

``--unattended``
  For a package post-install script; implies ``--yes`` and ``--plain``
  (`Package installs`_). It cannot be combined with ``--pause``, ``--resume``
  or ``--status``.

``--verity-manifest FILE``
  Enables fs-verity on the files the manifest lists, and runs nothing else
  (`fs-verity manifest`_). It cannot be combined with ``--pause``,
  ``--resume``, ``--status`` or ``--unattended``.

``--pause``, ``--resume``
  Stop the agent, and reboot to start it again (`Pause and resume`_).
  ``--pause``, ``--resume`` and ``--status`` exclude each other.

``-h``, ``--help``, ``--version``
  Print the usage or the version and exit 0.

An argument that is not an option is a usage error.

Exit status
-----------

``0``
  The install completed, or the action asked for succeeded.

``1``
  A stage is blocked, failed or was declined, or the self-check failed. With
  ``--status``, a stage needs work. With ``--verity-manifest``, a file was
  not done; with ``--pause`` or ``--resume``, its command failed.

``2``
  A usage error, a named file that cannot be read, a run that needs root
  without it, or a run with no terminal to ask on and no ``--yes``.

``10``
  A reboot is required. Running the same command after it continues the
  install.

``11``
  ``--unattended`` left the boot-path stages to a person.

A run
=====

Each stage probe answers with one of:

done
  Satisfied. The run moves on.

pending
  The stage's change can satisfy it now. The run prints the stage's
  explanation and ``Before this stage:`` with the probe's reason, and asks
  ``Apply this stage?`` (default yes). After the change the stage is probed
  again and must be satisfied; a boot-path stage still pending after a
  change to the boot chain in this run waits for the reboot.

needs reboot
  Satisfied only after a reboot. At the reboot checkpoint this ends the run
  with exit 10; elsewhere the run moves on and the checkpoint stops it.

blocked
  Needs something the installer does not do: a firmware setting, a package, a
  key. The run prints what, and exits 1.

failed
  The probe could not read the state, or the change failed. Exit 1.

Declining a stage ends the run with ``Aborted at your request.`` and exit 1;
nothing after it runs. In plain mode the question takes ``y``, ``yes``,
``n``, ``no``, ``q`` or ``quit``, and an empty line takes the default. Three
answers it cannot read decline the stage. Standard input that is not a
terminal, without ``--yes``, is refused with exit 2 before any stage runs.

The stages run in this order: preflight, package files, enforcement trust
material, the initramfs lock, the kernel integrity floor, the IMA appraisal
scope, the SELinux fence, the reboot checkpoint, the agent service,
enrollment and firmware-update readiness. The self-check ends a run in which
every stage is satisfied.

Interactive view
----------------

When standard output and standard input are terminals, ``TERM`` is not
``dumb`` and ``--plain`` is not given, the run probes every stage, prints the
verdicts, and opens a full-screen view: the stage list, the selected stage's
details and the output of the commands it runs. ``NO_COLOR`` turns colour
off. A terminal that cannot be switched to raw mode falls back to plain
output.

``↑``, ``↓``, ``j``, ``k``
  Select a stage. The view opens on the first unmet one.

``Enter``
  Run the selected stage, or the self-check on its row once every stage is
  satisfied. A pending stage asks for ``y`` or ``Enter``; ``n`` or ``Esc``
  cancels.

``a``
  Run the stages from the first unmet one, asking before each change unless
  ``--yes`` was given, and the self-check once all are satisfied. It stops at
  a stage it cannot apply and at the reboot checkpoint.

``r``
  Probe every stage again.

``PgUp``, ``PgDn``, ``Ctrl-U``, ``Ctrl-D``
  Scroll the output.

``q``, ``Ctrl-C``
  Quit. The exit status is 0 after a passed self-check, 10 when a reboot is
  pending and every stage before the checkpoint is satisfied or waits for
  it, and 1 otherwise; a closing line says which. While a stage runs a
  command, ``Ctrl-C`` stops that command and the view stays open.

Stages
======

Preflight
---------

``Preflight: Hardware and Host Requirements``. Blocked when:

* there is no ``/dev/tpmrm0`` or ``/dev/tpm0``;
* the machine booted through legacy BIOS;
* the firmware has no Secure Boot variable;
* Secure Boot is off or the firmware is in setup mode, with the steps for
  this machine: ``systemctl reboot --firmware-setup`` when the firmware takes
  it, the OVMF Secure Boot build on a virtual machine, and restoring the
  platform keys in setup mode;
* shim validation is off (``MokSBStateRT``), with the ``mokutil
  --enable-validation`` step;
* ``dracut``, ``grubby``, ``systemctl``, ``udevadm`` or ``lsinitrd`` is
  missing.

The stage changes nothing.

Package files
-------------

``LOTA Package Artifacts``. Blocked until these exist:

* ``/usr/bin/lota-agent``;
* ``/usr/lib/lota/lota_lsm.bpf.o``;
* ``/usr/lib/lota/lota-pcr14-lock``;
* ``lota-agent.service`` and ``lota-agent.socket`` in
  ``/usr/lib/systemd/system/``;
* ``/usr/lib/udev/rules.d/99-lota-tpm.rules``;
* ``/usr/lib/dracut/modules.d/90lota/module-setup.sh``.

Enforcement trust material
--------------------------

``Enforcement trust material``. The agent loads the BPF enforcement object
only when its signature verifies (:doc:`../agent/configuration`). The key is
the first of:

#. ``--policy-pubkey``;
#. ``policy_pubkey`` in ``/etc/lota/lota.conf``, read with the agent's
   parser: the last line in either spelling, when the file it names is
   readable;
#. ``/etc/lota/policy.pub``, the key of a fleet that signs enforcement
   itself, when readable;
#. ``/usr/lib/lota/enforcement.pub``, the key the package ships beside the
   object.

The stage runs ``lota-agent --verify-policy /usr/lib/lota/lota_lsm.bpf.o``,
with ``--policy-pubkey`` when one was given. It is blocked when the agent
would refuse ``lota.conf``, when no key is readable, when
``/usr/lib/lota/lota_lsm.bpf.o.sig`` is missing, and when the signature does
not verify; the last names the key, where it came from and, when there is one,
the key the agent would take without it. The installer generates no key and
signs nothing.

With ``--policy-pubkey`` the stage is done only when the ``policy_pubkey``
line of ``lota.conf`` names the file given. Otherwise it is pending and names
the key the agent verifies against until then, and a line naming a file that
is not readable. Its change creates ``/etc/lota/`` and ``lota.conf`` (mode
0644) when missing, and writes ``policy_pubkey = FILE`` after the top-level
keys, ahead of the first ``[profile`` section, so the agent takes it. The new
file keeps the owner, mode and SELinux label of the old one and replaces it
only when the agent's parser reads the key back.

Initramfs lock
--------------

``Boot-time PCR14 lock in the initramfs``. ``lota-pcr14-lock`` runs in the
initramfs and extends PCR 14 before the agent starts
(:doc:`../agent/lifecycle`). For each release in ``/lib/modules`` with a
``/boot/initramfs-<release>.img``, the stage reads the helper out of the
image with ``lsinitrd`` and compares it byte for byte with the installed
``/usr/lib/lota/lota-pcr14-lock``. With no such pair it compares the running
kernel's initramfs. A missing or different copy leaves the stage pending,
naming the releases.

The change runs ``dracut -f --regenerate-all``. A kernel installed later gets
the helper from the dracut module; a new helper reaches an existing image
only through this stage. Boot path.

Kernel integrity floor
----------------------

``Kernel integrity floor on the cmdline``. The agent refuses to start unless
module signatures are enforced (``/sys/module/module/parameters/sig_enforce``)
and lockdown is ``integrity`` or ``confidentiality``. Without IMA appraisal of
executables it starts with a warning, and every token has
``KERNEL_APPRAISAL`` clear (:doc:`../agent/tokens`).

The stage reads the booted kernel. The IMA mode counts as blocking under
Secure Boot, where the kernel takes its built-in mode and ignores
``ima_appraise=``, and otherwise when the command line sets
``ima_appraise=enforce``; a kernel built without IMA appraisal has no mode to
set. When the booted kernel has all three, the stage is done.

Otherwise it reads the default boot entry with ``grubby --info=DEFAULT``.
When that entry already carries the arguments the change would add, the
stage needs a reboot.
When the loaded IMA policy has an ``appraise`` rule, or cannot be read, and
the booted mode blocks nothing, ``ima_appraise=enforce`` would refuse from the
next boot every file such a rule reaches without a valid signature or hash:
the stage leaves it out, and is blocked when it is the only thing missing or
when the default entry carries it already.

The change runs ``grubby --update-kernel=ALL --args`` with the missing ones of
``ima_appraise=enforce``, ``module.sig_enforce=1`` and
``lockdown=integrity``. They apply from the next boot. Boot path.

IMA appraisal scope
-------------------

``IMA appraisal scope``. The kernel applies the appraisal mode to the rules
of its loaded policy, ``/sys/kernel/security/ima/policy``. A token sets
``KERNEL_APPRAISAL`` only for an ``appraise`` rule on ``BPRM_CHECK`` or one
without ``func=``. The stage reports whether the policy has one and, when it
has none, whether the policy demands signed rules (``appraise
func=POLICY_CHECK appraise_type=imasig``).

It loads no rules: a rule cannot name a path, so a rule that appraises the
agent appraises every executable it matches, and under Secure Boot in
enforce. The rules come with signed executables, from IMA-signed packages or
an image pipeline ("IMA appraisal policy" in
:doc:`bringup/manual-reference`). The stage is always done, except without
root, where the policy cannot be read.

SELinux fence
-------------

``SELinux fence on the TPM device``. Done when:

* ``/dev/tpmrm0`` and ``/dev/tpm0``, those present, are
  ``lota_tpm_device_t``;
* ``/usr/bin/lota-agent`` is ``lota_agent_exec_t``;
* ``/var/lib/lota`` is ``lota_var_t`` and ``/etc/lota`` is ``lota_etc_t``,
  when present;
* ``--ca-port`` and ``--verifier-port``, those given, need no port label.

A file system without SELinux labels passes each label check. A port that
cannot be checked, without ``semanage`` or when ``semanage port -l`` fails, is
not met. The stage is blocked when the ``lota`` module is not loaded and the
module file does not exist, and is otherwise pending with each check that is
not met.

The change:

#. ``semodule -i`` the module file, when ``semodule -l`` does not list
   ``lota``;
#. ``udevadm control --reload-rules``, then ``udevadm trigger --action=add``
   on both TPM nodes: the udev rule's ``SECLABEL`` applies on an add event
   only;
#. ``restorecon /usr/bin/lota-agent``;
#. ``semanage port -a -t lota_port_t -p tcp`` for each port given that is
   neither ``lota_port_t`` nor ``http_port_t`` and is not listed alone under
   another type; a failure here does not fail the stage;
#. ``restorecon -R`` on ``/var/lib/lota`` and ``/etc/lota``, when present.

It does not change the SELinux mode. A loaded module is kept, and a done
stage says that ``--selinux-module`` was not loaded. The policy is
:ghsrc:`selinux/README.rst`.

Reboot checkpoint
-----------------

``Reboot checkpoint``. It needs a reboot when an earlier stage of this run
needs one, and names those stages: the ones that rebuilt the initramfs or
changed the kernel command line in this run as changes to the boot chain, and
the others as configured and taking effect on the next boot. Without such a
stage it reads PCR 14 from sysfs:

* the lock value alone: done;
* another value with the agent running: done, this boot's agent commitment;
* another value with no lock run this boot (no ``/run/lota/pcr14_baseline``),
  as from shim's MOK measurement: needs a reboot;
* another value after the lock ran, a stale agent value: needs a reboot;
* zero, the lock has not run: needs a reboot.

An agent paused this boot (`Pause and resume`_) needs a reboot whatever
PCR 14 holds. An agent that failed this boot after loading its BPF program
spent PCR 14 the same way and is blocked: fix the error in ``journalctl -u
lota-agent -b``, then reboot. An agent that already refused to start this
boot, with nothing changed in this run, is blocked: its reason is in
``journalctl -u lota-agent -b``, and a reboot does not change it.

Stopping here prints ``Reboot is required before the install can continue:``
with the reason, and exits 10.

Agent service
-------------

``LOTA agent service``. Pending until ``lota-agent.service`` runs and
``lota-agent.service``, ``lota-agent.socket`` and ``lota-attest.service`` are
enabled. The change runs ``systemctl daemon-reload``, ``systemctl enable
--now lota-agent.socket lota-agent.service`` and ``systemctl enable --now
lota-attest.service``. When the agent does not come up, the stage prints the
last 15 lines of ``journalctl -u lota-agent -b`` and fails. The units are in
:doc:`../agent/lifecycle`.

Enrollment
----------

``Enrollment with a publisher's attestation CA``. Without ``--ca-cert`` the
stage is done: the agent enrolls with each publisher when a title first asks
for it (:doc:`../agent/publishers`). With it, the stage reads the AIK
certificate of the profile ``--ca-cert`` names:

* missing, with ``--ca-server``: pending; the change runs ``lota-agent
  --enroll --ca-server HOST [--ca-port PORT] --ca-cert FILE``;
* missing, without ``--ca-server``: blocked;
* expired: pending; the change runs ``lota-agent --reenroll --publisher ID
  --ca-cert FILE``;
* valid, with ``--ca-server`` and no profile in ``lota.conf`` whose
  ``ca_cert`` names the same publisher: pending;
* valid otherwise: done, with the days left.

After an enrollment or a renewal, or for a valid certificate with no profile,
the change with ``--ca-server`` records the publisher, unless ``lota.conf``
has it:

::

   lota-agent --add-publisher HOST [--ca-port PORT] --ca-cert FILE \
       [--server VERIFIER [--port PORT]] --reporting continuous

``--server`` and ``--port`` are passed only when ``--verifier`` was given.
The run then reloads the agent with ``systemctl try-reload-or-restart
lota-agent.service lota-attest.service``. The options are in
:doc:`../agent/command-line`.

Firmware-update readiness
-------------------------

``Firmware-update readiness``. Reports whether the ESRT has a system
firmware entry (``fw_type`` 1 under ``/sys/firmware/efi/esrt/entries``). On a
verifier that re-anchors without an operator, a firmware update with a
higher version re-pins on the strong path; with no version, on the
low-firmware-assurance path, which lists the client for operator review
("Re-anchor" in :doc:`../verifier/index`). The stage changes nothing and is
always done.

Self-check
----------

``Self-check & summary``. It prints the kernel integrity floor, whether
``lota-agent.service`` is active, the AIK certificate of ``--ca-cert``, the
ESRT state, and then attests:

* with ``--ca-server``, ``--ca-cert`` and ``--verifier``, and the publisher
  recorded in ``lota.conf``: it waits up to 90 seconds for an ``Attested``
  status of ``lota-attest.service`` counting at least the profiles that
  report continuously, and at least one; after a reload in this run, the
  status must also differ from the one before the reload;
* with profiles in ``lota.conf`` otherwise: no round, since each publisher
  has its own verifier; it names ``lota-agent --list-publishers``;
* with no profile and ``--verifier``: one round of ``lota-agent --attest
  --server VERIFIER``, with ``--port`` and ``--ca-cert`` when given;
* with neither: no round.

It fails when the floor is not met, the service is not active, the certificate
of ``--ca-cert`` is not valid, ``lota.conf`` cannot be read whole, the wait
times out or the round fails, and prints ``Self-check failed.`` with exit 1.
The run ends with the list of what each attestation report carries
(`What leaves the machine`_).

Under ``--status`` the self-check row reports readiness and attests nothing.

Package installs
================

The agent package's post-install script
(:ghsrc:`packaging/nfpm/scripts/agent-postinstall.sh`, and ``%post agent`` in
:ghsrc:`packaging/rpm/lota.spec`) runs ``lota-install --unattended`` after the
package files are in place, and ignores its exit status.

A run with ``--unattended``:

* exits 0 at once in a container (``systemd-detect-virt --container``) and on a
  machine without ``/sys/firmware/efi``, such as an image build;
* runs the host-local stages;
* leaves the initramfs lock and the kernel integrity floor to a person, marked
  pending, unless ``/etc/lota/auto-bringup`` exists or ``LOTA_AUTO_BRINGUP`` is
  ``1``;
* stops at the reboot checkpoint, when a stage was left, with exit 11 and the
  names of those stages and ``sudo lota-install`` to finish them;
* after a blocked stage adds ``Package install itself succeeded.``.

With no stage left, it stops at the checkpoint with exit 10 when the boot
chain changed, and otherwise continues through the agent service and the
self-check like any other run.

fs-verity manifest
==================

A title's runtime measurement covers only files with an fs-verity digest
(:doc:`../agent/runtime-measurement`). ``--verity-manifest FILE`` enables it
on the files FILE lists, one absolute path per line; blank lines and lines
starting with ``#`` are skipped, and a path with a ``..`` component is an
error. It needs root (exit 2 without).

Each file already carrying a digest is left alone. The others get SHA-256
with 4096-byte blocks. A file on a file system without fs-verity, or one the
ioctl refuses, is reported and counted. The run ends with the counts of the
files enabled, already carrying a digest and not done, and exits 1 when any
was not done.

The digest belongs to the inode: a file replaced by an update has none until
the manifest runs again.

Pause and resume
================

``--pause`` runs ``lota-agent --shutdown`` after asking ``Pause the agent
now?`` (default no, and none with ``--yes``), and needs root (exit 2
without). Declined, it exits 0 and changes nothing. The agent refuses
signals, and its shutdown extends PCR 14 so the boot cannot attest again
(:doc:`../agent/lifecycle`). A title the agent protects ends with it. The
exit status is 1 when ``lota-agent --shutdown`` fails.

``--resume`` explains that the agent starts again only after a reboot, and
as root asks ``Reboot now to resume?`` (default no) and runs ``systemctl
reboot``, exiting 1 when it fails. Without root, or declined, it prints the
command and exits 0. It says what starts the agent after the reboot: an
enabled ``lota-agent.service`` with the boot, an enabled ``lota-agent.socket``
alone on the first connection, and with neither, that nothing does until
``sudo lota-install`` enables the service.

A protected title is ended with ``lota-agent --terminate-protected``
(:doc:`../agent/protection`).

Titles under Proton or Wine
===========================

A Windows title reaches the agent through ``liblota_wine_hook.so``, which
Steam preloads through the launch option ``lota-proton-hook %command%``
(:doc:`../userspace-api/wine-hook`). ``lota-steam-setup``
(:ghsrc:`scripts/lota-steam-setup`) checks the setup of the account that
starts Steam and prints that launch option.

Without options it checks, in order:

* ``XDG_RUNTIME_DIR`` is set and exists;
* the agent socket (``LOTA_AGENT_SOCKET``, default ``/run/lota/lota.sock``)
  exists and this account can open it;
* the group ``lota`` exists and the account is in it;
* the hook library in ``/usr/lib64`` or ``/usr/local/lib64`` and in
  ``/usr/lib`` or ``/usr/local/lib``; one of the two halves alone is a
  warning, since Steam's launch chain loads both;
* the container socket ``$XDG_RUNTIME_DIR/lota/lota.sock``, after creating
  ``$XDG_RUNTIME_DIR/lota/`` (mode 0750, group ``lota``);
* the token directory ``$XDG_RUNTIME_DIR/lota-hook``, which must be a
  directory this account owns when it exists.

It then prints the launch option, and the ``LD_PRELOAD`` line for a title
started outside the Steam Runtime container. The exit status is 1 when a
check other than the hook library failed.

``--verify``
  The same checks, without creating the container socket directory.

``--register-uid``
  Adds ``container_listener_uid = UID`` to ``/etc/lota/lota.conf``
  (``LOTA_CONF``), with ``UID`` from ``SUDO_UID``, ahead of the first
  ``[profile`` section, or at the end without one
  (:doc:`../agent/configuration`). A UID already there is left alone. It
  needs root through ``sudo`` from the account: a root login has no
  ``SUDO_UID``. The edited file must pass
  ``lota-agent --dump-config``, or the original is restored. The agent reads
  the key at startup, so the container socket appears after the next boot,
  when the account logs in.

``--install-systemd-dropin``
  Writes ``/etc/systemd/system/lota-agent.service.d/10-xdg-runtime.conf``
  (``LOTA_SETUP_DROPIN_DIR``), which sets ``XDG_RUNTIME_DIR=/run/user/UID``
  for the agent, and runs ``systemctl daemon-reload`` unless
  ``LOTA_SETUP_DROPIN_DIR`` is set. It needs ``SUDO_UID`` as well, and root
  unless ``LOTA_SETUP_DROPIN_DIR`` is set. For a host with one such account;
  it cannot be given with ``--register-uid``. It applies at the next boot.

``-h``, ``--help``
  Print the usage.

An unknown option exits 1.

What leaves the machine
=======================

Every run that reaches the self-check prints a list of what leaves the
machine. Each attestation report to a verifier carries
(:doc:`../verifier/report-format`):

* the PCR values and a TPM quote over them;
* the AIK public key and the AIK certificate, whose subject is the device
  pseudonym the CA issued;
* the agent hash, the kernel measurement digest and the kernel path;
* the IOMMU state;
* the security state flags: TPM quote, IOMMU, boot measurement, Secure Boot,
  kernel lockdown, module signatures, IMA appraisal, the PCR 14 boot
  commitment and initramfs lock, whether the agent's LSM is loaded and
  enforcing, which of its mmap, exec, module, anonymous-exec and ptrace
  rules are on, bench mode and lost events;
* the boot event log, with the kernel command line and the disk UUIDs on it;
* the ESRT system firmware entry, or a mark that the platform has none;
* the shim MOK list, empty when it cannot be read.

The attestation CA receives the endorsement key certificate during
enrollment.

Probes and agent gates
======================

The floor and SELinux probes check what the agent checks at startup in
:ghsrc:`src/agent/bpf_loader.c`. A change to a startup check needs the
matching probe changed, and its tests in ``tests/test_installer_probe.c``
(``make test-unit``); a probe left behind reports a host ready that the agent
refuses.
