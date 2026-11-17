.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

==============
Startup checks
==============

The daemon checks the host each time it starts, in the order listed in
:doc:`../../agent/index`. This page lists the checks a bring-up has to
meet, and the script that meets them on a development host.

Host checks
===========

.. list-table::
   :header-rows: 1
   :widths: 30 35 35

   * - Check
     - On failure
     - To meet it
   * - Kernel lockdown at ``integrity`` or ``confidentiality``
     - Refused, exit status 78.
     - Secure Boot on a kernel that locks itself down under it, or
       ``lockdown=integrity`` on the command line (:doc:`../platform-support`).
   * - ``/sys/module/module/parameters/sig_enforce`` reads ``Y``
     - Refused, exit status 78.
     - Secure Boot, or ``module.sig_enforce=1`` on the command line.
   * - IMA appraises executables
     - Warning; tokens report ``KERNEL_APPRAISAL`` clear.
     - An IMA policy with an appraise rule for ``BPRM_CHECK``
       (:doc:`manual-reference`).
   * - ``/dev/tpmrm0`` and ``/dev/tpm0`` labelled ``lota_tpm_device_t``
     - Refused, exit status 78. With no TPM device present, or with no
       SELinux policy loaded, a warning. ``--insecure-allow-mutable-rootfs``
       turns a wrong label into a warning.
     - The udev rule and the SELinux module (:doc:`manual-reference`).
   * - The enforcement object's signature verifies
     - Refused, exit status 78; PCR 14 untouched.
     - ``<object>.sig`` beside the object, made with the key the daemon
       reads (:doc:`manual-reference`).
   * - The object's ``integrity_cfg`` layout matches the agent's
     - Refused, exit status 78; PCR 14 untouched.
     - An object built from the same release as the agent.
   * - The host booted via UEFI
     - Refused, exit status 78.
     - :doc:`../platform-support`.
   * - An AIK in the TPM has its record on disk
     - Refused, exit status 78.
     - :doc:`../../agent/tpm`.
   * - PCR 14 holds the initramfs lock or this binary's commitment
     - Refused, exit status 78.
     - A cold reboot after the initramfs carries ``lota``
       (:doc:`../../agent/lifecycle`).
   * - The kernel loads and attaches the enforcement object
     - ``Failed to load BPF program`` or ``Failed to attach BPF programs``,
       with the BPF library's own lines around it. A refused load adds ``A
       restart does not change the object or the kernel, so the agent stays
       stopped.`` and exits 78.
     - A kernel at or above the floor (:doc:`../platform-support`). The
       load and the attach follow the PCR 14 extend: after a failed load a
       start in the same boot carries ``AGENT_RESTARTED`` until reboot,
       after a failed attach the start is refused until reboot
       (:doc:`../../agent/lifecycle`).

Each refusal is a line at error level in ``journalctl -u lota-agent``. A
check that fails on a transient error, such as ``EIO`` or ``ENOMEM``, exits
1 instead. A refusal with exit status 78 keeps ``lota-agent.service`` in
the ``failed`` state, since the unit does not restart on it, and stops
``lota-agent.socket`` (:doc:`../../agent/lifecycle`).
The lockdown and signature checks run in every mode
(:ghsrc:`src/agent/bpf_loader.c`). With Secure Boot on, their refusal
names the kernel parameter to add; with it off, it points to the firmware
setting and ``lota-install --status``.

Mode
====

The five switches of ``lota.conf`` take effect only with ``mode = enforce``
(:doc:`../../bpf/index`). In ``monitor`` the daemon logs a line opening
``Armed and inert in`` that names the switches that are on, and
``lota-agent --dump-config`` prints the same list:

.. code-block:: text

   mode = monitor
   # mode = monitor leaves inert: strict_mmap, block_ptrace, block_anon_exec

Development host
================

``scripts/lota-dev-bringup.sh`` runs from a checkout, after ``sudo make
install``. That target copies the files, the SELinux module and the udev
rule; it loads neither of them and does not rebuild the initramfs. The
script runs as root and exits 2 otherwise, or on an unknown option.

.. code-block:: sh

   sudo make install
   sudo scripts/lota-dev-bringup.sh
   sudo reboot

In order, the script:

#. generates ``/etc/lota/policy.key`` and ``/etc/lota/policy.pub`` with
   ``lota-agent --gen-signing-key``, when either is missing;
#. signs ``/usr/lib/lota/lota_lsm.bpf.o`` with that key, unless
   ``lota-agent --verify-policy`` already accepts its signature under
   ``/etc/lota/policy.pub``;
#. copies ``configs/lota.conf.example`` to ``/etc/lota/lota.conf`` when the
   file is missing;
#. adds ``policy_pubkey = /etc/lota/policy.pub`` above the first profile
   section when no ``policy_pubkey`` line is there, and keeps the file as
   it was when ``lota-agent --dump-config`` refuses the result;
#. loads ``configs/ima/lota-ima-policy`` into the kernel only when the
   kernel appraises, appraisal is not in enforce, and the loaded policy
   does not already appraise executables. Under Secure Boot appraisal is
   in enforce, and the script only warns.

Each step that finds its result in place says so and skips. A failed step
ends the run with exit status 1 and keeps what the steps before it did.

``--reset`` also deletes the ``aik*``, ``clock*``, ``boot_commit*`` and
``snapshot*`` files in ``/var/lib/lota``, evicts the AIK at the
``aik_handle`` the agent reads from ``lota.conf``, and evicts the seal
primary with ``lota-agent --seal-evict-primary``. It leaves the AIKs of
the profiles in place. This destroys the host's attestation identity: a
certificate for the old AIK does not match the new one. It refuses while
``lota-agent.service`` or ``lota-attest.service`` is active, or while the
PID in ``/run/lota/lota-agent.pid`` is alive.

``LOTA_BRINGUP_ROOT`` prefixes the paths under ``/etc``, ``/usr``,
``/var``, ``/run``, ``/proc`` and ``/sys`` and lifts the root check, for
tests; systemd and the TPM are not redirected.
