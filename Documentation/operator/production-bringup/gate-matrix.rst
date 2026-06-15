.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

==========================================
Startup gate matrix and automated bring-up
==========================================

Startup gate matrix
===================

The agent's startup chain refuses to load BPF / attach LSM programs unless
every entry below is satisfied. Source references are file:line into the
current tree.

.. list-table::
   :header-rows: 1
   :widths: 28 32 40

   * - Gate
     - Check site
     - Operator action
   * - ``lockdown=integrity`` (or confidentiality)
     - ``src/agent/bpf_loader.c::kernel_lockdown_restrictive()``
     - Boot under Secure Boot or pass ``lockdown=integrity`` on the kernel
       cmdline.
   * - ``module.sig_enforce=1``
     - ``src/agent/bpf_loader.c::kernel_module_sig_enforced()``
     - Fedora 44 ships this by default. On distros that do not, add
       ``module.sig_enforce=1`` to the cmdline.
   * - IMA appraisal in an enforcing mode
     - ``src/agent/bpf_loader.c::kernel_ima_appraise_enforcing()``
     - Add ``ima_appraise=enforce`` (or ``fix``) to the kernel cmdline. ``log``
       and the default ``off`` do not satisfy the gate.
   * - ``/dev/tpm{rm,}0`` carries ``lota_tpm_device_t``
     - ``src/agent/bpf_loader.c::tpm_device_selinux_label_ok()``
     - Install the udev rule under ``configs/udev/99-lota-tpm.rules`` (handled by
       ``make install``) and run ``udevadm trigger``.
   * - fs-verity on ``/usr/bin/lota-agent``
     - ``src/agent/bpf_loader.c::agent_self_fsverity_enabled()``
     - Filesystem must have the verity feature enabled. Run
       ``fsverity enable /usr/bin/lota-agent`` (or let bring-up do it).
   * - BPF object Ed25519 signature
     - ``src/agent/bpf_loader.c::verify_bpf_object_signature()``
     - Sign ``lota_lsm.bpf.o`` against the operator key, install the ``.sig``
       next to the ``.o``, point ``policy_pubkey`` at the PEM.
   * - AIK persistent handle + metadata in sync
     - ``src/agent/tpm.c::tpm_aik_load_metadata()``
     - Evict any stale persistent handle (``tpm2_evictcontrol``) before first
       start so the AIK metadata is initialised cleanly.
   * - PCR14 fresh after boot
     - ``src/agent/tpm.c::tpm_extend_boot_commitment()``
     - Cold reboot before the first agent start; PCR14 only resets on hardware
       reset.

Every gate maps to a ``lota_err()`` line in the journal when it fails, so
``journalctl -u lota-agent`` is the canonical debugging surface.

Automated developer bring-up
============================

``scripts/lota-dev-bringup.sh`` runs the steps above in a fixed order:

.. code-block:: sh

    sudo make install                                  # land agent + BPF + units
    sudo scripts/lota-dev-bringup.sh                   # gate the host
    sudo reboot                                        # PCR14 baseline rebind
    sudo systemctl start lota-agent.socket lota-agent.service
    sudo systemctl status lota-agent.service --no-pager

The script is idempotent and prints which step it ran or skipped so re-runs
after a partial failure are safe. Read it before running.
