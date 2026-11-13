.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

==================
VM testing caveats
==================

The supported development environment is a KVM guest with a swTPM backend
attached over TIS. Two behaviours diverge from bare metal:

* **swTPM persists state across guest reboots.** The TPM resource manager runs
  as a host process backed by an NV state file. A ``sudo reboot`` inside the
  guest does **not** reset the TPM and even
  ``sudo virsh destroy <machine> && sudo virsh start <machine>`` from the
  host keeps the same ``resetCount`` unless the libvirt XML carries
  ``<backend ... persistent_state='no'/>`` or swTPM is started with
  ``--flags startup-clear``. The guest's PCR14 resets to all-zero on each
  Startup(CLEAR) but ``resetCount`` does not advance.

  A guest that boots with the ``90lota`` dracut module comes up normally
  anyway: the helper locks the cleared register, the agent finds the lock
  value and extends its commitment onto it exactly as on hardware. What the
  frozen counter costs is coverage -- the attributions that key off the counter
  moving (a cold boot the agent did not see, a rolled-back TPM state file)
  cannot be exercised on such a guest, so those paths are hardware or
  ``persistent_state='no'`` territory.

  The state that does survive is the TPM's: a guest reused across agent builds
  carries the earlier run's persistent AIK and the witness that names it. To
  start a test run from a clean slate, wipe the witness and evict the
  persistent AIK. ``lota-attest.service`` runs an agent of its own and rewrites
  the witness on its next round, so it has to stop with the daemon:

  .. code-block:: sh

      sudo systemctl stop lota-agent.service lota-agent.socket \
          lota-attest.service
      sudo find /var/lib/lota -mindepth 1 -delete
      # LOTA's handles only; others belong to other TPM users
      for h in 0x81010002 0x81010003 \
               0x81010010 0x81010011 0x81010012 0x81010013 \
               0x81010014 0x81010015 0x81010016 0x81010017; do
          sudo tpm2_evictcontrol -C o -c "$h" 2>/dev/null || true
      done

* **The repo is virtiofs-mounted read-only at** ``/mnt/<dir>``. ``sudo make
  install`` recurses into the ``all`` target through the
  ``install: check-version-tag all`` prerequisite, so ``make`` will try to write
  dependency files to ``build/`` in the current working directory and fail with
  ``EROFS`` on the virtiofs mount. Pass the build directory explicitly on the
  same invocation:

  .. code-block:: sh

      sudo make BUILD_DIR=/var/tmp/lota-build install

* ``sudo make install`` **does not load the SELinux module.** The install rule
  places ``lota.pp`` at ``/usr/share/lota/selinux/lota.pp``, where
  ``lota-install``'s SELinux stage reads it from, but nothing calls
  ``semodule -i`` on its own.
  After any change to :ghsrc:`selinux/lota.te`, rebuild the module on the host (the
  in-tree :ghsrc:`selinux/Makefile` writes to ``tmp/`` in the cwd, which the
  read-only virtiofs blocks), then load the package inside the guest:

  .. code-block:: sh

      # [host]
      cd selinux && make && sha256sum lota.pp
      # [guest]
      sudo semodule -i /mnt/<dir>/selinux/lota.pp

  Verify the rule landed with ``sesearch -A -s lota_agent_t ...`` before
  retrying the agent. The stock policy ``dontaudit``\ s many reads that the
  agent legitimately needs (e.g. securityfs), so denials may be silent: run
  ``sudo semodule -DB`` before reproducing to surface them, then
  ``sudo semodule -B`` to re-enable.

* ``/usr/bin/lota-agent`` **must carry** ``lota_agent_exec_t``. A fresh
  ``make install`` writes the file with the default ``bin_t`` label on systems
  where the in-tree ``lota.fc`` has not been loaded yet; without the executable
  type, ``init_t`` does not transition to ``lota_agent_t`` at exec and the daemon
  runs with no TPM, BPF, or ``/etc/lota`` access. Restore the label after
  install:

  .. code-block:: sh

      sudo restorecon -v /usr/bin/lota-agent
      ls -lZ /usr/bin/lota-agent
      # expect the type lota_agent_exec_t; the SELinux user in front of it is
      # system_u from a package and unconfined_u from a hand install,
      # and restorecon leaves either alone
