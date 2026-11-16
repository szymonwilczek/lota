.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

============================
Testing in a virtual machine
============================

A KVM guest with a swtpm backend runs the agent the way a host does, with
the BPF LSM, the TPM and the ``90lota`` dracut module. This page lists what
differs from bare metal and the steps a development guest needs that a
packaged install does for itself.

The TPM state outlives the guest
================================

swtpm keeps the TPM's state in a file on the host. A reboot inside the
guest, or a destroy and start of the domain, does not clear it: the
persistent objects and NV indices of the previous run are still there.

A reboot inside the guest raises the TPM's ``resetCount`` by one. Under
libvirt a destroy and start of the domain raises ``restartCount`` and
leaves ``resetCount`` as it was, so it does not stand in for a cold boot
in the checks that compare ``resetCount`` with the agent's snapshot
(:doc:`../agent/lifecycle`). Restoring an older copy of the state file
brings back the lower ``resetCount`` stored in it.

The guest must boot through UEFI firmware such as OVMF. When
``/sys/firmware/efi`` is absent the ``90lota`` helper exits with status 13,
and the agent logs ``SECURITY: this host did not boot via UEFI`` with the
reason, then refuses to start with ``This host cannot attest: it did not
boot via UEFI.`` With UEFI the helper locks PCR 14 and the agent extends
its commitment onto the lock value.

Starting from a clean slate
---------------------------

A guest reused across agent builds carries the earlier run's AIKs and the
files under ``/var/lib/lota`` that name them. To start over, stop every
unit that runs the agent, ``lota-attest.service`` included, since it runs
an agent of its own on the same key; clear the state; and evict the
persistent handles the agent stores its keys at: ``0x81010002`` for the
host AIK, ``0x81010003`` for the seal primary and ``0x81010010`` to
``0x81010017`` for the publishers' AIKs (:doc:`../agent/tpm`):

.. code-block:: console

   # systemctl stop lota-agent.service lota-agent.socket lota-attest.service
   # find /var/lib/lota -mindepth 1 -delete
   # for h in 0x81010002 0x81010003 \
   >         0x81010010 0x81010011 0x81010012 0x81010013 \
   >         0x81010014 0x81010015 0x81010016 0x81010017; do
   >     tpm2_evictcontrol -C o -c "$h" 2>/dev/null || true
   > done

The loop evicts whatever object is at each handle. When ``aik_handle`` in
``/etc/lota/lota.conf`` names another handle, the host AIK is there; evict
that handle in place of ``0x81010002``.

``sudo scripts/lota-dev-bringup.sh --reset`` does a narrower reset: it
removes the ``aik*``, ``clock*``, ``boot_commit*`` and ``snapshot*`` state
files, evicts the AIK at the ``aik_handle`` the agent reads from
``/etc/lota/lota.conf`` (``0x81010002`` by default), runs
``lota-agent --seal-evict-primary``, which leaves an object at
``0x81010003`` alone unless it is LOTA's seal primary, and leaves the
per-publisher AIKs and their profiles in place. It refuses while
``lota-agent.service`` or ``lota-attest.service`` is active, or while the
daemon's pid file names a live process.

Installing from a read-only source tree
=======================================

When the repository is shared into the guest read-only, for example over
virtiofs, ``make install`` cannot write to it. The install target depends
on ``all``, which writes to ``BUILD_DIR``, and on ``selinux-pp``, which
rebuilds ``selinux/lota.pp`` in the tree whenever ``lota.te``, ``lota.if``
or ``lota.fc`` is newer. Build the policy package on the host, then
install in the guest with a writable build directory:

On the host, in the repository:

.. code-block:: console

   $ make selinux-pp

In the guest, in the shared tree:

.. code-block:: console

   # make BUILD_DIR=/var/tmp/lota-build install

``install`` also runs ``check-hook32``, so the guest needs the 32-bit
toolchain on x86_64 (:doc:`testing`).

SELinux after a hand install
============================

``make install`` copies ``lota.pp`` to ``/usr/share/lota/selinux/`` but
does not load it; ``lota-install``'s SELinux stage and the package scripts
do. After a hand install, or after changing :ghsrc:`selinux/lota.te`, load
it in the guest:

.. code-block:: console

   # semodule -i /usr/share/lota/selinux/lota.pp

``make install`` writes ``/usr/bin/lota-agent`` with the label of the
directory, not ``lota_agent_exec_t`` from :ghsrc:`selinux/lota.fc`.
Without that type, systemd does not transition the daemon into
``lota_agent_t``. Under Fedora's targeted policy a ``bin_t`` daemon runs
as ``unconfined_service_t``, so the rules in :ghsrc:`selinux/lota.te` do
not apply to it. Restore the label after each install, and check that the
type is ``lota_agent_exec_t``:

.. code-block:: console

   # restorecon -v /usr/bin/lota-agent
   # ls -Z /usr/bin/lota-agent

When a denial does not show in the audit log, a ``dontaudit`` rule may be
hiding it. ``sudo semodule -DB`` rebuilds the policy without those rules;
``sudo semodule -B`` puts them back. ``sesearch -A -s lota_agent_t``
shows whether a rule is loaded.
