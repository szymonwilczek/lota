.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

=============================================
What still fails, and operational constraints
=============================================

What still fails after bring-up
===============================

The most common failures, with the gate that produced them:

* ``Kernel anti-tamper prerequisites are not satisfied``. Check
  ``cat /sys/kernel/security/lockdown`` (must show ``[integrity]`` or
  ``[confidentiality]``), ``cat /sys/module/module/parameters/sig_enforce``
  (must be ``Y``), and ``grep -oE 'ima_appraise=\w+' /proc/cmdline`` (must
  report ``enforce`` or ``fix``).
* ``Agent binary is not protected against offline tampering``. On
  ext4/btrfs/f2fs re-run ``fsverity enable`` on ``/usr/bin/lota-agent``; the
  verity merkle root is bound to the inode, so re-installs invalidate the bit
  and the bring-up script re-enables on every run. On XFS/ZFS (no verity)
  re-sign the binary into its ``security.ima`` xattr and confirm
  ``ima_appraise=enforce``; the agent accepts the signed xattr as equivalent.
* ``BPF object signature verification failed``. The object and the key no
  longer belong to each other. A ``policy_pubkey`` line naming a file that is
  no longer there does not cause this: the agent treats a key that has stopped
  resolving as absent and falls back, so a host an older installer configured
  keeps enforcing after an upgrade moved the key. The packaged key at
  ``/usr/lib/lota/enforcement.pub`` always matches the packaged object, so this
  means a key at ``/etc/lota/policy.pub`` (or one named by ``policy_pubkey``)
  is taking precedence and did not sign this object: move it aside to fall back
  to the packaged one, or re-sign the object with the fleet key.
* ``Failed to load AIK metadata: Key has been revoked``. The TPM has a
  persistent AIK but the operator wiped ``/var/lib/lota``. Either restore the
  metadata backup or evict the AIK handle and reboot so the agent re-provisions
  clean.
* ``PCR14 holds an unexpected value``. Cold reboot. PCR14 only resets on
  hardware reset; warm reboot keeps the value. On UEFI Secure Boot this also
  appears when the ``90lota`` initramfs lock did not run: shim leaves the MOK
  measurement in PCR14, and without the lock recording that baseline at
  ``/run/lota/pcr14_baseline`` the agent cannot anchor its derivation. Confirm
  the dracut module is installed and the initramfs was rebuilt (see
  :doc:`manual-reference`, section 5), then cold reboot.

Threat model implications of the dev path
=========================================

``scripts/lota-dev-bringup.sh`` lays down a self-signed operator key on disk in
``/etc/lota``. That key is the trust root for every BPF object the agent loads
on this host. An attacker with root can re-sign a tampered BPF object with the
same key and the agent will accept the load.

Production deployments treat the signing key as a sealed infrastructure
artefact: kept off-host, rotated through the operator's PKI, and never present
in ``/etc/lota`` on a live machine. The bring-up script's key generation is
explicitly developer-only.

Operational constraints
=======================

Agent restart requires reboot
-----------------------------

The agent's ``lota_task_kill`` LSM hook blocks ``SIGTERM`` and ``SIGKILL``
delivered from any other task -- including PID 1 -- because the hook treats the
agent itself as a protected target. This is the load-bearing surface that
prevents a local-root attacker from killing the agent out of band, dropping the
BPF coverage, and swapping a tampered binary into place before the next
attestation.

The trade-off is that ``systemctl restart lota-agent`` does **not** work the way
it does for other units. After the stop request, the old process keeps running,
refuses to release ``/run/lota/lota.sock`` and the BPF maps, and the next
``ExecStart=`` fails with ``-EPERM`` when libbpf tries to recreate the same map
names. The unit then loops on ``Restart=on-failure`` while the original PID
stays alive forever.

Two supported paths exist:

#. **Graceful via IPC.** ``ExecStop=/usr/bin/lota-agent --shutdown`` sends a
   privileged IPC command to the running agent; the handler sets
   ``g_agent.running = 0``, which exits the daemon loop cleanly. As long as the
   IPC socket is reachable and the agent is not wedged in a syscall, this is the
   canonical update path and does not require a reboot.
#. **Cold reboot.** If the IPC path is unreachable (agent hang, socket gone,
   kernel deadlock) the only remaining recovery is to reboot the host. There is
   no kill-bypass for PID 1 and there never will be: every grace window would be
   an attack surface for an init-domain compromise. Operators planning updates
   therefore schedule them alongside a regular maintenance reboot.

Continuous attestation
----------------------

``lota-agent.service`` only enforces locally (BPF LSM, PCR14 commitment); it
does not attest. A deployed host proves its state through a second unit,
``lota-attest.service``, which runs ``lota-agent --attest`` fire-and-forget and
renews the CA-issued AIK certificate before it expires. It is a separate unit
on purpose: the attestation loop is network-facing, so isolating it from the
enforcement daemon keeps that security core on a tight seccomp and capability
profile. The attest unit itself runs with no effective capabilities at all
(``SecureBits=noroot-locked`` with an empty ambient set), reaches the TPM only
through ``DeviceAllow``, and cannot load BPF or disable enforcement. A
compromise of the attest process at worst stops fresh attestations, which the
verifier sees as staleness and marks untrusted.

The unit arms a 60 s systemd watchdog: the attest loop pings it on a cadence
independent of ``attest_interval``, so a loop wedged on the TPM or a stalled
TLS socket misses the deadline and systemd restarts it.

Which unit a title talks to
~~~~~~~~~~~~~~~~~~~~~~~~~~~

``lota-agent.service`` owns ``/run/lota/lota.sock``, and it is the only unit
that does. It is the always-on one, it is what ``lota-agent.socket`` activates,
and it holds everything about the machine a title asks after: the BPF LSM
state, the enforcement policy digest a token carries, the Secure Boot and IOMMU
findings, and the publisher list a title selects from.

What it does not hold is a verifier's verdict, so the attestation loop connects
to that same socket as a local peer and trades state with it once per round --
verdicts out, sessions and enrollment requests in. That exchange is refused
unless the peer is the same agent binary running as the same user, and it is
never something an integrator sends: the SDK has no such call.

Two consequences worth knowing:

* **Stopping ``lota-attest.service`` does not stop a title from getting an
  answer.** The socket stays up and enforcement keeps running; what goes stale
  is the verdict, which is exactly what a verifier is watching for. Session-gated
  publishers stop being reported to, which is the safe direction.
* **Stopping ``lota-agent.service`` takes the socket down with it.** A title
  gets a connection failure rather than a wrong answer, and the attest loop
  keeps attesting and retries the link every 30 s. Session gating and runtime
  enrollment are off for that window, and the loop says so in the journal.

The verifier, port, CA certificate and cadence come from
``/etc/lota/lota.conf`` (``server``, ``port``, ``ca_cert``, ``attest_interval``);
no attestation flags are hardcoded in the unit. A zero ``attest_interval``
means this host never chose a cadence: with a ``[profile]`` list it attests to
every configured publisher at the default 300 s, and only a host with no
profile at all falls back to attesting once to ``server`` and exiting. A
non-zero value has to fall between the floor and the ceiling the agent prints
in ``--help``; the agent refuses to start on anything else, since an interval
past the ceiling mints tokens that sit outside every relying party's freshness
window.

``ca_cert`` must point at a path the hardened unit can read. The service runs
with ``ProtectHome=yes`` and ``ProtectSystem=strict``, so a certificate left in
an operator home directory (the ``--ca-cert ~/tls.crt`` used for a manual
``--enroll``) is invisible to it. Copy the verifier CA certificate under
``/etc/lota`` (root-owned, the unit mounts it read-only) and point ``ca_cert``
there, for example::

   sudo install -m 0644 verifier-ca.crt /etc/lota/verifier-ca.crt
   # then in /etc/lota/lota.conf: ca_cert = /etc/lota/verifier-ca.crt

A host that answers to more than one publisher lists them as ``[profile "name"]``
sections instead. Each section names the attestation CA it enrolls against, the
trust anchor that CA is verified with, the verifier it reports to, and
optionally its own cadence; ``ca_port`` and ``verifier_port`` default to the
same ports as the top-level keys. A profile missing the CA, the anchor or the
verifier is refused at load, and every anchor has to satisfy the same
readability constraint as the top-level ``ca_cert`` above.

Every key below a section header belongs to that section, so the top-level keys
go above the first profile and nothing top-level may follow one.
``lota-agent --dump-config`` prints profiles last for the same reason, which is
also what makes its output loadable again. See :ghsrc:`configs/lota.conf.example`
for a worked pair of profiles.

The section name is a label for the operator. A profile is identified by its
trust anchor's public key, so a publisher moving their CA to another address
keeps the same profile, and two publishers sharing a hostname cannot collide.
Publisher policy stays with the publisher: a profile grants no publisher any
say over this host's enforcement.

The list is what the attestation loop reports to. Every profile's verifier gets
its own report on that profile's cadence, signed with that publisher's own AIK,
and each profile carries its own failure state -- one unreachable verifier
backs off its own reporting and leaves the others on schedule. Since the list
replaces the single verifier rather than adding to it, ``--server`` and
``--pin-sha256`` are refused while profiles are configured; each profile is
anchored by its own ``ca_cert``.

A title says which publisher it plays for, and gets that publisher's answers.
It names the profile by the lowercase hex SHA-256 of that publisher's CA trust
anchor SubjectPublicKeyInfo -- the identity the profile directory is named
after, which the publisher knows about their own CA -- through
``publisher_profile`` in ``struct lota_connect_opts`` or
``struct lota_ac_config``. The connection's tokens are then signed by that
publisher's AIK, and the attested state it reads is that publisher's verifier's
verdict rather than every publisher on the host agreeing. Naming a publisher
this machine holds no enrollment for fails the connection: handing a title
another publisher's evidence under its own name would be worse than telling it
plainly.

A title that names nobody -- which is every enterprise integration, where the
host has one publisher -- gets the first profile's token and the host-wide
answer: attested only while **every** configured publisher is satisfied, with
the window closing at the earliest of theirs.

**A profile reports only while a title of its publisher is running.** That is
what ``reporting`` selects, and ``session`` is a profile's default: a report is
the only thing that leaves the machine, and a verifier receiving one every few
minutes from boot to poweroff learns when the player's machine is on, for a
game that is closed. A session is a title's connection to the agent, so it ends
when the process does, whether it exited or was killed. Set
``reporting = continuous`` on a profile whose fleet the operator owns and whose
continuous stream is the point; the single-verifier configuration keeps that
behaviour unchanged.

Enforcement and the PCR 14 boot commitment are never gated. They are local,
they send nothing, and they are what lets a session's first quote still prove
the whole boot-to-now window: the quote is a fresh signed read of state that
already existed. On-demand *enforcement* would prove nothing, which is why only
reporting follows the session.

While no title of a publisher's is running, that publisher has no live verdict:
the agent stops reporting to them and reports the host as not attested for
them. A title that names no publisher reads the host-wide answer, which is now
every *currently reporting* publisher agreeing -- and not attested when nothing
is reporting at all, since nothing is being checked.

**Nothing enrolls with a publisher until somebody here agrees to it.** An
attestation key is a stable handle that publisher can recognise this machine
by, so the decision to hand one out is recorded before the key exists, in the
profile directory. ``lota-agent --allow-publisher <hex>`` writes it, naming the
publisher by the SHA-256 of their CA anchor's SubjectPublicKeyInfo -- the same
identity everything else uses. ``lota-agent --enroll`` records it too: somebody
with root named that CA and asked for the key, which is the same decision made
a different way, and it keeps one rule for the agent to enforce.

A title that selects a publisher nobody has agreed to is refused with a
distinct error (``LOTA_ERR_CONSENT_REQUIRED``, readable through
``lota_connect_last_error()``) rather than a generic failure, because it is a
screen to show the player rather than a fault to report. Whatever shows that
screen calls ``--allow-publisher`` when they accept.

**What this machine holds for whom is inspectable, and revocable.**
``lota-agent --list-publishers`` shows every publisher with anything stored
here: when it was agreed to, where it enrolled, which TPM handle holds its
attestation key and how much validity that key's certificate has left.
``lota-agent --forget-publisher <hex>`` destroys that key and deletes the rest,
in that order -- a key with no directory left to name it would be worse than
either state alone, so nothing is deleted if the eviction fails.

Forgetting is about the identity, not about refusing the publisher. A profile
still in ``lota.conf`` can be agreed to again, and enrolls with a **new** key
that the old evidence cannot be linked to.

**Enrollment with a profile's publisher is a runtime action.** A profile that
names a CA (``ca``, ``ca_port``, ``ca_cert``) and has never enrolled is
enrolled by the agent itself: when the loop first reaches that publisher, and
immediately when a title selects it, which is the moment that matters on a
player's machine. Until it completes, that publisher's status is not attested
and the agent sends no report to their verifier -- evidence with no certificate
to chain is refused anyway. A failing CA backs off rather than being retried
every round, and the other publishers keep their cadence throughout.

Operator fleets that enroll at install time are unaffected: ``lota-agent
--enroll`` writes the same record, and a profile that already has one is never
re-enrolled. An enrollment token cannot be presented on the runtime path (a
publisher admitting players has no way to hand each of them a secret in
advance), so a CA that requires one has to be enrolled against with
``--enroll --enroll-token-file``.

First enrollment stays operator-driven. ``lota-attest.service`` carries
``ConditionDirectoryNotEmpty=/var/lib/lota/profiles`` and stays inactive until
the operator's first ``lota-agent --enroll`` creates a profile there (the
directory itself ships with the package, so only its contents say anything);
afterwards the loop renews the certificate automatically. Start it after the first enrollment
(or it activates on the next boot):

.. code-block:: sh

   sudo systemctl enable --now lota-attest.service

Installing the package enables nothing. ``lota-install`` enables the units it
brings up -- the agent socket, the enforcement daemon and the attestation
loop -- so a host that has not been through bring-up runs neither, and a
``dnf install`` on a machine nobody is sitting at cannot start enforcing on
its own.

VM testing caveats
------------------

The supported development environment is a KVM guest with a swTPM backend
attached over TIS. Two behaviours diverge from bare metal and the agent's
startup gates treat them as integrity violations unless the operator works
around them.

* **swTPM persists state across guest reboots.** The TPM resource manager runs
  as a host process backed by an NV state file. A ``sudo reboot`` inside the
  guest does **not** reset the TPM and even
  ``sudo virsh destroy <machine> && sudo virsh start <machine>`` from the
  host keeps the same ``resetCount`` unless the libvirt XML carries
  ``<backend ... persistent_state='no'/>`` or swTPM is started with
  ``--flags startup-clear``. The guest's PCR14 resets to all-zero on each
  Startup(CLEAR) but ``resetCount`` does not advance; the agent's witness records
  the old ``(resetCount, last_extend)`` tuple and the next start reports
  ``PCR14 cleared while resetCount=N unchanged since last extend``. Before each
  test run on a guest without that XML setting, wipe the witness and evict the
  persistent AIK:

  .. code-block:: sh

      sudo systemctl stop lota-agent.service lota-agent.socket
      sudo find /var/lib/lota -mindepth 1 -delete
      for h in 0x81010002 0x81010003 0x81010004 0x81010005 \
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
  lands ``lota.pp`` under the source tree but does not call ``semodule -i``.
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
  agent legitimately needs (e.g. kallsyms, securityfs), so denials may be
  silent: run ``sudo semodule -DB`` before reproducing to surface them, then
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
      # expect: system_u:object_r:lota_agent_exec_t:s0
