LOTA PCR Policies
=================

This directory contains PCR (Platform Configuration Register) policy templates
for the LOTA verifier.

Policy Files
------------

=================== ===================================================
File                Purpose
=================== ===================================================
``testing.yaml``    Minimal policy for development/testing environments
``production.yaml`` Template for production deployments
``strict.yaml``     High-security policy for competitive gaming
=================== ===================================================

Creating Custom Policies
------------------------

.. _1-export-baseline-from-target-system:

1. Export Baseline from Target System
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Run the LOTA agent on the target system to generate a complete policy:

.. code:: bash

   # Export full policy YAML to file
   sudo lota-agent --export-policy > my-policy.yaml

   # Or redirect diagnostic output
   sudo lota-agent --export-policy 2>/dev/null > my-policy.yaml

.. _2-customize-policy:

2. Customize Policy
~~~~~~~~~~~~~~~~~~~

The exported policy is ready to use as-is. Optionally edit to:

- Remove PCR values you don't want to enforce
- Adjust security requirements
- Change the policy name

.. code:: yaml

   name: my-production
   description: "My production environment policy"

   pcrs:
     0: "abc123..." # From baseline export
     1: "..." # From baseline export
     7: "def456..." # Secure Boot anchor, from baseline export
     8: "..." # Kernel cmdline (GRUB); PCR 12 on systemd-boot/UKI

   # kernel_hashes is advisory only (self-reported, spoofable) - leave empty
   # and trust the kernel via PCR 7 + PCR 8. See "Kernel trust" below.
   kernel_hashes: []

   agent_hashes:
     - "sha256_hash_of_lota_agent"

   require_iommu: true
   require_enforce: true

.. _3-deploy-policy:

3. Deploy Policy
~~~~~~~~~~~~~~~~

.. code:: bash

   # Start verifier with custom policy
   lota-verifier --policy /path/to/my-policy.yaml

PCR Meanings (SHA-256 Bank)
---------------------------

===== =========== =========================================
PCR   Measured By Description
===== =========== =========================================
0     UEFI        SRTM - firmware code measurements
1     UEFI        UEFI configuration data
2     UEFI        Option ROM code
3     UEFI        Option ROM configuration
4     UEFI        Boot loader code (GRUB/systemd-boot)
5     UEFI        GPT/MBR partition table
6     UEFI        Resume from S4/S5 state transitions
7     UEFI        Secure Boot state (policies/certificates)
8     OS          Kernel command line (grub2 measured boot)
9     OS          Bootloader-loaded files (kernel/initrd)
10    OS          Linux IMA measurements (if enabled)
11-13 OS          Application-defined
14    LOTA        Agent self-measurement
15    OS          Reserved
16-23 Apps        Application use
===== =========== =========================================

Security Requirements
---------------------

+----------------------------+--------------------------+----------------------+
| Requirement                | Description              | Typical Default      |
+============================+==========================+======================+
| ``require_iommu``          | DMA protection via       | ``true``             |
|                            | VT-d/AMD-Vi              |                      |
+----------------------------+--------------------------+----------------------+
| ``require_enforce``        | SELinux/AppArmor in      | ``true``             |
|                            | enforce mode             |                      |
+----------------------------+--------------------------+----------------------+
| ``require_module_sig``     | Kernel module signature  | Distro-dependent     |
|                            | enforcement              |                      |
+----------------------------+--------------------------+----------------------+
| ``require_secureboot``     | Secure Boot enabled      | ``true``             |
|                            | (event-log enforced)     |                      |
+----------------------------+--------------------------+----------------------+
| ``require_lockdown``       | Kernel lockdown mode     | ``false`` (optional) |
|                            | active                   |                      |
+----------------------------+--------------------------+----------------------+
| ``require_cmdline_policy`` | Kernel cmdline denylist  | ``true``             |
|                            | (event-log enforced)     |                      |
+----------------------------+--------------------------+----------------------+
| ``cmdline_deny``           | Operator extensions to   | ``[]``               |
|                            | the cmdline denylist     |                      |
+----------------------------+--------------------------+----------------------+

.. _kernel-trust-event-log-secure-boot--cmdline-policy:

Kernel trust: event-log Secure Boot + cmdline policy
----------------------------------------------------

Raw PCR pins (the ``pcrs:`` map) authenticate one firmware/bootloader
configuration and suit a homogeneous enterprise fleet. They cannot serve a
diverse single-machine population: PCR 7 differs per OEM key set and drifts on
dbx updates, and PCR 8 hashes the per-machine ``root=UUID``. The two knobs
below are the machine-independent alternative. Both read the TPM event log the
agent already ships and trust an extracted value only after the log replay
reproduces the TPM-quoted value of the PCR it came from, so a client cannot
fabricate or strip the underlying events. ``require_secureboot`` also unlocks
the diverse-fleet enrollment path: see "Boot enrollment ceremony" below for how
it lifts the per-machine PCR 0/1/7 pinning requirement.

``require_secureboot`` requires the firmware-measured ``SecureBoot`` EFI
variable (PCR 7, ``EV_EFI_VARIABLE_DRIVER_CONFIG``) to be present and enabled.
The agent-reported Secure Boot header flag is telemetry only; a compromised
kernel sets it freely. This check is bootloader-independent. Players must have
Secure Boot enabled in firmware setup; any kernel signed for Secure Boot
(including self-signed via MOK) passes, so custom performance kernels stay
usable.

``require_cmdline_policy`` requires the GRUB-measured kernel command line (PCR
8, ``EV_IPL``) to be free of denylisted parameters. The builtin denylist
rejects parameters that defeat the signed kernel's integrity guarantees and
never appear on a stock distribution command line:

+--------------------------------------+--------------------------------------+
| Entry                                | Why                                  |
+======================================+======================================+
| ``init=`` / ``rdinit=``              | arbitrary userspace entry point      |
+--------------------------------------+--------------------------------------+
| ``rd.break``                         | dracut pre-pivot root shell          |
+--------------------------------------+--------------------------------------+
| ``lockdown=none``                    | disables kernel lockdown             |
+--------------------------------------+--------------------------------------+
| ``module.sig_enforce=0``             | unsigned kernel modules              |
+--------------------------------------+--------------------------------------+
| ``selinux=0`` / ``enforcing=0`` /    | LSM off                              |
| ``apparmor=0`` / ``security=none``   |                                      |
+--------------------------------------+--------------------------------------+
| ``systemd.debug_shell``              | root shell on tty9                   |
+--------------------------------------+--------------------------------------+
| ``kgdboc=``                          | kernel debugger console (live memory |
|                                      | patch)                               |
+--------------------------------------+--------------------------------------+

Per-machine parameters (``root=UUID``, ``rootflags``, cosmetics) are ignored,
so one policy covers every machine. ``cmdline_deny`` extends the list per
fleet. Matching normalizes the kernel's ``-``/``_`` parameter-name equivalence.

Bootloader coverage: GRUB measures the command line into PCR 8 and is fully
checked. systemd-boot/UKI hosts measure the command line into PCR 12 via
sd-stub and skip the cmdline check (the quoted PCR 8 must be zero - a non-zero
PCR 8 with no measured cmdline events is treated as a truncated log and
rejected); ``require_secureboot`` applies everywhere regardless of bootloader.

Boot enrollment ceremony
------------------------

The production verifier defaults to
``VerifierConfig.RequireBootEnrollment = true``. Under that default the
verifier rejects any client whose PCR 0, PCR 1, or PCR 7 cannot be matched
against a known-good baseline. Three paths satisfy that contract:

1. **Pinned policy (homogeneous fleet).** The operator commits real PCR 0/1/7
   values into the YAML policy (production.yaml or strict.yaml) before the
   first attestation. New clients are accepted only when their live PCR 0/1/7
   match those pins. production.yaml ships its ``pcrs:`` block commented out;
   uncomment and fill it to pick this path.

2. **Out-of-band boot enrollment.** The operator runs
   ``lota-agent --export-policy`` on a single known-good host, signs the
   resulting policy, and ships it to the fleet; subsequent clients inherit the
   PCR 0/1/7 baseline from the signed policy without contacting the verifier
   first.

3. **Event-log-anchored enrollment (diverse fleet).** Raw PCR 0/1/7 differ per
   machine, so a diverse single-machine population (the gamer deployment) can
   satisfy neither path above. When the active policy sets
   ``require_secureboot: true`` and the report's quote-authenticated event log
   proves Secure Boot enabled, the verifier accepts the first attestation and
   TOFU-establishes the per-device PCR 0/1/7 row without any extra switch. This
   is a production-supported mode, not a weakened test path: the
   boot-with-Secure-Boot-off cheat is already rejected machine-independently by
   the event-log gate, so the TOFU row serves as a per-device
   rollback/consistency anchor (later drift in PCR 0/1/7 still rejects), not as
   the firmware trust control. The verifier logs a security-level line on every
   such first-use accept. Residual trust: firmware tampering that keeps Secure
   Boot enabled and reaches the device before its first attestation is not
   caught at first use; pair with ``require_cmdline_policy`` (production
   default) for the kernel command line, and see Documentation/security/threat-model.rst for the
   full residual-risk statement.

   Because the per-device PCR 0/1/7 row is a rollback anchor, a later
   *legitimate* firmware update (BIOS) also shifts PCR 0/1 and would reject the
   device until an operator clears its row. Start the verifier with
   ``-enable-self-service-reanchor`` to let it re-pin the baseline itself when
   the drift preserves the Secure Boot root of trust (PK/KEK/db unchanged,
   ``dbx`` append-only, Secure Boot still on, firmware version not rolled
   back); a host with no ESRT firmware version takes a Low-Firmware-Assurance
   path. The LFA re-anchor also applies automatically -- the player is never
   blocked -- but flags the device for post-fact operator review
   (``GET /api/v1/reanchor/review``, cleared with
   ``POST /api/v1/clients/{id}/reanchor-review-ack``). See
   Documentation/operator/production-bringup/index.rst. This is a diverse-fleet convenience only; do not
   enable it where raw PCR 0/1/7 are pinned in policy.

A short-lived ``--allow-tofu-boot-baseline`` switch on the verifier exists for
closed test fixtures. It explicitly weakens the contract above by accepting
whatever PCR 0/1/7 the first attestation reports regardless of policy or
event-log state; the verifier emits a warning-level log line on every accept
under that switch and the operator must turn it back off before the deployment
is considered production. A diverse fleet does not need it - path 3 covers that
case with the Secure Boot anchor intact.

PCR 14 (LOTA agent self-measurement) is not TOFU. It is derived
deterministically from the boot-commitment chain
(``tpm_boot_commitment_digest``) and the verifier rederives the same value
during signature verification; an agent rebuild that legitimately changes the
self-measurement is handled by updating the signed policy rather than by
trusting whatever value the next attestation happens to report.

Kernel trust
------------

Kernel is bound through the TPM-rooted boot measurements, not through a hash
the agent reports about itself:

- **PCR 7 (Secure Boot) is the anchor.** It reflects the signing chain that
  authorized the kernel, so a kernel signed by a trusted key keeps the same PCR
  7 across updates. Pinning it means "only a trusted-signed kernel booted" with
  no per-kernel maintenance: the distribution re-signs each kernel with the
  same key. This is the recommended baseline for every host.
- **PCR 8 (kernel command line) is recommended.** On GRUB the cmdline and boot
  config are measured into PCR 8; pinning it rejects a correctly signed kernel
  booted with a sabotaged command line (``init=``, ``lockdown=none``,
  ``module.sig_enforce=0``). The cmdline rarely changes, so this stays
  low-maintenance. On systemd-boot/UKI the cmdline is measured into PCR 12 -
  pin 12 there instead of 8.
- **``kernel_hashes`` is advisory only, not a trust control.** The value is the
  agent's userspace ``sha256(/boot/vmlinuz)``, self-reported by code running on
  the kernel, so a compromised kernel can spoof it. Leave it empty and rely on
  PCR 7 + PCR 8. A mismatch is at most a weak cross-check, never the boundary.
- **Exact-image (PCR 4/9) and a kernel-version floor are optional and not in
  the default templates.** Pinning the exact kernel image or initrd (PCR 4/9)
  adds anti-rollback at the cost of a per-kernel hash treadmill; a sound
  low-maintenance version floor needs the measured UKI ``.osrel`` and is
  revisited when systemd-boot/UKI is in scope. A kernel version read from
  userspace is spoofable and must never gate attestation.

Secure Boot must be on for PCR 7 to mean anything; that is the one firmware
setting a host needs for kernel trust to hold.

Updating Policies
-----------------

When software is updated:

1. PCR 7 stays stable across kernel updates (same signing key), so a signed
   kernel upgrade needs no policy change. Do not maintain per-kernel
   ``kernel_hashes`` - leave them empty (see "Kernel trust").
2. Update ``agent_hashes`` when the LOTA agent binary is upgraded.
3. PCR 0/1/7 typically only change with firmware or Secure Boot key updates;
   PCR 8 only when the kernel command line changes.
4. Clear the TOFU baseline if the agent binary changes legitimately.

.. code:: bash

   # Re-export policy after updates
   sudo lota-agent --export-policy > updated-policy.yaml
