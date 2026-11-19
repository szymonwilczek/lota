.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

============
Threat model
============

LOTA attests the boot and the runtime state of a Linux host to a remote
party: a game publisher's anti-cheat, or the operator of a fleet. This page
states what that party can rely on, against whom, and where it stops. Each
mechanism is described on its own page, linked from here.

LOTA reports what the host is running. Judging a player, a title or a
device is left to the anti-cheat or the operator on top of it.

Properties
==========

Against the adversaries below, a party that verifies a report or a token
can rely on these:

* The key that signed it lives in a TPM whose endorsement key certificate
  chains to a manufacturer root the attestation CA trusts. The CA proves
  that by credential activation before it certifies the key
  (:doc:`../admin-guide/bringup/ca-enrollment`).
* The verifier accepts a report only with an AIK certificate from the CA it
  trusts. It keeps no key of its own, so a key it has seen before gains
  nothing.
* A report answers a one-time nonce from the verifier, so it does not
  replay (:doc:`../verifier/index`). A token carries an expiry and the
  caller's nonce, when the caller gives one (:doc:`../agent/tokens`).
* PCR 0, 1, 7 and 14 enter every verification, and the verifier pins them
  per client (:doc:`../verifier/index`).
* The host booted through UEFI, and, where the policy asks, with Secure Boot
  on and a kernel command line free of the denylist. Both are read from the
  event log the quote binds (:ghsrc:`policies/README.rst`).
* PCR 14 names the agent binary that took the boot
  (:doc:`../agent/lifecycle`).
* While the agent runs, the kernel refuses a debugger, a read of process
  memory through ``/proc`` and a stopping signal aimed at a protected
  process from outside its instance, and reports the code objects the
  process maps (:doc:`../agent/protection`,
  :doc:`../agent/runtime-measurement`).
* A release can be rebuilt from its tag and checked against a signed
  manifest (:doc:`reproducible-builds`).

Adversaries
===========

A process on the host without root
  A cheat run by the player's own user, or another program on the machine.
  This is the adversary the enforcement on the host is built against.

The owner of the machine, with root
  Root reaches ``/dev/tpmrm0``, and the CA certifies any restricted signing
  key on a certified TPM, so root can sign a token or a report with any
  flags, runtime digest, protected PIDs or stopped time. Against root, what
  holds is what the TPM signs itself: the quoted PCR values, the nonce, and
  the TPM the key lives in. The device ID comes from the endorsement key
  (:doc:`../admin-guide/bringup/ca-enrollment`), so a ban outlasts a new
  enrollment.

The network
  The agent reaches the CA and the verifier over TLS and checks their
  certificates against a pinned anchor or the system store
  (:doc:`../agent/command-line`). The host is known by its AIK.

The kernel and the firmware are trusted as they booted. Their measurements
describe what was loaded; nothing in LOTA proves that a kernel which booted
clean stays honest.

Components
==========

Host
  The agent runs as root, holds the TPM, loads the BPF LSM programs, measures
  protected processes and builds reports and tokens. The checks the host
  has to pass before the agent starts are in
  :doc:`../admin-guide/bringup/gate-matrix`.

Attestation CA
  Sees the endorsement key certificate at enrollment and issues a
  short-lived AIK certificate. The endorsement key goes no further: a report
  has no field for it.

Verifier
  Checks the AIK certificate, the quote, the event log, the policy and the
  per-client baselines, and keeps revocations, bans and the audit log
  (:doc:`../verifier/index`).

Relying party
  Verifies the token a client presents, and optionally the boot evidence
  beside it (:doc:`../userspace-api/server`). The verifier gives it no
  credential of its own to check.

Threats
=======

.. list-table::
   :header-rows: 1
   :widths: 22 39 39

   * - Threat
     - Control
     - Limit
   * - A software attester
     - Credential activation against an endorsement key that chains to a
       pinned manufacturer root (:doc:`../admin-guide/bringup/ca-enrollment`).
     - The CA trusts the roots the operator pins. A root of a software TPM,
       pinned, certifies software.
   * - A replayed report
     - One-time nonces with an expiry; used nonces are recorded in the store
       (:doc:`../verifier/store`).
     - With ``--allow-insecure-memory-state`` the instance keeps the last
       10000 nonces, in memory.
   * - Fields of a report the agent states
     - The quote's ``extraData`` binds the flags, the agent and kernel hashes
       and the IOMMU state (:doc:`../verifier/report-format`).
     - They hold what an unmodified agent saw. Root can state anything.
   * - Firmware or Secure Boot drift
     - PCR 0, 1 and 7 are pinned by the policy or at first use, and moved
       only on the re-anchor paths (:doc:`../verifier/index`).
     - Firmware changed before a client's first attestation is pinned as
       found on the first-use road.
   * - Secure Boot off, to boot a modified kernel
     - ``require_secureboot`` reads the firmware's ``SecureBoot``
       measurement from the PCR 7 events before the separator.
     - A kernel signed by a key in ``db`` or MOK passes, whatever it does.
       The verifier lists the keys of each client
       (:doc:`../verifier/monitoring-api`) and judges none.
   * - A signed kernel with a hostile command line (``init=``,
       ``rd.break``, ``lockdown=none``)
     - ``require_cmdline_policy`` checks every command line measured into
       PCR 8 against the denylist (:ghsrc:`policies/README.rst`).
     - Only GRUB measures the command line into PCR 8. A quoted PCR 8 of zero,
       as under systemd-boot or a UKI, skips the check. The denylist names
       parameters one by one.
   * - A modified agent
     - PCR 14 carries the hash of the agent that took the boot, and
       ``agent_hashes`` lists the builds the policy accepts
       (:doc:`../verifier/index`).
     - A modified agent that extends an accepted hash passes; that takes
       root. With an empty ``agent_hashes`` the verifier pins the first hash
       a client reports. It refuses to load a policy with no PCR values,
       no ``kernel_hashes`` and no ``agent_hashes`` without
       ``--allow-permissive-policy``, and one that sets
       ``require_secureboot`` with no PCR values and no ``agent_hashes``
       without ``--allow-unpinned-agent``
       (:doc:`../verifier/command-line`).
   * - PCR 14 written before the agent
     - The initramfs helper extends a lock value before user space, and the
       agent refuses a register something else extended
       (:doc:`../agent/lifecycle`).
     - PCR 14 is writable from the operating system. Code that runs before
       the helper can write it.
   * - Code swapped into a protected process
     - The agent measures every code object the process maps. In
       ``enforce`` mode ``strict_mmap`` refuses one that is neither on the
       fs-verity allow-list nor a trusted library
       (:doc:`../agent/runtime-measurement`, :doc:`../bpf/index`).
     - Anonymous executable memory and a memfd carry no digest. They are
       reported as missing coverage; in ``enforce`` mode ``block_anon_exec``
       refuses executable anonymous memory.
   * - A debugger or a memory read
     - The LSM refuses ``ptrace`` and the ``/proc`` entries that read memory
       from outside the instance (:doc:`../agent/protection`).
     - Inside an instance every access passes and is recorded. Outside the
       protected set the kernel's own rules apply.
   * - Stopping or ending a protected process
     - The LSM refuses a stopping or dumping signal from outside the
       instance. ``--terminate-protected`` ends one through the agent, which
       reports it (:doc:`../agent/protection`).
     - A frozen cgroup stops a process without a signal; the token reports
       the time as ``stopped_ms``.
   * - A kernel module or a kexec image
     - The agent starts only with module signatures enforced and lockdown at
       ``integrity`` or above (:doc:`../admin-guide/bringup/gate-matrix`).
       The LSM refuses a kexec image in every mode, and in ``enforce`` mode
       with ``strict_modules`` a module or firmware off the fs-verity
       allow-list (:ghsrc:`include/lota.h`).
     - A module signed by a MOK key loads. A kernel vulnerability is out of
       reach.
   * - DMA from a device
     - The agent reports the IOMMU state, and ``require_iommu`` refuses a
       host without it.
     - The flag holds what the agent saw.
   * - A revoked or weak endorsement key
     - Manufacturer CRLs, and a refusal of ROCA moduli
       (:doc:`../admin-guide/bringup/ca-enrollment`).
     - An issuer with no CRL loaded is not checked.
   * - A swapped release artifact
     - A reproducible build and a signed manifest
       (:doc:`reproducible-builds`).
     - The packages are built with Fedora's toolchain, not the one of the
       first manifest, and are checked against a second one.

Identity and linkability
========================

Each publisher has its own AIK on a host, derived from the publisher's
identity (:doc:`../agent/tpm`), and the CA derives the device ID from the
endorsement key, its pseudonym key and the tenant
(:doc:`../admin-guide/bringup/ca-enrollment`). The device ID and the AIK in
the certificate a publisher's CA issues therefore differ from those another
publisher's CA issues; the tenant name can be the same. Each CA receives
the endorsement key certificate at enrollment, and that certificate is the
same for every publisher.

The evidence links them. A publisher whose titles check tokens reads the
boot PCRs and the Secure Boot measurements behind them; one that runs a
verifier also receives the event log, which names the disk the host boots
from. Every publisher receives the same values, so two that compare them
can tell they are looking at one machine. The agent says so when a player
agrees to a publisher and in ``--list-publishers``
(:ghsrc:`src/agent/enroll_client.c`).

Root of trust
=============

The boot measurements come from the static root of trust: the firmware
measures itself, its configuration and the Secure Boot state, and the boot
loader measures what it loads, before the kernel runs. A kernel booted
afterwards cannot take those measurements back.

The verifier refuses a report whose PCR mask omits PCR 0, 1 or 7, and one
whose event log carries no firmware measurement of the ``SecureBoot``
variable into the quoted PCR 7. Legacy BIOS measures no EFI variables, so a
host booted that way does not attest. Whether Secure Boot must be on is
``require_secureboot``.

PCR 7 is the anchor for a trusted kernel: it records the Secure Boot keys
and the authority that signed each image, and stays the same across kernel
updates signed by the same key. ``kernel_hashes`` pins the image digest the
boot loader measured into PCR 9, and needs PCR 9 quoted and the event log
replaying to it (:ghsrc:`policies/README.rst`).

The boot commitment
-------------------

PCR 14 holds the initramfs lock value and the agent's commitment chained on
it, and the verifier derives the expected value from the two
(:doc:`../verifier/index`). A host without the initramfs helper does not
attest, and the agent refuses to start there (:doc:`../agent/lifecycle`).

* Within a boot the register cannot be reset from user space, so a second
  writer moves it off the value the reported hash derives.
* A cold boot clears it, and the helper and the agent extend it in that
  order. A commitment already present after a reset means something ran
  before the agent.
* Freshness comes from the nonce. The same host running the same agent has
  the same commitment every boot.
* A suspend to RAM restores the register (:doc:`../agent/tpm`).

PCR 14 names the binary that committed; it does not show that the binary
is still running.

Dynamic root of trust
---------------------

LOTA uses no dynamic root of trust (Intel TXT, AMD SKINIT). A deployment
that needs the kernel's runtime integrity adds a layer below the kernel,
such as a measuring hypervisor or a confidential-computing environment.

Tenants
=======

The CA assigns a device its tenant and writes it into the AIK certificate
as the subject's ``OrganizationalUnit``; no OU is the ``default`` tenant.
The CA takes it from the enrollment token the host presents or from its
tenant manifest, or, with neither, puts the device in ``default``;
:doc:`../admin-guide/bringup/ca-enrollment` gives the order and the
enrollments it refuses.
The verifier reads it after the certificate chain checks out, and refuses a
certificate with more than one OU or a malformed name
(:ghsrc:`src/verifier/verify/tenant.go`). A report cannot change it.

Bans, revocations, baselines and the audit and decision logs carry the
tenant, and a ban applies in its tenant alone. A signed policy can name the
tenant it applies to. A monitoring API key scoped to tenants sees only
theirs (:doc:`../admin-guide/multi-tenancy`). The checks on the device are
the same in every tenant.

Audit
=====

Every admin route of the monitoring API that changes a client's state
refuses a request without an ``actor`` and a ``reason``. On an instance
with an audit log, both go into the action's row
(:doc:`../verifier/monitoring-api`). The ``actor`` is the text the caller
sends; the verifier does not tie it to the admin key that made the request.

Non-goals
=========

* Detecting cheats by their behaviour: memory, input, game state or
  network.
* Keeping a local root from the TPM. A relying party tracks the PCR digest
  of each device, bans its identity, and judges play on its server.
* Proving that a running kernel stays honest. A kernel compromised after
  boot produces the same boot measurements and runs under the agent.
* Measuring anonymous executable memory.
* Guarding memory a protected process shares with an unprotected one, or
  sections a wineserver started outside the instance hands it. Executable
  mappings of such memory are flagged writable (:doc:`../agent/protection`).
* Recording how a title was started: its arguments, working directory or
  environment.
* Making PCR 14 read-only to the operating system.

Operating requirements
======================

A deployment:

* installs the agent with its SELinux policy, udev rule, initramfs helper
  and signed BPF object (:doc:`../admin-guide/packages`,
  :doc:`../admin-guide/bringup/index`);
* enrolls each host through the CA, with an RSA endorsement key
  (:doc:`../admin-guide/bringup/ca-enrollment`);
* keeps the CA's manufacturer roots, intermediates and CRLs for the TPMs it
  supports;
* holds the CA key in a token (:doc:`ca-key`);
* runs the verifier with the CA root and a policy that lists
  ``agent_hashes`` (:doc:`../verifier/command-line`);
* verifies a release before installing it (:doc:`reproducible-builds`);
* reboots a host after an agent update (:doc:`../admin-guide/agent-update`).
