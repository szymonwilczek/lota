.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

========================
LOTA production bring-up
========================

This document walks an operator through the full set of prerequisites the
``lota-agent`` daemon enforces at startup. The agent is deliberately strict:
every gate documented below is a hard fail in production because the
corresponding bypass is part of the threat model (kernel module load, ptrace,
/proc/mem inspection, tampered BPF object, PCR14 rebind, ...).

There is **no shortcut**. The full chain is documented here and automated by
``scripts/lota-dev-bringup.sh`` for developer-host iteration. Production hosts
run the equivalent steps through their distro integrity tooling (signed RPMs,
kernel cmdline provisioned at install, IMA policy from
``/etc/sysconfig/integrity``, operator key in a sealed store).

This document is the operator/fleet reference. A player installing the agent on
a single machine uses the guided, reboot-resumable ``lota-install`` instead --
same gates, consent prompts and live-state probes -- see
`../player-install.rst <../player-install.rst>`_, including the list of inputs
the operator must ship for it.

Contents
========

* `Startup gate matrix and automated bring-up <gate-matrix.rst>`_ -- the gates
  the agent enforces and the developer bring-up script.
* `Manual reference: host gates <manual-reference.rst>`_ -- operator key, signed
  BPF object, fs-verity, IMA, the TPM SELinux label, and the AIK / PCR14 reset.
* `Attestation CA enrollment <ca-enrollment.rst>`_ -- standing up the CA,
  enrolling a host, and the re-anchor and rotation surfaces.
* `Sealed keys (offline local attestation) <sealed-keys.rst>`_ -- sealing
  secrets to boot state and anti-rollback.
* `What still fails, and operational constraints <post-bringup.rst>`_ --
  post-bring-up failures, the dev-path threat model, and restart/VM caveats.
