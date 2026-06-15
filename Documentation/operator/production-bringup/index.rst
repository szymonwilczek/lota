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
:doc:`../player-install <../player-install>`, including the list of inputs
the operator must ship for it.

Contents
========

* :doc:`Startup gate matrix and automated bring-up <gate-matrix>` -- the gates
  the agent enforces and the developer bring-up script.
* :doc:`Manual reference: host gates <manual-reference>` -- operator key, signed
  BPF object, fs-verity, IMA, the TPM SELinux label, and the AIK / PCR14 reset.
* :doc:`Attestation CA enrollment <ca-enrollment>` -- standing up the CA,
  enrolling a host, and the re-anchor and rotation surfaces.
* :doc:`Sealed keys (offline local attestation) <sealed-keys>` -- sealing
  secrets to boot state and anti-rollback.
* :doc:`What still fails, and operational constraints <post-bringup>` --
  post-bring-up failures, the dev-path threat model, and restart/VM caveats.

.. toctree::
   :hidden:

   gate-matrix
   manual-reference
   ca-enrollment
   sealed-keys
   post-bringup
