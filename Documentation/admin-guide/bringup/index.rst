.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

===================
Production bring-up
===================

These pages bring up a host step by step, without ``lota-install``: a host
built from source, where the operator signs the enforcement object with a
key of their own, or a fleet that provisions hosts with its own tooling.
``lota-install`` walks one machine through the same requirements and asks
before each change (:doc:`../lota-install`). The requirements of the
platform are in :doc:`../platform-support`, and the order in which the
daemon checks them in :doc:`../../agent/index`.

* :doc:`Startup checks <gate-matrix>` -- what the daemon checks before it
  starts, what a failed check does, and ``scripts/lota-dev-bringup.sh``,
  which meets them on a development host.
* :doc:`Manual steps <manual-reference>` -- the policy signing key and the
  signed object, the IMA policy, the label of the TPM device, and clearing
  the agent's TPM state.
* :doc:`Attestation CA enrollment <ca-enrollment>` -- the CA of a publisher
  and enrolling a host with it.
* :doc:`Sealed keys <sealed-keys>` -- secrets the TPM releases only in an
  expected boot state.
* :doc:`After bring-up <limitations>` -- what still fails on a host that
  passes every check.

.. toctree::
   :hidden:

   gate-matrix
   manual-reference
   ca-enrollment
   sealed-keys
   limitations
