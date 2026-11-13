.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

============================
Developer and testing policy
============================

All new work lands on the ``lota-next`` integration branch first.

``main`` carries only stable, released code.

See :doc:`../../process/branching` for the full model and the release flow.

Contents
========

* :doc:`Where the checks run <../../dev-tools/ci>` -- CI triggers, the Go
  toolchain, and dependency rules.
* :doc:`Testing policy <../../dev-tools/testing>` -- test layers and the
  surface-specific contracts they pin.
* :doc:`Local patch checks and the PR quality gate <../../process/patch-checks>` --
  ``check-patch``, ``format-patch``, and the documentation hints.
* :doc:`How the fuzzers work <../../dev-tools/fuzzing>` -- Go, C, and Syzkaller fuzzing.
* :doc:`BPF LSM program coding <../../bpf/coding>` -- verifier-acceptance rules and
  device/inode identity in the kernel programs.
* :doc:`The license boundary <../../process/license-boundary>` -- which zone each path
  belongs to, and the one-way dependency rule the gate enforces.
* :doc:`Public API and ABI surface <../../userspace-api/stability>` -- what an integrator may
  build against, and what a change to it costs.

.. toctree::
   :hidden:

   ../../dev-tools/ci
   ../../dev-tools/testing
   ../../process/patch-checks
   ../../dev-tools/fuzzing
   ../../bpf/coding
   ../../process/license-boundary
   ../../userspace-api/stability
   ../../verifier/report-format
   ../../verifier/store
   ../../agent/protection
   ../../agent/boot-evidence
   ../../agent/ipc
   ../../agent/tokens
   ../../agent/journal
   ../../agent/runtime-measurement
