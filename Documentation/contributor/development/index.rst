.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

============================
Developer and testing policy
============================

All new work lands on the ``lota-next`` integration branch first.

``main`` carries only stable, released code.

See :doc:`../branching <../branching>` for the full model and the release flow.

Contents
========

* :doc:`Where the checks run <where-checks-run>` -- CI triggers, the Go
  toolchain, and dependency rules.
* :doc:`Testing policy <testing-policy>` -- test layers and the
  surface-specific contracts they pin.
* :doc:`Local patch checks and the PR quality gate <patch-checks>` --
  ``check-patch``, ``format-patch``, and the hotpath documentation contract.
* :doc:`How the fuzzers work <fuzzing>` -- Go, C, and Syzkaller fuzzing.
* :doc:`Release candidates and promotion <release-flow>` -- cutting ``-rc``
  tags and promoting to ``main``.
* :doc:`BPF LSM program coding <bpf-coding>` -- verifier-acceptance rules and
  device/inode identity in the kernel programs.
* :doc:`Cross-component contracts <contracts>` -- wire-format, store-migration,
  and installer-probe surfaces two components must keep in sync.
* :doc:`The license boundary <license-boundary>` -- which zone each path
  belongs to, and the one-way dependency rule the gate enforces.

.. toctree::
   :hidden:

   where-checks-run
   testing-policy
   patch-checks
   fuzzing
   release-flow
   bpf-coding
   contracts
   license-boundary
