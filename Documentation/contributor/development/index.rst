============================
Developer and testing policy
============================

All new work lands on the ``lota-next`` integration branch first.

``main`` carries only stable, released code.

See `../branching.rst <../branching.rst>`_ for the full model and the release flow.

Contents
========

* `Where the checks run <where-checks-run.rst>`_ -- CI triggers, Go toolchain, and dependency rules.
* `Testing policy <testing-policy.rst>`_ -- test layers and the surface-specific contracts they pin.
* `Local patch checks and the PR quality gate <patch-checks.rst>`_ --
  ``check-patch``, ``format-patch``, and the hotpath documentation contract.
* `How the fuzzers work <fuzzing.rst>`_ -- Go, C, and Syzkaller fuzzing.
* `Release candidates and promotion <release-flow.rst>`_ -- cutting ``-rc``
  tags and promoting to ``main``.
* `BPF LSM program coding <bpf-coding.rst>`_ -- verifier-acceptance rules and
  device/inode identity in the kernel programs.
* `Cross-component contracts <contracts.rst>`_ -- wire-format, store-migration,
  and installer-probe surfaces two components must keep in sync.
