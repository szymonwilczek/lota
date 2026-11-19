.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

=================
Development tools
=================

These pages describe how LOTA is tested: the test suites and the targets
that run them, the fuzzers, the CI workflows that run them, and what
differs when the agent runs in a virtual machine.
The checks a patch must pass before review are in
:doc:`../process/patch-checks`.

* :doc:`testing` -- unit and integration tests, sanitizers, valgrind,
  Postgres-backed tests, the Go coverage ratchet and the tree gates.
* :doc:`ci` -- the workflows, what triggers them and what each job runs.
* :doc:`fuzzing` -- the Go and C fuzz targets, the BPF decision oracles and the
  committed reproducers.
* :doc:`vm-testing` -- a KVM guest with a software TPM.
* :ghsrc:`syzkaller/README.rst` -- kernel fuzzing of the BPF LSM.

.. toctree::
   :hidden:

   testing
   ci
   fuzzing
   vm-testing
