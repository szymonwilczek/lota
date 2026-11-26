.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

============================
Developer and testing policy
============================

All new work lands on the ``lota-next`` integration branch first.

``main`` carries only stable, released code.

See :doc:`../process/branching` for the full model and the release flow.

* :doc:`Where the checks run <ci>` -- CI triggers, the Go
  toolchain, and dependency rules.
* :doc:`Testing policy <testing>` -- test layers and the
  surface-specific contracts they pin.
* :doc:`How the fuzzers work <fuzzing>` -- Go, C, and Syzkaller fuzzing.
* :doc:`VM testing caveats <vm-testing>`

.. toctree::
   :hidden:

   ci
   testing
   fuzzing
   vm-testing
