.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

CS2 verification scenarios
==========================

Operator-runnable proof that the LOTA Wine/Proton hook produces a useful signal
during a live Counter-Strike 2 launch, and that the LOTA agent's runtime
enforcement layer actually rejects untrusted binaries against the same process
tree that hosts the hook.

Each scenario is a short walk-through that uses the artefacts already
documented in `examples/cs2/README.rst <../README.rst>`__ and adds a single
verification surface on top.

.. list-table::
   :header-rows: 1
   :widths: 40 60

   * - Scenario
     - What it proves
   * - `verify-attested.sh <verify-attested.sh>`__
     - watcher script that prints the ``TRUSTED / UNTRUSTED / OFFLINE`` verdict
       every time the hook flips state
   * - `agent-down.rst <agent-down.rst>`__
     - hook degrades gracefully when the agent goes down and re-attaches when it
       comes back; CS2 keeps running
   * - `lib-block.rst <lib-block.rst>`__
     - BPF LSM (``security_mmap_file``) blocks an unauthorised ``LD_PRELOAD``
       library before its constructor can run

The scenarios run on the same Fedora 44 + ``--test-signed`` setup the main CS2
walk-through bootstraps (real TPM Quote plus the in-tree fixture policy digest,
no production policy file needed). ``lib-block.rst`` is the exception: it
requires the full enforce-mode agent because the LSM gates only fire once the
BPF object is attached.
