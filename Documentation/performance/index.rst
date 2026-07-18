.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

===========
Performance
===========

* :doc:`Performance evaluation <evaluation>` -- baseline measurements of the
  LOTA hot paths.
* :doc:`Load testing with the synthetic fleet <load-testing>` -- driving a
  verifier at fleet scale with ``lota-loadgen``.

Methodology, tooling, and the L2/L3 runbooks live in :ghsrc:`benchmarks/README.rst`;
regenerate the raw data with ``make bench`` or :ghsrc:`benchmarks/scripts/run_all.sh`.

.. toctree::
   :hidden:

   evaluation
   load-testing
