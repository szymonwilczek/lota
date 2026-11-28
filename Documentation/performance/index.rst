.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

===========
Performance
===========

These pages cover the tools that measure LOTA and the figures they gave.
The micro-benchmarks time the verification and SDK hot paths
(:ghsrc:`benchmarks/README.rst`), ``lota-loadgen`` drives a verifier with a
synthetic fleet, and ``lota-bench`` measures what LOTA costs a running game.
None of these three ships in the packages.

.. toctree::
   :maxdepth: 1

   evaluation
   load-testing
   lota-bench
   agent-bench
