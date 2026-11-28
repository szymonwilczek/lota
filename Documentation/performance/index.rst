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

* :doc:`evaluation` -- the figures the tools gave on one reference host.
* :doc:`load-testing` -- ``lota-loadgen`` and a synthetic fleet against a
  live verifier.
* :doc:`lota-bench` -- the cost of LOTA to a running game, from cgroups
  and frame times.
* :doc:`agent-bench` -- what ``lota-agent --bench`` writes about the
  daemon, its BPF programs and the processes it protects.

.. toctree::
   :hidden:

   evaluation
   load-testing
   lota-bench
   agent-bench
