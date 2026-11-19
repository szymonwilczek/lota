.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

==================
LOTA documentation
==================

Linux Open Trusted Attestation (LOTA) attests the boot and the runtime state
of a Linux host to a remote party, with the host's TPM. This is the top level
of its documentation, grouped by what the reader does with LOTA.

Playing a game that uses LOTA
=============================

One page for a player: installing LOTA on a PC, so that a game can check
it. It assumes no prior knowledge.

.. toctree::
   :maxdepth: 1
   :caption: Playing a game that uses LOTA

   player/index

Running LOTA
============

Installing hosts, the packages and images, and running the verifier with
its fleet tooling.

.. toctree::
   :maxdepth: 1
   :caption: Running LOTA

   admin-guide/index

How LOTA works
==============

The agent on the attested host, the BPF LSM program it loads, the verifier
that checks its reports, and what an attestation proves.

.. toctree::
   :maxdepth: 1
   :caption: How LOTA works

   agent/index
   bpf/index
   verifier/index
   security/index

Integrating LOTA
================

The C and Go libraries that a game, its server and an anti-cheat use. The
example programs are listed in :ghsrc:`examples/README.rst`;
:ghsrc:`examples/anticheat-integration.rst` describes what a studio forking
the anti-cheat reference copies, links against and has to change.

.. toctree::
   :maxdepth: 1
   :caption: Integrating LOTA

   userspace-api/index

Developing LOTA
===============

How a change reaches LOTA, how it is tested, how its documentation is
written, and the tools that measure what LOTA costs.

.. toctree::
   :maxdepth: 1
   :caption: Developing LOTA

   process/index
   dev-tools/index
   doc-guide/index
   performance/index

Next to the code
================

Some components are described in a ``README.rst`` in their own directory.

* :ghsrc:`policies/README.rst` -- PCR policies of the verifier.
* :ghsrc:`selinux/README.rst` -- the SELinux policy module.
* :ghsrc:`configs/ek-roots/README.rst` -- bundles of TPM manufacturer
  roots for the attestation CA.
* :ghsrc:`examples/README.rst` -- the example programs and how they are
  built.
* :ghsrc:`benchmarks/README.rst` -- the micro-benchmarks.
* :ghsrc:`syzkaller/README.rst` -- kernel fuzzing of the BPF LSM.
* :ghsrc:`fuzz/regressions/README.rst` -- reproducers of the C fuzz
  targets.
