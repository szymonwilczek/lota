.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

========
Security
========

Start with the threat model and the reporting policy. Do not file public
issues for exploitable vulnerabilities.

* :doc:`Threat model <threat-model>` -- what LOTA protects, what it enforces,
  and what is out of scope.
* :doc:`Security reporting <reporting>` -- how to report a vulnerability.
* :doc:`Reproducible builds <reproducible-builds>` -- rebuild a release and
  verify its signature.
* :doc:`Attestation CA signing key <ca-key>` -- key ceremony, rotation, and
  topology.

.. toctree::
   :hidden:

   threat-model
   reporting
   reproducible-builds
   ca-key
