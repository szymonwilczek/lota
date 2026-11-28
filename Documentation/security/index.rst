.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

========
Security
========

These pages cover what an attestation from LOTA proves and against whom,
the signing key of the attestation CA, and how a release is checked against
its source. A vulnerability is reported privately, as
:doc:`../process/security-bugs` describes.

* :doc:`threat-model` -- what a party relying on an attestation can rely
  on, against whom, and where it stops.
* :doc:`ca-key` -- the ceremony, rotation and compromise of the key that
  signs AIK certificates.
* :doc:`reproducible-builds` -- building a release again from its tag and
  checking the signed manifests.

.. toctree::
   :hidden:

   threat-model
   ca-key
   reproducible-builds
