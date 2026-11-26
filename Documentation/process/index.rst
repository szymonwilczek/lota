.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

===========
Contributor
===========

Development happens on the ``lota-next`` integration branch. Open pull
requests there, not against ``main``.

* :doc:`Contribution rules <contributing>`
* :doc:`Branch model and release flow <branching>`
* :doc:`Code of Conduct <code-of-conduct>`
* :doc:`Local patch checks and the PR quality gate <patch-checks>` --
  ``check-patch``, ``format-patch``, and the documentation hints.
* :doc:`The license boundary <license-boundary>` -- which zone each path
  belongs to, and the one-way dependency rule the gate enforces.
* :doc:`Security reporting <security-bugs>`
* :doc:`Writing LOTA documentation <../doc-guide/index>`

Local tooling:

* ``scripts/check-patch`` -- local quality gate.
* ``scripts/format-patch`` -- commit-message normaliser.

.. toctree::
   :hidden:

   contributing
   code-of-conduct
   branching
   patch-checks
   license-boundary
   security-bugs
