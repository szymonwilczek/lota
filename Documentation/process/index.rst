.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

====================
Contributing to LOTA
====================

These pages describe how a change reaches LOTA: which branch it targets,
what a commit carries, which checks it has to pass, and under which license
each file sits. A suspected vulnerability follows its own path, set out in
:doc:`security-bugs`.

* :doc:`contributing` -- commit format, sign-off, code style, and what a pull
  request carries.
* :doc:`branching` -- ``lota-next``, ``main``, release tags and the two
  documentation channels.
* :doc:`patch-checks` -- ``scripts/check-patch``, ``scripts/format-patch`` and
  the pull request quality gate.
* :doc:`license-boundary` -- the MIT and GPL-2.0-only zones and the gate that
  keeps them apart.
* :doc:`security-bugs` -- private reporting and disclosure.
* :doc:`code-of-conduct` -- conduct in issues, pull requests, reviews and
  security reports.
* :doc:`../doc-guide/index` -- how the documentation is written.

.. toctree::
   :hidden:

   contributing
   branching
   patch-checks
   license-boundary
   security-bugs
   code-of-conduct
