.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

================================
Release candidates and promotion
================================

Release candidates
==================

Tagging releases is a maintainer action; contributors do not push tags. For
context, this is how a candidate is cut on ``lota-next``:

* The tag sits on a single commit that changes only ``VERSION``.
* ``release.yml`` builds reproducibly, signs ``SHA256SUMS`` with cosign
  keyless, and -- because the tag is ``0.x`` or carries a ``-`` suffix -- marks
  the GitHub release as a **pre-release**.
* Candidates iterate ``-rc1``, ``-rc2``, ... until one is stable.

Promotion to ``main``
=====================

When a candidate is stable, the maintainer -- ``@szymonwilczek`` -- promotes
``lota-next`` to ``main`` through a pull request merged as a **merge commit**
(no squash, no rebase), then tags the stable release (``vX.0.0``) on ``main``.

See `../../security/reproducible-builds.rst
<../../security/reproducible-builds.rst>`_ for how a tag is built and signed
and how to verify it yourself.
