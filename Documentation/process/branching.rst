.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

=============================
Branch model and release flow
=============================

LOTA has two long-lived branches. ``lota-next`` is the integration branch,
where every change lands first. ``main`` is the default branch and carries
released code only. Release candidates are tagged on ``lota-next``, stable
releases on ``main``::

    feature branch --PR--> lota-next --PR, merge commit--> main
                           v*-rc tags                      v* tags

Integration branch
==================

Pull requests open against ``lota-next``. A push to it runs the CI
workflows, the packaging workflow and ``notify-fuzz``, which wakes the
host that runs the long fuzzing campaigns
(:ghsrc:`.github/workflows/notify-fuzz.yml`). :doc:`../dev-tools/index`
describes the test layers; ``README-NEXT.rst`` in the repository root points
there.

Release candidates are tagged here as ``v<version>-rc<n>``.

Stable branch
=============

``main`` changes only through a pull request from ``lota-next``, merged as a
merge commit so the commits keep the hashes they had on ``lota-next``. The
maintainer opens and merges it and tags the stable release on ``main``.

Releases
========

A ``v*`` tag runs the release workflow
(:ghsrc:`.github/workflows/release.yml`), which builds the artifacts,
signs them and publishes a GitHub release. A tag whose version starts with
``0.`` or carries a ``-`` suffix is published as a pre-release; any other
tag is a normal release. :doc:`../security/reproducible-builds` describes
how a tag is built and how its artifacts are verified.

Documentation site
==================

The documentation is published to GitHub Pages as two channels
(:ghsrc:`.github/workflows/docs-deploy.yml`):

stable
  Built from ``main`` and served at the site root. It is labelled with the
  tag being built, or else with the newest ``v*`` tag reachable from
  ``main`` that is not a release candidate. Its source links point at
  ``main``.

development
  Built from ``lota-next`` and served under ``/lota-next/``. It is labelled
  ``lota-next (<short-sha>)``, carries a banner above every page and a
  ``noindex`` robots tag, and its source links point at ``lota-next``.

A push to either branch, or a ``v*`` tag without ``-rc``, rebuilds both
channels and deploys them together, so one channel never overwrites the
other. A switcher under the sidebar title links to the front page of the
other channel (:ghsrc:`Documentation/_templates/layout.html`).

Pull requests against main
==========================

A pull request opened or reopened against ``main`` by anyone other than the
maintainer, and not by a bot, is retargeted to ``lota-next`` with a comment
that explains the branch model (:ghsrc:`.github/workflows/pr-router.yml`).
If the branch then conflicts with ``lota-next``, rebase it onto
``lota-next``.
