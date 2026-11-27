.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

============
Contributing
============

Changes land on the ``lota-next`` integration branch, through a pull request.
``main`` carries released code only; :doc:`branching` describes both
branches. This page sets out what a commit and a pull request carry. The
checks that enforce it are described in :doc:`patch-checks`.

Security contract
=================

A change must not weaken TPM enrollment, verifier policy, BPF LSM
enforcement, SELinux confinement, release signing or reproducible builds,
including through a development shortcut.

A change to an external contract updates its documentation in the same
commit. External contracts include command-line flags, policy syntax, IPC
wire formats, systemd units, SELinux labels, SDK APIs and verifier
configuration. ``.github/pr-quality-hotpaths.txt`` maps source files to the
pages that describe them, and ``scripts/check-patch`` prints a note when a
commit changes one without the other.

Commits
=======

One logical change per commit. Each commit builds and passes the tests on
its own, and an unrelated refactor goes in a commit of its own.

Subject
-------

The subject starts with a bare prefix naming the area it changes::

    agent: reject stale AIK metadata
    verify: bind quote nonce to token epoch
    docs: verifier: describe monitoring API authentication
    sdk/server: agree on the token claim set
    ci: shard Go fuzz targets

A second prefix after ``": "`` names a submodule (``docs: verifier:``). A
slash joins two areas a commit changes together (``sdk/server:``).
``scripts/check-patch`` prints a note for either form so the author
can confirm it is the one meant. A Conventional Commits scope such as
``fix(agent):`` fails ``scripts/check-patch``.

Subjects, pull request titles and branch names are at most 75 columns.

Body
----

The body explains the change under two headings, each on a line of its own
with the text starting on the next line, and ends with the sign-off after
one blank line::

    Problem:
    What is wrong or missing, and why it matters.

    Solution:
    What the commit changes to fix it.

    Signed-off-by: Name <email@example.com>

Body lines are at most 75 columns. ``scripts/format-patch`` rewraps a body
and splits ``Problem: text`` onto two lines; :doc:`patch-checks` lists the
lines that keep their length.

Sign-off and signature
----------------------

Every commit carries a Developer Certificate of Origin trailer,
``Signed-off-by: Name <email>``, added by ``git commit -s``. The sign-off
certifies that the contribution may be submitted under the project's
licenses.

Every commit is also signed with GPG or SSH (``git commit -S``, or
``commit.gpgsign`` set to ``true``), so that GitHub marks it verified.

Code style
==========

C and BPF sources follow the repository ``.clang-format``: run
``clang-format -i`` on changed C and header files. Go sources are formatted
with ``gofmt``; ``golangci-lint``, configured by ``.golangci.yml``,
additionally checks ``gofumpt`` and ``goimports`` formatting.

Comments are terse and factual. They state the contract, the failure mode or
the specification a line follows.

Local validation
================

Every change builds and passes the unit tests, with the build directory and
the Go cache outside the tree:

.. code-block:: console

   $ env GOCACHE=/tmp/lota-gocache make BUILD_DIR=/tmp/lota-build all
   $ env GOCACHE=/tmp/lota-gocache make BUILD_DIR=/tmp/lota-build test-unit

``scripts/check-patch`` runs both, among its other checks. A change to a
wider surface needs more:

* BPF LSM or kernel hooks: a run in a guest with the production BPF object
  attached.
* TPM paths: a run against ``swtpm``. A claim that depends on hardware
  behaviour needs a run on a hardware TPM.
* Untrusted parsers: new or updated fuzz seeds, and a run of the matching
  fuzz target.
* Release artifacts: ``make reproducible-build``.
* SELinux policy: a rebuilt module and its AVC behaviour on an enforcing
  system.

:doc:`../dev-tools/index` describes the test layers and how each one runs.

Reporting issues
================

New issues start from a template; blank issues are disabled. **Bug** is for
a defect that is not a security problem, **Enhancement** for a proposed
change or capability. Both live in ``.github/ISSUE_TEMPLATE``.

A suspected vulnerability never goes into a public issue. The new-issue
chooser links **Private Security Reporting**, which opens a private GitHub
security advisory; :doc:`security-bugs` lists the email fallback.

Pull requests
=============

A pull request opens against ``lota-next``. Its description starts from
``.github/PULL_REQUEST_TEMPLATE.md``, whose sections follow the commit body:
Problem, Solution with one section per changed area, Docs, Tests and
Security boundary. A section that does not apply is deleted.

A pull request carries:

* one focused change set,
* tests, or the reason runtime validation needs operator hardware,
* documentation updates for changed behaviour,
* no generated build artifacts,
* no private operator files, local logs, TPM state or credentials.

Tagging a release and merging ``lota-next`` into ``main`` are maintainer
actions.
