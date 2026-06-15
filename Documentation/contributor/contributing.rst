============
Contributing
============

LOTA development happens on the ``lota-next`` integration branch. ``main``
carries only stable released code.

Open pull requests against ``lota-next`` - the branch model is documented in
`branching.rst <branching.rst>`_.

Security first
==============

Changes must preserve the production security contract. Do not add
development shortcuts that weaken TPM enrollment, verifier policy, BPF LSM
enforcement, SELinux confinement, release signing, or reproducible builds.

If a change affects an external contract, update the matching documentation in
the same commit. Examples include CLI flags, policy syntax, IPC wire formats,
systemd units, SELinux labels, SDK APIs, and verifier configuration.

Developer Certificate of Origin
===============================

Every commit must carry a DCO sign-off::

    Signed-off-by: Name <email@example.com>

Use ``git commit -s`` or add the line manually. The sign-off certifies that
the contribution can be submitted under the project's licenses.

Commit style
============

Use one logical change per commit. A commit should build and test on its own.
Keep unrelated refactors separate from behavior changes.

Commit subjects use a bare prefix::

    agent: reject stale AIK metadata
    verify: bind quote nonce to token epoch
    docs/verifier: describe monitoring API authentication
    ci: shard Go fuzz targets

Do not use Conventional Commit parentheses such as ``fix(agent):``.

Commit bodies for ALL changes should state::

    Problem: ...

    Solution: ...

    Signed-off-by: Name <email@example.com>

Code style
==========

C and BPF code follow the repository ``.clang-format``.

Run ``clang-format -i`` on modified C and header files before committing.

Go code must be formatted with ``gofmt``.

Comments should be terse and factual. State the contract, failure mode, or
relevant specification. Avoid narrative comments.

Local validation
================

For normal changes, run:

.. code-block:: sh

    env GOCACHE=/tmp/lota-gocache make BUILD_DIR=/tmp/lota-build all
    env GOCACHE=/tmp/lota-gocache make BUILD_DIR=/tmp/lota-build test-unit

Broaden validation when the change touches a wider surface:

* BPF LSM or kernel hooks: validate in a guest with the production BPF object
  attached.
* TPM paths: validate with ``swtpm`` - hardware TPM validation is required
  before release claims that depend on hardware behavior.
* Untrusted parsers: add or update fuzz seeds and run the matching fuzz target.
* Release artifacts: run ``make reproducible-build``.
* SELinux policy: rebuild the module and inspect the resulting AVC behavior on
  an enforcing system.

The full testing policy is in `development/index.rst <development/index.rst>`_.

Pull request expectations
=========================

A pull request should include:

* focused change set,
* tests or a clear reason why runtime validation needs operator hardware (if
  it does),
* documentation updates for changed behavior,
* no generated build artifacts,
* no private operator files, local logs, TPM state, or credentials.

Tagging releases and promoting ``lota-next`` to ``main`` are maintainer
actions.
