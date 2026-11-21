.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

============
Patch checks
============

Three scripts check a change before it lands:

``scripts/check-patch``
  Runs every local check over a commit range: the commit messages, the
  changed files, the build, the tests and the analyzers.

``scripts/check-pr-quality.sh``
  Checks the sign-off and the column limits of each commit. ``check-patch``
  runs it locally; the ``PR quality`` workflow runs it on every pull request.

``scripts/format-patch``
  Rewrites the commit messages of a range into the shape the checks
  require.

Running check-patch
===================

.. code-block:: console

   $ scripts/check-patch [<base> [<head>]]

The range is ``base..head``. ``head`` defaults to ``HEAD``. Without a
``base``, the script takes the merge base of ``HEAD`` with its upstream,
else with ``origin/lota-next``, else with ``lota-next``. An empty range
fails.

The changed files are those the range adds, copies, modifies, renames or
retypes, together with the staged and unstaged changes in the working tree.

Each check prints one line:

``PASS <check>``
  The check passed, or the patch touches nothing it covers.

``FAIL <check>``
  The check failed. The findings are printed above the line and a
  ``fix:`` line follows it.

``SKIP <check>``
  A tool the check needs is not installed. The next line names it.

``INFO <text>``
  A recommendation. It never fails the run.

The script exits 0 when no check failed, 1 when one did, and 2 outside a
git repository or on a wrong number of arguments.

The build, the unit tests and the fuzz targets build into
``$BUILD_DIR``, default ``/tmp/lota-build``, with ``$GOCACHE``, default
``/tmp/lota-gocache``. ``$GOLANGCI_LINT`` names the linter binary.

Commit messages
===============

These checks run on every commit in the range:

DCO and column limits
  ``scripts/check-pr-quality.sh`` over the same range, described in
  `The pull request quality check`_. Its notes are printed as ``INFO``.

commit signatures
  Every commit carries a good GPG or SSH signature: ``git log`` reports
  ``G`` or ``U``. A missing, bad, expired, revoked or unverifiable
  signature fails.

commit subject style
  A subject with a Conventional Commits scope, such as ``fix(agent):``,
  fails.

commit body contract
  The body has a ``Problem:`` line and a ``Solution:`` line, each alone on
  its line. ``Problem: text`` on one line fails. The version-bump commit is
  exempt: its subject is ``build: <version>``, it changes ``VERSION`` and
  nothing else, and the release workflow publishes its body as the release
  notes.

commit body layout
  A ``Signed-off-by:`` line follows a blank line or another
  ``Signed-off-by:`` line.

commit body detail
  A commit that changes 5 files or 100 lines has at least 80 words in its
  body; one that changes 3 files or 40 lines, at least 40. The subject and
  the ``*-by:`` trailers are not counted; other trailers, such as
  ``Link:``, are. A shorter body prints ``INFO`` and passes.

patch trailing whitespace
  ``git diff --check`` over each commit, the staged changes and the
  unstaged changes.

commit message trailing whitespace
  No message line ends in a space or tab, and no message ends in a blank
  line.

Changed files and the tree
==========================

These checks run on every invocation:

file trailing blank lines
  No changed text file ends in a blank line.

clang-format
  ``clang-format --dry-run --Werror`` over the changed C and header files,
  ``include/vmlinux.h`` excepted. ``clang-format-22`` is used when
  installed. When the patch changes a C or header file and neither binary
  is installed, the check fails.

gofmt
  ``gofmt -l`` over the changed Go files. When the patch changes a Go file
  and ``gofmt`` is not installed, the check fails.

build artifacts
  No tracked file is an executable, a shared library, an object file or an
  archive, read with ``file --mime-type``. Such a file is usually the output
  of ``go build`` or ``make`` run inside a source directory; list it in
  ``.gitignore``.

build
  ``make all``.

lint-go
  ``golangci-lint run`` with ``.golangci.yml`` over each Go module the
  patch touches, as a whole module. A change to ``.golangci.yml`` lints
  every module. The modules come from ``make print-lint-go-modules``. The
  ``Go static analysis`` workflow runs the linter on every pull request
  and every push to ``main`` or ``lota-next``.

lint-go coverage
  Every tracked ``go.mod`` is in ``LINT_GO_MODULES`` in the ``Makefile``.

unit tests
  ``make test-unit``.

license-boundary
  ``scripts/check-license-boundary.sh`` (:doc:`license-boundary`).

test-build-dir
  No test or example script names the default build directory. C and Go
  tests take the path as a ``-D`` from their recipe; shell scripts read
  ``$LOTA_BUILD_DIR`` and name the default only as its fallback. A
  ``build`` directory that is not the tree's goes in
  ``scripts/test-build-dir-exemptions.txt``.

test-names
  ``scripts/check-test-names.sh``: no test name in ``tests/`` is cut
  short in the report, and no script's group header is wider than it. A
  name built at run time is not checked.

doc-diagnostics
  Every sentence-shaped inline literal in the documentation is a message
  the source can print, except a literal listed in
  ``scripts/doc-diagnostics-exemptions.txt``. Adjacent C string literals are
  joined, and a format specifier matches the text it stands for. A code
  block is not checked.

config-commands
  Every option a file under ``policies/`` or ``configs/`` passes to a
  ``lota-*`` command is in that command's option table in the source.

docs-strict
  ``make check-docs-strict``: a full documentation build into a scratch
  tree with every warning an error, after the license check of the
  documentation toolchain. A full build reads every page, so a defect in a
  page the patch did not touch still fails.

abi
  ``scripts/check-abi.sh`` compares the SDK's exported symbols, sonames,
  installed headers and type layouts with the baseline in
  ``packaging/abi/``, then builds against a staged install
  (:doc:`../userspace-api/stability`). A deliberate change updates the
  baseline with ``make abi-baseline``.

doc-references
  ``make check-doc-references``: every symbol or command a comment or a
  page names exists in the tree.

When a patch touches
====================

These checks run only when the changed files match their trigger. A patch
that matches nothing passes them.

.. list-table::
   :header-rows: 1
   :widths: 22 30 48

   * - Check
     - Trigger
     - What it checks
   * - include-hygiene
     - C or header
     - ``scripts/check-includes.sh``: no translation unit includes a header
       it does not use, as ``clang-include-cleaner`` reports it. A header
       used only through another header is not reported. Fix with
       ``scripts/fix-includes.sh``.
   * - stack-frames
     - C or header
     - See `C static analysis`_.
   * - private-errno
     - C or header
     - See `C static analysis`_.
   * - sparse, smatch, coccicheck
     - C or header
     - See `C static analysis`_.
   * - fuzz
     - C, header, ``Makefile``, ``fuzz/``
     - ``make fuzz-regress``: every C fuzz target builds and passes
       ``fuzz/regressions/``. The targets link agent sources, so a change
       outside ``fuzz/`` can break one.
   * - bpf-mirror
     - ``src/bpf/lota_lsm.bpf.c``, ``fuzz/bpf_oracle/``
     - ``make check-bpf-mirror``: the BPF helpers the oracle fuzzers copy
       match ``fuzz/bpf_oracle/mirror.lock``, and nothing under
       ``fuzz/bpf_oracle/`` cites the BPF source by line number. After
       re-verifying a copy, ``make update-bpf-mirror`` updates the lock.
   * - syzkaller-matrix
     - ``src/bpf/lota_lsm.bpf.c``, ``syzkaller/``, ``Makefile``
     - Every LSM program has a row in the hook matrix of
       ``syzkaller/README.rst``, every row names a program the source has,
       and ``syzkaller/lota.cfg.example`` enables every call a row names.
   * - header-paths
     - ``include/``, ``Makefile``, ``scripts/check-patch``
     - Every tree path an installed header names exists.
       ``include/linux/`` paths are skipped.
   * - package-manifests
     - a manifest under ``packaging/``, ``Makefile``, a page, ``conf.py``,
       ``README.rst``
     - The nfpm configs and ``packaging/rpm/lota.spec`` ship the same paths
       and declare the same dependencies per package, and every page names
       the repository address the documentation site serves.
   * - player-build
     - ``Documentation/player/``, ``Makefile``
     - ``scripts/check-player-build.sh``: the build commands of the player
       page install in a clean Fedora container.
   * - helm-chart
     - ``deploy/helm/``
     - The chart takes its ``appVersion`` from ``VERSION`` and renders pods
       that start.
   * - container-images
     - the ``ko`` configurations, ``Makefile``, the release workflow
     - Each published image offers the CA key source its documentation
       states.

player-build, helm-chart, container-images and package-manifests also run
when their own script changes, and header-paths when
``scripts/check-patch`` changes.

C static analysis
=================

Sparse, Smatch and Coccinelle read every tracked ``.c`` file outside
``src/bpf/``, which targets the BPF machine. Sparse and Smatch get the
include paths, ``_GNU_SOURCE``, the ``pkg-config`` flags of the libraries
the tree links, and the defines the sources are built with
(``LOTA_INTERNAL_TESTS``, the SDK version, the benchmark include root).
``CFLAGS`` is not passed: its hardening, machine and sanitizer flags
confuse the parsers.

``make sparse``
  Runs Sparse with ``-Wsparse-all -Wno-declaration-after-statement``. A
  finding in a tracked file, or a non-zero exit, fails that file. A
  finding in a system header is not counted. An entry in
  ``scripts/sparse-exemptions.txt`` drops one message in one file and
  states why the source does not do what Sparse reports; the same message
  in any other file still fails.

``make smatch``
  Runs Smatch with the same include paths and defines. A file fails on a
  finding, ``file.c:LINE func() warn:`` or with ``error:``, ``info:`` or
  ``warning:`` in its place, on a front-end error or warning,
  ``file.c:LINE:COL: error:``, or on a non-zero exit. Output from system
  headers is not counted.
  Smatch has no distribution package: build it from
  ``https://repo.or.cz/smatch.git`` and put it on ``PATH``, or pass
  ``SMATCH=/path/to/smatch``. The ``C static analysis`` workflow builds
  the revision pinned in ``SMATCH_REV``.

``make coccicheck``
  Applies each rule under ``scripts/coccinelle/``, with ``.cocciconfig``.
  Any match fails.

``make check-stack-frames``
  Fails on a function in a shipped binary whose stack frame exceeds
  32 KiB; ``STACK_FRAME_LIMIT`` overrides the limit. The compiler flags
  are fixed in ``scripts/check-stack-frames.sh``, so a frame measures the
  same in every build mode. Tests are not measured. An object large enough
  to fail belongs on the heap, as ``config_new()`` in
  ``src/agent/config.c`` does it. The limit is only ever lowered.

``make check-private-errno``
  Fails when a value assigned from a ``tpm_*()`` or ``net_*()`` call
  reaches ``strerror()`` negated, with no other assignment between. Those
  layers return codes from 4097 and 4353, which ``strerror()`` prints as
  ``Unknown error <n>``; 4098 is ``LOTA_ERR_TPM_AUTH_FAIL``, the warning
  of a dictionary-attack lockout. ``tpm_strerror()`` and
  ``net_strerror()`` print the private codes and fall through to
  ``strerror()`` for the rest. A copy through a second variable is not
  caught.

Without the tool, Sparse, Smatch and Coccinelle print ``SKIP``. On Fedora,
``dnf install sparse coccinelle`` installs two of them; on Debian and
Ubuntu, ``apt-get install sparse coccinelle``. The ``C static analysis``
workflow runs Sparse, Smatch, Coccinelle and the stack-frame check on every
pull request and every push to ``main`` or ``lota-next``.

The pull request quality check
==============================

.. code-block:: console

   $ scripts/check-pr-quality.sh [--pr-diff] <base> <head>

``$BASE_SHA`` and ``$HEAD_SHA`` stand in for missing arguments. For each
commit in ``base..head``:

* The body carries ``Signed-off-by: Name <email>`` on a line of its own.
* The subject is at most 75 columns.
* Each body line is at most 75 columns, unless it is a single word, a
  trailer (``*-by:``, ``Fixes:``, ``Link:``, ``Closes:``,
  ``Docs-Not-Needed:``), a line containing a URL, a ``Merge branch`` line,
  a diffstat line, or a line led by a path followed by a colon.
* A merge commit, or a subject starting with ``Merge``, is exempt from
  both column limits.
* A trailer such as ``Co-authored-by:`` or ``Assisted-by:``, or an author
  or committer, that names an AI assistant sets ``ai_assisted=true`` in
  ``$GITHUB_OUTPUT``. It does not fail.

The branch name, ``$PR_BRANCH`` or the checked-out branch, is at most 75
columns, and ``$PR_TITLE``, when set, follows the subject rules. On the
``lota-next`` branch the column limits are not checked, since its commits
were checked when they landed.

A subject of the form ``a/b:`` or ``a: b:`` prints a note asking whether
the form is the intended one (:doc:`contributing`).

A commit that changes a file listed in ``.github/pr-quality-hotpaths.txt``
without a file of the documentation named for it prints a note naming that
documentation and the reason. Test files (``*_test.go``, ``tests/``,
``test/``, ``testdata/``, ``src/*/fuzz/``) do not trigger a note, and
neither do ``docs``, ``license`` or ``gitignore`` commits. A note never
fails.

With ``--pr-diff`` only non-merge commits whose parent already carries
``.github/pr-quality-hotpaths.txt`` are checked; every other commit is
skipped whole, sign-off, column limits and AI marker alike. No
documentation note is printed.

The script exits 0 when every checked commit passes, 1 on a failure, and 2
on a missing argument or commit, or when
``.github/pr-quality-hotpaths.txt`` is missing.

The ``PR quality`` workflow runs it with ``--pr-diff`` when a pull request
is opened, updated, reopened or edited, with the pull request's title and
branch. When it reports ``ai_assisted=true``, the workflow labels the pull
request ``AI-Assisted``.

Rewriting commit messages
=========================

.. code-block:: console

   $ scripts/format-patch [<base> [<head>]]

The range defaults as for ``check-patch``. ``head`` is the tip of the
checked-out branch. The script changes messages only; every commit keeps
its tree, author, committer and dates. In each message it:

* removes trailing spaces and tabs and the final blank lines,
* splits ``Problem: text`` and ``Solution: text`` into a heading and the
  text on the next line,
* puts one blank line before the first ``Signed-off-by:``,
* wraps the body paragraphs to 75 columns, leaving the exempt lines of
  `The pull request quality check`_ as written.

A subject over 75 columns is shortened by hand.

The script refuses a detached ``HEAD``, a ``head`` that is not the branch
tip, staged or unstaged changes, an empty range, and a range with a merge
commit. Before it moves the branch it saves the old tip as
``backup-<branch>-before-format-patch-<UTC time>``, removed again when no
message changed. It signs the rewritten commits only when
``commit.gpgsign`` is ``true``; otherwise they lose their signatures and
fail the signature check. Review every rewritten message before pushing.
