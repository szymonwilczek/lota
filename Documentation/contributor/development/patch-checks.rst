.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

==========================================
Local patch checks and the PR quality gate
==========================================

Local patch checks
==================

Contributors can run ``scripts/check-patch [<base> [<head>]]`` before pushing a
branch. The script reports each check with ``PASS`` or ``FAIL`` and includes a
suggested fix for failures. It validates commit message shape, DCO trailers,
commit signatures, message and patch whitespace, clang-format, gofmt, the full
build, include hygiene, the license boundary
(:doc:`license-boundary`), the public API and ABI surface
(:doc:`api-stability`), the same hotpath documentation policy enforced by
CI, and -- when the patch touches C -- the Sparse, Smatch and Coccinelle
analyzers and the stack-frame ceiling described below.

Every commit in ``base..head`` must carry a good GPG or SSH signature; the
check fails on any commit whose signature is missing, bad, or unverifiable.
Set ``commit.gpgsign true`` with a configured signing key, or commit with
``git commit -S``, so the commits match the repository ruleset that requires
signed commits and GitHub marks them verified.

Commit body headings must use standalone ``Problem:`` and ``Solution:`` lines,
with the explanatory text starting on the next line. **The version bump is the
one exception**: the release tag sits on it, and ``release.yml`` publishes its
description as the release notes, so its body is addressed to whoever reads the
release page. Body text is wrapped to 75 columns, with a two-column tolerance
when the final word reaches column 76 or 77. The DCO ``Signed-off-by`` trailer
must be separated from the description by one blank line.

The local hotpath check delegates to ``scripts/check-pr-quality.sh``, using the
same ``.github/pr-quality-hotpaths.txt`` manifest as the ``PR quality``
workflow.

C static analysis
=================

Three semantic checkers and a stack-frame ceiling run over the C sources --
every tracked ``*.c`` except ``src/bpf``, which targets the x86 BPF machine and
trips the checkers, the same exclusion clang-analyzer uses. Each is a
self-contained make target that passes a reduced flag set (includes,
``_GNU_SOURCE`` and the ``pkg-config`` dependency flags), because the
hardening, machine, and sanitizer flags in ``CFLAGS`` confuse the parsers:

* ``make sparse`` runs the Sparse semantic checker. It is **blocking**: any
  finding fails the target. Only findings in tracked files count -- Sparse
  does not know several glibc and gcc attributes and reports the C library by
  the hundred, which says nothing about this tree and differs per
  distribution. Sparse also gets the defines the sources are really built
  with (``LOTA_INTERNAL_TESTS``, the build-identity string, the benchmark and
  staged-SDK include roots); without them it walks a translation unit no build
  produces. One warning is switched off tree-wide:
  declaration-after-statement, a style rule rather than a defect class.
  Everything else stays on. Where Sparse is wrong,
  ``scripts/sparse-exemptions.txt`` drops that one message in that one file,
  with the reason written out, so the same finding anywhere else still fails
  the gate. It is not a backlog: an entry is only justified when Sparse
  reports something the source does not do and no code change can say it more
  clearly. The current entries cover constants folded through an inlined call
  or macro and reported as if the source wrote the specialised result, the
  flexible-array union that sizes a variable-length ioctl argument, and two
  whole-struct ``memset`` calls above Sparse's 100 KB copy limit.
* ``make smatch`` runs the Smatch flow analyzer. It is **blocking when it
  runs**: any finding fails the target. Smatch has no distribution package, so
  the target skips when the binary is absent -- build it from
  ``https://repo.or.cz/smatch.git`` and put it on ``PATH`` (or pass
  ``SMATCH=/path/to/smatch``). Skipping locally does not make it optional: the
  ``smatch`` job in the ``C static analysis`` workflow builds a pinned revision
  from source, caches it, and runs the same target on every pull request, so a
  finding cannot reach ``lota-next`` because a contributor lacked the tool.
  Build the revision that job pins if you want local results to match CI.

  It takes the same corrected flag set as Sparse -- Smatch is built from Sparse
  and parses with the same front end, so a translation unit one cannot assemble
  is one neither can analyse. Two shapes of output count. Smatch's own findings
  read ``file.c:LINE func() warn:``, with no column and ``warn`` rather than
  ``warning``, which is why the Sparse filter does not match them; front-end
  errors read ``file.c:LINE:COL: error:`` and mean the translation unit was
  never assembled, so the file went unanalysed. A gate that ignored the second
  kind would report success over sources it never read.
* ``make check-stack-frames`` fails on a function in a shipped binary whose
  stack frame exceeds 32 KB (``STACK_FRAME_LIMIT`` overrides it). The agent
  is a long-running daemon and the installer runs on whatever stack its caller
  has, so an object large enough to matter -- configuration, an allow-list, a
  rollback snapshot -- belongs on the heap, where a failed allocation is a
  value the caller can act on rather than a fault it cannot. Only the shipped
  sources are measured; tests are short-lived processes on the main thread's
  full stack. The compiler flags are pinned inside the script rather than
  taken from ``CFLAGS``, because hardening, machine and sanitizer flags move
  frame sizes and the gate is about the shape of the source, not of one build.
  The ceiling is a ratchet: lower it as the largest frames come in, never raise
  it to admit a new one. It currently sits just above the tree's high-water
  mark, and every frame near that mark is one ``struct profile_paths`` (24592
  bytes, six ``PATH_MAX`` strings by value) plus small locals -- so the next
  step down is a decision about that struct rather, not a change to this number.
* ``make coccicheck`` runs the Coccinelle semantic-patch rules under
  ``scripts/coccinelle`` (configured by ``.cocciconfig``). It is **blocking**:
  the rules are tuned to be clean on a healthy tree, so any match is a finding.

Install the front ends with ``dnf install sparse coccinelle`` on Fedora or
``apt-get install sparse coccinelle`` on Debian and Ubuntu, and build Smatch
from source. ``scripts/check-patch`` runs all four when the patch touches C and
skips each one whose tool is absent, so the gate stays usable without them --
but CI has every tool, so skipping locally postpones a failure rather than
avoiding one. The same four checks run in CI under the ``C static analysis``
workflow.

Use ``scripts/format-patch [<base> [<head>]]`` only to normalize local commit
messages before pushing. It rewrites commits in ``base..head`` to remove
trailing spaces, trailing tabs, and blank lines after the final content line.
It does not change file trees. It also fixes simple inline ``Problem:`` and
``Solution:`` headings, inserts the required blank line before
``Signed-off-by``, wraps body paragraphs, and tells the developer to review the
rewritten descriptions. The script requires a clean index and working tree,
refuses merge commits, and creates a backup branch before updating the current
branch.

Pull request quality gate
=========================

The ``PR quality`` workflow checks commit metadata and the hotpath
documentation contract before the build matrix runs:

* every non-merge commit created on top of a tree that already carries the
  quality gate must carry a DCO ``Signed-off-by`` trailer,
* commits with AI assistant co-author or generator trailers are labeled
  ``AI-Assisted``,
* a commit that changes a hotpath file must update the documentation its tier
  requires.

The hotpath-to-documentation contract is versioned in
``.github/pr-quality-hotpaths.txt``. Each rule maps a set of hotpath globs to
the companion docs that describe them and carries a tier:

* ``required`` -- the change must touch one of the companion docs, or the
  commit must carry a ``Docs-Not-Needed: <reason>`` trailer, or the gate fails.
  These cover the documented contracts: TPM enrollment, verifier policy, BPF
  LSM enforcement, SDK token formats, deployment policy, and operator
  provisioning.
* ``recommended`` -- a missing companion doc only warns, never fails. These
  cover process surfaces that seldom change a contract: CI, build, the gate
  scripts, and dependency manifests.

The commit type (the ``type:`` subject prefix) caps the tier. An
infrastructure type -- ``ci``, ``build``, ``test``, ``tests``, ``chore``,
``style``, ``refactor``, ``perf``, ``release`` -- is treated as recommended
even against a required rule; ``docs``, ``license``, and ``gitignore`` are
exempt; module-scoped commits (``agent:``, ``bpf:``, ``verifier:``, ...) and
``treewide:`` take the tier of the rule. A ``Docs-Not-Needed: <reason>``
trailer with a non-empty reason waives the requirement for the commit it sits
on and is recorded in history.

In ``--pr-diff`` mode a companion doc anywhere in the pull-request diff
satisfies a required rule, so a documentation commit can accompany a code
commit within the same pull request.

Scripts are split by audience: developer-workflow tooling (``check-*``,
``format-patch``, the CI gate scripts) maps to the contributor docs above,
while operator provisioning and host bring-up scripts (``lota-*``,
``setup-fsverity.sh``) are deployment steps and map to the operator-facing
:doc:`production bring-up <../../operator/production-bringup/index>` and the
relevant example READMEs instead.
