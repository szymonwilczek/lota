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
analyzers described below.

Every commit in ``base..head`` must carry a good GPG or SSH signature; the
check fails on any commit whose signature is missing, bad, or unverifiable.
Set ``commit.gpgsign true`` with a configured signing key, or commit with
``git commit -S``, so the commits match the repository ruleset that requires
signed commits and GitHub marks them verified.

Commit body headings must use standalone ``Problem:`` and ``Solution:`` lines,
with the explanatory text starting on the next line. Body text is wrapped to 75
columns, with a two-column tolerance when the final word reaches column 76 or
77. The DCO ``Signed-off-by`` trailer must be separated from the description by
one blank line.

The local hotpath check delegates to ``scripts/check-pr-quality.sh``, using the
same ``.github/pr-quality-hotpaths.txt`` manifest as the ``PR quality``
workflow.

C static analysis
=================

Three style semantic checkers run over the C sources -- every tracked
``*.c`` except ``src/bpf``, which targets the x86 BPF machine and trips the
checkers, the same exclusion clang-analyzer uses. Each is a self-contained make
target that passes a reduced flag set (includes, ``_GNU_SOURCE`` and the
``pkg-config`` dependency flags), because the hardening, machine, and sanitizer
flags in ``CFLAGS`` confuse the parsers:

* ``make sparse`` runs the Sparse semantic checker. It is **advisory**: it
  prints findings and exits zero. Set ``SPARSE_STRICT=1`` to fail on any
  finding.
* ``make smatch`` runs the Smatch flow analyzer, also advisory, with
  ``SMATCH_STRICT=1`` for the strict mode. Smatch has no distribution package;
  build it from ``https://repo.or.cz/smatch.git`` and put it on ``PATH`` (or
  pass ``SMATCH=/path/to/smatch``), otherwise the target skips.
* ``make coccicheck`` runs the Coccinelle semantic-patch rules under
  ``scripts/coccinelle`` (configured by ``.cocciconfig``). It is **blocking**:
  the rules are tuned to be clean on a healthy tree, so any match is a finding.

Install the front ends with ``dnf install sparse coccinelle`` on Fedora or
``apt-get install sparse coccinelle`` on Debian and Ubuntu, and build Smatch
from source. ``scripts/check-patch`` runs all three when the patch touches C
and skips each one whose tool is absent, so the gate stays usable without them.
The advisory status for Sparse and Smatch is deliberate -- the first pass over
the tree carries a backlog -- and the ``*_STRICT`` switches are the ratchet to
flip once it is burned down. The same three checks run in CI under the
``C static analysis`` workflow.

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
