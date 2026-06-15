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
message and patch whitespace, clang-format, gofmt, the full build, and the same
hotpath documentation policy enforced by CI.

Commit body headings must use standalone ``Problem:`` and ``Solution:`` lines,
with the explanatory text starting on the next line. Body text is wrapped to 75
columns, with a two-column tolerance when the final word reaches column 76 or
77. The DCO ``Signed-off-by`` trailer must be separated from the description by
one blank line.

The local hotpath check delegates to ``scripts/check-pr-quality.sh``, using the
same ``.github/pr-quality-hotpaths.txt`` manifest as the ``PR quality``
workflow. This keeps local contributor feedback aligned with the server-side
gate.

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

The ``PR quality`` workflow checks commit metadata and the aggregate pull
request diff before the build matrix runs:

* every non-merge commit created on top of a tree that already carries the
  quality gate must carry a DCO ``Signed-off-by`` trailer,
* commits with AI assistant co-author or generator trailers are labeled
  ``AI-Assisted``,
* a pull request that changes a hotpath file must update one of the documented
  companion files in the same pull request diff.

The hotpath-to-documentation contract is versioned in
``.github/pr-quality-hotpaths.txt``. It intentionally keys off critical
surfaces rather than commit size: TPM enrollment, verifier policy, BPF LSM
enforcement, SDK token formats, deployment policy, CI, build, and release
process.

Scripts are split by audience: developer-workflow tooling (``check-*``,
``format-patch``, the CI gate scripts) maps to the contributor docs above,
while operator provisioning and host bring-up scripts (``lota-*``,
``setup-fsverity.sh``) are deployment steps and map to the operator-facing
`production bring-up <../../operator/production-bringup/index.rst>`_ and the
relevant example READMEs instead.

Module and workspace manifests (``go.mod``, ``go.sum``, ``go.work``) map to
this file rather than a runtime surface: a dependency or Go-directive change is
a contributor concern, not a trust-model or integrator-contract change, so a
dependency refresh does not drag in a security-doc edit.
