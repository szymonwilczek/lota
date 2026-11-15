.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

====================
The license boundary
====================

LOTA is licensed in two zones. The code an adopter embeds and ships is MIT,
so a product built on it can stay closed. The code that attaches to kernel
interfaces is GPL-2.0-only, as the kernel requires.

The zone holds only while dependencies point one way: **a GPL-2.0-only file
may depend on an MIT file; an MIT file never depends on a GPL-2.0-only
file.** A definition the MIT zone needs therefore lives in an MIT file.

License identifiers
===================

Every source file names its license with an ``SPDX-License-Identifier`` tag
in its first 10 lines, as a comment in the file's own syntax::

    /* SPDX-License-Identifier: MIT */           C and headers
    // SPDX-License-Identifier: MIT              Go
    # SPDX-License-Identifier: MIT               scripts, after the shebang

The value is exactly ``MIT`` or ``GPL-2.0-only``. A file without a tag, or
with any other expression, fails the gate described below.

The zones
=========

.. list-table::
   :header-rows: 1
   :widths: 34 16 50

   * - Path
     - License
     - Contents
   * - ``src/bpf/lota_lsm.bpf.c``
     - GPL-2.0-only
     - The BPF LSM program. It attaches to kernel LSM hooks and declares
       ``SEC("license") = "GPL"``, which the kernel reads when it loads the
       program.
   * - ``selinux/lota.te``, ``lota.fc``, ``lota.if``, ``Makefile``
     - GPL-2.0-only
     - The SELinux policy module sources and their ``Makefile``.
   * - ``.clang-format``
     - GPL-2.0-only
     - The formatting configuration.
   * - ``include/vmlinux.h``
     - none
     - Generated from the running kernel's BTF by ``bpftool``. It is not
       edited and is exempt from the gate.
   * - Every other tagged file
     - MIT
     - The agent, SDK, verifier, attestation CA, installer, the initramfs
       PCR 14 lock helper (``src/initramfs/``), tools, tests and scripts.

The BPF program includes three MIT headers, ``include/lota.h``,
``include/lota_devt.h`` and ``include/lota_event_budget.h``. They hold the
constants, enums and structures the program and the agent exchange, so both
zones build against the same definitions.

The gate
========

``scripts/check-license-boundary.sh`` checks the tracked tree:

.. code-block:: console

   $ make check-license-boundary
   check-license-boundary: clean (663 files, 3 documentation packages)

It reads the tag of every tracked ``.c``, ``.h``, ``.go``, ``.py``, ``.pl``
and ``.pm`` file and of every tracked file whose first line is a shebang.
Other files are not zoned, which leaves the policy sources under
``selinux/`` and ``.clang-format`` unchecked.

For each MIT file it then resolves the dependencies that stay in the tree:

* A quoted C ``#include``, first next to the including file, then under
  ``include/``. An angle-bracket include is not resolved.
* A Go import under ``github.com/szymonwilczek/``, against the module paths
  in the tracked ``go.mod`` files. Every ``.go`` file in the imported
  package directory counts.
* A Python ``import`` or ``from ... import``, as ``<name>.py`` or
  ``<name>/__init__.py``, first next to the importing file, then from the
  repository root.
* A Perl ``use`` or ``require``, as the matching ``.pm`` file, in the same
  order.
* For a script, the path of any GPL-2.0-only script written in it, since
  that is how a script runs another.

A dependency that resolves to a GPL-2.0-only file is a violation. A
dependency outside the tree, such as libc, libbpf, tss2 or a third-party Go
module, is not checked.

Documentation toolchain
-----------------------

Every package listed in ``Documentation/requirements.txt`` carries a
permissive license: MIT, BSD, Apache-2.0, ISC or PSF. An expression that
names GPL in any form fails. The gate reads the installed package's
metadata with ``python3``, or with ``$PYTHON`` when it is set, taking
``License-Expression``, else a ``License`` field of at most 64 characters,
else the ``License ::`` classifiers.

A package that is not installed is listed as not checked and the gate
passes. With ``--doc-packages`` it fails instead.

Results
-------

The gate exits 0 and prints the counts of zoned files and read packages when
the tree is clean. It exits 1 when it finds a violation: each one is printed
on standard error, followed by the total and a pointer to this page. An
unknown option exits 2.

Where it runs
-------------

* ``make check-license-boundary`` runs it once.
* ``scripts/check-patch`` runs it on every invocation, whatever the patch
  touches (:doc:`patch-checks`).
* The ``license-boundary`` job of the CI workflow runs it on every push to
  ``main`` or ``lota-next`` and on every pull request.
* ``make check-docs-strict`` and the documentation workflow run it with
  ``--doc-packages``, after the documentation toolchain is installed.

``tests/integration/test_license_boundary_scripts.sh``, part of
``make test-unit``, runs the gate on throwaway trees: a Python import, a
script run by path, a missing tag, and non-permissive or missing
documentation packages. It is skipped without ``python3``.

Fixing a violation
==================

The fix is a licensing decision:

* **An MIT file needs a definition from a GPL-2.0-only file.** When the
  definition is LOTA's own, such as a constant, an enum or an exchanged
  structure, move it into an MIT header and include that header from both
  sides. A definition derived from kernel source stays in the GPL-2.0-only
  zone, and the MIT consumer is restructured so that it does not need it.
* **A file has no tag.** Add one: ``MIT``, unless the file attaches to a
  kernel interface or derives from kernel source.
* **A documentation package is not permissive.** Remove it from
  ``Documentation/requirements.txt``.

A new Go module needs no change to the gate, which reads the ``go.mod``
files on every run.

Packages
========

``lota-agent`` is licensed ``MIT AND GPL-2.0-only``: it ships the BPF object
and the compiled SELinux module next to MIT userspace. ``lota-verifier``,
``lota-attest-ca``, ``lota-sdk`` and ``lota-sdk-devel`` are ``MIT``. Both
package manifests state the same licenses (:doc:`../admin-guide/packages`).
