.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

=====================
The license boundary
=====================

LOTA is dual-licensed, and the split is a design constraint rather than an
accident of history. It exists so that a company or a game studio can build a
product on top of LOTA and ship it closed:

* **MIT** covers everything an adopter embeds: the SDK, the agent userspace,
  the verifier, the attestation CA, the installer, and the headers those share
  with the BPF program.
* **GPL-2.0-only** covers the kernel-facing BPF programs, because the kernel
  interfaces they attach to require it.

The promise only holds while dependencies run in one direction.

The rule
========

**A GPL-2.0-only file may include an MIT file. An MIT file may not depend on a
GPL-2.0-only file.**

The asymmetry is the whole point. A GPL program is free to consume permissively
licensed sources; the reverse pulls copyleft into the zone an adopter was told
they could close. There are no exemptions: an MIT file that needs something
from the GPL zone means either the dependency belongs in the MIT zone, or the
consumer belongs in the GPL zone.

Every source file must also name its license with an
``SPDX-License-Identifier`` tag in its first few lines. An unlabelled file
belongs to no zone and would escape the rule entirely, so the gate treats a
missing tag as a violation rather than assuming a default.

The zones
=========

.. list-table::
   :header-rows: 1
   :widths: 34 16 50

   * - Path
     - License
     - Why
   * - ``src/bpf/*.bpf.c``
     - GPL-2.0-only
     - Attaches to kernel LSM hooks and calls GPL-only kfuncs. The object also
       declares ``SEC("license") = "GPL"``, which is the kernel's requirement
       of the loaded program and is separate from the licensing of the headers
       it read.
   * - ``include/lota.h``, ``include/lota_devt.h``,
       ``include/lota_event_budget.h``
     - MIT
     - The contract the BPF program and the agent share: LOTA's own constants,
       enums and exchange structs. Nothing is derived from kernel source, so
       nothing here requires GPL, and the MIT zone can therefore depend on it.
   * - ``src/agent/``, ``src/sdk/``, ``installer/``
     - MIT
     - The on-host code an adopter ships. The initramfs PCR14 lock helper is
       here too: it links tss2 and OpenSSL, not kernel headers.
   * - ``src/verifier/``, ``src/attestca/``, ``src/crl/``,
       ``src/fleetctl/``
     - MIT
     - Server-side Go services and libraries.
   * - ``include/vmlinux.h``
     - (generated)
     - Produced from the running kernel's BTF by ``bpftool``. Not project
       source; exempt from the gate, and never edited by hand.

The gate
========

``scripts/check-license-boundary.sh`` enforces the rule mechanically:

.. code-block:: sh

   make check-license-boundary

It reads the SPDX tag of every tracked ``.c``, ``.h`` and ``.go`` file, then
resolves each dependency the way the toolchain does -- a quoted C ``#include``
against the including file's directory and then ``-Iinclude``, and an
intra-project Go import against the module paths declared in the ``go.mod``
files. A dependency that leaves the tree (libc, libbpf, tss2, third-party Go
modules) is not the boundary's concern and is ignored.

``scripts/check-patch`` runs the gate on every patch, so a violation fails the
same local check as a formatting or build error, and the ``license-boundary``
CI job runs it on every push and pull request. The gate needs no compiler or
compile database, which is why it is not gated on the patch touching C: an SPDX
tag can be dropped by an edit anywhere in the tree.

Working with the rule
=====================

When the gate reports a violation, the fix is a licensing decision, not a
build tweak:

* **A definition the MIT zone needs is in a GPL file.** If the definition is
  LOTA's own -- a constant, an enum, a struct the two sides exchange -- it
  belongs in an MIT header, like the three shared contract headers above. If it
  genuinely derives from kernel source, it cannot cross into the MIT zone at
  all and the consumer needs restructuring.
* **A new file has no SPDX tag.** Add one. MIT unless the file is a BPF program
  or otherwise kernel-derived.
* **A new Go module.** No action needed: the gate reads ``go.mod`` files, so a
  new module's imports resolve as soon as it exists.

Packaging carries the same boundary. ``lota-agent`` declares
``MIT AND GPL-2.0-only`` because it ships the BPF object alongside MIT
userspace; every other package is ``MIT``. A packaging convenience must not
blur that -- see :doc:`../../operator/packages`.
