.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

======================
BPF LSM program coding
======================

Rules for writing and changing the BPF LSM programs in ``src/bpf/``. The
in-kernel verifier rejects an object that violates them, and a rejected object
means the LSM never loads.

Conditionally-assigned pointers
===============================

An event pointer that is conditionally assigned -- for example only when the
telemetry budget admits a ``bpf_ringbuf_reserve`` -- must be initialized to
``NULL`` at declaration. The in-kernel verifier tracks pointer liveness per
path, so a read of a conditionally-assigned pointer can reject the whole
program depending on how clang laid out the branches. ``veristat`` in CI
catches acceptance regressions, but only for the kernel it runs on; the
NULL-init rule keeps acceptance independent of compiler layout.

Cross-CPU map updates
=====================

| State shared across CPUs through a plain (non-PERCPU) map must be updated with
  BPF atomics (``__sync_fetch_and_add``, ``__sync_val_compare_and_swap``, ...),
  never with read-modify-write C:
| Each hook can run concurrently on every CPU, and a torn counter or window flip
  silently corrupts whatever the value gates.

The fetch/CMPXCHG forms need kernel 5.12+ verifier support, which the BPF LSM
floor already exceeds.

Ring-buffer emission budget
===========================

Under ``LOTA_MODE_ENFORCE`` every event is rate-limited per one-second window
before it claims a ``bpf_ringbuf_reserve`` slot, so an attacker-driven flood
cannot fill the ring buffer faster than user space drains it. Allowed (benign)
and blocked (security-relevant) events are counted in separate windows, so a
flood of one class cannot consume the other's budget; blocked events get the
larger budget but are still bounded. Suppressing an event drops only its
per-event detail -- the block counts are tallied in the ``stats`` map
independently of ring-buffer emission, so an operator never loses the tally.

The budget arithmetic lives in ``include/lota_event_budget.h`` as pure helpers
(``lota_event_budget_limit``, ``lota_event_budget_window_expired``,
``lota_event_budget_exhausted``) with no map lookups or atomics, so it is
unit-tested in user space (``tests/test_event_budget.c``); the BPF program wraps
those helpers with the shared-map lookup and the cross-CPU atomics above. Change
the budgets or the window only through the header so the program and the test
stay in step.

Device and inode identity
=========================

The BPF programs identify a file by its ``(device, inode)`` pair and a device
node by its ``(major, minor)`` numbers. Both come from kernel structures read
in the hook:

* a regular file's filesystem device is ``super_block->s_dev``,
* its inode number is ``inode->i_ino``,
* and a character device's identity is ``inode->i_rdev``.

The kernel stores every ``dev_t`` in these fields in its
MKDEV layout -- a 20-bit minor with the major above it (``major = dev >> 20``,
``minor = dev & 0xFFFFF``). ``include/lota_devt.h`` defines this layout once
(``LOTA_DEVT_MAJOR``, ``LOTA_DEVT_MINOR``, ``LOTA_DEVT_MKDEV``) and the programs
use it for both jobs:

* The kernel-memory-device guard decodes ``i_rdev`` with ``LOTA_DEVT_MAJOR`` /
  ``LOTA_DEVT_MINOR`` and blocks opening character major 1, minor 1/2/4
  (``/dev/mem``, ``/dev/kmem``, ``/dev/port``).
* The trusted-library maps are keyed by ``(s_dev, i_ino)`` taken verbatim from
  the inode, so the key is already in the kernel MKDEV layout.

The agent populates the trusted-library maps from user space, where ``stat(2)``
reports ``st_dev`` in the glibc encoding rather than the kernel MKDEV layout.
The loader converts it with ``lota_devt_from_st()`` before writing a map key,
so the user-space key and the kernel-side key built from ``s_dev`` are the same
value and the lookup matches.
