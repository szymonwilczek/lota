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

Reading a veristat gate failure
===============================

The ``bpf-veristat`` CI job runs ``scripts/veristat-gate.sh`` in a VM booted on
the deployment kernel. On a failure the gate loads the object with ``bpftool
prog load`` and prints the verifier log of the first refused program; libbpf
stops there, so the next one's log shows once it loads. A load that fails
before the verifier (no root, or an enforcing ``lota-agent`` refusing map
creation) is reported as a setup failure. To run it as the job does:

.. code:: bash

   make bpf
   vng --run "$(uname -r)" --append "lsm=bpf" \
       --exec "cd '$PWD' && sh scripts/veristat-gate.sh build/lota_lsm.bpf.o"

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
cannot fill the ring buffer faster than user space drains it. Each
``enum lota_event_type`` has its own window in ``event_budget``, so one flooding
type cannot spend another's budget; the class sets the cap, tighter for allowed
events than for blocked ones. A suppressed event loses only its detail: block
counts are tallied in the ``stats`` map regardless of emission.

All types still share one ring, so emission is gated a second time: once
``bpf_ringbuf_query`` reports occupancy past ``LOTA_EVENT_RING_PRESSURE_PCT``,
a type that has emitted ``LOTA_EVENT_PRESSURE_SHARE`` events this window yields
the rest. This rule bounds the ring as a whole; a type firing at a human rate
never reaches its share. Yields are counted in ``STAT_EVENTS_YIELDED``
(``yielded=`` in the shutdown statistics); ``STAT_RINGBUF_DROPS`` counts detail
lost to a full ring, which may belong to a type that was not the loud one.

The budget arithmetic lives in ``include/lota_event_budget.h`` as pure helpers
(``lota_event_budget_limit``, ``lota_event_budget_window_expired``,
``lota_event_budget_exhausted``, ``lota_event_ring_under_pressure``,
``lota_event_type_yields``) with no map lookups or atomics, so it is
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
