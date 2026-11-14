.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

======================
BPF LSM program coding
======================

Rules for changing :ghsrc:`src/bpf/lota_lsm.bpf.c`. The daemon refuses to
start when the kernel's verifier rejects any program of the object, so a
change that one kernel accepts and the deployment kernel rejects stops every
host that installs it. What the programs do is in :doc:`index`.

Building
========

``make bpf`` compiles the object to ``build/lota_lsm.bpf.o`` with clang,
``-target bpf -g -O2 -mcpu=v3``, and ``__TARGET_ARCH_<arch>`` and
``__BPF_PROGRAM__`` defined. The kernel
types come from ``include/vmlinux.h``, which the build dumps from
``/sys/kernel/btf/vmlinux`` of the building host when it is missing. ``make
sign-bpf`` writes the detached signature ``build/lota_lsm.bpf.o.sig`` with
``SIGNING_KEY`` (default ``/etc/lota/policy.key``); the agent loads no
object without it (:doc:`index`).

Verifier rules
==============

Pointers assigned on one path
  A pointer set only on some paths, as an event that the budget admitted to
  ``bpf_ringbuf_reserve()``, is initialized to ``NULL`` where it is
  declared. The verifier tracks each path, and whether it accepts a read of
  such a pointer depends on how clang laid out the branches.

Trusted pointers
  A kfunc or task-storage helper takes a pointer the verifier trusts. Read
  such a field directly, as ``task->group_leader`` and ``bprm->file`` are
  read; ``BPF_CORE_READ()`` yields a scalar.

Task storage in a sleepable hook
  In an ``lsm.s/`` program the current task is trusted only under
  ``bpf_rcu_read_lock()``, so ``bpf_task_storage_get()`` there is called
  between ``bpf_rcu_read_lock()`` and ``bpf_rcu_read_unlock()``, as
  ``task_instance()`` and ``sleepable_task_is_agent_or_admin()`` do.

Copies
  clang refuses a ``memcpy()`` of variable length for BPF. Copy a constant
  size, one branch per size, as ``lota_verity_key_from_digest_buf()`` does
  for the two digest lengths.

State shared between CPUs
=========================

Every hook can run on every CPU at once. A value in a map that is not
per-CPU changes only through atomics (``__sync_fetch_and_add()``,
``__sync_val_compare_and_swap()``): ``inc_stat()`` counts that way, and the
budget window rotates by compare-and-swap. A value of more than one field
that must change as a whole carries a ``struct bpf_spin_lock``, as
``instance_stops`` and ``lota_refusal`` do; the agent reads it with
``BPF_F_LOCK``.

Decisions as plain functions
============================

A rule that decides is written as a function of scalars in
:ghsrc:`include/lota.h` or :ghsrc:`include/lota_event_budget.h`, with a
kernel-doc comment, and the hook reads the kernel structures and passes the
values in. The program and the unit tests include the same header, so the
tests run the code the kernel runs: ``tests/test_signal_policy.c``,
``tests/test_ptrace_policy.c``, ``tests/test_module_purpose.c``,
``tests/test_event_budget.c`` and others. Test a rule both ways: what it
refuses and what it lets through.

A rule that cannot leave the program, because it reads kernel structures
throughout, is copied into ``fuzz/bpf_oracle/lota_lsm_logic.h`` with the
reads lifted to parameters, and fuzzed against an independent reference.
``fuzz/bpf_oracle/mirror.lock`` holds a hash of each copied function and
the ``#define`` line of each copied macro. ``make check-bpf-mirror``, which
``scripts/check-patch`` runs, fails when the program differs from the lock;
update the copy, then run ``make update-bpf-mirror`` and commit the lock
with the change.

Adding a map
============

* Add its name to ``is_lota_managed_map()``, or ``lock_bpf`` leaves it open
  to every process (:doc:`index`).
* A structure the agent reads or writes is declared again in
  :ghsrc:`src/agent/bpf_loader.c` beside the others marked ``mirrors struct
  ... in lota_lsm.bpf.c``, with the same layout.
* The loader finds the map by name and marks its descriptor close-on-exec.

Adding a program
================

The loader attaches every LSM and tracing program in the object and fails
the start when one does not attach. It holds at most ``BPF_MAX_LSM_LINKS``
(32) links (:ghsrc:`src/agent/bpf_loader.h`); the object has 30 programs. A
program without which the agent must not run goes on the list of required
programs in ``bpf_loader_attach()``.

Events
======

A hook asks ``should_emit_event()`` before it reserves ring space. The caps,
the window and the pressure watermark live only in
:ghsrc:`include/lota_event_budget.h`, which the program and
``tests/test_event_budget.c`` include; change them there.

Most refusals have a counter of their own in ``stats``, kept whether or
not the event is emitted; a refused signal or limit change has none, and
past its budget only ``STAT_BLOCKED_EVENTS_SUPPRESSED`` counts it. Once a
second the daemon adds the ring-buffer drops, the events yielded under
pressure and the refused events past their budget. When the sum grew it
logs ``SECURITY: kernel left out N events (full=F yielded=Y
blocked_budget=B); log incomplete - enforcement unaffected`` and sets
``LOTA_STATUS_EVENTS_LOST`` until it ends (:ghsrc:`src/agent/daemon_loop.c`).
N is the growth since the last check; F, Y and B are totals since the load.
A permitted event past its budget does not count: an ordinary boot spends
that budget.

An event never worth a line is dropped before the reserve.
``lota_signal_event()`` drops a permitted signal 0, a liveness probe a
launcher sends many times a minute, and ``lota_task_kill`` counts it in
``STAT_KILL_PROBES``.

Device numbers
==============

The programs key a file by ``inode->i_sb->s_dev`` and ``inode->i_ino`` and
read a device node from ``inode->i_rdev``. The kernel keeps these in its own
layout, a 20-bit minor with the major above it, which
:ghsrc:`include/lota_devt.h` defines once (``LOTA_DEVT_MAJOR``,
``LOTA_DEVT_MINOR``, ``LOTA_DEVT_MKDEV``). The guard on ``/dev/mem``,
``/dev/kmem`` and ``/dev/port`` decodes ``i_rdev`` with it.

``stat(2)`` reports ``st_dev`` in another layout, and on btrfs the device of
the subvolume. The agent writes a key with the superblock's device from
``/proc/self/mountinfo``, for the mount ``statx()`` names
(:ghsrc:`src/agent/sb_dev.c`), so its keys match the ones the hooks build.

Checks in CI
============

``bpf-elf-inspect``
  Builds the object and checks that it is a BPF ELF with ``lsm/`` program
  sections, a ``license`` section and ``.maps``, and that its BTF dumps.

``bpf-veristat``
  Boots the Fedora kernel in a ``virtme-ng`` VM with ``lsm=bpf`` and runs
  :ghsrc:`scripts/veristat-gate.sh`, which passes every program through
  that kernel's verifier with ``veristat``. On a rejection it loads the
  object with ``bpftool prog load`` and prints the verifier log of the
  first program refused; libbpf stops there, so the next one's log shows
  once that one loads. A load that fails before the verifier, without root
  or on a host where the agent runs with ``lock_bpf``, is reported as such.

To run the gate as the job does:

.. code-block:: sh

   make bpf
   vng --run "$(uname -r)" --append "lsm=bpf" \
       --exec "cd '$PWD' && sh scripts/veristat-gate.sh build/lota_lsm.bpf.o"
