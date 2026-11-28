.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

===============
BPF LSM program
===============

The daemon enforces through one BPF object, :ghsrc:`src/bpf/lota_lsm.bpf.c`,
attached to LSM hooks, tracepoints and function entries. It refuses what the
startup policy and :doc:`../agent/configuration` refuse, guards the agent and
the protected processes (:doc:`../agent/protection`), and records what the
agent measures. The definitions it shares with user space are in
:ghsrc:`include/lota.h`; the loader is :ghsrc:`src/agent/bpf_loader.c`.

Contents
========

* :doc:`coding` -- rules for changing the program.

.. toctree::
   :hidden:

   coding

Loading
=======

The loader reads the object and its detached signature,
``<object>.sig``, checks the signature against the enforcement public key,
and opens the verified bytes from memory, so a file changed after the check
is not what loads. A refused signature or layout ends the start before PCR
14 is touched (:doc:`../agent/lifecycle`).

After the load, in this order:

#. ``lota_task_auth`` gets ``LOTA_TASK_AUTH_ADMIN`` and
   ``LOTA_TASK_AUTH_AGENT`` on the daemon's thread group leader, and the map
   is frozen. The flags are read on a task's group leader, so every thread
   of the daemon is the agent and no other process can become it.
#. ``lota_config`` gets ``LOTA_CFG_LOCK_BPF`` (`The bpf syscall`_).
#. ``integrity_cfg`` records whether module signatures are enforced and
   lockdown is at ``integrity`` or above. When either is off the daemon logs
   ``Kernel integrity baseline not met (...); module and firmware loads are
   refused in every mode``.
#. ``guarded_files`` gets the ``cgroup.kill`` and ``cgroup.freeze`` files of
   the agent's cgroup and its ancestors, and is frozen. With no unified
   cgroup hierarchy, or no such file, the map is frozen empty.
#. The startup policy writes ``lota_config`` (`Mode and switches`_).
#. Each program is attached. The start fails when one does not attach, or
   when any of ``lota_ptrace_access_check``, ``lota_agent_exit``,
   ``lota_no_core``, ``lota_agent_moved``, ``lota_stop_enter`` and
   ``lota_stop_leave`` is missing from the object.

Mode and switches
=================

``lota_config`` holds the mode, five switches of ``lota.conf`` and
``LOTA_CFG_LOCK_BPF``. The startup policy writes them, and a reload writes
the changed ones:

.. list-table::
   :header-rows: 1
   :widths: 30 30 40

   * - Key
     - ``lota.conf``
     - Effect
   * - ``LOTA_CFG_MODE``
     - ``mode``
     - ``LOTA_MODE_MONITOR`` (0) or ``LOTA_MODE_ENFORCE`` (1).
   * - ``LOTA_CFG_STRICT_MMAP``
     - ``strict_mmap``
     - Executable mappings of a protected process; trusted libraries.
   * - ``LOTA_CFG_BLOCK_PTRACE``
     - ``block_ptrace``
     - ``ptrace`` attach to any process.
   * - ``LOTA_CFG_BLOCK_ANON_EXEC``
     - ``block_anon_exec``
     - Anonymous executable memory of a protected process.
   * - ``LOTA_CFG_STRICT_EXEC``
     - ``strict_exec``
     - ``execve`` of files outside ``allow_verity``.
   * - ``LOTA_CFG_STRICT_MODULES``
     - ``strict_modules``
     - Modules and firmware outside ``allow_verity``.
   * - ``LOTA_CFG_LOCK_BPF``
     - none
     - LOTA maps and links closed to other processes.

The five ``lota.conf`` switches take effect only in ``enforce`` mode; in
``monitor`` mode they change nothing. ``LOTA_CFG_LOCK_BPF`` and the rules
that guard the agent, the protected processes and the kernel hold in both
modes.

Hooks
=====

A hook refuses with ``-EPERM``, but ``lsm/task_alloc`` when it cannot
store a mark. A kernel path that asks ``ptrace_access_check`` returns its
own error: an open of ``/proc/<pid>/mem`` fails with ``EACCES``.

Execution and kernel input
--------------------------

``lsm/bprm_check_security``
  Reads the fs-verity digest of the file. In ``enforce`` mode with
  ``strict_exec`` it refuses a script starting with ``#!``, an interpreter a
  binfmt handler hands the exec to, an exec through a descriptor, and a file
  whose digest is missing or not in ``allow_verity``. Emits ``EXEC`` or
  ``EXEC_BLOCKED``.

``lsm/kernel_read_file``, ``lsm/kernel_load_data``
  Rule on modules, firmware, kexec images, IMA policy and certificates with
  ``lota_kread_denied()`` (`Verdict functions`_). Emit ``MODULE_LOAD`` or
  ``MODULE_BLOCKED``.

``lsm/bprm_committed_creds``
  Notes in ``born_protected`` that a protected process executed its current
  image under protection.

``lsm/task_fix_setuid``
  Emits ``SETUID`` when the real uid changes. Refuses nothing.

Memory mappings
---------------

``lsm.s/mmap_file``, ``lsm/file_mprotect``
  Record an executable mapping of a file: in ``mapped_seen`` for every
  process, in ``exec_history`` for a protected one. Memory with no file
  behind it, a ``/dev/zero`` mapping, SysV shared memory, and an unlinked
  tmpfs or hugetlbfs file count as anonymous; with ``block_anon_exec`` a
  protected process is refused them (``ANON_EXEC_BLOCKED``). With
  ``strict_mmap`` a protected process is refused an executable mapping that
  is writable, or whose file is neither in ``allow_verity`` nor a trusted
  library (``MMAP_EXEC``, ``MMAP_BLOCKED``). The last refused object is kept
  in ``lota_refusal``.

Files and mounts
----------------

``lsm.s/file_open``
  Refuses, in every mode:

  * ``/dev/mem``, ``/dev/kmem`` and ``/dev/port``;
  * an entry of ``/proc/<pid>`` that reads the memory of the agent, or of a
    protected process from outside its instance (``PTRACE_BLOCKED``); the
    agent's reads and a process's reads of itself pass;
  * a write open of a guarded cgroup file to all but the agent
    (``KILL_GUARD_BLOCKED``);
  * a write open of a file in ``mapped_exec`` (``MAPPED_WRITE_BLOCKED``).

  In ``enforce`` mode with ``strict_mmap`` it refuses a write open of a
  trusted library. ``O_WRONLY``, ``O_RDWR`` and ``O_TRUNC`` count as write.

``lsm/path_truncate``
  Refuses a truncate of a file in ``mapped_exec``, and of a trusted library
  under ``strict_mmap``.

``lsm/sb_mount``, ``lsm/move_mount``
  In ``enforce`` mode with ``strict_mmap``, refuse a ``mount(2)`` with
  ``MS_BIND`` or ``MS_MOVE`` and a ``move_mount(2)`` onto a trusted library
  (``MOUNT_BLOCKED``).

``lsm.s/file_post_open``
  Answers the agent's questions in ``exe_hash_slots``: the file's IMA hash,
  or whether a pin holds (:doc:`../agent/runtime-measurement`).

Processes and signals
---------------------

``lsm/ptrace_access_check``
  Rules with ``lota_ptrace_denied()`` and emits ``PTRACE`` or
  ``PTRACE_BLOCKED``. An access inside one instance is recorded in
  ``instance_actors``.

``lsm/task_kill``
  Rules with ``lota_signal_denied()`` on a signal at the agent or a
  protected process, and emits ``KILL`` or ``KILL_BLOCKED``. A signal inside
  one thread group, from the agent, or a parent-death signal is not judged.

``lsm/file_send_sigiotask``
  Rules with ``lota_sigio_denied()`` on a signal ``F_SETOWN`` aims at the
  agent or a protected process, with the sender counted as outside the
  instance and none of the exceptions of ``lsm/task_kill``, and emits
  ``KILL_BLOCKED`` when it refuses.

``lsm/task_setrlimit``
  Refuses a change to the limits of the agent, and of a protected process
  from outside its instance (``KILL_BLOCKED``).

``lsm/task_alloc``
  Marks a child of a protected process before it first runs, and refuses
  the clone when the mark cannot be stored or ``lota_clone_refused()``
  says so.

``tp_btf/signal_deliver``
  Ends a protected process with ``SIGKILL`` when a core-dumping signal it
  does not handle is delivered (``KILL_BLOCKED``).

``tp_btf/sched_process_exit``
  When the agent's thread group exits, sends ``SIGKILL`` to every protected
  process.

``lsm/task_free``
  Removes a protected process from ``protected_pids`` when its group leader
  is freed.

Sockets
-------

``lsm/socket_post_create``, ``lsm/socket_bind``, ``lsm/socket_listen``
  Mark a unix socket a process of an instance created, bound or listens on.

``lsm/unix_stream_connect``, ``lsm/unix_may_send``
  Record in ``instance_actors`` a process outside the instance that connects
  or sends to a marked socket. Refuse nothing.

Cgroups
-------

``fentry/cgroup_attach_task``
  A move of the agent to another cgroup ends every protected process and the
  agent before the move takes effect (``AGENT_MOVED``).

``fentry/cgroup_enter_frozen``, ``fexit/cgroup_leave_frozen``
  Add the time a thread of an instance stands stopped to ``instance_stops``
  of the instance root (:doc:`../agent/protection`).

The bpf syscall
---------------

With ``LOTA_CFG_LOCK_BPF`` set, in every mode, ``lsm/bpf_map`` refuses a
descriptor of a map the object declares in ``.maps`` to all but the agent,
and ``lsm/bpf`` refuses ``BPF_LINK_DETACH``. The hook compares the map's
address with those maps, so a map of another program with the same name
stays open, and so does the frozen map of the object's string constants.

Maps
====

.. list-table::
   :header-rows: 1
   :widths: 25 20 55

   * - Map
     - Type
     - Contents
   * - ``events``
     - ring buffer, 256 KiB
     - `Events`_; the agent reads them.
   * - ``stats``
     - array
     - `Statistics`_.
   * - ``lota_config``
     - array
     - `Mode and switches`_; written by the agent.
   * - ``integrity_cfg``
     - array
     - Module signature enforcement and lockdown, written at load.
   * - ``event_budget``
     - array
     - One emission window per event type (`Event budget`_).
   * - ``lota_task_auth``
     - task storage
     - The agent's flags, written at load and frozen.
   * - ``lota_instance``
     - task storage
     - The instance root a process inherited.
   * - ``born_protected``
     - task storage
     - Set by ``bprm_committed_creds``.
   * - ``instance_stops``
     - task storage
     - Stopped threads and stopped time of an instance root.
   * - ``lota_refusal``
     - task storage
     - The last refused mapping and its time.
   * - ``verity_scratch``
     - per-CPU array
     - Scratch space for a digest.
   * - ``protected_pids``
     - hash, 1024
     - Protected processes: TGID to start time in clock ticks; written by the
       agent.
   * - ``trusted_libs``
     - hash, 512
     - Trusted libraries by device and inode (``trust_lib``).
   * - ``guarded_files``
     - hash, 64
     - Guarded cgroup files, written at load and frozen.
   * - ``mapped_exec``
     - hash, 16384
     - Files the agent pinned while they are mapped.
   * - ``mapped_seen``
     - LRU hash, 65536
     - Size and change time of each file seen mapped executable.
   * - ``exec_history``
     - hash, 65536
     - Executable mappings of protected processes.
   * - ``lota_sock_owner``
     - socket storage
     - The instance a unix socket belongs to.
   * - ``instance_actors``
     - hash, 4096
     - Actors of each instance.
   * - ``allow_verity``
     - hash, 1024
     - Allowed fs-verity digests, SHA-256 or SHA-512 (``allow_verity``).
   * - ``exe_hash_slots``
     - hash, 64
     - One question per agent thread for ``file_post_open``.

Device numbers in the keys of ``trusted_libs``, ``guarded_files`` and
``mapped_exec`` use the kernel's layout (:ghsrc:`include/lota_devt.h`).

Events
======

Each event is a ``struct lota_exec_event``. Every type sets
``timestamp_ns``, ``pid``, ``tgid``, ``uid`` and ``comm``; ``uid`` is 0 on
the module types. Beyond those:

.. list-table::
   :header-rows: 1
   :widths: 40 60

   * - Type
     - Fields
   * - ``EXEC``
     - ``filename``, ``hash`` (the first 32 bytes of the fs-verity digest)
   * - ``MODULE_LOAD``
     - ``filename``
   * - ``MMAP_EXEC``
     - ``filename``, ``flags``
   * - ``ANON_EXEC``
     - ``filename``: a fixed label, or a refused memory file's name
   * - ``PTRACE``
     - ``target_pid``, ``filename`` (the target's), ``flags``
   * - ``KILL``
     - ``target_pid``, ``signal``, ``filename`` (a fixed label)
   * - ``SETUID``
     - ``target_uid`` (the new uid)
   * - ``AGENT_MOVED``
     - ``target_pid``, ``filename`` (the cgroup)
   * - ``PTRACE_BLOCKED`` on a ``/proc`` open
     - ``target_pid``, ``filename`` (the entry)
   * - ``MOUNT_BLOCKED``, ``KILL_GUARD_BLOCKED``, ``MAPPED_WRITE_BLOCKED``
     - ``filename``
   * - Other ``*_BLOCKED``
     - As the base type

``LOTA_EVENT_FLAG_PROTECTED`` marks a mapping by a protected process,
which the agent measures again; ``LOTA_EVENT_FLAG_INSIDE_INSTANCE`` a
``ptrace`` access within one instance.

The agent writes each event to the journal at ``info``, ``AGENT_MOVED`` at
``warn`` (:ghsrc:`src/agent/event.c`); most types as:

.. code-block:: text

   [TIMESTAMP] TYPE COMM: FILENAME (pid=P, uid=U)

Event budget
------------

In ``enforce`` mode each type has a one-second window: 256 events of a
permitted type, 1024 of a refused one. ``MOUNT_BLOCKED``,
``KILL_GUARD_BLOCKED``, ``MAPPED_WRITE_BLOCKED`` and the ``PTRACE_BLOCKED``
of an open take the refused cap in both modes; ``SETUID`` and
``AGENT_MOVED`` have none. In ``monitor`` mode the other types are emitted
without a cap. Past 75% of the ring, a type under a cap that emitted 8 in
the window yields to quieter ones (:ghsrc:`include/lota_event_budget.h`).

Statistics
==========

``stats`` counts executions, mappings, refusals, ``ptrace`` access checks,
events sent, ring-buffer drops, events suppressed or yielded by the budget,
signal-0 probes, and the entries ``exec_history``,
``instance_actors`` and ``instance_stops`` could not store. When the daemon
leaves its event loop it logs them on one line that starts ``Shutdown
statistics: exec=``, without the suppressed events, ``STAT_EXEC_BLOCKED``,
``STAT_ANON_EXEC`` and ``STAT_ANON_EXEC_BLOCKED``.

Verdict functions
=================

The decisions of the hooks are plain functions in :ghsrc:`include/lota.h`,
compiled into the object and into the unit tests alike.

.. kernel-doc:: include/lota.h
