.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

===================
Protected processes
===================

A title asks the agent to protect it. The BPF LSM then keeps other
processes out of its memory and its signals, and every token lists it with
a digest of the code it mapped (:doc:`tokens`). A protected process and
every process it starts form an *instance*. The hooks are in
:ghsrc:`src/bpf/lota_lsm.bpf.c`, the requests in :ghsrc:`src/agent/ipc.c`.

Protecting a process
====================

``PROTECT_PID`` (:doc:`ipc`), ``lota_protect_self()`` in the SDK,
protects the process that opened the connection. The PID comes from
``SO_PEERPIDFD``; the request carries 0 and any other value is
``LOTA_IPC_ERR_BAD_REQUEST``. The answer is the 32-byte digest of the
startup enforcement policy. ``protect_pid`` in :doc:`configuration` and
``--protect-pid`` (:doc:`command-line`) protect a PID from the agent's
side.

The request is refused with:

* ``LOTA_IPC_ERR_ACCESS_DENIED`` when the caller runs in another PID
  namespace or has exited, or when it is held by a tracer: protection
  stops new attaches, not one already there;
* ``LOTA_IPC_ERR_RATE_LIMITED`` past 60 requests per uid in a minute;
* ``LOTA_IPC_ERR_NO_ENFORCEMENT`` when the agent applied no startup policy;
* ``LOTA_IPC_ERR_BAD_REQUEST`` when ``LOTA_MAX_PROTECTED_PIDS`` (1024)
  processes are protected.

A process already protected gets the same answer again. On a connection
bound to a publisher (:doc:`ipc`), the process is noted as protected for
that publisher.

A process created by a protected one is marked before it first runs
(``lsm/task_alloc``); when the mark cannot be stored the clone fails. A
protected process held by a tracer outside its instance creates no
process or thread. The agent adds the children to its protected set when
it next looks at it. A process leaves the set when it exits.

What protection enforces
========================

From outside the instance:

* ``ptrace`` access, read or attach, is refused in every mode, and so is
  an open of a ``/proc/<pid>`` entry that reads the process's memory. The
  agent's own reads of ``/proc/<pid>/exe`` and ``maps`` pass.
* A signal that stops the process (``SIGSTOP``, ``SIGTSTP``, ``SIGTTIN``,
  ``SIGTTOU``) or whose default writes a core file is refused, from
  ``kill(2)`` and from ``F_SETOWN``. Every other signal passes, so the
  process can be ended. A signal from the agent, a parent-death signal
  and one the kernel sends itself are not judged.
* Its resource limits cannot be changed, but by the agent.

Inside the instance every signal and ``ptrace`` access passes: a
``wineserver`` drives the processes it hosts with signals. A signal whose
default writes a core file and that the process does not handle ends the
whole process group with ``SIGKILL`` (``tp_btf/signal_deliver``), so no
core file is written.

In ``enforce`` mode, ``strict_mmap`` and ``block_anon_exec``
(:doc:`configuration`) refuse executable mappings of a protected process
(:doc:`runtime-measurement`). The program that refuses each is described
in :doc:`../bpf/index`.

When the agent exits, ``tp_btf/sched_process_exit`` sends ``SIGKILL`` to
every protected process: nothing the agent vouched for outlives it.

The agent itself
----------------

Signals to the agent are refused from every process but the agent
itself; a probe (signal 0) and ``SIGHUP``, its reload, pass. The agent
stops with ``--shutdown``.

A write to ``cgroup.kill`` or ``cgroup.freeze`` ends or stops a cgroup
past every signal hook. At startup the loader stores both files of the
agent's cgroup and of each ancestor in ``guarded_files`` and freezes the
map, and ``lota_file_open`` refuses a write open of them to all but the
agent. A move between cgroups has no security
hook, and a frozen cgroup freezes what enters it, so
``fentry/cgroup_attach_task`` ends the protected processes and the agent
before a move of the agent takes effect. A protected process's own cgroup
is not guarded: killing it ends only that process.

Ending a protected process
==========================

``lota-agent --terminate-protected PID`` (:doc:`command-line`) sends
``TERMINATE_PROTECTED`` (:doc:`ipc`), which sends ``SIGTERM`` or
``SIGKILL`` to a protected process and records that it did. It applies
the rule of ``kill(2)``: the caller is root or the real uid of the
target. The command adds only the record, since the caller could send the
same signal.

The decision, in :ghsrc:`src/agent/terminate_policy.h`, runs in this
order:

#. PID 1: ``LOTA_IPC_ERR_TARGET_REFUSED``.
#. The agent itself: ``LOTA_IPC_ERR_TARGET_REFUSED``.
#. A process not in the protected set: ``LOTA_IPC_ERR_NOT_PROTECTED``.
#. A signal other than ``SIGTERM`` or ``SIGKILL``:
   ``LOTA_IPC_ERR_ACCESS_DENIED``.
#. A caller that is neither root nor the target's real uid:
   ``LOTA_IPC_ERR_ACCESS_DENIED``.

Before it, PID 0 or a PID past ``INT_MAX`` is ``LOTA_IPC_ERR_BAD_REQUEST``,
and a caller outside the host's PID namespace
``LOTA_IPC_ERR_ACCESS_DENIED``. The daemon opens a pidfd on the target
before it reads the owner, and signals through it: a process reaped in
between is not replaced by one that took its PID, and the request is
``LOTA_IPC_ERR_BAD_REQUEST``. A refusal is logged as
``TERMINATE_PROTECTED denied for uid=N pid=M target=T sig=S: why``, a
signal sent as ``Protected pid=T (uid=U) terminated with signal
S at the request of uid=N pid=M``.

The answer repeats the PID and the signal and counts the other protected
processes of the target's instance. ``LOTA_STATUS_PROTECTED_TERMINATED``
is then set in the host's status and in the status of the publisher the
target was protected for, until the agent ends. An agent started again in
the same boot sets ``LOTA_STATUS_AGENT_RESTARTED`` (:doc:`lifecycle`).

What a protected process mapped
===============================

A token carries one registry digest per protected process. The list
behind it is too long for a token, so ``GET_REGISTRY`` (:doc:`ipc`)
hands it out in pages: ``struct lota_ipc_registry_page`` followed by
entries, objects first, then actors (:ghsrc:`include/lota_ipc.h`). The
request names the PID and the index of the first entry; an index past the
end is ``LOTA_IPC_ERR_BAD_REQUEST``.

The list is the one the last token round built. A process that round did
not measure, or a PID that names another process, is
``LOTA_IPC_ERR_NOT_PROTECTED``. Only the process's owner calling from its
instance may read it, the caller that could read its ``maps``; root
outside the instance is ``LOTA_IPC_ERR_ACCESS_DENIED``.

``lota_get_registry()`` in ``liblotagaming`` fetches every page, and
starts over when a round replaces the list between two of them.

Objects
-------

Every code object the process mapped or made executable since it was
protected, with its size, device and inode, and a digest where one was
taken (``road``: fs-verity or content hash, :doc:`runtime-measurement`).
At most ``LOTA_IPC_REGISTRY_MAX_OBJECTS`` (1024) are listed.

* An object still mapped at the round carries its path.
* An object already unmapped carries ``LOTA_IPC_REGISTRY_ENTRY_UNMAPPED``,
  the file's name in place of a soname, and no path or digest. The kernel
  records each executable mapping as it is made (``exec_history``), a
  refused one included, so an object loaded and dropped between two
  rounds is listed.
* ``LOTA_IPC_REGISTRY_ENTRY_WRITABLE``: when mapped, the file was open
  for write or mapped shared and writable elsewhere; for a memfd or shm
  segment, no ``F_SEAL_WRITE`` or ``F_SEAL_FUTURE_WRITE`` kept it from
  writes. A digest says what the pages held at the round, not between
  rounds.
* ``LOTA_IPC_REGISTRY_ENTRY_MEMORY``: backed by memory only (memfd, shm,
  tmpfs or hugetlbfs).

Neither flag refuses anything. The kernel sees only mappings made under
protection; for an older one the agent reads the memory and seal facts
off the open file at the round, and a writer of a named file is not seen.

Page flags
----------

``LOTA_IPC_REGISTRY_MEASURED``
  ``registry_digest`` is the token's entry for the process.

``LOTA_IPC_REGISTRY_HISTORY_LOST``
  The kernel could not record a mapping; the list may lack an object.

``LOTA_IPC_REGISTRY_ACTORS_LOST``
  The kernel could not record an actor, or there were more than
  ``LOTA_IPC_REGISTRY_MAX_ACTORS`` (256).

``LOTA_IPC_REGISTRY_FROM_EXEC``
  The current image was executed under protection
  (``lsm/bprm_committed_creds``), so nothing it mapped predates the list.
  A process protected after it started, or forked from a protected one
  and not executed since, lacks it.

``LOTA_IPC_REGISTRY_TRUNCATED``
  The process had more executable mappings than one measurement holds
  (``LOTA_RUNTIME_IMAGE_MAX_MODULES``, the first in address order). Those
  past the limit are unmeasured and clear
  ``LOTA_STATUS_IMAGE_FULLY_MEASURED``; one the history knows is listed
  as unmapped. A process whose executable falls past the limit is not
  measured.

Actors
------

An actor is a process that reached a process of the instance on a road
the hooks let through (``instance_actors``). ``kind`` says which:

``LOTA_IPC_REGISTRY_ACTOR_CONNECT``, ``LOTA_IPC_REGISTRY_ACTOR_SEND``
  From outside: a stream or seqpacket connect to, or a datagram sent to, a
  unix socket a process of the instance created, bound or listens on.

``LOTA_IPC_REGISTRY_ACTOR_PTRACE_READ``
  From inside: one process of the instance reading another.

``LOTA_IPC_REGISTRY_ACTOR_PTRACE_ATTACH``
  From inside: one process of the instance attaching to another.

``LOTA_IPC_REGISTRY_ACTOR_SIGNAL``
  From inside: one process of the instance signalling another.

``LOTA_IPC_REGISTRY_ACTOR_ANON_EXEC``
  A process of the instance made anonymous memory executable, refused or
  not; ``owner_tgid`` equals ``tgid``. Such code leaves no object to list.

An actor carries its PID, start time, real uid, the device and inode of
its executable, its command name, the process it reached and that one's
name, and how many times. Nothing is refused: the relying party decides
what an actor means.

The digest
----------

Hashing the page's ``flags``, ``total`` and ``actor_total`` and every
entry in order, as :ghsrc:`include/lota_registry_digest.h` does, yields
``registry_digest``. Every field of every entry is hashed, so a list with
an entry dropped, reordered or changed, or a list from another round, does
not match the token. ``round`` only keeps the pages of one listing
together. ``lota_server_registry_digest()`` in ``liblotaserver`` computes
the hash (:doc:`../userspace-api/server`).

Stopped time
============

``stopped_ms`` in a token is how long any thread of the caller's instance
stood stopped. A frozen cgroup, a job-control stop and a ptrace stop all
pass through ``cgroup_enter_frozen()`` and ``cgroup_leave_frozen()`` in the
stopped thread, and ``instance_stops`` on the instance root holds the
result. The clock runs while at least one thread is stopped, and is
``bpf_ktime_get_ns()``, which does not count a suspend. The agent adds
the period still open when it reads. Withdrawing protection from a root
closes its open period and keeps the total.
