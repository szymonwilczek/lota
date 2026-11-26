.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

===================
Protected processes
===================

Ending a protected process
==========================

``lota_task_kill`` delivers every signal to a protected process and records
it; a killed title cheats in nothing. It refuses signals to the agent from
anything but the agent itself, a holder of ``LOTA_TASK_AUTH_ADMIN`` or the
kernel; that flag is set on the agent's PID before the map is frozen, so
nothing else on the machine holds it and root is no exception.
``LOTA_IPC_CMD_TERMINATE_PROTECTED`` ends a protected process on request and
leaves a record of it.

That hook covers signals only. A write to ``cgroup.kill`` kills a whole
cgroup from cgroup code, past every security hook, and a write to
``cgroup.freeze`` stops it the same way, so ``lota_file_open`` refuses write
opens of the files in ``guarded_files``. The loader arms it at startup with
both files of the agent's cgroup and of its ancestors: an agent killed or
frozen that way drops enforcement for the rest of the boot while PCR 14 still
holds the boot commitment. Moving a task between cgroups has no security hook,
and a cgroup frozen beforehand freezes what enters it, in either hierarchy, so
no file guard covers a move. ``lota_agent_moved`` on ``cgroup_attach_task``
therefore ends the protected processes and the agent before the move takes
effect, as the agent's own exit does. It is an fentry program because the
tracepoint of that name runs under a spinlock, where signals go through one
per-CPU slot. A protected process's cgroup is not armed: killing it ends only
its own session, and its owner can end it with an ordinary signal anyway.

The handler applies ``kill(2)``'s own rule -- the owner of the target, or root
-- and nothing wider. It deliberately does **not** call
``ipc_client_is_privileged()``, which ``SHUTDOWN`` does:
that gate demands a caller whose executable is on the operator's verity
allowlist, which is empty on a default install, so requiring it here would
reproduce the dead end the command exists to end. What keeps the widening
bounded is that the caller could send the same signal itself; the command
adds only the record.

Four refusals sit around that rule: a signal other than ``SIGTERM`` or
``SIGKILL``, so the command cannot drive a process that stays in the measured
set; a target nobody protected, which the caller can already signal; PID 1 and
PID 0; and the agent itself, whose stopping is ``--shutdown``'s business
because PCR 14 commits for the whole boot.

Each of those answers with its own result code, because the code is all the
caller gets and the sentence it turns into has to match what happened:
``LOTA_IPC_ERR_NOT_PROTECTED`` for a process nobody protected;
``LOTA_IPC_ERR_TARGET_REFUSED`` for a target the
command does not speak for at all, PID 0, PID 1 and the agent;
``LOTA_IPC_ERR_ACCESS_DENIED`` for a request that is not this caller's to
make, which covers both the wrong signal and the wrong owner; and
``LOTA_IPC_ERR_BAD_REQUEST`` for a target that is not there. Collapsing them
misdirects: with one code, ending the agent's own PID reads back as a
permission problem with somebody else's process.

The handler opens a pidfd on the target before reading its owner from
``/proc``, and sends the signal through that pidfd. A pidfd names the process,
not the number: once the process is reaped its number can be handed to another
one, and a signal sent through the pidfd fails with ``ESRCH`` instead of
reaching it. A target that has exited by the time its owner is read, or has
been reaped by the time the signal is sent, answers
``LOTA_IPC_ERR_BAD_REQUEST``.

The caller must run in the agent's PID namespace, since ``pid`` is read in it;
one whose pidfd fdinfo lists more than one ``NSpid`` is refused with
``LOTA_IPC_ERR_ACCESS_DENIED``.

``LOTA_STATUS_PROTECTED_TERMINATED`` is then set for the rest of the boot: in
the host's answer, and in the answers of the publisher the target was protected
for, taken from the owner table before the signal. The host's bit is kept
beside ``status_flags``, because that word is republished wholesale on every
attestation round; ``ipc_update_status`` folds it back in. The publisher's bit
lives on its profile, and ``client_attestation_view`` gives a connection that
named a publisher that one in place of the host's, so the status answer, the
token and the notification of one connection carry it from one source. That agreement is load-bearing: the anti-cheat heartbeat
binds the flags it read from ``GET_STATUS`` into the nonce the token is quoted
over, so a bit set in one and not the other surfaces as a nonce mismatch.

The record lives in the agent and ends with it. An agent that starts and finds
PCR 14 already holding the boot's commitment follows one that ended without a
shutdown, since only a shutdown spends it, so it sets
``LOTA_STATUS_AGENT_RESTARTED`` for the rest of the boot the same way. A token
that dropped ``PROTECTED_TERMINATED`` across a restart carries that bit instead,
and the register it rests on is not one root can reset.

What a protected process mapped
===============================

The token carries one registry digest per protected process. ``8192`` bytes hold
no list of the objects themselves, so ``LOTA_IPC_CMD_GET_REGISTRY`` hands them
out in pages: every code object the process mapped or mprotected executable
since it was protected, each with its size, device, inode and, where one was
taken, its digest.

Objects still mapped when the token round measured the process carry their
path. Objects the process had already unmapped carry
``LOTA_IPC_REGISTRY_ENTRY_UNMAPPED``, the file's name in place of a soname, and
no path or digest. The kernel records each mapping as it is made
(``exec_history`` in ``src/bpf/lota_lsm.bpf.c``), a refused one included, so
an object loaded and dropped between two rounds is still listed. A record the
kernel could not keep sets ``LOTA_IPC_REGISTRY_HISTORY_LOST`` on every list of
the round: such a list may lack an object.

The history starts when protection does. ``LOTA_IPC_REGISTRY_FROM_EXEC`` says
the process's current image was executed under protection (``born_protected``,
set by ``lsm/bprm_committed_creds``), so nothing the image mapped predates the
list. A process protected after it started, or forked from a protected one and
never executed, lacks the flag; withdrawing protection clears it.

One measurement holds ``LOTA_RUNTIME_IMAGE_MAX_MODULES`` objects, the first in
address order. Mappings past them are unmeasured and clear
``LOTA_STATUS_IMAGE_FULLY_MEASURED``, and ``LOTA_IPC_REGISTRY_TRUNCATED`` says so
on the list. They have no entry of their own: one the history knows is listed
as unmapped. A process whose own executable falls past the limit is not
measured.

A file can change under a mapping without being written again: another process
holds it open for write, or maps it shared and writable, and stores into the
pages the protected process runs. The kernel notes, at every executable
mapping, whether the file had such a writer, and whether it lives in memory
only (memfd, shm, tmpfs or hugetlbfs), where no file on disk names the code.
A memfd or shm segment has no name to open, so its fds never count as
writers: such an object counts as written unless a seal
(``F_SEAL_WRITE`` or ``F_SEAL_FUTURE_WRITE``) forbade writes when it was
mapped.
An object mapped once with a writer carries
``LOTA_IPC_REGISTRY_ENTRY_WRITABLE``, one backed by memory
``LOTA_IPC_REGISTRY_ENTRY_MEMORY``, mapped or unmapped alike. A digest taken
at the round says what the pages held then, not what they held between two
rounds. Nothing is refused on either flag.

The kernel sees only mappings made under protection. For an older one the
agent's walk reads the same memory and seal facts off the open file, as they
stand at the round. A writer of a named file shows only at the mapping itself.

After the objects come the actors: every process that reached a process of
the instance on a road the kernel lets through. An instance is the protected
process and everything it started. From outside, the road is a unix socket:
a process connected to a unix stream socket, or sent a datagram to one, owned
by a process of the instance. The kernel marks a socket with its owner when a
process of the instance creates, binds or listens on it. From inside, the
road is one process of the instance reading another (``ptrace`` in read mode),
attaching to it or writing into it (``ptrace`` attach, ``process_vm_writev``,
``/proc/<pid>/mem``), or signalling it, as ``wineserver`` does to the title.
A process of the instance is also listed for itself when it maps anonymous
memory executable or mprotects it to executable, a refused attempt included:
such code leaves no object to list, so the entry (``ANON_EXEC``, with
``owner_tgid`` equal to ``tgid``) says who did it and how many times.
The kernel records each contact as it is made (``instance_actors`` in
``src/bpf/lota_lsm.bpf.c``). An actor carries its
PID, start time, uid, the device and inode of its executable, its command
name, the owning process and its name, how it reached in and how many times.
Nothing is refused: the list says who reached in, the relying party decides
what that means. A record the kernel could not keep, or a list longer than
``LOTA_IPC_REGISTRY_MAX_ACTORS``, sets ``LOTA_IPC_REGISTRY_ACTORS_LOST``. Indices
below ``total`` are objects, the next ``actor_total`` are actors, and the pages
hand them out in that order.

A token also says how long the caller's instance stood stopped, in
``stopped_ms``. A frozen cgroup, job control and a ptrace stop all pass through
``cgroup_enter_frozen()`` and ``cgroup_leave_frozen()`` in the thread that
stands, so one pair of programs covers the three, and ``instance_stops`` on the
root task holds the result. The clock runs while at least one thread stands, not
once per thread, and it is ``bpf_ktime_get_ns()``, which skips a suspend. The
agent adds the period still open when it reads. Withdrawing protection from a
root closes its open period and keeps the total, because a thread of an
unprotected process leaves its stop unseen. The value never falls while the root
lives.

The token binds the list. Hashing the page's ``flags``, ``total`` and
``actor_total`` and every entry in order as ``lota_registry_digest.h`` does
yields the page's
``registry_digest``, which is the token's entry for that process while
``LOTA_IPC_REGISTRY_MEASURED`` is set. Every field of every entry is in the
hash, the entries without a digest and the actors included, so a list with an entry dropped,
reordered or rewritten does not hash to the token's value. A list from another
round does not either, so a relying party that checks the hash needs no further
pairing; the ``round`` field only keeps the pages of one listing together.

The owner of the process may read its registry from inside the process's
instance, the callers that could read its ``maps`` themselves; root outside the
instance is refused too. A process the last round did not measure is
answered ``LOTA_IPC_ERR_NOT_PROTECTED``.

``lota_get_registry()`` in ``liblotagaming`` fetches every page and starts over
when a token round replaces the listing between two of them;
``lota_server_registry_digest()`` in ``liblotaserver`` is the hash, so a
relying party checks the list without reimplementing it.
