.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

=========================
Cross-component contracts
=========================

Surfaces that two components must agree on. Changing one side without the other
ships either a build that fails to link or a mixed-version fleet that silently
stops interoperating.

Runtime image measurement: which numbers identify a mapping
===========================================================

Measuring a protected process's executable images means enumerating its
mappings from ``/proc/<pid>/maps``, opening each through
``/proc/<pid>/map_files/<range>``, and confirming the handle still describes
what was enumerated. That confirmation is the contract, and it is easy to get
wrong in a way that only shows on some filesystems.

**A device number from ``/proc/<pid>/maps`` and one from ``stat()`` are not the
same quantity.** ``maps`` prints the filesystem's ``s_dev``; ``stat()`` returns
whatever the filesystem chooses to report, and btrfs reports a separate
anonymous device per subvolume. For one live mapping on a btrfs root the two
differ, so code that compares one against the other rejects every mapping on
that host -- silently, since the rejection looks like a mapping that moved.

The identity is therefore built from numbers of one kind:

* the device and inode of the enumerated range, and the device and inode of the
  range re-read from ``/proc/<pid>/maps`` after the handle was opened, are
  compared with each other -- same API, same meaning;
* the opened handle's own inode is compared against the enumerated inode, which
  is what ties the file being measured to the range that was enumerated.

Both halves are load-bearing. Dropping the device comparison would accept the
same inode number appearing on another filesystem; dropping the handle's inode
would accept a measurement of whatever the range points at now.

The same rule decides **which mapping is the process's own executable**, and
that decision is not cosmetic: an executable that cannot be measured fails the
measurement, while a library that cannot be measured is coverage the relying
party judges. The measurement therefore reports the identity of the handle it
opened (``struct lota_rt_open_identity``, a ``stat()`` device and inode) and
the caller compares that against a ``stat()`` of ``/proc/<pid>/exe``. Comparing
either against a number parsed out of ``maps`` recognises no executable at all
on a per-subvolume-device filesystem, which downgrades the fatal case to a
coverage note and makes the refusal name whichever object was recorded last.

A mapping the agent cannot open, or one that no longer resolves to the inode
enumerated, is a gap of the same kind and never contributes a digest. Its
handle gives no identity, so it stops the measurement only when no mapping
measured as the executable; the refusal then carries the errno of the open.

What the agent journals about a measurement round
=================================================

Every token round measures each protected process, but an fs-verity digest
does not change while mapped, so the answer rarely differs from the last one.
The journal carries only answers that differ:

- **A first answer is written**, unless every object measured.
- **A changed answer is written, both ways.** The line ending a run says how
  many further rounds the replaced answer held.
- **The sentence is compared**, not the verdict, so a new unmeasurable object
  mid-session is news.
- **An answer with no room in the table is written**, not assumed a repeat.

The sentence names the object's path and role. ``LOTA_RT_REASON_MAX`` and
``MEASURE_REPORT_STATEMENT_MAX`` must hold a whole path, or two objects cut to
one prefix compare equal; a new field grows both.

A standing answer has no window, unlike a decision-log row: every token
carries the measured coverage in ``LOTA_FLAG_IMAGE_FULLY_MEASURED``, so a
quiet journal hides no evidence. Shutdown reports the quiet as
``Runtime measurement reports: repeated=`` and ``unremembered=``.

The decision lives in the pure header ``src/agent/measure_report.h``, tested
both ways: a missing line fails as readily as a repeated one.

What the agent journals about a refused token
=============================================

Token requests come on the same timer, and a refusal's cause (no publisher
named, no TPM) does not move between rounds. A refusal follows the rules
above: written as a first answer or a change, counted while it stands.
It differs from the measurement path in three ways:

- **The subject is the connection.** The publisher and peer a refusal turns
  on are bound there, so a reconnect's refusal is a first answer.
- **The client is refused every round.** Only the line is withheld; tests
  check the result code each round beside the line count.
- **Silent refusals stay silent** and are not counted.

Shutdown reports the quiet as ``Token answer reports: repeated=``.

Both paths share ``src/agent/standing_answer.h``: what is remembered, when a
round is news, and the clause carrying the ended run's length. Only the
keying differs: a table swept against the protected set for measurements, a
connection field for tokens.

Publisher selection over IPC
----------------------------

``LOTA_IPC_CMD_SET_PROFILE`` binds a connection to one publisher, named by the
SHA-256 of that publisher's CA trust anchor SubjectPublicKeyInfo -- the same
identity ``/var/lib/lota/profiles/`` is keyed by. It is connection state, not a
per-request argument, because a title plays for one publisher: after it,
``GET_TOKEN`` quotes with that publisher's AIK and ``GET_STATUS`` answers with
that publisher's verdict and validity window.

The token carries the processes of the caller's own instance, the one the
kernel isolates it in. Its PID list, ``runtime_protect_digest``, coverage flags
and the per-token limit are taken over that part of the set, so one title
neither sees another instance's processes nor loses coverage to them, whichever
publisher either one names. The publisher's name selects the AIK and the
verdict and does not authenticate the title. A caller outside every instance,
one that is not protected, gets a token of no processes.

Three rules the agent holds to:

* An identity the host has no profile for is **refused**
  (``LOTA_IPC_ERR_UNKNOWN_PROFILE``), never quietly answered for another
  publisher.
* The attestation loop leaves the TPM bound to the first profile between
  rounds, so a connection bound elsewhere rebinds for its quote and restores
  the binding afterwards. They share one TPM and the loop expects the binding
  it left.
* A connection that never sends it keeps the host-wide answers: attested only
  while every configured publisher is satisfied.

``LOTA_IPC_VERSION`` is 2 for this command. The agent refuses any other
version outright rather than negotiating: ``lota_ipc.h`` is internal, and the
agent and the SDK that speaks to it ship together.

Status flags are the same bits on both sides of that boundary:
``LOTA_STATUS_*`` in ``include/lota_ipc.h`` and ``LOTA_FLAG_*`` in
``include/lota_gaming.h`` are two names for one wire value, and the SDK copies
the word through rather than translating it. A flag added to one header
without the other silently means something different to the title than to the
agent, so ``test_publisher_profile`` asserts the agreement.

``LOTA_STATUS_TOKEN_ONLY`` is the flag that makes a cleared
``LOTA_STATUS_ATTESTED`` readable. A publisher configured with
``verifier = none`` is never reported to, so the host holds no verdict of
theirs; without a second bit, a title could not tell that from a machine that
failed verification, and the two call for opposite behaviour. It is set on a
connection bound to such a publisher, and on the host-wide answer when no
configured publisher runs a verifier at all.

Ending a protected process
--------------------------

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
-------------------------------

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

Boot evidence
-------------

A token quotes PCRs 0, 1, 7 and 14 by their digest alone, so a publisher who
runs no verifier cannot read how the machine booted from it.
``LOTA_IPC_CMD_GET_BOOT_EVIDENCE`` answers with the values of the PCRs the
token quotes and every extended PCR 7 event: its SHA-256 digest, and its data
only when it measures the EFI global ``SecureBoot`` variable. The rest of PCR 7
is the firmware's key databases, tens of kilobytes that fit no frame. The wire
format is in ``include/lota_token.h``; ``src/agent/boot_evidence.c`` builds it.

The agent vouches for none of it. The relying party hashes the PCR values
against the digest a verified token quotes and replays the events to the
PCR 7 value, so evidence root edits no longer matches its token.
``lota_get_boot_evidence()`` in ``liblotagaming`` fetches it, and the Wine
hook writes it to ``lota-boot-evidence.bin`` next to the token.

``lota_server_verify_boot_evidence()`` in ``liblotaserver`` is the check, and
``VerifyBootEvidence`` in ``sdk/server`` holds the same rules for Go. Event
types sit outside the digests, so it reads none: the separator is the first
event that extends SHA-256 of four zero bytes, and Secure Boot reads on only
when every ``SecureBoot`` measurement before it carries the single byte 1 and
there is at least one. Evidence with no separator reads off: firmware that
reports an error separator leaves no point after which root's extends stop
counting. Root extends PCR 7 only after the firmware is done, so
a measurement it adds lands past the separator, and one it sends without data
reads as missing.

GET_TOKEN rate limits
=====================

Every ``GET_TOKEN`` costs a fresh TPM quote, so the agent limits how fast
they can be asked for. The limits are two, and they measure different things
(``TOKEN_RATE_LIMIT_PER_SESSION`` and ``TOKEN_RATE_LIMIT`` in
``src/agent/ipc.h``).

The **session budget** is what one title may spend. A connection is a
session, and a title holds one, so the budget is held on the connection and
dies with it. It is sized so no realistic heartbeat reaches it.

The **uid ceiling** is the bound on how much of the TPM one user may consume.
It has to hold several sessions at once, because on a player's machine every
title runs as the same uid: a ceiling sized for one title throttles the second
game for what the first one spent.

``GET_BOOT_EVIDENCE`` reads the TPM and the event log, so it is charged to the
uid ceiling too.

Both are needed. Without the session budget one title can spend the whole uid
allowance; without the uid ceiling a caller opens connections until the TPM is
saturated. Three ``_Static_assert``\ s in ``ipc.h`` keep the relationship
honest: the session budget must exceed the reference heartbeat rate, the uid
ceiling must cover at least two sessions, and the session budget must stay
the tighter of the two. Changing either constant without the other fails the
build rather than starving a title at runtime.

At the uid ceiling of one token a second, tokens occupy the TPM about 5% of
the time at the 48 ms per token measured on the validation host, and about
17% at the ~171 ms per quote also recorded there. The reference 5-second
heartbeat costs about 1%. The limits are sized against the slower figure.
:doc:`../../operator/platform-support` carries both measurements and the
method.

Attestation token quote binding
===============================

The token's TPM quote signs one 32-byte value, its ``extraData``, and that
value is what ties every other field in the token to the signature:

.. code-block:: text

   extraData = SHA256(valid_until || flags || pcr_mask || nonce ||
                      policy_digest || runtime_protect_digest ||
                      stopped_ms)

Integers are little-endian. Three implementations must agree on it byte for
byte: the agent that builds the quote
(``include/lota_token_quote_nonce.h``), the C verifier
(``lota_server_verify_token()`` in ``src/sdk/lota_server.c``) and the Go one
(``ComputeTokenQuoteNonce`` in ``sdk/server/verify.go``). A field that is not
in this digest is *not* signed, however trustworthy it looks in the struct,
so adding one to the token means adding it here in all three places.

A relying party should call one of the two verifiers rather than
reimplement the binding.

Both also apply the same freshness window, and that is the second thing
they must agree on. The token carries an expiry and no issue time, so
``valid_until`` is the only temporal anchor: an agent on the default
attestation interval mints a token expiring one interval from now, and both
verifiers refuse one whose expiry is further ahead than
``LOTA_SERVER_MAX_TOKEN_AGE_SEC`` plus ``LOTA_SERVER_MAX_CLOCK_SKEW_SEC``
(``DefaultMaxTokenAge`` and ``MaxClockSkew`` in Go). Raising the agent's
``attest_interval`` above that window makes every token it mints
unverifiable, so the two move together. A relying party that wants a
tighter bound than the window applies it to the verified ``valid_until``
itself.

IPC token payload budget
========================

Signed token returned over the local socket (``struct lota_ipc_token`` in
``include/lota_ipc.h``, built by ``src/agent/ipc.c``, parsed by the SDK in
``src/sdk/lota_gaming.c``) must fit ``LOTA_IPC_MAX_PAYLOAD``. Every protected
PID costs four bytes in the PID list plus a 32-byte registry digest, so
``LOTA_IPC_TOKEN_MAX_PROTECT_PIDS`` is derived from the payload budget left
after the header, a maximum quote and a maximum signature -- it is the real
per-token limit, not a round number.

Both sides of the socket take the cap from that header, so the agent and the
SDK parser stay in lockstep; changing the payload size or the per-PID cost
must keep the derived cap and ``tests/test_ipc_token_cap`` in agreement.

The same number bounds the token *wire* format, because an agent returning a
token over the socket is the only thing that produces one.
``include/lota_ipc.h`` is internal and is not installed, so the installed
``include/lota_token.h`` writes the derived value out as
``LOTA_TOKEN_MAX_PROTECT_PIDS`` for the side that has only the wire format,
and ``src/sdk/lota_gaming.c`` -- the one translation unit that sees both
headers -- fails the build when they disagree. ``MaxProtectPIDs`` in
``sdk/server/verify.go`` is the Go SDK's copy of the same number and is held
to the header by a test in that package. Raising the payload budget therefore
raises one cap in one place, and the build says which other spellings have to
follow.

The maximum a relying party sizes a receive buffer from --
``LOTA_TOKEN_MAX_SIZE``, ``TokenMaxSize`` in Go -- covers a full token at that
cap *including* the per-PID registry digests. A maximum that
counts only the PID list describes a token nobody sends.

Installer probes and agent gates
================================

The guided installer's stage probes (``installer/probe.c``) must mirror the
agent's startup gates in ``src/agent/bpf_loader.c``. When a gate changes,
change the matching probe and the pinned parser tests in
``tests/test_installer_probe.c`` (part of ``make test-unit``); otherwise the
installer reports a host green that the agent would refuse to run on.
