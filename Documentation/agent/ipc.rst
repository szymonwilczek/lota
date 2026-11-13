.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

===
IPC
===

The daemon answers local clients over a Unix stream socket: titles through
the SDK, the attestation loop and the one-shot verbs of :doc:`command-line`.
The protocol is in :ghsrc:`include/lota_ipc.h`, the server in
:ghsrc:`src/agent/ipc.c`. The header is not installed and its layout carries
no compatibility promise; a title links :ghsrc:`include/lota_gaming.h`,
whose ``LOTA_FLAG_*`` bits have the values of the ``LOTA_STATUS_*`` bits
below.

The daemon also serves a D-Bus interface (`D-Bus`_) that reads the status;
tokens come from the socket alone.

Sockets
=======

The socket is ``/run/lota/lota.sock``, mode 0660, owner root and group
``lota``. The daemon that binds the socket itself sets the directory
``/run/lota`` to mode 0750 with the same owner and group; under socket
activation the directory keeps the mode it was created with, 0755 and
``root:root`` when the initramfs lock created it (:doc:`lifecycle`). With
no group ``lota`` the socket stays root's and the agent warns.

``lota-agent.socket`` may hand the socket over; the daemon then takes it
from systemd and binds nothing. Otherwise the daemon binds the path itself,
with a backlog of 16. A path a live listener answers on is never taken over
(``EADDRINUSE``); a stale one is removed first. Once running, the daemon
watches ``/run/lota`` with inotify; when somebody removes or replaces the
socket file, it binds the path again, whatever answers there, with the
warning that the socket is rebound.

Container listener
------------------

A title inside a container that shares the user's runtime directory, such
as a Steam runtime container, reaches ``/run/user/<uid>/lota/lota.sock``.
The daemon serves one such socket for each user in
``container_listener_uid`` (at most 4, :doc:`configuration`), or, with no
entry, for the user of its own ``XDG_RUNTIME_DIR``. The directory
``lota`` under the runtime directory is mode 0750. A daemon running as
root hands it to group ``lota``; with no such group it serves no container
socket and logs an error.

The daemon watches ``/run/user`` and opens a listener when the user's
runtime directory appears, at login, and closes it when the directory goes,
at logout. A runtime directory outside ``/run/user`` is bound once at start.

Both sockets speak the same protocol and apply the same checks.

Discovery
---------

The SDK connects to ``/run/lota/lota.sock`` and falls back to
``$XDG_RUNTIME_DIR/lota/lota.sock``. ``socket_path`` in
``struct lota_connect_opts`` names another path.

Framing
=======

Every message is a 16-byte header and a payload. The four fields of both
headers are 32-bit, in host byte order:

.. list-table::
   :header-rows: 1
   :widths: 25 75

   * - Field
     - Value
   * - ``magic``
     - ``LOTA_IPC_MAGIC``, ``0x4C4F5441``.
   * - ``version``
     - ``LOTA_IPC_VERSION``, 1.
   * - ``cmd`` / ``result``
     - The command of a request; the result code of a response.
   * - ``payload_len``
     - Bytes of payload after the header.

A request with another magic is answered ``LOTA_IPC_ERR_BAD_REQUEST``, and
one with another version ``LOTA_IPC_ERR_BAD_VERSION``. A payload is at most
``LOTA_IPC_MAX_PAYLOAD`` (8192) bytes; a request that announces more closes
the connection. Every command accepts only its own payload lengths
(:ghsrc:`src/agent/ipc_payload.h`); another length is answered
``LOTA_IPC_ERR_BAD_REQUEST`` and logged as a warning.

A client may send requests back to back. The daemon answers them in order
and reads the next request only once the previous response is sent.

Peers
=====

The daemon reads the peer's uid and PID from ``SO_PEERCRED`` at accept, and
the process's start time from ``/proc``. A check that rests on the PID also
compares the start time, so a PID the kernel has given to another process
does not inherit the peer's rights. Commands that act on the calling process
itself take it from ``SO_PEERPIDFD``.

At most 2048 clients are connected at once; past that the daemon refuses
the connection and warns ``Max clients (2048) reached, rejecting
connection``.

Commands
========

.. list-table::
   :header-rows: 1
   :widths: 30 10 60

   * - Command
     - Value
     - Request and answer
   * - ``PING``
     - 0x01
     - No payload. Answers the daemon's uptime in seconds (64-bit) and its
       PID (32-bit).
   * - ``GET_STATUS``
     - 0x02
     - No payload. Answers ``struct lota_ipc_status`` (`Status`_).
   * - ``GET_TOKEN``
     - 0x03
     - No payload, or a 32-byte nonce. Answers a signed token
       (:doc:`tokens`).
   * - ``SUBSCRIBE``
     - 0x04
     - A 32-bit event mask (`Notifications`_). Answers with no payload.
   * - ``PROTECT_PID``
     - 0x05
     - A 32-bit PID that must be 0. Protects the calling process and
       answers the 32-byte startup policy digest (:doc:`protection`).
   * - ``SHUTDOWN``
     - 0x07
     - No payload. Stops the daemon (`Privileged commands`_).
   * - ``SET_PROFILE``
     - 0x08
     - A 32-byte publisher id (`Publisher selection`_).
   * - ``SYNC_ATTEST``
     - 0x09
     - The attestation loop's verdicts (`Privileged commands`_).
   * - ``TERMINATE_PROTECTED``
     - 0x0A
     - A PID and a signal, both 32-bit (`Ending a protected process`_).
   * - ``GET_REGISTRY``
     - 0x0B
     - A PID and a start index, both 32-bit. Answers one page of the
       process's registry (:doc:`protection`).
   * - ``GET_BOOT_EVIDENCE``
     - 0x0C
     - No payload. Answers the boot evidence (:doc:`boot-evidence`).
   * - ``GET_REFUSAL``
     - 0x0D
     - No payload. Answers the last refusal the enforcement object recorded
       for the calling process: ``struct lota_ipc_refusal``, the
       ``CLOCK_MONOTONIC`` time in nanoseconds and the object's path in 256
       bytes, all zero when there is none.

Another command is answered ``LOTA_IPC_ERR_UNKNOWN_CMD``.

Getting a token
---------------

``GET_TOKEN`` checks, in this order:

#. A TPM in dictionary-attack lockout: ``LOTA_IPC_ERR_TPM_LOCKOUT``.
#. No verdict for the caller's view of the status and no
   ``LOTA_STATUS_TOKEN_ONLY``: ``LOTA_IPC_ERR_NOT_ATTESTED``.
#. 20 tokens on this connection in the current minute, then 60 for the
   caller's uid: ``LOTA_IPC_ERR_RATE_LIMITED``. A request the connection
   limit refuses does not count for the uid.
#. More than one publisher profile and no ``SET_PROFILE`` on the
   connection: ``LOTA_IPC_ERR_UNKNOWN_PROFILE``.
#. No TPM: ``LOTA_IPC_ERR_NO_TPM``.
#. The publisher's key not loaded and no TPM slot for it:
   ``LOTA_IPC_ERR_NO_KEY_SLOT``.
#. More processes in the caller's instance than a token holds:
   ``LOTA_IPC_ERR_TOO_MANY_PROTECTED_PIDS``.
#. The caller's own code not measured:
   ``LOTA_IPC_ERR_UNMEASURABLE_SELF`` (:doc:`runtime-measurement`).
#. The quote fails: ``LOTA_IPC_ERR_TPM_LOCKOUT`` when the TPM locked out,
   ``LOTA_IPC_ERR_TPM_FAILURE`` otherwise.

``LOTA_IPC_ERR_INTERNAL`` answers any other failure. With one profile the
token is signed by that publisher's AIK, with none by the host AIK. A token
issued under ``LOTA_STATUS_TOKEN_ONLY`` is valid for 240 seconds.

A token holds at most ``LOTA_IPC_TOKEN_MAX_PROTECT_PIDS`` protected
processes: what the 8192-byte payload leaves beside the token header, the
largest quote (1024 bytes) and the largest signature (512 bytes), at 36
bytes per process, 181. The SDK sizes its receive buffer from
``LOTA_IPC_TOKEN_MAX_SIZE``.

Publisher selection
===================

``SET_PROFILE`` binds the connection to one publisher, named by the
SHA-256 of the SubjectPublicKeyInfo of its CA trust anchor
(:doc:`publishers`). From then on the connection's tokens are signed by
that publisher's AIK, and its status reads that publisher's verdict.

The command is refused with:

* ``LOTA_IPC_ERR_UNKNOWN_PROFILE`` when no profile has that id; a profile
  whose trust anchor the daemon could not read is named in a warning;
* ``LOTA_IPC_ERR_CONSENT_REQUIRED`` when nobody on the machine has agreed
  to that publisher, as an answer to a publisher hands it a stable
  handle on the machine;
* ``LOTA_IPC_ERR_NO_KEY_SLOT`` when the publisher's key is not loaded and
  the TPM has no room for it.

A bound connection counts as a session of its publisher. A publisher with
no enrollment is marked as asked for, and the attestation loop enrolls it
(`Privileged commands`_).

Status
======

``struct lota_ipc_status`` is 36 bytes, packed: the status word, a reserved
word, the time of the last accepted report and the time the verdict lapses
(64-bit Unix times, 0 for none), the counts of accepted and failed reports,
the mode (``LOTA_MODE_*``) and three reserved bytes.

.. list-table::
   :header-rows: 1
   :widths: 10 40 50

   * - Bit
     - Flag
     - Set when
   * - 0
     - ``ATTESTED``
     - The host is attested. Under ``TOKEN_ONLY`` no verdict stands
       behind it.
   * - 1
     - ``TPM_OK``
     - The TPM is initialized.
   * - 2
     - ``IOMMU_OK``
     - The IOMMU is verified.
   * - 3
     - ``BPF_LOADED``
     - The BPF LSM is active.
   * - 4
     - ``SECURE_BOOT``
     - Secure Boot is enabled.
   * - 5
     - ``TPM_LOCKOUT``
     - The TPM is in dictionary-attack lockout.
   * - 6
     - ``EVENTS_LOST``
     - The kernel left out an event: the event log is incomplete,
       enforcement is not affected. Set until the agent ends.
   * - 7
     - ``UPDATE_PENDING``
     - The agent binary on disk differs from the running one; the update
       takes effect on the next boot.
   * - 8
     - ``TOKEN_ONLY``
     - The publisher runs no verifier; the token is the evidence, with a
       validity the agent bounds itself.
   * - 9
     - ``IMAGE_FULLY_MEASURED``
     - Every protected object is measured (:doc:`runtime-measurement`).
   * - 10
     - ``PROTECTED_TERMINATED``
     - The agent ended a protected process for its owner or root. Set
       until the agent ends.
   * - 11
     - ``KERNEL_APPRAISAL``
     - IMA is in a blocking mode with an appraise rule on ``BPRM_CHECK``
       or with no ``func=``.
   * - 12
     - ``IMAGE_CONTENT_HASHED``
     - An object is measured by a content hash.
   * - 13
     - ``BENCH``
     - The agent runs with ``--bench``.
   * - 14
     - ``ENFORCE``
     - The mode is ``enforce`` and the LSM is loaded.
   * - 15 to 19
     - ``STRICT_MMAP``, ``STRICT_EXEC``, ``STRICT_MODULES``,
       ``BLOCK_ANON_EXEC``, ``BLOCK_PTRACE``
     - The switch of the same name applies; set only with ``ENFORCE``.
   * - 20
     - ``AGENT_RESTARTED``
     - PCR 14 already held this boot's commitment when the agent started.
       Set until the next boot.
   * - 21
     - ``REENROLLING``
     - The publisher's certificate does not name the key at its handle,
       and the attestation loop enrolls the host again.

On a connection bound to a publisher, ``ATTESTED``, ``REENROLLING``,
``PROTECTED_TERMINATED`` and the lapse time are that publisher's, and
``TOKEN_ONLY`` is set when the publisher runs no verifier. Every other bit,
and every bit on an unbound connection, is the host's.

Notifications
=============

``SUBSCRIBE`` takes a mask of ``LOTA_IPC_EVENT_STATUS`` (bit 0),
``LOTA_IPC_EVENT_ATTEST`` (bit 1) and ``LOTA_IPC_EVENT_MODE`` (bit 2); 0
ends the subscription. Other bits are dropped, and a mask left empty by
that is ``LOTA_IPC_ERR_BAD_REQUEST``. ``LOTA_IPC_EVENT_PROFILE`` (bit 3)
belongs to the attestation loop.

A notification is a response whose result is ``LOTA_IPC_NOTIFY`` (0x80),
with ``struct lota_ipc_notify``: the events, then the fields of the status
as the subscriber reads it. ``STATUS`` reaches a subscriber when its own
status word moves. Events that arrive while a notification is still being
sent are merged into the next one.

Rate limits
===========

Each limit counts in a fixed 60-second window:

* ``GET_TOKEN``: 20 per connection and 60 per uid;
* ``GET_BOOT_EVIDENCE``: counted against the same 60 per uid;
* ``PROTECT_PID``: 60 per uid.

A refusal is ``LOTA_IPC_ERR_RATE_LIMITED``. The per-uid table holds 256
users. When it is full a uid it does not hold takes over an entry whose
window has ended; with all 256 windows live it is refused, and the daemon
warns ``… rate limiter table exhausted``.

Ending a protected process
==========================

``TERMINATE_PROTECTED`` sends ``SIGTERM`` or ``SIGKILL`` to a protected
process (:doc:`protection`). The caller must run in the host's PID
namespace. The daemon refuses with:

* ``LOTA_IPC_ERR_BAD_REQUEST`` for PID 0, a PID past ``INT_MAX``, or a
  process that is gone;
* ``LOTA_IPC_ERR_TARGET_REFUSED`` for PID 1 or the daemon itself;
* ``LOTA_IPC_ERR_NOT_PROTECTED`` for a process outside the protected set;
* ``LOTA_IPC_ERR_ACCESS_DENIED`` for another signal, or a caller that is
  neither root nor the process's real uid.

The answer repeats the PID and the signal, and counts the protected
processes left.

Privileged commands
===================

``SHUTDOWN`` is accepted from a peer whose uid is the daemon's effective
uid and whose PID still names the process that connected. With
``allow_verity`` entries the peer's executable must also be one of them.
The daemon logs ``Privileged shutdown requested via IPC by uid=N pid=M``,
answers, and leaves its event loop. A refusal is
``LOTA_IPC_ERR_ACCESS_DENIED``, logged as ``SHUTDOWN denied for uid=N
pid=M``.

``SYNC_ATTEST`` is accepted only from a process of the daemon's uid whose
start time matches; the attestation loop sends it after each round. The
payload carries the counts, the last report time, the host flags the loop
saw and one verdict per publisher; a count that does not match the payload
is ``LOTA_IPC_ERR_BAD_REQUEST``. The answer lists, per publisher, the
connected sessions and whether a title asked for it with no enrollment,
and the connection receives ``LOTA_IPC_EVENT_PROFILE`` from then on.

D-Bus
=====

The daemon owns ``org.lota.Agent1`` on the system bus, object
``/org/lota/Agent1``, interface ``org.lota.Agent1``. The bus policy lets
root own the name and lets root and group ``lota`` call it. When the bus is
unavailable the daemon warns ``D-Bus unavailable, using socket IPC only``
and goes on.

Every value is the host's: a bus connection names no publisher.

Properties
  ``StatusFlags`` (``u``), ``Mode`` (``s``: ``monitor`` or ``enforce``),
  ``AttestCount`` and ``FailCount`` (``u``), ``LastAttestTime`` and
  ``ValidUntil`` (``t``), each emitting ``PropertiesChanged``; ``Version``
  (``s``), constant.

Methods
  ``Ping()`` answers the uptime and PID (``tu``). ``GetStatus()`` answers
  the status word, mode, last report time, lapse time and the two counts
  (``usttuu``). ``GetToken()`` answers the status word while the host is
  attested and the error ``org.lota.Agent1.NotAttested`` otherwise; it
  carries no signature.

Signals
  ``StatusChanged`` (``u``), ``AttestationResult`` (``b``) and
  ``ModeChanged`` (``s``).
