.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

==========
Gaming SDK
==========

``liblotagaming.so`` is the client library a game process links to talk to the
local agent: it reads the host's attestation status, puts the process under
protection, fetches a token the game server verifies with the server SDK, and
lists what a protected process mapped. The header is ``lota_gaming.h``
(:ghsrc:`include/lota_gaming.h`), the implementation
:ghsrc:`src/sdk/lota_gaming.c`, and the pkg-config module ``lota-gaming``:

.. code-block:: sh

   cc $(pkg-config --cflags lota-gaming) -o game game.c \
      $(pkg-config --libs lota-gaming)

The library speaks the agent's socket protocol (:doc:`../agent/ipc`); every
call below is one request and its answer.

Connecting
==========

``lota_connect()`` opens a connection with the defaults and
``lota_connect_opts()`` with a ``struct lota_connect_opts``:

``struct_size``
  ``sizeof(struct lota_connect_opts)``. A value below
  ``LOTA_CONNECT_OPTS_SIZE_MIN`` is refused with ``LOTA_ERR_INVALID_ARG``.

``socket_path``
  The agent socket. ``NULL`` tries ``/run/lota/lota.sock``, then
  ``$XDG_RUNTIME_DIR/lota/lota.sock``, the path a container reaches, and
  connects to the first that exists and accepts.

``timeout_ms``
  The connect timeout, 5000 ms when 0 or negative. It is also the request
  timeout until ``lota_set_request_timeout()`` changes it.

``publisher_profile``
  The publisher the connection answers for, as the 64-character hex SHA-256
  (``LOTA_PUBLISHER_PROFILE_LEN``) of the SubjectPublicKeyInfo of its
  attestation-CA anchor. It selects the AIK that signs the tokens and the
  verdict ``lota_is_attested()`` reports. With ``NULL``, a host enrolled with
  one publisher answers for it, and a host enrolled with several refuses a
  token with ``LOTA_ERR_UNKNOWN_PROFILE``. When the agent cannot answer for
  the named publisher, the connection fails. Publisher selection is
  described in :doc:`../agent/ipc`.

A failed connect returns ``NULL``, and ``lota_connect_last_error()`` gives the
reason. The value is kept per thread and set by every connect attempt.

.. code-block:: c

   #include <lota/lota_gaming.h>

   struct lota_connect_opts opts = {
           .struct_size = sizeof(opts),
           .publisher_profile = publisher_hex,
   };
   struct lota_client *c = lota_connect_opts(&opts);

   if (!c) {
           fprintf(stderr, "lota: %s\n",
                   lota_strerror(lota_connect_last_error()));
           return -1;
   }

``lota_disconnect()`` closes the socket and frees the handle.
``lota_get_fd()`` returns the socket for a caller's own ``poll()`` loop.

Status
======

``lota_get_status()`` fills ``struct lota_status``:

.. list-table::
   :header-rows: 1
   :widths: 25 75

   * - Member
     - Content
   * - ``flags``
     - ``LOTA_FLAG_*`` bitmask, below.
   * - ``last_attest_time``
     - Unix time of the last attestation, 0 if none.
   * - ``valid_until``
     - Unix time the verdict lapses, 0 if none.
   * - ``attest_count``
     - Successful attestations.
   * - ``fail_count``
     - Failed attestations.

``lota_is_attested()`` returns 1 when ``LOTA_FLAG_ATTESTED`` is set, and 0
when it is clear or the call failed. ``lota_flags_to_string()`` writes the set
bits by name without the ``LOTA_FLAG_`` prefix, separated by commas, and
leaves out bits it has no name for.

A caller tests the bits it needs and ignores the others
(:doc:`stability`).

.. list-table::
   :header-rows: 1
   :widths: 6 34 60

   * - Bit
     - Flag
     - Set when
   * - 0
     - ``LOTA_FLAG_ATTESTED``
     - The verifier of the connection's publisher holds a passing verdict
       on the host; with no publisher named, the host-wide verdict.
   * - 1
     - ``LOTA_FLAG_TPM_OK``
     - The TPM opened and answered when the agent started.
   * - 2
     - ``LOTA_FLAG_IOMMU_OK``
     - The agent's IOMMU check passed.
   * - 3
     - ``LOTA_FLAG_BPF_LOADED``
     - The agent loaded the BPF LSM object.
   * - 4
     - ``LOTA_FLAG_SECURE_BOOT``
     - efivarfs shows ``SecureBoot`` set to 1.
   * - 5
     - (no name)
     - The agent sees the TPM in dictionary-attack lockout. ``lota_gaming.h``
       has no name for the bit and ``lota_flags_to_string()`` leaves it out.
   * - 6
     - ``LOTA_FLAG_EVENTS_LOST``
     - The kernel left an event out of the agent's log. Refusals still hold
       and the token's lists are kept apart from that log. Set until the
       agent ends; it can arrive a second or more after the loss.
   * - 7
     - ``LOTA_FLAG_UPDATE_PENDING``
     - A package update replaced the agent binary. The running build stays
       in PCR 14 and attestation keeps succeeding until the next boot.
   * - 8
     - ``LOTA_FLAG_TOKEN_ONLY``
     - The publisher runs no verifier, or with none named, no publisher of
       the host does. ``LOTA_FLAG_ATTESTED`` stays clear; the game server
       checks a token with ``lota_server_verify_token()``.
   * - 9
     - ``LOTA_FLAG_IMAGE_FULLY_MEASURED``
     - Every file-backed executable mapping of every protected process was
       measured, in a token of every one it carries. Clear when an object
       could not be measured or nothing is protected.
   * - 10
     - ``LOTA_FLAG_PROTECTED_TERMINATED``
     - The agent ended a protected process for its owner or root: one of the
       connection's publisher, or any one when it named none. Set until the
       agent ends.
   * - 11
     - ``LOTA_FLAG_KERNEL_APPRAISAL``
     - IMA is in a blocking mode and its policy has an appraise rule on
       ``BPRM_CHECK`` or with no ``func=``.
   * - 12
     - ``LOTA_FLAG_IMAGE_CONTENT_HASHED``
     - An object of a protected process had no fs-verity digest and was
       measured by hashing its contents while nothing could write it.
   * - 13
     - ``LOTA_FLAG_BENCH``
     - The agent runs with ``--bench``. Its policy is unchanged.
   * - 14
     - ``LOTA_FLAG_ENFORCE``
     - Enforce mode with the LSM loaded.
   * - 15
     - ``LOTA_FLAG_STRICT_MMAP``
     - A protected process maps no file executable outside the allowlist.
   * - 16
     - ``LOTA_FLAG_STRICT_EXEC``
     - An exec of a file outside the allowlist is refused.
   * - 17
     - ``LOTA_FLAG_STRICT_MODULES``
     - A module or firmware load outside the allowlist is refused.
   * - 18
     - ``LOTA_FLAG_BLOCK_ANON_EXEC``
     - A protected process makes no anonymous mapping executable.
   * - 19
     - ``LOTA_FLAG_BLOCK_PTRACE``
     - A ptrace attach on any task is refused.
   * - 20
     - ``LOTA_FLAG_AGENT_RESTARTED``
     - An earlier agent of this boot ended without a shutdown. A token with
       this bit says nothing of what happened before the restart. Set until
       the host reboots.
   * - 21
     - ``LOTA_FLAG_REENROLLING``
     - The publisher's certificate does not name the host's attestation key,
       as after a TPM clear, and the agent is enrolling again.
       ``LOTA_FLAG_ATTESTED`` stays clear until that completes.

Bits 14 to 19 are all clear in monitor mode. The agent and the protected
processes stay guarded with all of them clear. The policy keys behind them
are described in :doc:`../agent/protection`.

Notifications
=============

``lota_subscribe()`` registers a callback for the ``LOTA_EVENT_*`` bits:

``LOTA_EVENT_STATUS``
  The status flags changed.

``LOTA_EVENT_ATTEST``
  An attestation completed, passed or failed.

``LOTA_EVENT_MODE``
  The enforcement mode changed.

``LOTA_EVENT_ALL`` subscribes to all three. The callback runs from
``lota_poll_events()`` and from any other call that reads a notification off
the socket, on the calling thread. A subscription ends with the connection;
after ``LOTA_ERR_NOT_CONNECTED`` the caller connects and subscribes again.

Protection
==========

``lota_protect_self()`` asks the agent to protect the calling process. The
agent identifies it by the pidfd of the socket peer, so no PID is sent, and
needs no trusted executable to do so. The LSM guards the process and its
children from then on; the hooks and the policy keys are described in
:doc:`../agent/protection`.

``lota_get_refusal()`` returns the last object the runtime gate refused to
map into the calling process, with the ``CLOCK_MONOTONIC`` time of the
refusal. The Wine hook uses it to report a failed ``dlopen()``.

Tokens
======

``lota_get_token()`` asks the agent for a token over a 32-byte nonce the game
server issued, and fills ``struct lota_token``. The caller sends the result
of ``lota_token_serialize()`` to the server, sized with
``lota_token_serialized_size()``, and releases the token with
``lota_token_free()``:

.. code-block:: c

   struct lota_token tok;
   uint8_t buf[LOTA_TOKEN_MAX_SIZE];
   size_t len;

   if (lota_get_token(c, server_nonce, &tok) != LOTA_OK)
           return -1;
   if (lota_token_serialize(&tok, buf, sizeof(buf), &len) == LOTA_OK)
           send_to_server(buf, len);
   lota_token_free(&tok);

``struct lota_token`` holds the token as the agent sent it: ``valid_until``,
the status ``flags`` at issue time, the ``nonce`` the quote answers,
``sig_alg``, ``hash_alg``, ``pcr_mask``, ``policy_digest``,
``runtime_protect_digest`` with ``runtime_protect_version`` and
``stopped_ms``. Four arrays are on the heap and belong to the token:
``protected_pids`` and ``protected_registry_digests``, each of
``protect_pid_count`` entries, ``attest_data`` of ``attest_size`` bytes and
``signature`` of ``signature_len`` bytes. ``lota_token_free()`` releases them.
What each field means on the wire is on the server SDK page.

``LOTA_TOKEN_MAX_SIZE`` is in ``lota_token.h``, which ``lota_gaming.h`` does
not include. The wire format and what the server checks are on the server
SDK page; how the agent builds a token and how often it issues one are
in :doc:`../agent/tokens`.

``lota_get_boot_evidence()`` returns the values of the PCRs a token quotes and
the PCR 7 events behind them, for a server with no verifier. It matches the
token only while those PCRs hold the same values, so the caller fetches it
together with the token.

Registry
========

``lota_get_registry()`` returns what the last token round found in one
protected process the caller owns, of its own instance: the code objects it
mapped executable and the processes that reached it. The caller releases the
result with ``lota_registry_free()``. ``round`` is the measurement round the
list comes from, ``pid`` the process asked for, and ``objects`` and ``actors``
hold ``count`` and ``actor_count`` entries. ``registry_digest`` covers the
flags, the objects and the actors; ``round`` and ``pid`` are outside it.
With ``LOTA_REGISTRY_MEASURED`` set it is the token's
``protected_registry_digests`` entry for the PID, and the server recomputes it
with ``lota_server_registry_digest()`` before it trusts the list. How the
agent builds the list is in :doc:`../agent/protection`.

``struct lota_registry`` flags:

``LOTA_REGISTRY_MEASURED``
  ``registry_digest`` is the token's entry for the process.

``LOTA_REGISTRY_HISTORY_LOST``
  An executable mapping went unrecorded, so an object may be missing.

``LOTA_REGISTRY_ACTORS_LOST``
  An actor went unrecorded, so a process that reached in may be missing.

``LOTA_REGISTRY_FROM_EXEC``
  The image was executed under protection and the list starts at its exec.
  Without it the list starts when protection did.

``LOTA_REGISTRY_TRUNCATED``
  The process had more executable mappings than one measurement holds; those
  past the limit are unmeasured.

``struct lota_registry_object`` describes one object: ``size``, ``dev``,
``ino``, the ``soname`` (at most ``LOTA_REGISTRY_SONAME_MAX`` bytes) and
``path`` (``LOTA_REGISTRY_PATH_MAX``), a ``digest`` of ``digest_len`` bytes
(0, 32 or 64), how it was taken in ``road``:

``LOTA_REGISTRY_ROAD_NONE``
  No digest.

``LOTA_REGISTRY_ROAD_VERITY``
  The fs-verity measurement.

``LOTA_REGISTRY_ROAD_CONTENT``
  The contents hashed while the process ran.

and its ``flags``:

``LOTA_REGISTRY_OBJECT_UNMAPPED``
  Mapped since protection began and gone when measured: no path, no digest,
  the soname is the file's name.

``LOTA_REGISTRY_OBJECT_WRITABLE``
  When it was mapped executable, something held it open for write or mapped
  it shared writable, or it was a memfd or shm segment with no write seal.

``LOTA_REGISTRY_OBJECT_MEMORY``
  Backed by memory only (memfd, shm, tmpfs, hugetlbfs).

``struct lota_registry_actor`` describes one process that reached a process
of the instance: ``tgid``, ``uid``, ``comm``, its start time in clock ticks
(``start_ticks``), the device and inode of its executable, the process it
reached (``owner_tgid``, ``owner_comm``), how many times (``count``) and how
(``kind``):

``LOTA_REGISTRY_ACTOR_CONNECT``
  Connected to a stream or seqpacket unix socket of the instance.

``LOTA_REGISTRY_ACTOR_SEND``
  Sent a datagram to one.

``LOTA_REGISTRY_ACTOR_PTRACE_READ``
  A read-mode ptrace access from inside the instance.

``LOTA_REGISTRY_ACTOR_PTRACE_ATTACH``
  ptrace, ``process_vm_*`` or ``/proc/<pid>/mem`` access from inside the
  instance.

``LOTA_REGISTRY_ACTOR_SIGNAL``
  A signal from inside the instance.

``LOTA_REGISTRY_ACTOR_ANON_EXEC``
  The process made its own anonymous memory executable; ``owner_tgid`` is
  its own ``tgid``.

Errors
======

Calls return ``LOTA_OK`` (0) or a negative ``enum lota_error``.
``lota_strerror()`` describes a code.

.. list-table::
   :header-rows: 1
   :widths: 7 33 60

   * - Value
     - Code
     - Meaning
   * - -1
     - ``LOTA_ERR_NOT_CONNECTED``
     - The connection is gone; connect again.
   * - -2
     - ``LOTA_ERR_CONNECTION_FAILED``
     - No agent answered, or it hung up.
   * - -3
     - ``LOTA_ERR_TIMEOUT``
     - No answer within the timeout.
   * - -4
     - ``LOTA_ERR_PROTOCOL``
     - A malformed answer.
   * - -5
     - ``LOTA_ERR_NOT_ATTESTED``
     - No valid attestation exists for a token.
   * - -6
     - ``LOTA_ERR_INVALID_ARG``
     - A bad argument or option, or a refusal without a code of its own.
   * - -7
     - ``LOTA_ERR_BUFFER_TOO_SMALL``
     - The caller's buffer cannot hold the result.
   * - -8
     - ``LOTA_ERR_AGENT_ERROR``
     - The agent failed the request.
   * - -9
     - ``LOTA_ERR_NO_MEMORY``
     - An allocation failed.
   * - -10
     - ``LOTA_ERR_RATE_LIMITED``
     - The caller exceeded a rate limit of the agent.
   * - -11
     - ``LOTA_ERR_ACCESS_DENIED``
     - The agent refused the caller for this request.
   * - -12
     - ``LOTA_ERR_UNKNOWN_PROFILE``
     - No profile for the named publisher, or none named on a host enrolled
       with several.
   * - -13
     - ``LOTA_ERR_CONSENT_REQUIRED``
     - Nobody on the host agreed to answer to that publisher.
   * - -14
     - ``LOTA_ERR_UNMEASURABLE_SELF``
     - The caller's own executable has no measurable identity, so no token
       is issued; the agent's log names the object.
   * - -15
     - ``LOTA_ERR_NO_TPM``
     - The agent holds no TPM.
   * - -16
     - ``LOTA_ERR_NO_ENFORCEMENT``
     - The agent applied no policy and loaded no LSM, so a call that changes
       enforcement is refused.
   * - -17
     - ``LOTA_ERR_NO_KEY_SLOT``
     - The agent's attestation-key handle range is full.
   * - -18
     - ``LOTA_ERR_TPM_LOCKED``
     - The TPM is in dictionary-attack lockout.
   * - -19
     - ``LOTA_ERR_NOT_PROTECTED``
     - The last token round did not measure the process.
   * - -20
     - ``LOTA_ERR_TOO_MANY_PROCESSES``
     - The caller's instance holds more protected processes than one token
       lists.

Functions
=========

.. kernel-doc:: include/lota_gaming.h
