.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

==============
Anti-cheat SDK
==============

``liblota_anticheat.so`` carries both ends of an anti-cheat session. In the
game process the producer opens a session and builds heartbeats: small
packets that wrap a token whose nonce binds the session, the sequence number,
the time, the game and the process's own code. On the backend the verifier
checks a heartbeat with the token verification of :doc:`server`. The header
is ``lota_anticheat.h`` (:ghsrc:`include/lota_anticheat.h`), the
implementation :ghsrc:`src/sdk/lota_anticheat.c` and the pkg-config module
``lota-anticheat``:

.. code-block:: sh

   cc $(pkg-config --cflags lota-anticheat) -o producer producer.c \
      $(pkg-config --libs lota-anticheat)

The library links the gaming and server objects in, with their symbols
local (:doc:`stability`), so a program that also calls ``lota_connect()`` or
``lota_server_verify_token()`` itself links ``liblotagaming.so`` or
``liblotaserver.so`` as well. A working producer and backend are in
:ghsrc:`examples/demo_anticheat` and :ghsrc:`examples/demo_server`.

Sessions
========

``lota_ac_init()`` takes a ``struct lota_ac_config``:

``struct_size``
  ``sizeof(struct lota_ac_config)``. A value below
  ``LOTA_AC_CONFIG_SIZE_MIN`` is refused with ``LOTA_AC_ERR_CONFIG_SIZE``.

``provider``
  ``LOTA_AC_PROVIDER_EAC`` or ``LOTA_AC_PROVIDER_BATTLEYE``. The value goes
  into every heartbeat; the library attaches no other meaning to it.

``game_id``
  The title's identifier, 1 to 63 bytes.

``required_flags``
  ``LOTA_FLAG_*`` bits the session requires besides ``LOTA_FLAG_ATTESTED``
  before it reports itself trusted.

``direct``
  1 to talk to the agent through the gaming SDK, 0 to read the files of the
  Wine hook.

``token_dir``
  File mode: the hook's output directory. ``NULL`` takes a non-empty
  ``$LOTA_HOOK_TOKEN_DIR`` whether or not the directory exists, and an
  empty string skips it. Otherwise the first of
  ``$XDG_RUNTIME_DIR/lota-hook`` and ``/tmp/lota-<uid>`` that is a directory
  is taken. With neither, it is ``$XDG_RUNTIME_DIR/lota-hook``, and without
  that variable the session starts in ``LOTA_AC_STATE_ERROR`` with
  ``LOTA_AC_ERR_TOKEN_DIR``.

``socket_path``, ``publisher_profile``
  Direct mode: as in ``struct lota_connect_opts`` (:doc:`gaming`). A host
  enrolled with several publishers refuses a session that names none.

At init the library draws a random 16-byte session id and computes the game
binding hash of the running executable (below). In direct mode it connects
to the agent; a session that finds no agent is returned in
``LOTA_AC_STATE_ERROR`` with the reason in ``lota_ac_last_error()``, and
never connects later, so the title opens another session once the host is
ready. ``NULL`` means a bad configuration, no memory, or a failed session id
or game binding hash.

``lota_ac_tick()`` refreshes the state: in direct mode one status request and
one token request with no nonce, in file mode a read of the snapshot file. The
state is then:

``LOTA_AC_STATE_TRUSTED``
  ``LOTA_FLAG_ATTESTED`` and every ``required_flags`` bit are set.

``LOTA_AC_STATE_UNTRUSTED``
  A token, or a status with any flag set, arrived without those bits.

``LOTA_AC_STATE_ERROR``
  Nothing to judge: no agent, no snapshot or one whose token has expired,
  a refused request, or neither a token nor any flag.

``LOTA_AC_STATE_IDLE`` is a ``NULL`` session, and ``LOTA_AC_STATE_RUNNING``
does not outlast ``lota_ac_init()``. ``lota_ac_get_state()`` and
``lota_ac_get_info()`` read this state out of the game's own memory, which
the player controls; they serve the title's interface, and a backend trusts
only a verified heartbeat. ``lota_ac_shutdown()`` closes the connection and
frees the session.

Heartbeats
==========

``lota_ac_heartbeat()`` builds one packet in direct mode. Each call measures
the process's loaded code, computes the heartbeat nonce and asks the agent
for a token over it, so a beat costs one token of the agent's rate limit
(:doc:`../agent/tokens`). The token sets the state from its flags; a token
request that times out or fails with ``LOTA_ERR_PROTOCOL``, as one to a lost
agent does, sets ``LOTA_AC_STATE_ERROR``. The sequence number starts at 0 and
grows by one with each packet built. File mode returns
``-EOPNOTSUPP``: the hook's token was issued with no nonce, so it cannot carry
a heartbeat's.

.. code-block:: c

   #include <lota/lota_anticheat.h>

   struct lota_ac_config cfg = {
           .struct_size = sizeof(cfg),
           .provider = LOTA_AC_PROVIDER_EAC,
           .game_id = "example-title",
           .direct = 1,
           .publisher_profile = publisher_hex,
   };
   struct lota_ac_session *s = lota_ac_init(&cfg);
   uint8_t pkt[LOTA_AC_MAX_HEARTBEAT];
   size_t len;

   if (!s)
           return -1;
   if (lota_ac_heartbeat(s, pkt, sizeof(pkt), &len) == 0)
           send_to_backend(pkt, len);
   else
           show(lota_ac_strerror(lota_ac_last_error()));

The heartbeat nonce is

.. code-block:: text

   SHA256("lota-ac-heartbeat:v1\0" || session_id || provider ||
          sequence || timestamp || game_id_hash || domain_version ||
          runtime_measure)

with integers little-endian. The header's ``lota_flags`` are the token's,
which the TPM signs with the token, so the signature covers every header
field but ``magic``, ``version``, ``total_size`` and ``token_size``.
``domain_version`` selects the pair of domain strings used for the nonce and
the game binding; ``LOTA_AC_DOMAIN_VERSION_V1`` is the only one.

``lota_ac_boot_evidence()`` returns the boot evidence that goes with the
session's tokens, from the agent in direct mode or from the hook's
``lota-boot-evidence.bin`` in file mode. A buffer of
``LOTA_BOOT_EVIDENCE_MAX_SIZE`` holds it. The producer sends it with a
heartbeat.

Game binding and runtime measure
================================

The game binding hash names the title and its executable on disk:

.. code-block:: text

   SHA256("lota-ac-game-binding:v1\0" || game_id || SHA256(executable))

The producer hashes ``/proc/self/exe`` at init. The backend computes the
value it expects with ``lota_ac_compute_game_binding_hash()`` from the
``game_id`` and a copy of the executable it ships.

The runtime measure hashes the code the process has mapped at the time of the
beat: the executable ``PT_LOAD`` segments of every file-backed object
``dl_iterate_phdr()`` lists, the vDSO left out. Each object's digest covers
its segments in ascending address; the combined digest folds the objects
sorted by file basename, so neither load order nor library path changes it.
The layout is in the header comment. ``lota_ac_list_runtime_objects()`` lists
the files it covers, and ``lota_ac_compute_expected_runtime_measure_set()``
computes the same digest from those files on the backend. The live and the
file digests differ for an object with ``DT_TEXTREL``. A process started by
running the dynamic loader on its executable cannot be measured
(``-ENOTSUP``), nor can more than 256 objects or 16 executable segments in
one (``-E2BIG``).

The measure is computed inside the game process, so a player who controls
that process controls the value. The nonce keeps it from changing between the
producer and the backend; it says nothing a cheat could not have prepared.
What the agent measured of the process is in the token's
``runtime_protect_digest`` and the registry (:doc:`server`).

Verifying a heartbeat
=====================

``lota_ac_verify_heartbeat()`` takes the packet, the client's AIK, the game
binding hash and the runtime measure the backend expects, and fills
``struct lota_ac_info``. It checks, in order:

#. ``magic``, ``version``, the sizes, the provider and ``domain_version``;
#. ``game_id_hash`` against the expected one;
#. ``runtime_measure`` against the expected one
   (``LOTA_AC_ERR_RUNTIME_IMAGE``);
#. ``timestamp`` within 120 seconds of the backend's clock;
#. the token, with ``lota_server_verify_token()`` and the heartbeat nonce
   recomputed from the header as ``expected_nonce``;
#. the header's ``lota_flags`` against the token's.

``info.state`` is ``LOTA_AC_STATE_TRUSTED`` when the signed flags carry
``LOTA_FLAG_ATTESTED``; the producer's ``required_flags`` are not in the
packet, and a backend that requires more bits reads ``info.lota_flags``, the
token's word. ``info.pcr_mask`` and ``info.pcr_digest`` are the token's, for
``lota_ac_verify_boot_evidence()``, which applies the boot evidence rules of
:doc:`server` and returns ``LOTA_AC_ERR_BAD_EVIDENCE`` on a mismatch.
``info.session_start`` is 0, as one packet does not carry it.

The backend issues no nonce: the producer derives it, so the freshness of a
packet rests on the 120-second ``timestamp`` window and the token's expiry.
The verifier keeps no state between calls. A backend that refuses a packet
seen before records the last ``sequence`` of each ``session_id`` and accepts
only a higher one.

The AIK is the one the backend holds on record for the account, as for
:doc:`server`. Without it the call returns ``LOTA_AC_ERR_INVALID_ARG``.

Snapshot file
=============

In file mode the session reads ``lota-attestation.bin``
(``LOTA_SNAPSHOT_FILE_NAME``) in the token directory, which the
:doc:`wine-hook` writes. ``lota_snapshot.h``
(:ghsrc:`include/lota_snapshot.h`) gives its 16-byte header, little-endian,
followed by the token:

.. list-table::
   :header-rows: 1
   :widths: 10 8 22 60

   * - Offset
     - Size
     - Field
     - Content
   * - 0
     - 4
     - ``magic``
     - ``LOTA_SNAPSHOT_MAGIC``, ``"LOTA"`` in memory.
   * - 4
     - 2
     - ``version``
     - ``LOTA_SNAPSHOT_VERSION`` (1).
   * - 6
     - 2
     - ``reserved``
     - 0.
   * - 8
     - 4
     - ``flags``
     - The ``LOTA_FLAG_*`` word the hook last read.
   * - 12
     - 4
     - ``token_size``
     - ``LOTA_TOKEN_HEADER_SIZE`` to ``LOTA_AC_MAX_TOKEN`` bytes of token
       follow.

The file sits in a directory the player owns, so its ``flags`` are what the
session shows locally and nothing more.

Heartbeat wire format
=====================

``struct lota_ac_heartbeat_wire`` is the ``LOTA_AC_HEADER_SIZE`` (110) byte
header, little-endian and packed, followed by the token. A packet is at most
``LOTA_AC_MAX_HEARTBEAT`` bytes.

.. list-table::
   :header-rows: 1
   :widths: 10 8 22 60

   * - Offset
     - Size
     - Field
     - Content
   * - 0
     - 4
     - ``magic``
     - ``LOTA_AC_MAGIC``, ``"HCAL"`` on the wire.
   * - 4
     - 1
     - ``version``
     - ``LOTA_AC_VERSION`` (1).
   * - 5
     - 1
     - ``provider``
     - ``enum lota_ac_provider``.
   * - 6
     - 2
     - ``total_size``
     - Header and token.
   * - 8
     - 16
     - ``session_id``
     - Random, per session.
   * - 24
     - 4
     - ``sequence``
     - Packet number in the session.
   * - 28
     - 4
     - ``lota_flags``
     - The token's ``LOTA_FLAG_*`` word.
   * - 32
     - 8
     - ``timestamp``
     - Unix time the packet was built.
   * - 40
     - 32
     - ``game_id_hash``
     - The game binding hash.
   * - 72
     - 2
     - ``token_size``
     - Bytes of token.
   * - 74
     - 4
     - ``domain_version``
     - ``LOTA_AC_DOMAIN_VERSION_*``.
   * - 78
     - 32
     - ``runtime_measure``
     - The producer's runtime measure.

Errors
======

The codes lie below ``LOTA_AC_ERR_BASE`` (-1000), so none collides with the
negative ``errno`` the hash and measure functions return. The producer functions
return a negative ``errno`` and leave the ``LOTA_AC_ERR_*`` reason in
``lota_ac_last_error()``, kept per thread; the verifiers return the
``LOTA_AC_ERR_*`` code itself. ``lota_ac_strerror()`` words either kind.

.. list-table::
   :header-rows: 1
   :widths: 8 34 58

   * - Value
     - Code
     - Meaning
   * - -1001
     - ``LOTA_AC_ERR_INVALID_ARG``
     - A bad argument, a buffer too small, or no AIK.
   * - -1002
     - ``LOTA_AC_ERR_MALFORMED``
     - The packet does not parse, names another game, lies outside the
       timestamp window, or its flags differ from the token's.
   * - -1003
     - ``LOTA_AC_ERR_VERSION``
     - Another ``version``, ``domain_version`` or token version.
   * - -1004
     - ``LOTA_AC_ERR_SIG_FAIL``
     - The token signature does not verify.
   * - -1005
     - ``LOTA_AC_ERR_NONCE_FAIL``
     - The token does not answer the heartbeat nonce.
   * - -1006
     - ``LOTA_AC_ERR_EXPIRED``
     - The token expired or expires beyond the window.
   * - -1007
     - ``LOTA_AC_ERR_CRYPTO``
     - The key does not decode or is not RSA of 2048 bits or more, or
       OpenSSL failed.
   * - -1008
     - ``LOTA_AC_ERR_CONFIG_SIZE``
     - ``struct_size`` unset or too small.
   * - -1009
     - ``LOTA_AC_ERR_GAME_ID``
     - ``game_id`` missing, empty or too long.
   * - -1010
     - ``LOTA_AC_ERR_PROVIDER``
     - Neither EAC nor BattlEye.
   * - -1011
     - ``LOTA_AC_ERR_NO_MEMORY``
     - An allocation failed.
   * - -1012
     - ``LOTA_AC_ERR_INTERNAL``
     - The session id or the game binding hash failed.
   * - -1013
     - ``LOTA_AC_ERR_NO_AGENT``
     - No agent answers, or file mode found no snapshot or one whose token
       has expired.
   * - -1014
     - ``LOTA_AC_ERR_CONSENT_REQUIRED``
     - Nobody on the host agreed to that publisher.
   * - -1015
     - ``LOTA_AC_ERR_UNKNOWN_PROFILE``
     - The host is not enrolled with that publisher, or with several and
       none was named.
   * - -1016
     - ``LOTA_AC_ERR_ACCESS_DENIED``
     - The agent refused the caller.
   * - -1017
     - ``LOTA_AC_ERR_TOKEN_DIR``
     - File mode found no hook directory.
   * - -1018
     - ``LOTA_AC_ERR_NOT_ATTESTED``
     - The host holds no verdict to issue a token on.
   * - -1019
     - ``LOTA_AC_ERR_RATE_LIMITED``
     - Beating faster than the agent issues tokens.
   * - -1020
     - ``LOTA_AC_ERR_STATUS``
     - The agent refused a status request.
   * - -1021
     - ``LOTA_AC_ERR_TOKEN``
     - The agent refused a token, or the request for one failed.
   * - -1022
     - ``LOTA_AC_ERR_MEASURE``
     - The runtime measure failed.
   * - -1023
     - ``LOTA_AC_ERR_SERIALIZE``
     - The token did not serialize.
   * - -1024
     - ``LOTA_AC_ERR_RUNTIME_IMAGE``
     - The runtime measure is not the expected one, or the token's PID and
       registry digests do not match its signed digest.
   * - -1025
     - ``LOTA_AC_ERR_NO_KEY_SLOT``
     - The agent has no attestation-key slot left for that publisher.
   * - -1026
     - ``LOTA_AC_ERR_TPM_LOCKOUT``
     - The TPM is in dictionary-attack lockout.
   * - -1027
     - ``LOTA_AC_ERR_NO_EVIDENCE``
     - No boot evidence to hand over.
   * - -1028
     - ``LOTA_AC_ERR_BAD_EVIDENCE``
     - Boot evidence malformed or of another boot.

Functions
=========

.. kernel-doc:: include/lota_anticheat.h
