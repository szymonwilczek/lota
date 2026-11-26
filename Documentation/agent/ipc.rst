.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

===
IPC
===

Publisher selection over IPC
============================

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
