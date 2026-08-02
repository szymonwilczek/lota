.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

==========================================
Integrating LOTA into an anti-cheat stack
==========================================

The anti-cheat reference is four programs under ``examples/`` plus the two
SDK libraries they link. This page is the map for a studio or an
anti-cheat vendor forking it: what each piece is for, which of them you
copy and which you consume, what you must change, and where the licence
line falls.

Everything named here is MIT. **You can fork this closed.** That is the
point of the project's split, stated in the licensing section of the top
level ``README.rst``: the BPF programs that attach to kernel hooks are
GPL-2.0-only and stay on the host, while the SDK, the agent userspace and
every example below are MIT, so what you embed and ship is yours to keep.
Every source file carries its ``SPDX-License-Identifier``, so the zone a
file belongs to is readable from the file.

What each piece is
==================

.. list-table::
   :header-rows: 1
   :widths: 26 16 58

   * - Piece
     - You
     - Role
   * - ``liblota_anticheat.so``
     - link
     - Session state and signed heartbeats. Your producer's whole LOTA
       dependency.
   * - ``liblotaserver.so`` / ``sdk/server`` (Go)
     - link
     - Token verification for your backend. C and Go implementations of
       one contract; use whichever your server is written in.
   * - ``examples/demo_anticheat/``
     - **fork**
     - Reference producer: opens a session, mints heartbeats, ships them.
       ~500 lines of C, and the file you start from.
   * - ``examples/demo_server/``
     - **fork**
     - Reference backend: issues nonces, decodes heartbeats, verifies
       tokens, keeps a verdict.
   * - ``examples/demo_game/``
     - read
     - How a game process reads its own trust state to show the player.
   * - ``examples/cs2/``
     - read
     - The Proton/Wine path, for a Windows-build game running under
       Steam Play.
   * - ``examples/runtime_remeasure/``
     - read
     - How the runtime measurement is derived, if you need to reason
       about what it covers.

The producer and the backend are the two you fork. The rest is
documentation with a compiler.

The shape of the integration
============================

1. **The game host runs the LOTA agent.** It owns the TPM, attests, and
   answers the local socket. Your producer does not talk to a TPM.
2. **Your producer opens a session** with ``lota_ac_init()``, naming the
   provider and the game id, and calls ``lota_ac_heartbeat()`` on a timer.
   Each heartbeat wraps a TPM-signed token in a small header that binds
   your game id and session.
3. **Your backend verifies.** It issues a nonce, decodes the heartbeat,
   and calls ``lota_ac_verify_heartbeat()`` (C) or ``VerifyToken`` (Go)
   against the AIK it has on record for that client.
4. **Your backend decides.** LOTA reports what the host is; the gameplay
   consequence -- kick, queue separation, flag for review -- is yours and
   is deliberately not in this repository.

Build against the package, not the tree
=======================================

Both reference programs build the way your build will: through
``pkg-config`` against the installed ``lota-sdk-devel``.

.. code:: sh

   cc $(pkg-config --cflags lota-anticheat) -o producer producer.c \
      $(pkg-config --libs lota-anticheat)

``lota-anticheat`` is the only LOTA module on that line. The library
carries the gaming and server SDK inside it, so a producer calling only
``lota_ac_*`` links one thing; add ``lota-gaming`` or ``lota-server`` when
the same binary calls those APIs directly. The frozen surface those
modules describe is in
``Documentation/contributor/development/api-stability.rst``.

What you must change
====================

Forking the producer without touching these leaves you with the demo, not
an integration:

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Thing
     - What it has to become
   * - Game id
     - Your title's identifier. It is hashed into every heartbeat with
       the producer binary's digest, so the backend can tell your
       producer from another build of it.
   * - Provider id
     - ``LOTA_AC_PROVIDER_EAC`` or ``LOTA_AC_PROVIDER_BATTLEYE`` today.
       An in-house stack picks one and keeps it consistent with the
       backend.
   * - Transport
     - The demo POSTs to an HTTP endpoint with libcurl. Yours goes over
       whatever channel your client already has, authenticated the way
       that channel already is.
   * - Nonce source
     - The demo asks the reference server. Yours comes from your session
       service, and it must be per-session and single-use, or the
       heartbeat proves only that a host was attested at some point.
   * - AIK trust
     - The demo trusts one key from a file. Yours comes from enrolment
       records -- see ``examples/enrollment/README.rst`` -- so the
       backend knows which TPM belongs to which account.
   * - Verdict handling
     - The demo prints. Yours is your anti-cheat policy.

What the token actually proves
==============================

Worth being precise about, because it decides what you can build on it:

* The host booted a measured, policy-conforming state, and a TPM on that
  host signed a statement to that effect **for the challenge you issued**.
  A replayed or borrowed token fails, and so does one from a different
  machine.
* The producer process was in the protected set at the time, and the
  runtime measurement covers its loaded objects -- every one of them when
  the token carries ``LOTA_FLAG_IMAGE_FULLY_MEASURED``, and otherwise the
  subset the kernel holds an fs-verity digest for. A stock distribution
  ships its libraries without one, so partial coverage is the normal case
  and full coverage is something a platform provides. Whether you require
  it is your policy; what the agent guarantees either way is that the
  producer's own executable was measured, and that nothing unmeasured was
  folded in as if it had been.

It does **not** prove the player is not cheating. It proves the platform
underneath is what it claims to be, which removes the layer where a cheat
would otherwise be invisible to you: a tampered kernel, an unsigned
module, a patched loader. Cheats that live entirely in your process are
still your problem, and are still where your existing detection works.

Try it before you fork
======================

.. code:: sh

   make all examples
   ./examples/demo_anticheat/run.sh

That runs the whole chain -- swTPM, agent, backend, producer -- with no
root and no real TPM, and asserts both the trusted path and a tampered
heartbeat being refused on the signature. It is the fastest way to see the
shape of the integration end to end, and it is a reasonable first thing to
keep working after you fork.

For the Windows-build-under-Proton case, ``examples/cs2/README.rst`` walks
through the hook, the Steam launch options, and the scenarios it was
exercised against.
