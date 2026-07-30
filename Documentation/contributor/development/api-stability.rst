.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

==========================
Public API and ABI surface
==========================

LOTA is a framework, so parts of it are surface an integrator builds against
and the rest is implementation. Only what this page names is public. Anything
else may change in any release, whatever its linkage says.

Installed headers
=================

``lota-sdk-devel`` installs six headers into ``/usr/include/lota``, and that
set is the public C API:

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Header
     - What it declares
   * - ``lota_gaming.h``
     - The client API: connect to the agent, query status, fetch and
       serialize a token, subscribe to events.
   * - ``lota_server.h``
     - The verification API a game or workload server links: parse and
       verify a token against an AIK.
   * - ``lota_anticheat.h``
     - The session and heartbeat layer an anti-cheat provider consumes.
   * - ``lota_wine_hook.h``
     - The ``LD_PRELOAD`` hook's state accessors and the paths and names of
       the files it writes.
   * - ``lota_token.h``
     - The token struct ``lota_server_parse_token()`` fills.
   * - ``lota_snapshot.h``
     - The header of the atomic snapshot file, for a reader that parses it
       rather than calling the SDK.

Each must compile on its own against the installed set alone. A public
header that pulls in one that is not installed builds in tree, where
everything is under ``-Iinclude``, and fails for the integrator.

``include/lota_ipc.h`` is deliberately **not** installed. It is the wire
between the agent and the SDK that ships with it, so a caller that speaks
the socket directly is pinned to the agent build it compiled against, and
the protocol changes whenever both sides change together. The gaming SDK
owns that protocol and offers the same capability behind an ABI that does
carry a promise. Every other header under ``include/`` is agent, verifier
or BPF internals.

Shared-library symbols
======================

Each installed library exports the functions its installed header declares,
and nothing else. The list lives in a linker version script next to the
sources it filters:

.. list-table::
   :header-rows: 1
   :widths: 32 30 38

   * - Library
     - Header
     - Version script
   * - ``liblotagaming.so``
     - ``include/lota_gaming.h``
     - ``src/sdk/liblotagaming.map``
   * - ``liblotaserver.so``
     - ``include/lota_server.h``
     - ``src/sdk/liblotaserver.map``
   * - ``liblota_anticheat.so``
     - ``include/lota_anticheat.h``
     - ``src/sdk/liblota_anticheat.map``
   * - ``liblota_wine_hook.so``
     - ``include/lota_wine_hook.h``
     - ``src/sdk/liblota_wine_hook.map``

Without a version script every non-static symbol is exported, which makes the
public surface an accident of which helpers happened to need external linkage.
It also matters beyond tidiness in two places. ``liblota_anticheat.so`` and
``liblota_wine_hook.so`` link the gaming and server SDK objects in statically
so an integrator can ship one file; if those symbols were global, a process
that also loads ``liblotagaming.so`` would hold two definitions of
``lota_connect()`` and link order would decide which copy each caller reaches.
The Wine hook is worse, because it is ``LD_PRELOAD``\ ed and therefore resolves
before the game's own libraries. An integrator that wants the gaming or the
token-verification API links that library directly and gets it from there.

The filter applies to the shared libraries only. ``liblotagaming.a`` and
``liblotaserver.a`` are static archives, so a program that links one pulls in
whichever objects it references, including symbols that are not API. Static
linking opts out of the ABI guarantee along with it.

Soname and ABI version
======================

``LOTA_ABI_MAJOR`` in the top-level ``Makefile`` is the soname major every
installed library carries, and it is **1**. It tracks the ABI, not the
release: a 1.x product release does not move it, and it moves on the first
incompatible change whether or not the release number moves with it.

A ``.so.0`` soname tells a distribution packager the library may break at
will, which is the opposite of what a declared surface says. The libraries
are installed as
``libX.so.MAJOR.MINOR.PATCH`` with the soname and the unversioned linker name
as symlinks onto it, so two majors can coexist on a host when one eventually
arrives.

Adding and removing symbols
---------------------------

Adding a function is a compatible change: declare it in the header and add it
to a new version node below the current one, for example ``LOTAGAMING_1.1
{ global: lota_new_call; } LOTAGAMING_1.0;``. A program built against the
older node keeps running against the newer library.

Removing a function, renaming it, or changing its signature or the layout of a
struct it takes is an ABI break. It bumps ``LOTA_ABI_MAJOR``, which changes
every soname, and the old library can no longer be replaced in place. Do not
work around a break by leaving the symbol in the
version script with different semantics behind it -- that is the one failure a
version script cannot catch.

The gate
========

``make check-abi`` compares the surface against the baseline checked in under
``packaging/abi``: the exported symbols of each library, the soname each one
carries against ``LOTA_ABI_MAJOR``, and the installed header set as stated in
three places that must agree -- ``packaging/abi/public-headers.list``, the
``make install`` rule, and ``packaging/nfpm/lota-sdk-devel.yaml``. It then
compiles every public header on its own against a prefix holding the
installed set and nothing else.

``scripts/check-patch`` runs it on every patch and CI runs it as its own
``abi`` job, which is what makes it blocking: CI drives selected gates
directly rather than the whole of ``check-patch``.

When the gate fires, the question is which kind of change it caught:

* **An accident** -- a helper that stopped being static, a header added to
  the package but not to the list. Fix the code, not the baseline.
* **A deliberate addition.** Declare it in the header, add it to the version
  script under a new node, then ``make abi-baseline`` and commit the diff
  alongside the change.
* **A deliberate break.** The same, plus the ``LOTA_ABI_MAJOR`` bump and a
  release note. The baseline diff is the record of what broke.

There is no way to silence the gate for one file, which is deliberate: the
baseline diff in a patch is exactly the review signal a surface change needs.

Go modules
==========

The repository is a Go workspace of six modules. **One is public:**

.. code-block:: text

    github.com/szymonwilczek/lota/sdk/server   ->  sdk/server

It is the server-side counterpart of ``liblotaserver.so``: a game or workload
server imports it to verify an attestation token against an AIK.
``examples/demo_server`` is the worked example.

The other five -- ``src/verifier``, ``src/attestca``, ``src/crl``,
``src/fleetctl`` and ``examples/demo_server`` -- are internal to this
repository's own binaries. They are ordinary Go modules so the workspace can
build them separately, not an invitation to import them; their exported
identifiers change without a major bump.

That is enforced by construction rather than by convention. A module is
fetchable only when its declared path matches its directory in the
repository, and the internal five declare paths without their ``src/``
prefix, so ``go get`` cannot resolve any of them. Do not "fix" those paths:
the mismatch is what keeps the internal surface internal. The public module
is the one whose path and directory agree, which is why ``sdk/server`` sits
at the top level rather than under ``src/`` with the C SDK.
