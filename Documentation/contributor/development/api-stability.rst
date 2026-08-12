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

How an integrator finds them
----------------------------

The ``-devel`` package ships a pkg-config module per library --
``lota-gaming``, ``lota-server``, ``lota-anticheat``, ``lota-wine-hook`` --
generated from the templates in ``packaging/pkgconfig``:

.. code-block:: sh

   cc $(pkg-config --cflags lota-anticheat) -o producer producer.c \
      $(pkg-config --libs lota-anticheat)

Each module reports the **ABI** version rather than the release version,
because the ``.pc`` describes the linkable contract and that is what governs
it: ``pkg-config --atleast-version=1 lota-gaming`` asks the question an
integrator means.

Each resolves its prefix from the file's own location, so the SDK is
consumable from a staged prefix -- a ``DESTDIR`` install, a container layer,
an unpacked package in CI -- and not only from ``/usr``. That is also how
the gate below builds against it without installing anything.

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

Status flags
============

``LOTA_FLAG_*`` in ``lota_gaming.h`` is a bitmask, so a release may define a
new bit and a program built against an older header keeps working: it reads
the bits it knows and ignores the rest. The values already assigned never
change meaning, which is what makes ignoring the unknown ones safe.

A caller must therefore test the bits it cares about rather than compare the
word, and must not treat an unfamiliar bit as a failure. ``LOTA_FLAG_UPDATE_PENDING``
is the case that makes this concrete: it reports that a package update takes
effect on the next cold boot, on a session that is attesting perfectly well,
so a caller that read the whole word as a health check would refuse a healthy
machine.

Which version answers which question
====================================

Two different questions get called "the version", and conflating them is how
a surface ends up stating its version in several places that drift apart.

**"What may I link against?"** is compatibility, and it is answered by the ABI
in two places and no others: the soname the loader resolves at run time, and
the ABI version the pkg-config module reports at build time. Both derive from
``LOTA_ABI_MAJOR``. No header defines a version macro for this -- a macro
would be a third statement of the same number with nothing reconciling it, and
``pkg-config --atleast-version`` already asks the question properly.

**"Which build is this?"** is provenance -- the question an advisory, a
support ticket, a log line or a reproducible-build check asks.
``lota_sdk_version()`` and ``lota_server_sdk_version()`` both answer it, both
return the same string, and that string is the release from the ``VERSION``
file, injected at build time as ``LOTA_BUILD_VERSION_STRING`` by the objects'
own Makefile rules, which take ``VERSION`` as a prerequisite so a bump
recompiles them. There is no fallback value: a translation unit compiled
without the define fails with ``#error``, because a library reporting
``unknown`` is worse in an incident than one that refused to build.

The string is **opaque**. Match it, do not parse it; its format carries no
promise, and a compatibility decision made by parsing it is asking the
provenance question and reading it as the compatibility answer.

Neither function is an authentication input. ``lota_sdk_version()`` runs
inside the calling process -- on a player's machine, memory an attacker
controls -- so a relying party must never decide trust from a version a client
reports about itself. The build identity that carries weight is the agent
binary hash pinned in the verifier's policy and committed to PCR 14.

The gate
========

``make check-abi`` compares the surface against the baseline checked in under
``packaging/abi``: the exported symbols of each library, the soname each one
carries against ``LOTA_ABI_MAJOR``, and the installed header set as stated in
three places that must agree -- ``packaging/abi/public-headers.list``, the
``make install`` rule, and ``packaging/nfpm/lota-sdk-devel.yaml``.

It then stages a prefix holding exactly what the packages install and builds
against it the way an integrator does: every public header on its own, and a
compile-and-link through each pkg-config module that calls one function from
the library it names. In tree everything builds with ``-Iinclude`` and
``-Lbuild``, so a header the package does not ship, or a ``.pc`` naming a
library that is not there, works in tree and fails for the integrator.

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

Wire protocols
==============

The libraries are one surface; the messages LOTA's own programs exchange are
another, and they version separately from both the release and the ABI. Each
carries its version in the message:

.. list-table::
   :header-rows: 1
   :widths: 24 22 54

   * - Protocol
     - Version constant
     - Rule
   * - Attestation report
     - ``LOTA_VERSION_MAJOR`` / ``types.ReportVersion``
     - Exact match. The verifier refuses a report from a wire it was not
       built to parse rather than guessing at the layout of the message
       every trust decision rests on, so a layout change is a flag day for
       the agent fleet and the verifier tier together.
   * - Enrollment
     - ``LOTA_ENROLL_VERSION``, ``LOTA_ENROLL_VERSION_TOKEN``
     - Additive and negotiated. Both frame versions are current modes, and
       the CA answers in the version of the request it received.
   * - Session token
     - ``LOTA_TOKEN_VERSION``
     - Public API, because ``lota_token.h`` is installed and a server links
       ``lota_server_parse_token()`` against that layout. A change to it is
       an ABI break like any other struct change.
   * - Runtime protection
     - ``LOTA_RUNTIME_PROTECT_V1``
     - Names the identity a protected PID set commits to. New semantics
       allocate the next value rather than redefining this one.

The report and enrollment wires are between LOTA's own programs, so their
versions constrain which agent, verifier and CA builds interoperate rather
than what an integrator may link against.

What a release promises
=======================

From 1.0, within a major release series:

* A program built against an earlier 1.x SDK runs against a later 1.x
  library without recompiling. Symbols are added under new version nodes,
  never removed or redefined.
* A public header keeps its declarations, and a struct an installed
  function takes keeps its layout. New fields go in new structs.
* The installed header set only grows.
* A wire protocol changes only under its own rule above, independently of
  the release number.

A major bump is what may break each of those, and it must say which in the
release notes. Nothing outside this page carries a promise: the agent's
command-line flags, its configuration keys, the verifier's HTTP endpoints
and its database schema are operator surfaces documented elsewhere, and
the internals behind any of them may change in a patch release.
