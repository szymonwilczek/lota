.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

==========================
Public API and ABI surface
==========================

The public surface of LOTA is the set of headers, shared libraries, archives,
pkg-config modules and one Go module an integrator builds against. This page
names that set, the rules a change to it follows and the gate that checks
them. Everything else in the repository is implementation and may change in
any release.

Installed headers
=================

``lota-sdk-devel`` installs headers into ``/usr/include/lota``. The list
is :ghsrc:`packaging/abi/public-headers.list`.

.. list-table::
   :header-rows: 1
   :widths: 25 75

   * - Header
     - Declares
   * - ``lota_gaming.h``
     - The client API of ``liblotagaming.so``: connection to the agent,
       status, tokens, boot evidence, the registry of a protected process,
       subscriptions.
   * - ``lota_server.h``
     - The verification API of ``liblotaserver.so``: token and boot evidence
       verification against an AIK, the registry digest.
   * - ``lota_anticheat.h``
     - The session and heartbeat API of ``liblota_anticheat.so``.
   * - ``lota_wine_hook.h``
     - The accessors of ``liblota_wine_hook.so``, its environment variables
       and the names of the files it writes.
   * - ``lota_token.h``
     - The wire formats of the token and of the boot evidence.
   * - ``lota_snapshot.h``
     - The header of the snapshot file the Wine hook writes and the
       anti-cheat SDK reads.

Each header compiles on its own against the installed set. The other headers
under ``include/`` belong to the agent, the BPF program, the verifier and the
CA, and are not installed. ``lota_ipc.h`` is one of them: it describes the
socket protocol between the agent and the gaming SDK built with it, and a
program that speaks the socket directly depends on that agent build.

Libraries and pkg-config modules
================================

.. list-table::
   :header-rows: 1
   :widths: 26 22 26 26

   * - Library
     - Header
     - pkg-config module
     - Exported symbols
   * - ``liblotagaming.so``
     - ``lota_gaming.h``
     - ``lota-gaming``
     - :ghsrc:`src/sdk/liblotagaming.map`
   * - ``liblotaserver.so``
     - ``lota_server.h``
     - ``lota-server``
     - :ghsrc:`src/sdk/liblotaserver.map`
   * - ``liblota_anticheat.so``
     - ``lota_anticheat.h``
     - ``lota-anticheat``
     - :ghsrc:`src/sdk/liblota_anticheat.map`
   * - ``liblota_wine_hook.so``
     - ``lota_wine_hook.h``
     - ``lota-wine-hook``
     - ``LOTA_HOOK_EXPORT``

The modules are generated from :ghsrc:`packaging/pkgconfig` and installed into
``/usr/lib64/pkgconfig``:

.. code-block:: sh

   cc $(pkg-config --cflags lota-anticheat) -o producer producer.c \
      $(pkg-config --libs lota-anticheat)

A module reports the ABI version (``1.0.0``), not the release, so
``pkg-config --atleast-version=1 lota-gaming`` asks for a compatible library.
Each module computes its prefix from its own location (``${pcfiledir}/../..``),
so a ``DESTDIR`` install or an unpacked package works without installing into
``/usr``.

``liblotagaming.a`` and ``liblotaserver.a`` are built as well. Each holds one
object, so a program that calls one function links the whole API.

Exported symbols
----------------

A shared library exports the functions its header declares, and the Wine
hook ``dlopen()`` besides (below). Three libraries filter their symbols through
the linker version script named in the table, with every other symbol ``local``.
``liblota_anticheat.so`` links the gaming and server objects in, and
``liblota_wine_hook.so`` the gaming object, so that one file ships; their copies
stay local, because a second global ``lota_connect()`` in a process that also
loads ``liblotagaming.so`` would bind each caller to the copy the link order
picks. A program that calls the gaming or the server API links that library.

The Wine hook defines ``dlopen()`` so that it can report an object the
runtime gate refused, and callers reach ``dlopen`` through glibc's version
node. A version script would hide the wrapper behind that node, so the hook
is compiled with ``-fvisibility=hidden`` and marks each export
``LOTA_HOOK_EXPORT``. The wrapper returns what the real ``dlopen()``
returned, with ``dlerror()`` and ``errno`` left as it left them, and is not
part of the API.

An archive carries no version script: every function in
:ghsrc:`src/sdk/lota_gaming.c` and :ghsrc:`src/sdk/lota_server.c` that the
header does not declare is ``static``, which the gate checks. An archive also
records no soname and no version node, so a statically linked program carries
no record of the surface it was built against.

Soname and ABI version
======================

``LOTA_ABI_MAJOR`` in the top-level ``Makefile`` is the soname major of every
installed library; its value is 1 and the full ABI version is
``LOTA_ABI_MAJOR.0.0``. Both are independent of the release in ``VERSION``.
A library is installed as ``libX.so.1.0.0``, with the soname ``libX.so.1`` and
the linker name ``libX.so`` as symlinks to it. The 32-bit Wine hook in
``/usr/lib`` gets no linker name, because the loader opens it by soname and
nothing links against it.

Changing the surface
====================

Compatible changes:

* A function is added to the header and to a version node below the current
  one, for example
  ``LOTAGAMING_1.1 { global: lota_new_call; } LOTAGAMING_1.0;``. A program
  built against ``LOTAGAMING_1.0`` keeps running.
* A member is appended to ``struct lota_connect_opts`` or
  ``struct lota_ac_config``. Both start with ``size_t struct_size``, which the
  caller sets to ``sizeof`` of its own copy, and the library reads only the
  members that size covers. A size below ``LOTA_CONNECT_OPTS_SIZE_MIN`` or
  ``LOTA_AC_CONFIG_SIZE_MIN`` is refused, zero included.
* A ``LOTA_FLAG_*`` bit is assigned. A caller tests the bits it knows and
  ignores the others; comparing the whole word refuses a healthy host, for
  example one with ``LOTA_FLAG_UPDATE_PENDING`` set.
* An error code takes the next unused value of ``enum lota_error`` or another
  error enum. A ``switch`` over the enum keeps a ``default`` arm, and
  ``lota_strerror()`` returns ``"Unknown error"`` for a code it does not know.

Breaking changes bump ``LOTA_ABI_MAJOR``, which changes every soname:

* removing or renaming a function, or changing its signature;
* changing the layout of a struct an installed function takes, other than
  appending to a struct with ``struct_size``;
* changing the value or meaning of an enumerator, a ``LOTA_FLAG_*`` bit or
  another ``LOTA_*`` constant.

A function whose semantics change under an unchanged symbol is also a break.
No version script detects it.

Release version
===============

``lota_sdk_version()`` and ``lota_server_sdk_version()`` return the release
in ``VERSION``, compiled in as ``LOTA_BUILD_VERSION_STRING``. An object built
without that define fails with ``#error``. The string identifies a build for
logs and support; its format is not part of the API, so a program matches it
and does not parse it. Compatibility is the soname and the pkg-config
version.

The string comes from the calling process, which on a player's machine the
player controls, so a relying party does not base a trust decision on it. The
agent build a verifier trusts is set by ``agent_hashes`` in its policy and
checked against PCR 14.

The ABI gate
============

``make check-abi`` runs :ghsrc:`scripts/check-abi.sh`, which compares the
build with the baseline under :ghsrc:`packaging/abi`:

* the exported symbols of each shared library, with their version nodes, and
  its soname against ``LOTA_ABI_MAJOR``;
* the symbols of the two archives, and that each holds one object;
* the header set in ``public-headers.list``, in the ``make install`` rule and
  in ``packaging/nfpm/lota-sdk-devel.yaml``;
* in ``types.list``, the size, alignment and member offsets of every public
  struct, the value of every enumerator and of every ``LOTA_*`` constant, read
  from a program compiled against the headers.

It then stages a prefix with the installed headers, libraries and
pkg-config modules, compiles each header on its own against it, checks that
each module reports the ABI version, and compiles and links one call through
each module. Without ``pkg-config`` the module checks are skipped.

``scripts/check-patch`` runs the gate and CI runs it as the ``abi`` job. A
failure is one of three cases:

* an accident, such as a helper that lost ``static`` or a header added to one
  list only: fix the code;
* an addition: add the function to a version node below the current one,
  run ``make abi-baseline`` and commit the baseline with the change;
* a break: the same, with the ``LOTA_ABI_MAJOR`` bump.

Go module
=========

``github.com/szymonwilczek/lota/sdk/server`` (:ghsrc:`sdk/server`) is the one
public Go module: the token verification of ``liblotaserver.so`` for a server
written in Go (:doc:`go-sdk`). The workspace in :ghsrc:`go.work` holds other
modules, which build the repository's own programs and change without notice:

.. list-table::
   :header-rows: 1
   :widths: 40 60

   * - Directory
     - Module path
   * - ``src/verifier``
     - ``github.com/szymonwilczek/lota/verifier``
   * - ``src/attestca``
     - ``github.com/szymonwilczek/lota/attestca``
   * - ``src/crl``
     - ``github.com/szymonwilczek/lota/crl``
   * - ``src/fleetctl``
     - ``github.com/szymonwilczek/lota/fleetctl``
   * - ``examples/demo_server``
     - ``github.com/szymonwilczek/lota/examples/demo_server``
   * - ``examples/ci-gate/gate``
     - ``github.com/szymonwilczek/lota/examples/ci-gate/gate``

Wire formats
============

The token and boot evidence formats in ``lota_token.h`` and the snapshot
header in ``lota_snapshot.h`` are installed, so their layout is part of the
ABI and ``types.list`` records it; ``LOTA_TOKEN_VERSION``,
``LOTA_BOOT_EVIDENCE_VERSION`` and ``LOTA_SNAPSHOT_VERSION`` name the
versions. A token protected-set encoding with other semantics takes the next
``LOTA_RUNTIME_PROTECT_*`` value. The report and enrollment protocols between
the agent, the verifier and the CA have versions of their own, described in
:doc:`../admin-guide/protocol-versions`.

Release promises
================

From release 1.0 on, within one ``LOTA_ABI_MAJOR``:

* a program built against an earlier SDK runs against a later library without
  recompiling;
* a public header keeps its declarations, and a struct an installed function
  takes keeps its layout, apart from appending to a struct with
  ``struct_size``;
* the installed header set only grows.

The agent's command line and configuration, the verifier's HTTP API and its
database schema are operator surfaces with their own pages, and are outside
these promises.
