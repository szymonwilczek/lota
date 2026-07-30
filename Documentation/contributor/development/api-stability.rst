.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

==========================
Public API and ABI surface
==========================

LOTA is a framework, so parts of it are surface an integrator builds against
and the rest is implementation. Only what this page names is public. Anything
else may change in any release, whatever its linkage says.

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

Adding and removing symbols
---------------------------

Adding a function is a compatible change: declare it in the header and add it
to a new version node below the current one, for example ``LOTAGAMING_1.1
{ global: lota_new_call; } LOTAGAMING_1.0;``. A program built against the
older node keeps running against the newer library.

Removing a function, renaming it, or changing its signature or the layout of a
struct it takes is an ABI break. It bumps ``LOTA_ABI_MAJOR`` in the top-level
``Makefile``, which changes every soname, and the old library can no longer be
replaced in place. Do not work around a break by leaving the symbol in the
version script with different semantics behind it -- that is the one failure a
version script cannot catch.
