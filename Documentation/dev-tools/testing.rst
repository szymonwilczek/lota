.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

=======
Testing
=======

The C code is tested by programs under ``tests/`` and shell scripts under
``tests/integration/``, the Go modules by ``go test``. The table lists what
runs them; the CI jobs that do so are in :doc:`ci`.

.. list-table::
   :header-rows: 1
   :widths: 40 60

   * - Command
     - Runs
   * - ``make test-unit`` (``make test``)
     - the C unit tests, the integration scripts and the cross-language
       checks, after ``make all``
   * - ``make test-go``
     - the Go tests of every Go module
   * - ``go test ./...`` in a Go module
     - that module's Go tests
   * - ``make SANITIZE=address,undefined test-unit``
     - ``make test-unit`` under the sanitizers
   * - ``make valgrind-unit``, ``make valgrind-smoke``
     - unit tests and command-line paths under valgrind memcheck
   * - ``go test -tags pg_integration`` in ``src/verifier``
     - the store and session tests against a live Postgres
   * - ``scripts/check-go-coverage.sh``
     - ``go test -cover`` in every Go module, against recorded floors
   * - ``make test-hardware``
     - the agent's IOMMU and TPM self-tests, as root
   * - ``make fuzz-all``, ``make fuzz-regress``
     - the C fuzz targets (:doc:`fuzzing`)
   * - ``make bench-c``, ``make bench-go``
     - the micro-benchmarks (:doc:`../performance/index`)

Unit and integration tests
==========================

``make test-unit`` builds ``all`` and every test program, then runs:

* every program built from ``tests/test_*.c``, except those listed in
  ``TEST_MANUAL`` (`Tests that need a live system`_).
* the scripts under ``tests/integration/`` that run without root or a
  running agent. A script whose tool is missing (``openssl``, ``python3``,
  ``go``, ``clang``, ``pkg-config``, ``sphinx-build``, ``softhsm2-util``)
  is reported as skipped.
* two cross-language checks. ``tests/cross_lang/test_gen.go`` signs a token
  with the Go server SDK and ``test_cross_lang_verify`` verifies it with the
  C one. ``test_cross_lang_report_gen`` writes an attestation report with
  the agent's serializer and ``tests/cross_lang/report_verify.go`` parses
  it with the verifier's. Both need ``go``.

The Go tests are not part of ``make test-unit``; ``make test-go`` runs them.

A script reads the build directory from ``LOTA_BUILD_DIR``, which the make
recipe exports. A script that drives one binary also takes its path from the
environment, such as ``LOTA_INSTALL_BIN`` for ``lota-install`` or
``LOTA_TRUST_PONG`` for the ``trust_pong`` example.

Test output
-----------

Every program and script runs, whatever the one before it returned.
``make test-unit`` collects the results in
``$(BUILD_DIR)/test-summary.tsv``, ``make test-go`` in
``$(BUILD_DIR)/test-go-summary.tsv``, and each ends with
``tests/lib/summary.sh``, which prints the totals and every failed test and
fails the target. ``LOTA_TEST_COLOR`` is ``always``, ``never`` or ``auto``.

Adding a C test
---------------

A test program reports through ``TEST()``, ``FAIL()`` and ``SKIP()`` of
``tests/test.h``; its header shows their use.

The ``Makefile`` builds every ``tests/test_*.c`` into
``$(BUILD_DIR)/test_<name>``. A test that needs more than its own source
declares it in the test section::

   $(BUILD_DIR)/test_foo: $(AGENT_DIR)/foo.c
   $(BUILD_DIR)/test_foo: TEST_CFLAGS := -DFOO
   $(BUILD_DIR)/test_foo: TEST_LDLIBS := -lcrypto

``-DLOTA_INTERNAL_TESTS`` exposes the agent's test entry points
(``src/agent/agent_internal.h``).
A new test is run by ``make test-unit`` unless it is added to
``TEST_MANUAL``, and under valgrind only once it is added to
``VALGRIND_UNIT_BINS``.

Adding an integration test
--------------------------

A script reports through ``tests/lib/test.sh``, the shell form of
``tests/test.h``; its header shows its use. A script run by
``make test-unit`` goes in the recipe through ``$(call test_run,...)``, and
a missing tool is reported through
``$(call test_skip,<group>,<path>,<reason>)``.

Tests that need a live system
-----------------------------

``TEST_MANUAL`` lists the programs the loop leaves out: ``test_sdk_ipc``,
``test_ipc_client``, ``test_ipc_dos``, ``demo_sdk`` and ``test_tls_verify``,
which need a server, and ``hook_preload_target``,
``test_cross_lang_report_gen`` and ``test_cross_lang_verify``, which other
tests run.

* When ``/run/lota/lota.sock`` exists, ``make test-unit`` also runs
  ``test_sdk_ipc``, ``test_ipc_client status`` and ``demo_sdk`` against the
  agent behind it. ``make test-sdk`` prints how to start an agent with
  ``--test-ipc`` for them. ``test_ipc_dos`` opens more than 64 connections
  to such an agent and is only run by hand.
* ``test_tls_verify`` needs ``openssl s_server`` on port 9443 with a
  certificate whose only SAN is ``DNS:localhost``. ``make test-unit`` runs
  it when ``LOTA_RUN_TLS_TESTS`` is set, or when
  ``/tmp/lota-tls-test/ca.pem`` exists and a server listens on 9443. The
  program takes another CA file as its argument.
* ``make test-hardware`` runs ``lota-agent --test-iommu`` and
  ``lota-agent --test-tpm`` (:doc:`../agent/command-line`), as root.
* ``tests/integration/test_bpf_gates.sh`` drives the BPF LSM gates scoped to
  protected processes against an agent enforcing with BPF attached. It needs
  root and ``make all examples``, and no make target runs it.

Sanitizers and valgrind
=======================

``SANITIZE=<list>`` adds ``-fsanitize=<list>`` to the compile and link flags
of the host C code, not the BPF object, with
``-fno-sanitize-recover=all``, so a finding aborts the process and fails the
test. CI runs ``make test-unit`` with ``SANITIZE=address,undefined``, under
gcc and clang, and with ``SANITIZE=thread``.

``make sanitizer-build`` builds ``all``, the examples, the C benchmark,
``lota-bench`` and the syzkaller loader under ``address,undefined`` and runs
nothing.

``make valgrind-unit`` runs the programs in ``VALGRIND_UNIT_BINS`` under
``$(VALGRIND)`` (default ``valgrind``) with::

   --error-exitcode=1 --leak-check=full
   --errors-for-leak-kinds=definite,indirect --track-origins=yes -q

``test_hardening`` is left out: valgrind cannot run its seccomp filters.
``make valgrind-smoke`` runs ``lota-agent --help`` with an empty
configuration file, and ``--help`` of the ``demo_anticheat`` and
``trust_pong`` examples when they are built, with the same flags.

Go tests
========

Each Go module (``src/verifier``, ``src/attestca``, ``sdk/server``,
``src/crl``, ``src/fleetctl`` and the two example modules) is tested on its
own with ``go test ./...`` in its directory. ``make test-go`` runs every
module through ``tests/lib/go-test.sh``, passing ``GO_TEST_FLAGS`` to
``go test``.

Postgres-backed tests
---------------------

The verifier's Postgres store and session code is tested only under the
``pg_integration`` build tag, against a live server named by
``LOTA_TEST_PG_DSN``:

.. code-block:: console

   $ podman run -d -e POSTGRES_USER=lota -e POSTGRES_PASSWORD=lota \
   >     -e POSTGRES_DB=lota -p 55432:5432 docker.io/library/postgres:16-alpine
   $ cd src/verifier
   $ LOTA_TEST_PG_DSN="postgres://lota:lota@127.0.0.1:55432/lota?sslmode=disable" \
   >     go test -tags pg_integration -p 1 -count=1 ./store/ ./verify/

``-p 1`` is needed: both packages truncate the tables of the one database.
Without ``LOTA_TEST_PG_DSN`` the tests skip.

Two variables enable more cases; without them those cases skip, and CI
sets neither:

* ``LOTA_TEST_PG_SHARD_DSNS``: two databases, comma separated, for the
  sharded store tests, which check which database answered.
* ``LOTA_TEST_PG_EMPTY_DSN``: a database no verifier has built, for the
  read-only open refusal.

Go coverage ratchet
-------------------

``scripts/check-go-coverage.sh`` runs ``go test -cover ./...`` in
``src/verifier``, ``src/attestca``, ``sdk/server``, ``src/crl`` and
``src/fleetctl`` and compares each package with its floor in
``.github/go-coverage-baseline``, or the file given as its argument. It
exits 1 when a package falls below its floor, or when a package with a
non-zero floor reports no coverage, and 2 when the baseline file is
missing.

With ``LOTA_TEST_PG_DSN`` set it adds ``-tags pg_integration -p 1`` for
``src/verifier``. The floors of the ``store`` and ``verify`` packages
assume those tests ran; without the variable both fall below them. The
floors are raised as tests land and never lowered.

Tree gates
==========

These targets check the tree as a whole. ``scripts/check-patch`` runs each
when a patch touches its inputs (:doc:`../process/patch-checks`).

Include hygiene
---------------

``make check-includes`` runs ``scripts/check-includes.sh``. It builds a
compile database at ``build/compile_commands.json`` with ``bear`` over
``make -B -k`` of ``all``, ``examples``, ``test-bins``, ``fuzz-all``,
``bench-c``, ``lota-bench`` and ``syzkaller-fuzz-loader``, and keeps the
first entry of a file compiled twice. It then runs
``clang-include-cleaner`` over every C file in the database except
``src/bpf/``, and fails on each include the tool reports as unused. A header
reached only through another include is not reported.

Some headers are exempt, because the tool reports them wrongly:

* ``<errno.h>``, ``<sys/types.h>``, ``<unistd.h>``, ``<getopt.h>``,
  ``<termios.h>``, ``<sys/time.h>`` and ``<sys/socket.h>``, whose symbols
  it credits to the glibc and kernel uapi implementation headers.
* ``SDL*.h``: SDL's public header is ``<SDL.h>``, and the others are
  implementation detail.
* ``<systemd/sd-bus-protocol.h>``, whose symbols systemd moves between it
  and ``<systemd/sd-bus.h>`` across releases.

``scripts/fix-includes.sh [file.c ...]`` rewrites the include lists with
``include-what-you-use``, over the whole database when given no file. The
mapping files under ``scripts/iwyu/`` keep the SDL and TSS2 umbrella
headers. The tool does not see a symbol used only through a macro or under
conditional compilation, so review the diff and rebuild; an include needed
that way carries ``// IWYU pragma: keep``, as in ``tests/test_seal_aik.c``.

The gate needs ``clang-include-cleaner`` (clang-tools-extra) and ``bear``,
and exits 1 without them. The fixer needs ``include-what-you-use``,
``iwyu_tool.py``, ``fix_includes.py`` and ``bear``.

Package manifests
-----------------

Packages are described twice: by the nfpm configs under ``packaging/nfpm``,
which ``make packages`` and the release workflow build, and by
``packaging/rpm/lota.spec``, which COPR builds
(:doc:`../admin-guide/packages`). ``make check-package-manifests`` runs
``scripts/check-package-manifests.sh``, which fails when:

* the two manifests ship different installed paths for a package. A
  directory that only holds other listed paths is dropped from both sides,
  so a directory shipped empty is still compared. Modes and ownership are
  not compared.
* their Requires differ by name, apart from those rpmbuild derives from
  sonames, which the nfpm config lists by hand.
* a sibling is pinned to one build (``=``) in one manifest and not in the
  other.
* an nfpm config's ``pkgconfig(<name>)`` provides and its shipped ``.pc``
  files differ. rpmbuild derives the provides from the files and nfpm does
  not.
* a package's ``Summary`` is not the first line of its nfpm description,
  or its ``%description`` is not the rest.
* the spec's ``Version`` or newest ``%changelog`` entry is not the
  ``@VERSION@`` or ``@CHANGELOG@`` placeholder that ``make srpm`` fills
  from ``VERSION``.
* the spec ships a file ``make install`` writes only when it exists, and no
  target the spec's ``%build`` runs produces it.
* a path under ``/var/lib/lota``, ``/etc/lota``, ``/usr/lib/lota`` or
  ``/usr/share/lota`` has no parent directory a package owns.
* a shipped unit is not stopped by both ``%systemd_preun`` and the nfpm
  pre-remove script.
* the packages ship a file under ``/usr/share/lota`` that ``make install``
  does not place.
* ``LOTA_REPO_BASEURL`` or a ``lota.repo`` or ``RPM-GPG-KEY-lota`` address
  in a page is not under ``<site>/rpm``, where ``<site>`` is ``_site`` in
  ``Documentation/conf.py``.

A file added to a package is therefore added to the ``Makefile`` install
rule, the nfpm config and the spec's ``%files``.

The player page's build in a clean Fedora
-----------------------------------------

A development host already has every package an earlier build needed, so it
cannot show a package the player page leaves out.
``make check-player-build`` runs ``scripts/check-player-build.sh``. It
starts ``registry.fedoraproject.org/fedora:44`` (``LOTA_PLAYER_IMAGE``
overrides it) and runs the commands of the *Building it yourself* section
of ``Documentation/player/index.rst``, read from the page. A copy of the
tree under test replaces the ``git clone``, and ``sudo`` is dropped, since
the container runs as root.

A failing step prints its number and the last 20 lines of its output. After
the last step the script checks that ``/usr/bin/lota-install``,
``/usr/bin/lota-steam-setup``, ``/usr/bin/lota-proton-hook`` and both
``liblota_wine_hook.so.1`` builds, under ``/usr/lib64`` and ``/usr/lib``,
are installed. A missing 32-bit package makes the build skip the 32-bit
hook, and ``make install`` then refuses the tree on x86_64.

The script needs podman and network access. With
``LOTA_PLAYER_IN_CONTAINER=1`` it runs in place, from ``LOTA_PLAYER_SRC``
(default ``/src``), as the CI job does inside a Fedora 44 image.
