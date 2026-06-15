==============
Testing policy
==============

.. list-table::
   :header-rows: 1
   :widths: 12 44 44

   * - Layer
     - What
     - How
   * - Unit
     - Go (``verifier``, ``attestca``, ``sdk/server``) and C (agent, SDK)
     - ``make test-unit``, ``go test ./...``
   * - Sanitizers
     - ASan / UBSan on the C side
     - ``SANITIZE=address,undefined make test-unit``
   * - Memory
     - valgrind memcheck
     - ``make valgrind-unit``, ``make valgrind-smoke``
   * - Fuzz (Go)
     - verifier / SDK / attest-CA parsers of untrusted bytes
     - ``go test -run x -fuzz=Fuzz... ./...``
   * - Postgres
     - verifier store/session backends against a real server
     - ``go test -tags pg_integration -p 1 ./store/ ./verify/`` with
       ``LOTA_TEST_PG_DSN``; CI job ``postgres-integration``
   * - Fuzz (C)
     - IPC, config, TLS-pin, wire, enrollment-reply decoders,
       sealed-envelope parser/AEAD, TPM attest unmarshal, policy signature
       verify, server SDK token verify, TPM2B response/credential unmarshal
     - ``make fuzz-all``
   * - Kernel
     - BPF LSM live in a guest
     - Syzkaller harness ``lota_bpf_fuzz`` (see ``syzkaller/README.rst``)
   * - Repro
     - bit-for-bit build
     - ``make reproducible-build``; gated in CI
   * - Includes
     - every header used directly, no transitive deps
     - ``make check-includes``

A fuzz crash leaves a reproducer under ``testdata/fuzz/<Target>/``. Commit it
so the regression is locked in.

Include hygiene
===============

Every translation unit must include the headers it uses directly and no
others; a header reached only transitively through another include is a
defect. ``make check-includes`` enforces this. It builds a compile database
with ``bear`` and runs ``clang-include-cleaner`` -- the same engine clangd's
editor diagnostic uses -- over every C source the build knows about (``all``,
``examples``, ``test-bins``, ``fuzz-all``, ``bench-c``,
``syzkaller-fuzz-loader``). The gate fails on any header pulled in but not used
directly.

``scripts/fix-includes.sh [file.c ...]`` rewrites the include lists
automatically with ``include-what-you-use``; with no arguments it processes the
whole database. Always review the diff and rebuild: the tools cannot see
symbols reached only through a macro or behind conditional compilation, so an
include needed only that way must carry an ``// IWYU pragma: keep`` comment
(see ``tests/test_seal_tpm.c`` for practice example).

A few exemptions live in both ``scripts/check-includes.sh`` and the local
``.clangd``, and must stay in sync:

* The C/POSIX headers ``clang-include-cleaner`` mis-attributes to the glibc /
  kernel-uapi implementation headers (``bits/``, ``asm-generic/``) -- it
  reports the public ``<errno.h>``, ``<sys/types.h>`` and friends as unused.
  The idiomatic public headers are kept and that fixed set is exempted.
* Library umbrellas (``<SDL.h>``, the TSS2 ESYS headers) whose granular
  sub-headers are implementation detail; the umbrella the code includes is kept
  via the mapping files under ``scripts/iwyu/``.
* ``<systemd/sd-bus-protocol.h>``, whose symbols systemd relocates between
  releases: ``SD_BUS_NAME_REPLACE_EXISTING`` sits in ``<systemd/sd-bus.h>`` on
  systemd 255 (Ubuntu 24.04) but in ``sd-bus-protocol.h`` on 259 (Fedora 44),
  so the header reads as used on one and unused on the other. It is exempted
  instead of churned per systemd version.
* The generated ``include/vmlinux.h`` and the BPF program (``src/bpf/``) are
  skipped: the host analyzer cannot model a ``-target bpf`` unit.

Requires ``clang-include-cleaner`` (clang-tools-extra), ``bear``, and -- for
the fixer -- ``include-what-you-use``.

Postgres-backed tests and the coverage ratchet
==============================================

The multi-instance verifier ships a Postgres backend (``jackc/pgx/v5``,
pure-Go, stdlib ``database/sql`` driver). Its store and session code is
compiled into every build but only exercised by tests behind the
``pg_integration`` build tag, which need a live server:

.. code-block:: bash

    podman run -d -e POSTGRES_USER=lota -e POSTGRES_PASSWORD=lota \
      -e POSTGRES_DB=lota -p 55432:5432 docker.io/library/postgres:16-alpine
    cd src/verifier
    LOTA_TEST_PG_DSN="postgres://lota:lota@127.0.0.1:55432/lota?sslmode=disable" \
      go test -tags pg_integration -p 1 -count=1 ./store/ ./verify/

Use ``-p 1``: both packages truncate tables in one shared database, and pick a
host port that is actually free -- a foreign Postgres already bound to the port
answers with confusing auth failures. The coverage ratchet
(``scripts/check-go-coverage.sh``) enables the tag for ``src/verifier`` when
``LOTA_TEST_PG_DSN`` is set; the CI ``go-coverage-ratchet`` job provides a
postgres service, so the recorded floors for the ``store`` and ``verify``
packages assume the Postgres tests ran. Without the DSN the script still works
but those two packages report lower coverage than their floors.
