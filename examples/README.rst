.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

========
Examples
========

The programs and scripts under ``examples/`` show LOTA from the side of the
software that relies on it: a game client, a game server, an anti-cheat
heartbeat, a CI step and the deployments around the verifier. Each
directory has a ``README.rst`` with what it runs, what it needs and what
it prints.

Directories
===========

.. list-table::
   :header-rows: 1
   :widths: 22 78

   * - Directory
     - Content
   * - `demo/ <demo/README.rst>`_
     - ``setup.sh`` runs ``demo_server``, ``demo_anticheat`` and
       ``trust_pong`` against an agent on a software TPM;
       ``demo_tamper.sh`` makes the heartbeat fail on demand.
   * - `demo_server/ <demo_server/README.rst>`_
     - Go server that issues nonces, verifies heartbeats and reports the
       verdict to the game client (``demo_server``).
   * - `demo_anticheat/ <demo_anticheat/README.rst>`_
     - C heartbeat producer built on the anti-cheat SDK
       (``demo_anticheat``).
   * - `demo_game/ <demo_game/README.rst>`_
     - SDL2 client that shows the server's verdict (``trust_pong``).
   * - `block-demo/ <block-demo/README.rst>`_
     - A protected process that maps a library outside the trust set
       (``block_victim``, ``evil.so``).
   * - `runtime_remeasure/ <runtime_remeasure/README.rst>`_
     - Computes the runtime measurement of a process image without an
       agent, verifier or TPM (``runtime_remeasure``).
   * - `ci-gate/ <ci-gate/README.rst>`_
     - A CI step that proves its host is attested before a relying party
       releases a secret (``lota-ci-attest``, ``lota-release-gate``).
   * - `cs2/ <cs2/README.rst>`_
     - The Wine and Proton hook in a Steam title, with failure scenarios
       under ``cs2/scenarios/``.
   * - `enrollment/ <enrollment/README.rst>`_
     - Enrollment of an AIK with ``lota-attest-ca`` and attestation to a
       verifier that trusts only the CA.
   * - `hsm-ca/ <hsm-ca/README.rst>`_
     - ``lota-attest-ca`` with its signing key in a PKCS#11 token.
   * - `mtls/ <mtls/README.rst>`_
     - The heartbeat producer and the server over mutual TLS.
   * - `ha-postgres/ <ha-postgres/README.rst>`_
     - Two verifiers sharing one Postgres database.
   * - `sealed-key/ <sealed-key/README.rst>`_
     - A secret sealed to the boot state and unsealed offline.

`anticheat-integration.rst <anticheat-integration.rst>`_ describes what a
studio forking the anti-cheat reference copies, links against and has to
change.

Building
========

``make examples`` from the repository root builds the C and Go examples
into ``$(BUILD_DIR)/examples/``, by default ``build/examples/``. The
``all`` target does not include them.

The target runs ``sdk-stage`` first, which installs the public headers,
the SDK libraries and their ``.pc`` files under ``$(BUILD_DIR)/stage/``
in ``include/lota/``, ``lib64/`` and ``lib64/pkgconfig/``, the directories
the ``lota-sdk`` and ``lota-sdk-devel`` packages install into under
``/usr``. Each ``examples/*/Makefile.fragment`` then compiles against that
prefix through ``pkg-config`` and links with an ``rpath`` to its
``lib64/``. ``make`` stops at the first fragment that fails. After the
fragments, ``demo_server`` is built with ``go build`` when ``go`` is
installed; otherwise the target prints
``SKIP: demo_server (go not installed or stub absent)``.

``make examples-clean`` removes ``$(BUILD_DIR)/examples/`` and runs each
fragment's ``clean`` rule.

Optional dependencies
---------------------

SDL2 and libcurl are not required to build LOTA. A fragment that needs
them sets ``LOTA_OPTIONAL_PKGS`` and includes
`optional-deps.mk <optional-deps.mk>`_, which sets ``LOTA_OPTIONAL_OK`` to
``yes`` when ``pkg-config`` finds every listed package. Without them the
fragment prints a ``SKIP:`` line naming the packages to install, and the
other fragments still build:

.. list-table::
   :header-rows: 1
   :widths: 30 25 45

   * - Fragment
     - Needs
     - Without it
   * - ``demo_game``
     - ``sdl2``, ``libcurl``
     - ``trust_pong`` is skipped
   * - ``demo_anticheat``
     - ``libcurl``
     - ``demo_anticheat`` is skipped
   * - ``ci-gate``
     - ``libcurl``
     - ``lota-ci-attest`` is skipped; ``lota-release-gate`` is built
   * - ``ci-gate``
     - ``go``
     - ``lota-release-gate`` is skipped

`test_examples_optional_deps.sh
<../tests/integration/test_examples_optional_deps.sh>`_ hides one
package at a time and checks that the rest of the tree builds.
