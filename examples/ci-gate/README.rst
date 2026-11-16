.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

==================
CI/CD release gate
==================

A pipeline step proves that the host it runs on is attested before a
relying party releases a secret to it. ``lota-ci-attest`` is the step: it
takes a challenge from the gate, has the local agent answer it with a
token and writes the secret the gate releases. ``lota-release-gate`` is
the relying party: it guards one secret and releases it to a token that
answers a challenge it issued, verifies against the AIK it trusts and
carries the flags it requires.

Building
========

``make examples`` builds both into ``build/examples/``:

``lota-ci-attest``
  From ``attest_step.c`` against ``lota-gaming`` from the staged SDK (see
  `Building <../README.rst>`__) and ``libcurl``. Without ``libcurl`` it
  prints ``SKIP: lota-ci-attest (install libcurl-devel)`` and builds the
  gate alone. With the SDK installed, the build is:

  .. code-block:: console

     $ cc $(pkg-config --cflags lota-gaming libcurl) -o lota-ci-attest \
           attest_step.c $(pkg-config --libs lota-gaming libcurl)

``lota-release-gate``
  From ``gate/`` with ``go build``, against ``sdk/server`` of the
  repository. Without ``go`` it prints
  ``SKIP: <build>/examples/lota-release-gate (go not installed)``. The
  tests run from the module directory:

  .. code-block:: console

     $ cd examples/ci-gate/gate && go test ./...

lota-ci-attest
==============

.. code-block:: console

   $ lota-ci-attest --gate https://gate.example:8500 --out secret.bin

.. list-table::
   :header-rows: 1
   :widths: 25 20 55

   * - Option
     - Default
     - Meaning
   * - ``-g``, ``--gate URL``
     - required
     - Base URL of the gate; the step posts to ``URL/nonce`` and
       ``URL/release``.
   * - ``-o``, ``--out FILE``
     - required
     - File the released secret is written to.
   * - ``-s``, ``--socket PATH``
     - discovery
     - Agent socket, as in ``lota_connect_opts()`` (see
       `the gaming SDK <../../Documentation/userspace-api/gaming.rst>`_).
   * - ``-c``, ``--ca-cert FILE``
     - system CAs
     - CA that verifies an ``https://`` gate.
   * - ``-t``, ``--timeout SEC``
     - 15
     - Limit of each request to the gate, a whole number of seconds
       above 0.
   * - ``-h``, ``--help``
     -
     - Print the usage to stderr and exit 0.

The step runs in this order and stops at the first step that fails:

1. It removes ``--out``, so a failed run leaves no file from an earlier
   one. This happens before the other options are checked: a run that
   names ``--out`` and exits 2 has removed it too.
2. It connects to the agent, with a 5 second timeout, before any request
   to the gate.
3. ``POST /nonce`` must answer 200 with a ``nonce`` of 32 bytes in base64.
4. ``lota_get_token()`` answers that nonce, and the token is serialized
   with ``lota_token_serialize()``.
5. ``POST /release`` sends ``{"nonce": ..., "token": ...}``, both base64,
   and must answer 200 with a ``secret`` in base64.
6. The decoded secret is written to ``--out``, created with mode
   ``0600`` under the umask. A short write removes the file.

On success it prints
``ci-attest: host attested; secret written to <file>`` to stderr.

Exit codes
----------

.. list-table::
   :header-rows: 1
   :widths: 10 90

   * - Code
     - Meaning
   * - 0
     - The secret is in ``--out``; ``--help``.
   * - 2
     - An unknown option, an option without its value, a bad
       ``--timeout``, or no ``--gate`` or ``--out``. The usage follows on
       stderr.
   * - 3
     - ``ci-attest: no LOTA agent on this host; cannot attest``.
   * - 4
     - ``ci-attest: agent issued no token: <SDK error>``, or the token
       could not be serialized.
   * - 5
     - No challenge, or no answer to the token: the gate is unreachable,
       answers ``/nonce`` with a status other than 200, or its nonce is
       missing or not 32 bytes.
   * - 6
     - ``/release`` answered without a usable secret:
       ``ci-attest: release refused: <reason>`` with the reason of the
       gate, ``gate released no secret``, or
       ``released secret is not base64``.
   * - 7
     - ``--out`` could not be removed or written.

A pipeline can tell 6, the policy of the gate, from 5, a gate it did not
reach. The step reads the string fields of the answers by a plain scan
and decodes no escapes; it is written for the answers of
``lota-release-gate``.

lota-release-gate
=================

.. code-block:: console

   $ lota-release-gate --aik-pub aik.pem --secret-file secret.txt \
         --require attested,tpm,secureboot

Options take one dash or two:

.. list-table::
   :header-rows: 1
   :widths: 30 20 50

   * - Option
     - Default
     - Meaning
   * - ``-listen HOST:PORT``
     - ``127.0.0.1:8500``
     - Listen address.
   * - ``-aik-pub PATH``
     - required
     - AIK public key of the host let through, RSA in PKIX form, PEM or
       DER.
   * - ``-secret-file PATH``
     - required
     - The secret, released as read with trailing newlines removed. An
       empty secret does not start the gate.
   * - ``-require LIST``
     - ``attested,tpm``
     - Comma-separated flags the token must carry: ``attested``, ``tpm``,
       ``iommu``, ``bpf``, ``secureboot``. An empty list requires none.
   * - ``-nonce-ttl DURATION``
     - ``60s``
     - How long an issued challenge can be spent.
   * - ``-max-token-life DURATION``
     - ``15m``
     - Refuse a token whose remaining validity exceeds this, or that
       never expires; 0 disables the check.
   * - ``-tls-cert PATH``, ``-tls-key PATH``
     - none
     - PEM certificate and key; either one makes the gate serve HTTPS,
       which needs both.

The five names are ``LOTA_FLAG_ATTESTED``, ``LOTA_FLAG_TPM_OK``,
``LOTA_FLAG_IOMMU_OK``, ``LOTA_FLAG_BPF_LOADED`` and
``LOTA_FLAG_SECURE_BOOT``, described in
`the gaming SDK <../../Documentation/userspace-api/gaming.rst>`__.

The gate exits 2 when an option, the key, the secret or the ``-require``
list cannot be used, and 1 when the listener fails, as with a TLS
certificate or key that is missing or cannot be read. It logs to stdout
with the prefix ``ci-gate:`` and the UTC date and time:

.. code-block:: text

   ci-gate: <date> <time> listening on http://127.0.0.1:8500
       require=[attested,tpm] max-token-life=15m0s
   ci-gate: <date> <time> release granted nonce=<12 chars>...
       flags=[attested,tpm] expires_at=<RFC 3339>
   ci-gate: <date> <time> release refused nonce=<12 chars>...
       reason="<reason>"

The lines are wrapped here. ``flags`` names only the five flags above.
``nonce`` is ``-`` for a refusal of the body, the nonce or the token
before the gate looks the nonce up. The ``listening`` line is logged
before the listener opens; a listener that fails logs
``server: <error>`` after it.

POST /nonce
-----------

The answer is ``{"nonce": "<base64>", "expires_at": <unix time>}``: 32
random bytes, spendable until ``-nonce-ttl`` has passed. The gate keeps
the issued nonces in memory; a restarted gate knows none of them.

POST /release
-------------

The body is ``{"nonce": "<base64>", "token": "<base64>"}`` of at most
64 KiB. The answer is 200 ``{"secret": "<base64>"}``, or 403
``{"reason": "<reason>"}`` from the first check that fails:

.. list-table::
   :header-rows: 1
   :widths: 45 55

   * - Check
     - ``reason``
   * - The body is JSON.
     - ``malformed request: <error>``
   * - The nonce is 32 bytes in base64.
     - ``nonce is not 32 base64-encoded bytes``
   * - The token is base64 and not empty.
     - ``token is not base64-encoded``
   * - The gate holds the nonce: it issued it, it has not been spent,
       and no ``POST /nonce`` came after it expired.
     - ``nonce was not issued by this gate``
   * - The nonce has not expired.
     - ``nonce expired before the token arrived``
   * - ``VerifyToken()`` accepts the token against the AIK with that
       nonce.
     - ``token verification failed: <error>``
   * - The token carries the nonce of the request, which ``VerifyToken()``
       has already checked.
     - ``verified token carries a different nonce``
   * - The token carries every flag of ``-require``.
     - ``host is missing required state: <flags>``
   * - The token expires, unless ``-max-token-life`` is 0.
     - ``token never expires; -max-token-life 0 accepts it``
   * - The validity left is at most ``-max-token-life``.
     - ``token outlives the gate's window: <left> remaining, limit
       <limit>``

The nonce is spent by the first request that reaches its lookup, one
whose body and nonce decode and whose token is base64 and not empty,
whatever the verdict after: a token refused from there on cannot be
tried again with the same challenge. A request refused before the lookup
leaves the nonce unspent. ``VerifyToken()`` and its errors are described
in `the Go SDK <../../Documentation/userspace-api/go-sdk.rst>`_. It refuses
a token that expires more than 360 seconds ahead of the clock of the
gate, so a ``-max-token-life`` of 6 minutes or more refuses no token it
accepted that expires. The agent issues a token whose expiry is 0, one
that never expires, for a publisher with no verdict; the gate accepts it
only with ``-max-token-life 0``.

The gate trusts one AIK; an enrolled fleet is checked by a verifier, as
in `enrollment/ <../enrollment/README.rst>`_.

run.sh
======

``run.sh`` drives the step and the gate against an agent on a software
TPM, without root. It needs ``swtpm``, ``swtpm_setup``,
``tpm2_readpublic``, ``systemd-socket-activate``, ``openssl`` and
``make all examples``:

.. code-block:: console

   $ examples/ci-gate/run.sh

It works in ``/tmp/lota-ci-gate.XXXXXX`` and prints one line per step:

1. ``swtpm`` on TCP port ``TPM_PORT`` (42521), its control channel on the
   next port.
2. ``lota-agent --test-signed`` under ``systemd-socket-activate`` on
   ``lota.sock`` in the run directory, with the AIK metadata there too.
   It names no configuration file, so the agent reads
   ``/etc/lota/lota.conf`` when that exists and, when it cannot read it,
   goes on with the defaults.
3. One run of the step, with no gate up, starts the agent and provisions
   the AIK, whose public key ``tpm2_readpublic`` then exports from handle
   ``0x81010002``.
4. The gate on ``GATE_ADDR`` (``127.0.0.1:8500``) with that AIK and
   ``--require attested,tpm``: the step must exit 0 and write the secret
   byte for byte with mode ``0600``.
5. The gate with a fresh RSA key in place of the AIK: the step must exit
   6, leave no file where one existed and leave ``release refused`` in
   the log of the gate. A run with an unknown option must then exit 2 and
   leave no file either.

The run ends with:

.. code-block:: text

   PASS: the gate releases to an attested host and refuses everything else

A missing binary, a missing command other than
``openssl``, or a failed step prints a line starting ``missing`` or
``FAIL:``, plus the log of the gate when step 4 is refused, and exits 1.
A ``swtpm_setup`` that fails ends the script with its own exit status and
no such line.
A missing ``openssl`` ends step 5 with no line of its own.

``LOTA_BUILD_DIR`` (``build``), ``BIN`` (the build directory) and
``EXAMPLES_BIN`` (its ``examples/``) say where the binaries are.
``TPM_PORT`` and ``GATE_ADDR`` move the listeners. The run directory is
removed at exit. The ``examples`` job of CI runs the script (see
`CI <../../Documentation/dev-tools/ci.rst>`_).
