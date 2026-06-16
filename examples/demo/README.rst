.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

Live demo
=========

End-to-end walk-through of the LOTA attestation chain on a single Fedora 44
host. The runner stands up an isolated ``swtpm``, the LOTA agent, the demo
verifier/server, the heartbeat producer, and the SDL2 client, then hands off to
the operator. A second script flips the trust verdict on demand so the failure
path is visible during a walk-through.

Five-step operator path
-----------------------

1. **Clone** the repository and ``cd`` into it.

2. **Install dependencies.** Project build prerequisites plus the demo-only
   tools listed under `Dependencies <#dependencies>`__. On Fedora 44 the
   demo-only set is

   .. code:: sh

      sudo dnf install swtpm swtpm-tools tpm2-tools tpm2-tss-devel \
                       SDL2-devel libcurl-devel golang

3. **Run the paced runner.** From the repository root:

   .. code:: sh

      sudo -E examples/demo/setup.sh

   The script pauses at each phase (``press ENTER to continue:``). On the sixth
   ENTER ``trust_pong`` opens with a green ``TRUSTED`` banner and a live score
   against the back wall. The runner prints the sandbox path
   (``/tmp/lota-demo.XXXXXX``) and the marker path ``<sandbox>/tamper.marker``
   at the producer step so the next script needs no configuration.

4. **Watch the green path.** Every heartbeat tick (default 5 s, see
   ``--interval``) writes one line to the producer's log under the sandbox
   ``logs/`` directory:

   ::

      demo_anticheat: seq=7 state=TRUSTED latency=12.4ms http=200

   The ``trust_pong`` banner mirrors the same verdict; the score counter keeps
   incrementing.

5. **Trigger the failure path.** From a second terminal, with the demo still
   running:

   .. code:: sh

      examples/demo/demo_tamper.sh

   The script discovers the active sandbox, arms the tamper marker, and holds
   it until Ctrl-C. The next producer tick flips the banner to red
   ``INTEGRITY LOSS`` and (after two consecutive UNTRUSTED ticks, matching
   ``trust_pong``'s ``untrusted_streak >= 2``) the play field freezes with
   ``INTEGRITY LOSS - session terminated``. Ctrl-C on ``demo_tamper.sh``
   unlinks the marker and the verdict stream returns to ``TRUSTED``, but the
   freeze is a one-way latch (``trust_pong.c``: ``g.frozen`` is never cleared)
   - the session stays terminated. Restart ``trust_pong`` for a fresh session.

Press Esc or close the ``trust_pong`` window to end the demo. The runner's EXIT
trap stops every background process, tears down ``swtpm``, and removes the
sandbox unless ``--keep-tmp`` was passed.

Asciinema capture
-----------------

The ``trust_pong`` window is a GUI, so the recorded terminal cannot be the one
running ``setup.sh`` (it blocks on the game). Record a second terminal that
tails the producer's per-tick verdict lines while the tamper script flips the
state; that text is what carries the TRUSTED -> UNTRUSTED -> TRUSTED transition
in the cast.

The sandbox is a ``mktemp -d`` owned by root, so the recorded terminal reads
its logs and arms the marker as root.

Terminal A (not recorded) brings up the chain with a fast tick and keeps the
sandbox alive:

.. code:: sh

   sudo BUILD_DIR=build examples/demo/setup.sh \
        --no-build --keep-tmp --interval 2 --yes

Terminal B (recorded) tails the verdict stream, arms the tamper for a fixed
window, then lets it auto-disarm:

.. code:: sh

   sudo -v   # refresh sudo so no password prompt lands in the cast
   sudo asciinema rec -i 2 examples/demo/asciinema.cast
   # inside the recorded root shell:
   SANDBOX=$(ls -1dt /tmp/lota-demo.* | head -n1)
   tail -n 2 -f "$SANDBOX/logs/demo_anticheat.log" &
   sleep 8
   examples/demo/demo_tamper.sh --demo-dir "$SANDBOX" --hold-sec 12
   sleep 10
   kill %1; exit

``-i 2`` collapses idle gaps to two seconds so the playback stays under two
minutes and the cast under 200 KiB. The producer's per-tick log lines make the
verdict transition visible without narration.

The agent rate-limits ``GET_TOKEN`` per UID. ``setup.sh`` runs its agent,
liveness check, and heartbeat producer all as root, so they share the uid-0
token bucket. For a long or fast recording run the recording producer under a
separate, non-root UID (or kill ``setup.sh``'s own ``demo_anticheat --server``
first) so it gets its own bucket and does not starve the demo's heartbeats.

Dependencies
------------

Install the normal project dependencies plus the demo tools:

============== =======================================================
Tooling        Fedora package examples
============== =======================================================
TPM sandbox    ``swtpm``, ``swtpm-tools``, ``tpm2-tools``
TSS2 loader    ``tpm2-tss-devel``
examples build ``SDL2-devel``, ``libcurl-devel``, ``golang``, ``make``
============== =======================================================

The runner uses the ``swtpm`` TCTI directly through the agent's ``LOTA_TCTI``
override; it does not talk to ``/dev/tpmrm0``. This is a LOTA-level environment
variable passed into the TSS2 TCTI loader, not a promise that libtss2 itself
reads ``LOTA_TCTI``. AIK metadata and AIK auth are redirected with
``LOTA_AIK_META_PATH`` into the same temporary demo directory.

``LOTA_TCTI`` and ``LOTA_AIK_META_PATH`` are developer/demo hooks only. They
are honored on the agent's interactive one-shot commands (the demo drives
``--test-signed``), but the **persistent daemon ignores them**, so a stray
environment cannot point the production root of trust at a different TPM or AIK
key store. Production selects the TPM through ``/dev/tpmrm0`` and the
compiled-in AIK paths.

.. _setupsh-reference:

setup.sh reference
------------------

====================== ==============================================
Flag                   Meaning
====================== ==============================================
``--dry-run``          print the ordered steps without starting them
``--yes``              skip ENTER gates
``--no-build``         require existing artifacts under ``build/``
``--keep-tmp``         keep logs and swtpm state after exit
``--listen HOST:PORT`` demo server listen address
``--interval SEC``     heartbeat interval for ``demo_anticheat``
``--tpm-port PORT``    swtpm command port; control port is ``PORT+1``
====================== ==============================================

The runner exposes the marker path through the producer step so
``demo_tamper.sh`` can discover it without flags; for non-default sandboxes
feed it explicitly with ``--demo-dir`` or ``--marker``.

The real run currently needs root because ``lota-agent --test-signed`` binds
``/run/lota/lota.sock``. If you want build artifacts owned by your normal user,
build first and skip the build phase:

.. code:: sh

   make all
   make examples
   sudo -E examples/demo/setup.sh --no-build

CI and quick ordering checks use:

.. code:: sh

   examples/demo/setup.sh --dry-run --yes

.. _demo_tampersh-reference:

demo_tamper.sh reference
------------------------

================== ==========================================================
Flag               Meaning
================== ==========================================================
``--marker PATH``  explicit marker file; refused outside ``/tmp/lota-demo.*``
``--demo-dir DIR`` sandbox root; marker is ``DIR/tamper.marker``
``--hold-sec SEC`` auto-disarm after ``SEC`` seconds instead of Ctrl-C
================== ==========================================================

The script picks the newest ``/tmp/lota-demo.*`` directory if neither
``--marker`` nor ``--demo-dir`` is given. Disarming happens through a single
``trap`` on EXIT / INT / TERM, so killing the script (or letting ``--hold-sec``
lapse) always removes the marker; the producer's next tick returns to
``TRUSTED`` without operator intervention.

Runtime notes
-------------

The runner refuses to start if ``/run/lota/lota.sock`` already exists. All
background processes write logs under the sandbox ``logs/`` directory printed
at the start of the demo:

::

   agent.log            lota-agent --test-signed
   demo_server.log      Go demo server / verifier
   demo_anticheat.log   heartbeat producer (per-tick verdict lines)
   swtpm.log            swtpm sandbox
   tpm2_*.log           tpm2-tools probes used during AIK export

On normal exit the runner asks the signed IPC server to shut down, stops the
demo server and heartbeat producer, stops ``swtpm``, and removes the temp
directory unless ``--keep-tmp`` was passed.

Component documentation
-----------------------

Each binary keeps its own integrator-facing README next to the source:

- `examples/demo_server/README.rst <../demo_server/README.rst>`__ - HTTP surface,
  accepted payloads, expected response schema.
- `examples/demo_anticheat/README.rst <../demo_anticheat/README.rst>`__ -
  producer flags, exit codes, tamper hook, and integration notes against EAC /
  BattlEye.
- `examples/demo_game/README.rst <../demo_game/README.rst>`__ - SDL2 client
  flags, controls, cold-launch contract, verdict palette.
