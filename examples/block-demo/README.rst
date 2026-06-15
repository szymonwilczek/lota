.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

block-demo: evidence that LOTA blocks unauthorised code loads
=============================================================

This directory ships the minimal end-to-end proof that the BPF LSM strict_mmap
gate actually rejects a hostile shared object inside a process that opted into
LOTA's runtime enforcement.

Two artifacts are built under ``make examples``:

+---------------------------------+-------------------------------------------+
| Artifact                        | Purpose                                   |
+=================================+===========================================+
| ``build/examples/evil.so``      | Tiny shared object whose                  |
|                                 | ``__attribute__((constructor))`` only     |
|                                 | writes to stderr. Never executes during a |
|                                 | successful block (``security_mmap_file``  |
|                                 | returns ``-EPERM`` before the loader maps |
|                                 | the .so), so the message is the canary    |
|                                 | that fires on a regression.               |
+---------------------------------+-------------------------------------------+
| ``build/examples/block_victim`` | Self-protecting process. Calls            |
|                                 | ``lota_protect_self()`` to land in        |
|                                 | ``protected_pids``, then ``dlopen()``\ s  |
|                                 | the evil object. Exit code reports        |
|                                 | whether the gate fired.                   |
+---------------------------------+-------------------------------------------+

Building
--------

.. code:: sh

   make all examples

The fragment is wired into the top-level ``make examples`` target, so the
artifacts land in ``build/examples/`` next to the other demo binaries.

Bring-up requirements
---------------------

The diagnostic ``--test-ipc`` / ``--test-signed`` paths do **not** load the BPF
object. The block-demo needs the LSM hooks live, so the agent must be running
through the production daemon entry (no ``--test-*`` flag) with:

- ``mode = enforce``
- ``strict_mmap = true`` (the lota.conf default)
- BPF object loadable: either signed via ``make sign-bpf`` and pointed at by
  ``bpf_path``, or the agent invoked with the signing-skip override the build
  documents.
- A reachable verifier or the matching ``--no-verify-tls`` insecure flag for a
  sandbox host. The verifier wiring is outside this demo's scope; see the
  top-level README for the full production bring-up.

The demo binary then registers itself through the SDK on first connect, so the
agent does not need a pre-populated ``protect_pid`` entry.

Running the demo
----------------

With the agent live in enforce mode:

.. code:: sh

   examples/block-demo/run.sh

For an out-of-tree build (e.g. inside a VM with the repo virtiofs-mounted
read-only and artefacts under ``/var/tmp/lota-build``), point the script at the
alternate build root through the environment:

.. code:: sh

   BUILD_DIR=/var/tmp/lota-build sudo -E examples/block-demo/run.sh

``BUILD_DIR`` defaults to ``$REPO_DIR/build`` to match the Makefile default;
the same override works for ``tests/integration/test_bpf_gates.sh``.

Expected output on a successful block:

::

   [victim] pid=12345 evil=/.../build/examples/evil.so
   [victim] registered self into protected_pids
   [victim] dlopen blocked: /.../build/examples/evil.so: cannot ...
   [block-demo] kernel-side journal since the demo started:
     lota-agent[...]: BPF event: MMAP_BLOCKED pid=12345 path=evil.so
   [block-demo] PASS: evil.so blocked by BPF LSM gate

A ``FAIL`` line plus exit code ``1`` means the loader successfully mapped the
.so; the constructor's ``evil.so: loaded into pid N`` message will be in stderr
above it. If you see that, the gate did not fire -- audit the agent's mode, the
``strict_mmap`` flag, and confirm the BPF object actually attached
(``journalctl -u lota-agent | grep "BPF programs attached"``).

What the demo proves
--------------------

- ``security_mmap_file`` blocks file-backed ``PROT_EXEC`` mappings for
  processes in ``protected_pids`` regardless of how the .so was reachable
  (LD_PRELOAD-equivalent path: ``dlopen`` from the victim itself).
- The block fires before the dynamic loader runs the constructor, so even a
  malicious .so that tries to be useful on first call never gets the chance.
- A second process that does NOT call ``lota_protect_self()`` remains
  unaffected -- run the victim twice, comment out the SDK call in one copy, see
  the difference.

What the demo does NOT prove
----------------------------

The cross-process attack surface (a sibling process attaching ptrace to the
game, sending it SIGSTOP, or reading ``/proc/<game>/mem``) is gated by separate
LSM hooks in the same BPF object:

+------------------------------+---------------------------------+------------------------------+
| Hook                         | Source                          | Scope                        |
+==============================+=================================+==============================+
| ``lota_ptrace_access_check`` | ``src/bpf/lota_lsm.bpf.c:1467`` | ``is_protected_task(child)`` |
|                              |                                 | rejects every external       |
|                              |                                 | ptrace/peek against a        |
|                              |                                 | registered PID.              |
+------------------------------+---------------------------------+------------------------------+
| ``lota_task_kill``           | ``src/bpf/lota_lsm.bpf.c:1667`` | Same scope, rejects external |
|                              |                                 | signals (SIGSTOP / SIGKILL)  |
|                              |                                 | targeted at a registered     |
|                              |                                 | PID.                         |
+------------------------------+---------------------------------+------------------------------+

Those are covered by ``tests/integration/test_bpf_gates.sh`` (see the top-level
``tests/integration/`` directory), not this demo.
