.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

==========
block-demo
==========

``block_victim`` puts itself in the protected set of the agent and then
``dlopen()``\ s ``evil.so``, a library outside the trust set. With the
agent in ``enforce`` mode and ``strict_mmap`` on, the ``mmap_file``
program refuses the executable mapping of the library before its
constructor runs. ``run.sh`` runs the victim and reports the result.

Building
========

``make examples`` builds two files into ``build/examples/``:

``block_victim``
  Links ``lota-gaming`` from the staged SDK (see
  `Building <../README.rst>`__) and ``libdl``.

``evil.so``
  A shared object whose constructor only prints
  ``evil.so: loaded into pid <pid>`` to stderr, so a load that gets
  through is harmless and visible.

The agent
=========

The ``--test-*`` modes of the agent load no BPF, so the demo needs the
daemon itself with, in ``lota.conf`` (see
`configuration <../../Documentation/agent/configuration.rst>`_):

.. code-block:: text

   mode = enforce
   strict_mmap = true

``strict_mmap`` is off by default. With it, a protected process is
refused an executable mapping that is writable, or whose file is neither
an ``allow_verity`` entry nor a ``trust_lib`` entry; ``evil.so`` is
neither. The program is described in `the BPF programs
<../../Documentation/bpf/index.rst>`_ and the protected set in
`protection <../../Documentation/agent/protection.rst>`_.

Running
=======

.. code-block:: console

   $ examples/block-demo/run.sh

The script runs ``block_victim`` on ``build/examples/evil.so``. A build
elsewhere is named by ``BUILD_DIR``, else ``LOTA_BUILD_DIR``:

.. code-block:: console

   $ BUILD_DIR=/var/tmp/lota-build examples/block-demo/run.sh

A refused load prints:

.. code-block:: text

   [block-demo] launching victim against /run/lota/lota.sock
   [victim] pid=<pid> evil=<build>/examples/evil.so
   [victim] registered self into protected_pids
   [victim] dlopen blocked: <dlerror text>

   [block-demo] agent journal for pid <pid>:
   <prefix> [<ns>] MMAP_BLOCKED block_victim: <file> (pid=<pid>, uid=<uid>)

   [block-demo] PASS: evil.so blocked by BPF LSM gate

The journal lines are those of ``journalctl -t lota-agent`` since the
script started that name the victim with ``MMAP_BLOCKED`` or
``ANON_EXEC_BLOCKED``. An agent that does not log to the journal, or a
user who cannot read it, leaves none, and the script says so; the exit
code does not depend on them.

.. list-table::
   :header-rows: 1
   :widths: 10 90

   * - Exit
     - Meaning
   * - 0
     - ``PASS``: the victim could map ``evil.so`` executable before it was
       protected, and ``dlopen()`` failed with ``failed to map segment``
       after.
   * - 1
     - ``[block-demo] FAIL: evil.so loaded (gate did not fire)``. The
       constructor line and
       ``[victim] FAIL: dlopen succeeded, evil.so constructor ran``
       come before it.
   * - 2
     - A file is missing, ``/run/lota/lota.sock`` is not a socket, or the
       victim ended with another status, a signal included:
       ``[block-demo] INCONCLUSIVE: victim exit=<status>``.

block_victim
============

.. code-block:: console

   $ build/examples/block_victim [PATH | --sleep]

``PATH`` is the library to load, default ``/tmp/evil.so``. The victim
first maps one page of it ``PROT_READ | PROT_EXEC`` while unprotected,
so a file that cannot be mapped executable at all, such as one on a
``noexec`` mount, is not taken for a refusal. It then connects with
``lota_connect()``, calls ``lota_protect_self()`` and loads the library
with ``dlopen(RTLD_NOW)``.

It exits 0 when ``dlopen()`` fails with ``failed to map segment``, 1 when
the library loads, and 2 when the first mapping, the connection,
``lota_protect_self()`` or ``dlopen()`` fails for another reason, with
a line on stderr.

``--sleep`` protects the process and holds it until stdin closes, then
exits 0. ``tests/integration/test_bpf_gates.sh`` uses it as the target of
its ``ptrace`` and signal stages, and runs ``run.sh`` for its
``mmap_file`` stage.
