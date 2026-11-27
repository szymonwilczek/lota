.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

=========
lib-block
=========

A library the agent does not allow is preloaded into Counter-Strike 2.
The processes ``lota-protect`` put in the protected set are refused its
executable mapping before its constructor runs; the processes that start
the title before them are not protected and load it.

The refusal comes from the ``mmap_file`` program of the agent (see
`the BPF programs <../../../Documentation/bpf/index.rst>`_). It applies to
a process of the protected set while the agent is in ``enforce`` mode
with ``strict_mmap`` on: an executable mapping that is writable, or of a
file neither an ``allow_verity`` nor a ``trust_lib`` entry covers, is
refused. The ``--test-*`` modes of the agent load no BPF, so the scenario
needs the daemon.

The agent
=========

``strict_mmap`` and ``trust_lib`` take effect on a reload, so the daemon
is not restarted. In ``/etc/lota/lota.conf`` (see
`configuration <../../../Documentation/agent/configuration.rst>`_):

.. code-block:: text

   mode = enforce
   strict_mmap = true

.. code-block:: console

   $ sudo systemctl reload lota-agent lota-attest

Every object a protected process maps executable needs an entry: the
loader and the libraries of each program the title runs, the hook itself,
Proton, Wine and the title. ``trust_lib`` takes at most 64 entries, on a
reload; ``allow_verity`` at most 256, at the next start. An object
without one is refused like the library below, and the hook logs each
refusal of a ``dlopen()``, as in
`The cost of protection <../README.rst>`_. With ``strict_mmap`` back to
false and a reload, the refusals stop.

The library
===========

A library whose constructor only prints, so a load that gets through is
harmless and visible:

.. code-block:: console

   $ mkdir -p ~/lota-lib-block && cd ~/lota-lib-block
   $ cat > evil.c <<'EOF'
   #include <stdio.h>
   #include <unistd.h>

   __attribute__((constructor)) static void evil_init(void)
   {
           fprintf(stderr, "evil.so: loaded into pid %d\n", (int)getpid());
   }
   EOF
   $ cc -shared -fPIC -o evil.so evil.c

``make examples`` builds the same library as ``build/examples/evil.so``
(see `block-demo <../../block-demo/README.rst>`__).

Running it
==========

Set the launch option of CS2 to:

.. code-block:: text

   PRESSURE_VESSEL_FILESYSTEMS_RW=<home>/lota-lib-block
       LD_PRELOAD=<home>/lota-lib-block/evil.so
       LOTA_HOOK_LOG_LEVEL=info lota-proton-hook %command%

on one line, with ``<home>`` the home directory. ``lota-proton-hook``
keeps both variables and adds to them: the hook goes before ``evil.so``
in ``LD_PRELOAD``, and the token and socket directories after the
library directory in ``PRESSURE_VESSEL_FILESYSTEMS_RW``, which shares it
with the container.

In a terminal, follow the refusals the agent logs:

.. code-block:: console

   $ sudo journalctl -f -t lota-agent | grep MMAP_BLOCKED

Launch CS2.

What it shows
=============

``lota-proton-hook``, ``lota-protect`` and the processes that start them
are not in the protected set, so each prints
``evil.so: loaded into pid <pid>``.
``lota-protect`` then puts itself in the set and executes the command;
from there on, every process of the title is protected and is refused
the library. The loader reports that it cannot preload it, the
constructor does not run, and the agent logs, for each such process:

.. code-block:: text

   <prefix> [<ns>] MMAP_BLOCKED <comm>: <file> (pid=<pid>, uid=<uid>)

A refused ``LD_PRELOAD`` is not a ``dlopen()``, so the hook does not
report it and the status file carries no ``LOTA_REFUSED_OBJECT`` for it.
A refusal does not change the status of the host. ``strict_mmap`` in
effect sets ``LOTA_FLAG_STRICT_MMAP`` in its flags, which ``LOTA_FLAGS``
of the status file carries.

Without CS2
===========

`block-demo <../../block-demo/README.rst>`__ makes the same refusal with
one process, which protects itself after its libraries are mapped and
then calls ``dlopen()`` on ``evil.so``. It needs no entries in the
configuration and is the check
``tests/integration/test_bpf_gates.sh`` runs.

Afterwards
==========

Remove ``LD_PRELOAD`` and the library directory from the launch option,
and set ``strict_mmap`` back with a reload if it was off before.
