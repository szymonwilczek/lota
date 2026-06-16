.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

Scenario: BPF LSM blocks an unauthorised library load
=====================================================

This walk-through shows the LOTA agent's runtime enforcement layer catching an
unauthorised shared object before the kernel maps it into a game process. The
block happens at the ``security_mmap_file`` LSM hook in
```src/bpf/lota_lsm.bpf.c`` <../../../src/bpf/lota_lsm.bpf.c>`__ and is emitted
as a structured event on the agent's journal and the BPF ring buffer.

``security_mmap_file`` and the matching ``security_file_mprotect`` gate are
scoped to opted-in tasks tracked in the ``protected_pids`` BPF map. A process
that has not been registered (via ``LOTA_IPC_CMD_PROTECT_PID`` or the
``--protect-pid`` / ``protect_pid =`` CLI/config knobs) bypasses the verdict
and is only logged. The scope keeps ``strict_mmap = enforce`` host-safe even
when the trust set is empty, while still catching every dlopen / LD_PRELOAD /
mprotect(PROT_EXEC) attempt inside the game process.

Unlike the ``agent-down.rst`` scenario this one needs the **full agent**, not
``--test-ipc``. ``--test-ipc`` is the IPC bridge for the attestation token; the
LSM gates run only when the agent loads its BPF object and attaches the LSM
programs at startup.

Prerequisites
-------------

- Linux kernel with ``CONFIG_BPF_LSM=y`` and ``bpf`` listed in
  ``/sys/kernel/security/lsm``. Fedora 44's default kernel meets this; verify
  with ``cat /sys/kernel/security/lsm``.
- The agent is built with the BPF object available (``make all`` produces
  ``build/agent/lota_lsm.bpf.o`` or ``/usr/lib/lota/lota_lsm.bpf.o`` after
  ``sudo make install``).
- A throwaway "evil" shared object the operator deliberately builds outside the
  trust set. I've used a one-file no-op .so whose constructor only prints to
  stderr so the scenario does not actually load anything dangerous.

Build the dummy:

.. code:: sh

   cat > /tmp/evil.c <<'EOF'
   #include <stdio.h>
   __attribute__((constructor)) static void evil_init(void)
   {
       fprintf(stderr, "evil.so: loaded into pid %d\n", (int)getpid());
   }
   EOF
   gcc -shared -fPIC -o /tmp/evil.so /tmp/evil.c

Walk-through
------------

Terminal 1: start the agent in enforce mode
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code:: sh

   sudo systemctl stop lota-agent.socket lota-agent.service
   sudo env XDG_RUNTIME_DIR=/run/user/"$(id -u)" \
       /usr/bin/lota-agent --mode enforce --block-anon-exec

Watch the banner. A healthy startup announces both IPC listeners, loads the BPF
object, and attaches the LSM programs:

::

   IPC listening on /run/lota/lota.sock
   IPC extra listener on /run/user/1000/lota/lota.sock
   BPF programs attached: 11
   LSM mode: enforce

The gate is armed but has nothing to guard until at least one process opts in.
Two paths feed the protected_pids map:

- **Game-side auto-register.** ``liblota_wine_hook.so`` calls
  ``lota_protect_self()`` on its first successful connect, so any CS2 / Proton
  launch wired through ``lota-proton-hook`` registers itself without operator
  intervention. This is the production path; nothing else needs to happen on
  the agent CLI.
- **Manual register.** For out-of-game reproductions, or for a binary that does
  not link the hook, pass ``--protect-pid <pid>`` to the agent at startup. The
  PID must already exist when the agent attaches its BPF programs.

Terminal 2: follow the kernel-side block events
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code:: sh

   sudo journalctl -fu lota-agent | grep -E "BLOCK|mmap|exec_mmap"

This stays quiet until something trips a policy gate.

Terminal 3: try the unauthorised preload from a CS2 launch
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Set CS2's Steam launch options to include the operator's evil library next to
the LOTA hook:

::

   PRESSURE_VESSEL_FILESYSTEMS_RW=/run/user/1000/lota:/tmp \
   LOTA_HOOK_SOCKET=/run/user/1000/lota/lota.sock \
   LOTA_HOOK_LOG_LEVEL=info \
   LD_PRELOAD=/tmp/evil.so \
   lota-proton-hook %command%

The ``:`` separator in ``PRESSURE_VESSEL_FILESYSTEMS_RW`` requests two
bind-mounts: the LOTA socket directory and ``/tmp`` so the evil library is
reachable inside the container.

Launch CS2.

What the operator observes
~~~~~~~~~~~~~~~~~~~~~~~~~~

- ``evil.so: loaded into pid <N>`` does **not** appear in Steam's
  ``console-linux.txt``. The kernel returned EPERM from ``mmap(PROT_EXEC)``
  before the constructor ran.

- Terminal 2 shows a structured event:

  ::

     lota-agent: BLOCK exec_mmap pid=<cs2-pid> comm=cs2
         path=/tmp/evil.so reason=trust-set-miss

- ``verify-attested.sh`` in another terminal stays at ``TRUSTED``: the LOTA
  hook itself is in the trust set, the agent stays up, attestation is
  unaffected.

Reproducing the block without launching CS2
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A self-contained out-of-game reproduction lives under
```examples/block-demo/`` <../../block-demo/>`__ and is the path
``tests/integration/test_bpf_gates.sh`` exercises in CI. It builds a tiny
victim that calls ``lota_protect_self()`` and then asks the loader to
``dlopen()`` a dummy "evil" .so, asserting the kernel rejected the load. Reach
for that demo whenever you want to verify the gate without bringing up the full
CS2 launch chain.

The same gate fires for any process registered in ``protected_pids``. Reproduce
out-of-game by registering the shell that runs the LD_PRELOAD victim and then
preloading the evil library inside it:

.. code:: sh

   # terminal B: open a fresh shell, capture its PID
   echo "victim pid: $$"

   # terminal A: stop the previously launched agent, restart with
   # --protect-pid pinned to the victim shell PID printed above
   sudo env XDG_RUNTIME_DIR=/run/user/"$(id -u)" \
       /usr/bin/lota-agent --mode enforce --block-anon-exec \
       --protect-pid <victim-pid>

   # back in terminal B, try the LD_PRELOAD load
   LD_PRELOAD=/tmp/evil.so /usr/bin/cat /etc/os-release

``cat`` exits with ``error while loading shared libraries`` plus an EPERM trace
in the journal. A second shell that never registered its PID can run
``LD_PRELOAD=/tmp/evil.so cat`` unaffected -- the gate is scoped to the
opted-in set on purpose, so a single agent can guard the game without breaking
the rest of the host. The cross-process threat surface (an external aimbot
reading ``/proc/<game>/mem``) is covered by the ptrace and task_kill hooks in
the same BPF object, both of which already scope by ``is_protected_task()`` and
reject untrusted readers regardless of whether the attacker is themselves
registered.

What this proves
----------------

- The LSM hook is exercised end-to-end by a real PROT_EXEC mmap attempt rather
  than a synthetic unit test.
- The block is operator-visible in two independent places: the game's own
  stderr (the constructor never ran) and the agent journal (the BPF program
  emitted the structured event).
- The attestation surface (``lota-status`` / ``lota-token.bin``) is orthogonal
  to the runtime block. A game that crashed on the block would still have a
  valid attested status at the moment of the crash; an integrator can record
  both signals independently.

Tear-down
---------

.. code:: sh

   rm /tmp/evil.so
   # remove LD_PRELOAD=/tmp/evil.so from CS2 launch options
   sudo systemctl start lota-agent.socket
