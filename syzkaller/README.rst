.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

==================
Syzkaller for LOTA
==================

Coverage-guided kernel fuzzing of the LOTA BPF LSM with
`syzkaller <https://github.com/google/syzkaller>`__.

What this fuzzes
================

syzkaller drives the kernel through system calls, follows kernel coverage
with KCOV and reports panics and KASAN findings. The part of LOTA in the
kernel is the set of BPF LSM programs in ``lota_lsm.bpf.o``, so the
campaign runs system call sequences through those hooks.

It does not test the agent's user-space parsers: a crash there is a
SIGSEGV in a normal process, which syzkaller does not see. The libFuzzer
harnesses cover them (``Documentation/dev-tools/fuzzing.rst``).

The bring-up harness
====================

The hooks run only while the programs are loaded, attached and configured.
``lota_bpf_fuzz`` (``lota_bpf_fuzz.c``, built by ``make
syzkaller-fuzz-loader``) does that inside the guest at boot:

1. forks four idle victim processes;
2. loads the object named by its first argument, by default
   ``/usr/lib/lota/lota_lsm.bpf.o``;
3. sets the mode to enforce and turns on ``block_ptrace`` and
   ``lock_bpf``;
4. adds itself, the victims and any further PIDs given on the command line
   to ``protected_pids``;
5. attaches every program in the object, the LSM programs and the
   ``tp_btf``, ``fentry`` and ``fexit`` programs alike, prints
   ``lota-bpf-fuzz: N hooks attached, M victims protected; victim pids: ...``
   and ``ready for syz-executor``, and waits for a signal. N counts every
   attached program.

The map writes come before the attach: once the ``bpf`` and ``bpf_map``
hooks are live they refuse writes to LOTA's maps from any task but the
agent. A program that fails to attach is reported and skipped. When none
attaches, the harness exits with
``no LSM programs attached (need lsm=...,bpf)``. It also exits when the
object does not open or load, when ``lota_config`` or ``protected_pids``
is missing from it, and on a PID argument that is not a decimal number
from 1 to 4294967295.

``strict_mmap``, ``strict_exec``, ``strict_modules`` and
``block_anon_exec`` stay off. With no trusted libraries and no fs-verity
allowlist each of them refuses every exec or executable mapping on the
system, ``sshd`` and ``syz-executor`` included, and the manager loses the
guest. ``block_ptrace`` applies only to protected targets and ``lock_bpf``
only to LOTA's maps. Every hook still runs its mode and map lookups on
each matching call.

The harness does not touch the agent, the TPM or the IPC socket.

Hook coverage matrix
--------------------

Every LSM program the harness attaches has a row naming the
``lota.cfg.example`` ``enable_syscalls`` entries that reach it, as
``make check-syzkaller-matrix`` enforces:

+------------------------------+------------------------------------------------------+
| LSM program                  | Driven by (``enable_syscalls`` entries)              |
| (``src/bpf/lota_lsm.bpf.c``) |                                                      |
+==============================+======================================================+
| ``bprm_check_security``      | ``execve``, ``execveat``                             |
+------------------------------+------------------------------------------------------+
| ``bprm_committed_creds``     | ``execve``, ``execveat``                             |
+------------------------------+------------------------------------------------------+
| ``mmap_file``                | ``mmap`` (PROT_EXEC of a file fd), ``memfd_create``  |
|                              | then ``mmap``; every exec maps its image             |
+------------------------------+------------------------------------------------------+
| ``file_mprotect``            | ``mprotect`` (to PROT_EXEC)                          |
+------------------------------+------------------------------------------------------+
| ``file_open``                | ``openat``; ``openat$lota_mem``,                     |
|                              | ``openat$lota_kmem`` and ``openat$lota_port`` take   |
|                              | the refusal branch                                   |
+------------------------------+------------------------------------------------------+
| ``file_post_open``           | ``openat``; hashes only opens the agent asked about  |
+------------------------------+------------------------------------------------------+
| ``path_truncate``            | ``truncate``                                         |
+------------------------------+------------------------------------------------------+
| ``kernel_read_file``         | ``finit_module`` on a file from ``openat$binfmt``    |
+------------------------------+------------------------------------------------------+
| ``kernel_load_data``         | ``init_module``, ``kexec_load``                      |
+------------------------------+------------------------------------------------------+
| ``ptrace_access_check``      | ``ptrace$setopts`` (PTRACE_SEIZE)                    |
+------------------------------+------------------------------------------------------+
| ``task_kill``                | ``kill``, ``tgkill``, ``pidfd_send_signal``          |
+------------------------------+------------------------------------------------------+
| ``file_send_sigiotask``      | ``fcntl$setown``, ``fcntl$setsig``                   |
+------------------------------+------------------------------------------------------+
| ``task_setrlimit``           | ``prlimit64``, ``setrlimit``                         |
+------------------------------+------------------------------------------------------+
| ``task_fix_setuid``          | ``setuid``, ``setreuid``, ``setresuid``              |
+------------------------------+------------------------------------------------------+
| ``sb_mount``                 | ``mount``, including MS_BIND and MS_MOVE             |
+------------------------------+------------------------------------------------------+
| ``move_mount``               | ``move_mount`` of a tree from ``open_tree``, or of a |
|                              | mount from ``fsopen``,                               |
|                              | ``fsconfig$FSCONFIG_CMD_CREATE`` and ``fsmount``     |
+------------------------------+------------------------------------------------------+
| ``bpf``                      | every bpf() command, such as ``bpf$MAP_CREATE``,     |
|                              | ``bpf$MAP_LOOKUP_ELEM`` and ``bpf$OBJ_GET_MAP``      |
+------------------------------+------------------------------------------------------+
| ``bpf_map``                  | ``bpf$MAP_CREATE``, ``bpf$OBJ_GET_MAP``: each hands  |
|                              | out a map fd                                         |
+------------------------------+------------------------------------------------------+
| ``socket_post_create``       | ``socket$unix``                                      |
+------------------------------+------------------------------------------------------+
| ``socket_bind``              | ``bind$unix``                                        |
+------------------------------+------------------------------------------------------+
| ``socket_listen``            | ``listen``                                           |
+------------------------------+------------------------------------------------------+
| ``unix_stream_connect``      | ``connect$unix``                                     |
+------------------------------+------------------------------------------------------+
| ``unix_may_send``            | ``sendmsg$unix``, ``sendto``                         |
+------------------------------+------------------------------------------------------+
| ``task_alloc``               | ``clone``, ``clone3``; every executor fork           |
+------------------------------+------------------------------------------------------+
| ``task_free``                | process exit (exercised as executors die)            |
+------------------------------+------------------------------------------------------+

Four victims are protected so that ``ptrace_access_check`` and
``task_kill``, which judge their target, take their refusal branch.

``file_open`` refuses ``/dev/mem``, ``/dev/kmem`` (where the kernel still
has it) and ``/dev/port`` in every mode. The ``openat$lota_*`` calls in
``lota_hooks.txt`` open them, which the generic ``openat`` rarely does.
With ``strict_mmap`` off, ``file_open``, ``sb_mount`` and ``move_mount``
do not reach their trusted-file branches, and ``file_mprotect`` and
``mmap_file`` do not reach the branch that judges a protected caller.

Prerequisites
=============

* a Go toolchain new enough for syzkaller's ``go.mod``,
* gcc and clang,
* ``qemu-system-x86_64``,
* a Linux source tree to build with KASAN, KCOV and the BPF LSM,
* libbpf 1.0 or later for the harness.

Setup
=====

Build syzkaller
---------------

syzkaller compiles the system call descriptions under ``sys/linux`` into
its binaries, so copy LOTA's in before ``make``:

.. code-block:: console

   $ git clone https://github.com/google/syzkaller syzkaller/repo
   $ cp syzkaller/lota_hooks.txt syzkaller/lota.txt syzkaller/repo/sys/linux/
   $ make -C syzkaller/repo

Build the kernel
----------------

``BPF_LSM`` is required, since without it nothing attaches.
``FUNCTION_TRACER`` and ``DYNAMIC_FTRACE`` are required on x86, where BPF
trampolines patch the function entry. KASAN and KCOV provide the bug
detection and the coverage feedback:

.. code-block:: console

   $ cd <linux source tree>
   $ make defconfig
   $ ./scripts/config \
   >     -e KASAN -e KASAN_GENERIC -e KASAN_INLINE \
   >     -e KCOV -e KCOV_INSTRUMENT_ALL -e KCOV_ENABLE_COMPARISONS \
   >     -e DEBUG_FS -e DEBUG_INFO_DWARF4 -e DEBUG_INFO_BTF \
   >     -e KALLSYMS -e KALLSYMS_ALL \
   >     -e NAMESPACES -e UTS_NS -e IPC_NS -e PID_NS -e NET_NS -e USER_NS \
   >     -e CGROUPS \
   >     -e BPF_SYSCALL -e BPF_JIT -e BPF_LSM \
   >     -e FUNCTION_TRACER -e DYNAMIC_FTRACE \
   >     -e MODULES -e MODULE_UNLOAD \
   >     -e VIRTIO_NET -e VIRTIO_BLK -e VIRTIO_PCI -e VIRTIO_CONSOLE
   $ make olddefconfig
   $ make -j"$(nproc)"

Build the LOTA artifacts
------------------------

From the repository root:

.. code-block:: console

   $ make bpf                     # build/lota_lsm.bpf.o
   $ make syzkaller-fuzz-loader   # build/lota_bpf_fuzz

Create the image
----------------

``lota.cfg.example`` names a Debian trixie image made with syzkaller's
``tools/create-image.sh``:

.. code-block:: console

   $ syzkaller/repo/tools/create-image.sh --distribution trixie

Install the harness into the image so that it starts at boot:

.. code-block:: console

   # mount -o loop trixie.img /mnt
   # install -D build/lota_bpf_fuzz /mnt/usr/local/bin/lota_bpf_fuzz
   # install -D build/lota_lsm.bpf.o /mnt/usr/lib/lota/lota_lsm.bpf.o
   # install -D syzkaller/lota-bpf-fuzz.service.example \
   >     /mnt/etc/systemd/system/lota-bpf-fuzz.service
   # mkdir -p /mnt/etc/systemd/system/sysinit.target.wants
   # ln -sf /etc/systemd/system/lota-bpf-fuzz.service \
   >     /mnt/etc/systemd/system/sysinit.target.wants/lota-bpf-fuzz.service
   # umount /mnt

The unit runs the harness before ``sysinit.target`` and restarts it when
it exits. Boot the image once by hand: ``journalctl -u lota-bpf-fuzz``
must show ``N hooks attached``.

Configure
---------

Copy ``lota.cfg.example`` to ``lota.cfg`` and set ``kernel_obj``,
``image``, ``sshkey``, ``syzkaller`` and the ``vm.kernel`` path, and
``email_addrs`` to your own address or an empty list. Keep
``"sandbox": "none"``, since the harness and the hooks act in the initial
namespaces, and keep ``bpf`` in the ``lsm=`` list of ``vm.cmdline``.

``enable_syscalls`` names calls from both description files. A call that
``syz-manager`` lists as disabled at start-up does not run; none of the
calls in the matrix above may be among them.

Running
=======

.. code-block:: console

   $ cd syzkaller/repo
   $ bin/syz-manager -config ../lota.cfg

The example binds the dashboard to ``0.0.0.0:56741``, so it is reachable
from other machines on the network. Coverage should reach the LOTA hook
functions (``lota_bprm_check_security``, ``lota_task_kill``, ...); when it
does not, the harness did not attach, and the guest journal says why.

``syz-manager`` keeps each crash, with a reproducer when it can derive
one, under ``crashes/`` in its work directory.

``syz-manager`` mails crashes through ``mailx`` when ``email_addrs`` is
set. On a host that has ``msmtp`` instead, put the wrapper first in
``PATH``:

.. code-block:: console

   $ install -D -m 0755 syzkaller/mailx-msmtp-wrapper.sh <dir>/mailx
   $ PATH=<dir>:$PATH bin/syz-manager -config ../lota.cfg

Running as a host service
-------------------------

``lota-fuzz.service.example`` runs ``syz-manager`` on the host as user
``syz`` from ``/srv/lota/syzkaller`` and restarts it when it exits. Adjust
the user and paths, then:

.. code-block:: console

   # cp syzkaller/lota-fuzz.service.example \
   >     /etc/systemd/system/lota-fuzz.service
   # systemctl daemon-reload
   # systemctl enable --now lota-fuzz
   # journalctl -u lota-fuzz -f

The agent's IPC protocol
========================

``lota.txt`` describes the agent's IPC protocol on
``/run/lota/lota.sock``. The harness does not open that socket, so the
``$lota`` calls fail to connect unless a provisioned agent runs in the
guest. A crash of the agent is a user-space fault syzkaller does not see;
these calls exercise what the agent does in the kernel on their behalf.
The libFuzzer harness ``make fuzz-agent`` covers the parser itself.
