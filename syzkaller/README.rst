Syzkaller for LOTA
==================

Coverage-guided kernel fuzzing of the LOTA BPF LSM layer with
`google/syzkaller <https://github.com/google/syzkaller>`__.

What this fuzzes, and what it does not
--------------------------------------

syzkaller drives the **kernel** through syscalls and measures **kernel**
coverage (KCOV), catching kernel panics and KASAN reports. The part of LOTA
that runs in the kernel is the set of BPF LSM programs in ``lota_lsm.bpf.o``.
So syzkaller's job here is to hammer those hooks with adversarial syscall
sequences and prove they never corrupt kernel memory or wedge the kernel.

It does **not** test the agent's userspace parsers (IPC, config, TLS, wire
formats). Those are C in a normal process; a crash there is a SIGSEGV syzkaller
never sees. They are covered by the libFuzzer + AddressSanitizer harnesses
(``make fuzz-all``) and the ASan/valgrind CI jobs instead. Do not expect
syzkaller to find agent userspace bugs.

Why the BPF LSM must be made live first
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A LOTA hook only runs when the BPF program is **loaded, attached, and the
config map says enforce**. If nothing attaches the programs, the guest is a
bare kernel and syzkaller re-tests upstream Linux while touching zero LOTA code
-- it burns power and finds nothing. This was the gap in the previous
configuration: it pointed syscalls at an agent IPC socket that did not exist in
the image and never attached a single hook.

The fix is ``lota_bpf_fuzz`` (built from ``lota_bpf_fuzz.c``): a small bring-up
harness that loads the **production** ``lota_lsm.bpf.o``, populates the config
map into enforce with every strict flag on, registers protected PIDs, attaches
every LSM hook, and idles. It runs inside the guest at boot. It is not a second
agent and bypasses no agent security path -- it just makes the same kernel
programs the agent ships live so the fuzzer can reach them.

Hook coverage matrix
--------------------

With the harness live and the syscalls below enabled, syz-executor reaches
every stage of the kernel surface:

+--------------------------------------+--------------------------------------+
| LSM hook                             | Driven by syscalls                   |
| (``src/bpf/lota_lsm.bpf.c``)         |                                      |
+======================================+======================================+
| ``bprm_check_security``              | ``execve``, ``execveat``             |
+--------------------------------------+--------------------------------------+
| ``mmap_file``                        | ``mmap`` (PROT_EXEC of a file fd),   |
|                                      | ``memfd_create``\ +\ ``mmap``        |
+--------------------------------------+--------------------------------------+
| ``file_mprotect``                    | ``mprotect`` (to PROT_EXEC)          |
+--------------------------------------+--------------------------------------+
| ``kernel_read_file``                 | ``finit_module``                     |
+--------------------------------------+--------------------------------------+
| ``kernel_load_data``                 | ``init_module``, ``kexec_load``      |
+--------------------------------------+--------------------------------------+
| ``ptrace_access_check``              | ``ptrace(PTRACE_ATTACH/SEIZE)``      |
+--------------------------------------+--------------------------------------+
| ``task_kill``                        | ``kill``, ``tgkill``,                |
|                                      | ``pidfd_send_signal``                |
+--------------------------------------+--------------------------------------+
| ``task_fix_setuid``                  | ``setuid``, ``setreuid``,            |
|                                      | ``setresuid``                        |
+--------------------------------------+--------------------------------------+
| ``sb_mount``                         | ``mount``, ``move_mount``,           |
|                                      | ``fsmount``                          |
+--------------------------------------+--------------------------------------+
| ``bpf`` / ``bpf_map``                | ``bpf()`` (all commands)             |
+--------------------------------------+--------------------------------------+
| ``task_free``                        | process exit (exercised as executors |
|                                      | die)                                 |
+--------------------------------------+--------------------------------------+

The harness keeps four idle **protected** victim processes alive so the
PID-scoped gates (``ptrace_access_check``, ``task_kill``, ``file_mprotect``,
``mmap_file``) can take their enforcement branch, not only their lookup path.
The global gates (``bpf``, module load, mount, setuid) fire on the executor
directly.

Prerequisites
-------------

1. **Go toolchain** 1.18+
2. **C compiler**: gcc and clang
3. **QEMU**: ``qemu-system-x86_64``
4. **Linux kernel source** built with KASAN, KCOV, and BPF LSM.

Setup
-----

.. _1-build-syzkaller:

1. Build syzkaller
~~~~~~~~~~~~~~~~~~

.. code:: bash

   git clone https://github.com/google/syzkaller syzkaller/repo
   cp syzkaller/lota.txt syzkaller/repo/sys/linux/lota.txt   # MODE B only, see below
   cd syzkaller/repo
   make

.. _2-compile-the-kernel:

2. Compile the kernel
~~~~~~~~~~~~~~~~~~~~~

``BPF_LSM`` is mandatory -- without it the harness cannot attach and the whole
exercise is pointless. ``FUNCTION_TRACER``/``DYNAMIC_FTRACE`` are also
mandatory on x86 because BPF trampolines patch the function-entry NOPs; without
them LSM attach can fail with ``-EBUSY``. KASAN + KCOV give the bug detection
and coverage feedback.

.. code:: bash

   wget https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.18.10.tar.xz
   tar xJf linux-6.18.10.tar.xz
   cd linux-6.18.10
   make defconfig
   ./scripts/config \
       -e KASAN -e KASAN_GENERIC -e KASAN_INLINE \
       -e KCOV -e KCOV_INSTRUMENT_ALL -e KCOV_ENABLE_COMPARISONS \
       -e DEBUG_FS -e DEBUG_INFO_DWARF4 -e DEBUG_INFO_BTF \
       -e KALLSYMS -e KALLSYMS_ALL \
       -e NAMESPACES -e UTS_NS -e IPC_NS -e PID_NS -e NET_NS -e USER_NS \
       -e CGROUPS \
       -e BPF_SYSCALL -e BPF_JIT -e BPF_LSM -e DEBUG_INFO_BTF \
       -e FUNCTION_TRACER -e DYNAMIC_FTRACE \
       -e MODULES -e MODULE_UNLOAD \
       -e VIRTIO_NET -e VIRTIO_BLK -e VIRTIO_PCI -e VIRTIO_CONSOLE
   make olddefconfig
   make -j"$(nproc)"

.. _3-build-the-lota-artefacts-the-guest-needs:

3. Build the LOTA artefacts the guest needs
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

From the repo root, on a host with libbpf >= 1.0:

.. code:: bash

   make bpf                     # build/lota_lsm.bpf.o
   make syzkaller-fuzz-loader   # build/lota_bpf_fuzz

.. _4-create-the-image-and-bake-lota-in:

4. Create the image and bake LOTA in
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code:: bash

   wget https://raw.githubusercontent.com/google/syzkaller/master/tools/create-image.sh -O create-image.sh
   chmod +x create-image.sh
   ./create-image.sh --distribution bookworm

Mount ``bookworm.img`` and install the harness so it starts at boot:

.. code:: bash

   sudo mount -o loop bookworm.img /mnt
   sudo install -D build/lota_bpf_fuzz        /mnt/usr/local/bin/lota_bpf_fuzz
   sudo install -D build/lota_lsm.bpf.o       /mnt/usr/lib/lota/lota_lsm.bpf.o
   sudo install -D syzkaller/lota-bpf-fuzz.service.example \
       /mnt/etc/systemd/system/lota-bpf-fuzz.service
   sudo ln -sf /etc/systemd/system/lota-bpf-fuzz.service \
       /mnt/etc/systemd/system/sysinit.target.wants/lota-bpf-fuzz.service
   sudo umount /mnt

Every booted VM now attaches the LOTA LSM before fuzzing starts. Verify once by
hand: boot the image, ``journalctl -u lota-bpf-fuzz`` must show
``N hooks attached``.

.. _5-configure:

5. Configure
~~~~~~~~~~~~

Edit ``lota.cfg`` (start from ``lota.cfg.example``) and set ``kernel_obj``,
``image``, ``sshkey``, ``syzkaller``, and the ``kernel`` bzImage path. Keep
``sandbox: "none"`` (the harness and gates assume the initial namespaces) and
the ``lsm=...,bpf`` cmdline. The ``enable_syscalls`` list already covers the
hook-coverage matrix above.

Running
-------

.. code:: bash

   cd syzkaller/repo
   bin/syz-manager -config ../lota.cfg

Dashboard at ``http://<host-lan-ip>:56741``; ``lota.cfg.example`` binds
``0.0.0.0:56741`` so the UI is reachable from another machine on the same LAN.
Coverage should climb into the LOTA hook functions
(``lota_bprm_check_security``, ``lota_task_kill``, ...); if it does not, the
harness is not attaching -- check the guest journal.

``syz-manager`` sends crash mail through a ``mailx`` binary when
``email_addrs`` is set. On hosts that use ``msmtp`` directly, install the
wrapper and start the manager with that directory in ``PATH``:

.. code:: bash

   install -D -m 0755 syzkaller/mailx-msmtp-wrapper.sh /var/tmp/lota-syz/bin/mailx
   PATH=/var/tmp/lota-syz/bin:$PATH bin/syz-manager -config ../lota.cfg

Leaving it running (host systemd)
---------------------------------

``lota-fuzz.service.example`` runs syz-manager continuously on the **host**
(distinct from the guest ``lota-bpf-fuzz.service``). Adjust paths/user:

.. code:: bash

   sudo cp syzkaller/lota-fuzz.service.example /etc/systemd/system/lota-fuzz.service
   sudo systemctl daemon-reload
   sudo systemctl enable --now lota-fuzz
   journalctl -u lota-fuzz -f

MODE B: fuzzing the agent IPC parser (optional)
-----------------------------------------------

``lota.txt`` describes the LOTA IPC wire protocol for fuzzing ``ipc.c``. This
only does something if the **real agent** is running in the guest and listening
on ``/run/lota/lota.sock``; the bring-up harness does not open that socket.
Because an agent crash is a userspace SIGSEGV that syzkaller cannot observe,
this mode mainly drives the agent to surface kernel-side effects, and is
secondary to the libFuzzer IPC harness (``make fuzz-agent``). Enable it only
when you have provisioned the full agent (TPM + attestation) in the image.
