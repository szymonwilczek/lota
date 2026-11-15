.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

=======
Fuzzing
=======

LOTA has three kinds of fuzz target: Go fuzz functions beside the code they
cover, libFuzzer harnesses for the C parsers under ``fuzz/``, and oracles
that check the BPF LSM's decision helpers against an independent reference.
Kernel fuzzing of the live BPF LSM uses syzkaller and is described in
:ghsrc:`syzkaller/README.rst`.

Go targets
==========

Each Go fuzz function is a ``func FuzzXxx(f *testing.F)`` in a
``fuzz_<name>_test.go`` file in the package it covers, since a test in
another directory cannot reach unexported code.

.. list-table::
   :header-rows: 1
   :widths: 28 72

   * - Package
     - Targets
   * - ``src/verifier/verify``
     - ``FuzzParseEventLog``, ``FuzzReplayEventLog``, ``FuzzParsePCRPolicy``,
       ``FuzzParsePolicyPublicKeyPEM``, ``FuzzParseRSAPublicKey``,
       ``FuzzParseTPMSAttest``, ``FuzzParseUEFIVariableData``,
       ``FuzzReanchorDecision``, ``FuzzVerifyNonceInAttest``,
       ``FuzzVerifyPCRDigest``, ``FuzzVerifyPolicySignature``,
       ``FuzzVerifyReport``
   * - ``src/verifier/store``
     - ``FuzzDecodeBanCursor``, ``FuzzParseAIKCertificate``,
       ``FuzzParseHardwareID``
   * - ``src/verifier/types``
     - ``FuzzParseReport``
   * - ``src/verifier/server``
     - ``FuzzAPIRequestBody``
   * - ``src/attestca/wire``
     - ``FuzzReadFrame``, ``FuzzDecodeBegin``, ``FuzzDecodeChallenge``,
       ``FuzzDecodeComplete``, ``FuzzDecodeResult``
   * - ``src/attestca/ca``
     - ``FuzzParseEKBundleManifest``, ``FuzzVerifyEKCertificate``
   * - ``src/attestca/credential``
     - ``FuzzValidateAIK``
   * - ``src/attestca/enroll``
     - ``FuzzServiceBegin``
   * - ``src/attestca/server``
     - ``FuzzServerHandle``
   * - ``sdk/server``
     - ``FuzzParseWireHeader``, ``FuzzParseToken``, ``FuzzVerifyToken``,
       ``FuzzVerifyBootEvidence``, ``FuzzParseRSAPublicKeySDK``,
       ``FuzzParseTPMSAttestSDK``

No ``make`` target runs them. Run one from its module::

   $ cd src/verifier
   $ go test -run '^$' -fuzz '^FuzzParseEventLog$' -fuzztime 60s ./verify/

Plain ``go test`` runs every fuzz function once over its seed corpus and
the inputs committed under the package's ``testdata/fuzz/``.

C targets
=========

The harnesses are built with clang and ``-fsanitize=fuzzer,address -g -O1``
on top of the normal ``CFLAGS``. Each ``make`` target writes its binary to
the build directory under the target's name; ``make fuzz-all`` builds them
all.

.. list-table::
   :header-rows: 1
   :widths: 28 72

   * - Target
     - Input
   * - ``fuzz-agent``
     - the agent's IPC request parser (``fuzz/fuzz_ipc.c``), linked with the
       agent objects
   * - ``fuzz-config``
     - the agent configuration parser
   * - ``fuzz-enroll``
     - the decoders for the attestation CA's enrollment replies, and the walk
       over the certificate chain stored in TPM NV
   * - ``fuzz-seal-envelope``
     - the sealed-envelope header parser and its AES-256-GCM core
   * - ``fuzz-tpm-attest``
     - ``TPMS_ATTEST`` unmarshalling of a quote
   * - ``fuzz-tpm-resp``
     - the ``TPM2B`` structures unmarshalled during enrollment and from TPM
       responses
   * - ``fuzz-policy-sign``
     - the Ed25519 verifier for signed policies and BPF objects
   * - ``fuzz-server-sdk``
     - ``lota_server_verify_token()``, the server SDK token verifier
   * - ``fuzz-bench-result``
     - the ``lota-bench`` session file validator
   * - ``fuzz-bench-frames``
     - the ``lota-bench`` MangoHud log reader

Run a target with a corpus directory and libFuzzer options::

   $ make fuzz-config
   $ build/fuzz-config -max_total_time=60 corpus/

BPF decision oracles
====================

The BPF helpers read their inputs from kernel structures and cannot be
linked into a user-space program. The oracles under ``fuzz/bpf_oracle/`` run
the decision logic on scalar inputs and abort when it disagrees with
``reference.h``, which derives the expected verdict from the system headers
instead of the program's own constants. They need only libc; ``make
fuzz-bpf-all`` builds the six of them.

``fuzz-bpf-devt`` and ``fuzz-bpf-event-budget`` include
``include/lota_devt.h`` and ``include/lota_event_budget.h``, the headers
the BPF program includes, unchanged.

``fuzz-bpf-open-flags``, ``fuzz-bpf-kmem-device``,
``fuzz-bpf-inaccessible-exec`` and ``fuzz-bpf-shebang`` run copies, in
``fuzz/bpf_oracle/lota_lsm_logic.h``, of ``is_write_open_flags``,
``is_kernel_mem_device``, ``is_inaccessible_exec_path`` and
``is_shebang_binprm`` from ``src/bpf/lota_lsm.bpf.c``.

``fuzz/bpf_oracle/mirror.lock`` holds a hash of each copied helper's body
and the ``#define`` of each constant the copies use. ``make
check-bpf-mirror`` fails when ``src/bpf/lota_lsm.bpf.c`` no longer matches
the lock, or when a file under ``fuzz/bpf_oracle/`` cites that source by
line number. After changing a helper, update its copy (and
``reference.h`` when the intended verdict changed), run ``make
update-bpf-mirror`` and commit the lock with the change.
``scripts/check-patch`` runs the check when either side changes.

The oracles cover the helpers, not the hooks that call them, and not
helpers that walk live kernel objects; syzkaller covers those.

Leak detection
==============

LeakSanitizer attaches to the process's threads with ptrace before it
scans. Where the attach is refused, by an agent enforcing
``block_ptrace``, seccomp or Yama scope 3, the scan aborts and libFuzzer
records the abort as a crash. Every C target links ``fuzz/lsan_options.c``,
which probes the attach at start-up and, when it is refused, prints
``leak detection is off for this process`` and disables leak detection.
Leaks are caught only on hosts that allow the attach.

Reproducers
===========

Commit a fuzz failure's reproducer in the commit before its fix, so that
commit fails and the fix makes it pass.

Go
  ``go test -fuzz`` writes the failing input to
  ``testdata/fuzz/<FuzzTarget>/`` in the package, and plain ``go test``
  replays it. Commit the file as written.

C
  libFuzzer writes ``crash-<sha1>``, ``leak-<sha1>`` or
  ``timeout-<sha1>`` into its working directory. Copy it to
  ``fuzz/regressions/<make-target>/`` under a name that says what it
  caught, and check that it fails the unfixed target.

  ``make fuzz-regress`` builds every target and runs each against the
  files in its directory, skipping ``*.rst``. Output goes to
  ``regress-<target>.log`` under the build directory's ``fuzz/``, along
  with any new artifacts. A target that still fails prints the tail of
  its log and fails the run. The ``fuzz`` CI job and ``scripts/check-patch``
  run it.

Kernel
  ``syz-manager`` keeps each crash, with a reproducer when it can derive
  one, under ``crashes/`` in its work directory. Nothing in the tree
  replays the BPF programs: report the crash with that reproducer, and have
  the fix carry a test that drives the same hook, such as
  ``tests/integration/test_bpf_gates.sh``.
