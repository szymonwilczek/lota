====================
How the fuzzers work
====================

* **Go fuzzing** is native (``func FuzzXxx(f *testing.F)``). Targets cover the
  bytes that arrive from an untrusted peer: attestation tokens, TPM
  quote/attest blobs, event logs, certificates, signed policies, and the
  enrollment wire protocol. Each target seeds from its own encoder and asserts
  the real contract.
* **C fuzzers** are libFuzzer harnesses under ``fuzz/``, one ``fuzz_<name>.c``
  per target, built by ``make fuzz-*`` (or all at once with ``make fuzz-all``);
  they link the agent sources under ``src/agent/`` that they exercise.
* **Go fuzz functions stay in-package** -- Go cannot reach unexported code from
  another directory -- so each lives in a ``fuzz_<name>_test.go`` file beside
  the code it covers, sharing the same ``fuzz_`` prefix as the C harnesses.
* **Syzkaller** loads the production BPF LSM object and attaches every hook in
  enforce mode inside a guest, so ``syz-executor``'s syscalls actually traverse
  the LOTA kernel surface (MODE A). It runs against ``lota-next``.
