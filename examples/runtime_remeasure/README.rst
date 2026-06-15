.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

Runtime re-measurement demo
===========================

   **Trust model note.** The measurement this demo computes runs **inside the
   game process** and is therefore forgeable by an attacker with code in that
   process. It is now **advisory only**: the heartbeat still carries it for
   tamper-evidence, but it no longer gates trust. The **authoritative** runtime
   measurement is taken by the agent from the **kernel side** and bound into
   the TPM-signed token; see *Kernel-side measurement (authoritative)* below.
   This demo remains useful for understanding what a per-object image
   measurement is and why an in-process one is insufficient.

``runtime_remeasure`` is a TPM-free reference for the runtime measurement that
the LOTA anti-cheat heartbeat binds into every beat. The session-start
game-binding hash only pins the main executable **on disk**; nothing in it
reflects the code pages that are actually mapped and running, and it says
nothing about the shared libraries the process loads. This closes that gap by
re-measuring the live image - the main executable plus every loaded shared
object - and binding the digest into the TPM-signed heartbeat nonce, so a
verifier can tell when the running code of any module no longer matches the
registered binaries.

The canonical digest (see ``include/lota_anticheat.h``) measures every
file-backed object, excluding the kernel vDSO. Each object yields a
content-only digest over its executable segments:

::

   object_digest =
     SHA-256("lota-ac-runtime-object:v1\0" || seg_count_LE32 ||
             for each executable (PF_X) PT_LOAD segment, ascending p_vaddr:
                 p_vaddr_LE64 || p_offset_LE64 || p_filesz_LE64 ||
                 segment_bytes)

and the combined image digest folds the objects, keyed by soname (file
basename) and sorted, so neither load order nor library search path matters:

::

   SHA-256("lota-ac-runtime-measure:v2\0" || object_count_LE32 ||
           for each object: soname_len_LE32 || soname_bytes || object_digest)

For position-independent x86-64 code with full RELRO the executable segments
carry no load-time relocations (the GOT/PLT data, not code, is what the loader
mutates), so each live object mapping is byte-identical to its on-disk segment
content. This demo needs no agent, no verifier and no TPM, so it runs
unmodified inside a plain VM.

Build
-----

.. code:: sh

   make BUILD_DIR=/var/tmp/lota-build all
   make BUILD_DIR=/var/tmp/lota-build examples

The binary lands at ``/var/tmp/lota-build/examples/runtime_remeasure``.

Modes
-----

+---------------------------------------+--------------------------------------+
| Invocation                            | What it shows                        |
+=======================================+======================================+
| ``runtime_remeasure``                 | the live mapped image (all loaded    |
|                                       | objects) equals the set measure of   |
|                                       | its on-disk files                    |
+---------------------------------------+--------------------------------------+
| ``runtime_remeasure --list-objects``  | the trusted runtime manifest: one    |
|                                       | object path per line                 |
+---------------------------------------+--------------------------------------+
| ``runtime_remeasure --manifest FILE`` | reproduce the set measure from a     |
|                                       | manifest and compare to the live     |
|                                       | image (verifier side)                |
+---------------------------------------+--------------------------------------+
| ``runtime_remeasure --patch-demo``    | a 1-byte code patch flips an object  |
|                                       | digest (the closed TOCTOU)           |
+---------------------------------------+--------------------------------------+
| ``runtime_remeasure --watch SEC``     | repeated re-measurements of a steady |
|                                       | process stay stable                  |
+---------------------------------------+--------------------------------------+
| ``runtime_remeasure --count N``       | number of ``--watch`` ticks (default |
|                                       | 5)                                   |
+---------------------------------------+--------------------------------------+
| ``runtime_remeasure --exe PATH``      | ELF copied for ``--patch-demo``      |
|                                       | (default ``/proc/self/exe``)         |
+---------------------------------------+--------------------------------------+

The default and ``--manifest`` modes print the digests they computed and a
final ``RESULT:`` line, and exit non-zero on a mismatch (or on drift during
``--watch``), so they are safe to wire into a script.

A quick round-trip - capture the manifest, then verify against it:

.. code:: sh

   runtime_remeasure --list-objects > manifest.txt
   runtime_remeasure --manifest manifest.txt   # RESULT: MATCH

Relationship to the heartbeat
-----------------------------

``runtime_remeasure`` (no flags) is the producer side of runtime re-measurement
in isolation: ``lota_ac_compute_runtime_measure()`` is exactly what
``lota_ac_heartbeat()`` calls every beat. ``--manifest`` shows the verifier
side, ``lota_ac_compute_expected_runtime_measure_set()``, which the demo server
runs over the trusted runtime manifest (captured with
``demo_anticheat --print-runtime-objects``) to obtain the value an honest
producer must report.

Kernel-side measurement (authoritative)
---------------------------------------

The in-process measurement above can be forged: a process can report any digest
about itself. The authoritative measurement is therefore taken by the
**agent**, on the far side of the IPC boundary, and bound under the TPM quote
so the measured process cannot influence it:

1. When a protected process requests a token, the agent enumerates that
   process's file-backed executable mappings from ``/proc/<pid>/maps``
   (kernel-maintained, so the process cannot forge the list) and opens the
   exact backing inode of each through ``/proc/<pid>/map_files/<range>`` (a
   kernel magic symlink, so no path swap can redirect it).
2. For each backing object the agent reads the kernel-computed **fs-verity**
   digest (``FS_IOC_MEASURE_VERITY``). No process memory is hashed; under W^X a
   file-backed executable mapping equals its on-disk file, which the kernel has
   already measured.
3. The per-object digests are folded into a per-process image digest, and the
   per-PID image digests are folded into the token's ``runtime_protect_digest``
   (version 2), which is bound into the TPM quote. A verifier recomputes that
   digest from the PID list and the per-PID image digests carried in the token
   and checks it against the quote-bound value.

If any protected process's objects cannot be measured (for example they are not
fs-verity protected) the token **fails closed** instead of being issued without
a measurement.

Trust argument across an untrusted root
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Measured boot -> ``lockdown=integrity`` -> ``module.sig_enforce`` -> the signed
BPF LSM loaded -> the BPF LSM constrains what a protected process may map ->
the agent's kernel-side measurement bound under the AIK quote. LOTA already
gates every one of those rungs, so root cannot silently swap the measuring code
without breaking a signature, lockdown, or the measured-boot chain.

Per-module known-good set
-------------------------

Robustness across lazy ``dlopen`` and cross-distribution library drift comes
from a **per-module** known-good set, not a single combined digest: the BPF
LSM's fs-verity allow-list (``allow_verity``, loaded from the game's module
manifest via ``--allow-verity``) admits an executable mapping only if its
backing file's fs-verity digest is known-good. Any allowed module may load in
any order; an unknown module is refused at ``mmap`` time. The combined image
digest is bound for attestation, but per-module trust is enforced in the
kernel.

Event-driven re-measurement
---------------------------

Measurement is not limited to periodic beats. The BPF LSM flags executable
``mmap``/``mprotect`` events from a protected process, and the agent
re-measures that process's image on such an event, narrowing the window in
which image drift between heartbeats goes unobserved. A burst of events from
one process (lazy ``dlopen`` at startup emits one per object) is coalesced
behind a short per-process cooldown, so a re-measure stays O(objects) rather
than O(objects squared). In enforce mode an untrusted mapping is already
blocked at the source, so this is the monitor-mode and forensic complement to
that enforcement.

Scope and honest limits
-----------------------

- **JIT / self-modifying code is out of scope.** Engines that generate
  executable code at runtime (.NET, V8, some anti-cheats) produce anonymous or
  ``RWX`` executable pages that have no file-backed, fs-verity-measurable
  origin. The kernel-side measurement deliberately covers only file-backed
  executable mappings; anonymous executable mappings are reported (and, in
  enforce mode with the anonymous-exec gate, blocked) but not measured. A game
  that relies on JIT must either run it under a measured AOT image or accept
  that its JIT regions are outside the measured set.
- **Completeness is bounded by W^X.** The equivalence "file-backed executable
  mapping == on-disk file" holds only while write and execute are kept
  separate. A determined ``RWX``/self-modifying mapping is not fully covered,
  which is why this measurement is complementary to W^X enforcement and the
  anonymous-exec gate rather than a replacement.
