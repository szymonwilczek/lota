<!-- SPDX-License-Identifier: MIT -->
# BPF LSM oracle-fuzzing sandbox

Differential fuzzers for the LOTA BPF LSM decision logic. Each harness runs a
copy of the production verdict logic against an independent reference and
aborts on any divergence, so a logic bug or a wrong hand-defined constant is
caught as a fuzzer crash. This finds *logic* faults, not just memory safety:
the BPF programs are memory-safe by verifier construction, so the interesting
bugs are wrong allow/deny verdicts.

BPF helpers are `static __always_inline` and read their inputs from kernel structs
via `BPF_CORE_READ`, so they cannot be compiled or linked in user space directly.
Harnesses reach the logic two ways.

## Zero-copy

Harness includes the real production header and fuzzes it unchanged. No
copy, so no drift.

| Harness | Production code under test |
|---|---|
| `fuzz_devt.c` | `include/lota_devt.h` (`LOTA_DEVT_MAJOR/MINOR/MKDEV`, `lota_devt_from_st`) |
| `fuzz_event_budget.c` | `include/lota_event_budget.h` (`lota_event_budget_limit/window_expired/exhausted`) |

## Mirror (drift-guarded)

Helper body is copied verbatim into `lota_lsm_logic.h` with the kernel reads
lifted to scalar parameters. `reference.h` reimplements the intended verdict
independently, sourced from the system ABI headers rather than the BPF
program's hand-defined constants.

| Harness | Mirror (`lota_lsm_logic.h`) | Production helper (`src/bpf/lota_lsm.bpf.c`) |
|---|---|---|
| `fuzz_open_flags.c` | `mirror_is_write_open_flags` | `is_write_open_flags` (+ `LOTA_O_*` macros) |
| `fuzz_kmem_device.c` | `mirror_is_kernel_mem_device` | `is_kernel_mem_device` (+ `S_IFMT`, `S_IFCHR`) |
| `fuzz_inaccessible_exec.c` | `mirror_is_inaccessible_exec` | `is_inaccessible_exec_path` (+ `BINPRM_FLAGS_PATH_INACCESSIBLE`) |
| `fuzz_shebang.c` | `mirror_is_shebang` | `is_shebang_binprm` |

### Keeping the mirror honest

`mirror.lock` pins each mirrored helper by a hash of its body and each macro by
its `#define`. `make check-bpf-mirror` (run by `scripts/check-patch`) fails when
production no longer matches the lock, or when a file here cites
`src/bpf/lota_lsm.bpf.c` by line number; name the helper or macro instead.

On a reported change, update the block in `lota_lsm_logic.h` (and `reference.h`
if the intended verdict changed), run `make update-bpf-mirror` and commit the
lock with the change.

## Build / run

```
make fuzz-bpf-all
./build/fuzz-bpf-open-flags -max_total_time=60 corpus/
```

`clang -fsanitize=fuzzer,address`, libc only, no kernel or `tss2` needed,
so these run anywhere.

## Scope and limits

Covers the pure-decision subset only: helpers whose logic is a function of
scalar inputs once the kernel reads are done. Helpers that walk live kernel
objects (`task_struct` traversal, map lookups, `bpf_probe_read`) are out of
reach in user space and need `BPF_PROG_TEST_RUN` or syzkaller instead.
The mirror also covers the helper logic, not the LSM hook glue that calls it.

## Future: Remove the copy

Once the sandbox has proven its worth, the mirrored helpers can be factored
out of `src/bpf/lota_lsm.bpf.c` into a shared header that both the BPF program
and these harnesses include.

Mirror then equals production by construction and Mirror tier becomes Zero-copy.
That is out of scope for now, deliberately deferred out of this sandbox.
