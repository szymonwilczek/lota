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

| Harness | Mirror (`lota_lsm_logic.h`) | Production source |
|---|---|---|
| `fuzz_open_flags.c` | `mirror_is_write_open_flags` | `src/bpf/lota_lsm.bpf.c:737` (+ `O_*` macros `:83-94`) |
| `fuzz_kmem_device.c` | `mirror_is_kernel_mem_device` | `src/bpf/lota_lsm.bpf.c:760` (+ `S_IF*` macros `:96-100`) |
| `fuzz_inaccessible_exec.c` | `mirror_is_inaccessible_exec` | `src/bpf/lota_lsm.bpf.c:801` (+ flag `:64-65`) |
| `fuzz_shebang.c` | `mirror_is_shebang` | `src/bpf/lota_lsm.bpf.c:788` |

### Keeping the mirror honest

Mirror is a copy and can drift from production. When a mirrored helper or
macro in `src/bpf/lota_lsm.bpf.c` changes, update the matching block in
`lota_lsm_logic.h` and the line references in this file. A `check-bpf-mirror`
guard that diffs the production lines against the mirror is the planned next
step; until then this is a manual review obligation on changes to the
referenced source lines.

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
