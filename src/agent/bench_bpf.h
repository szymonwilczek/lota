/* SPDX-License-Identifier: MIT */
/*
 * The --bench view of the daemon's own BPF programs and maps.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */
#ifndef LOTA_AGENT_BENCH_BPF_H
#define LOTA_AGENT_BENCH_BPF_H

#include "bench_protected.h"
#include "bench_snapshot.h"
#include "bpf_loader.h"

/**
 * bench_bpf_enable_stats() - Ask the kernel to count BPF run time.
 *
 * Return: a descriptor that holds the count on while it is open,
 * or a negative errno.
 */
int bench_bpf_enable_stats(void);

/* Fill @out from the loaded object; false when nothing is loaded */
bool bench_bpf_sample(const struct bpf_loader_ctx *ctx, bool run_stats,
		      struct bench_bpf *out);

/* The protected set from the daemon's map; returns the count or -errno */
int bench_bpf_protected(const struct bpf_loader_ctx *ctx, struct bench_pid *out,
			size_t max);

#endif /* LOTA_AGENT_BENCH_BPF_H */
