/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */

#include "bench_bpf.h"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#include "bench_proc.h"

int bench_bpf_enable_stats(void)
{
	/* the kernel opens it O_CLOEXEC */
	int fd = bpf_enable_stats(BPF_STATS_RUN_TIME);

	return fd < 0 ? -errno : fd;
}

bool bench_bpf_sample(const struct bpf_loader_ctx *ctx, bool run_stats,
		      struct bench_bpf *out)
{
	struct bpf_program *prog;
	struct bpf_map *map;
	int dirfd;

	memset(out, 0, sizeof(*out));
	if (!ctx || !ctx->loaded || !ctx->obj)
		return false;

	out->run_stats = run_stats;

	bpf_object__for_each_program(prog, ctx->obj) {
		struct bpf_prog_info info;
		__u32 len = sizeof(info);
		struct bench_prog *p;
		int fd = bpf_program__fd(prog);

		if (fd < 0)
			continue;
		if (out->prog_count == LOTA_BENCH_MAX_PROGS) {
			out->prog_dropped++;
			continue;
		}
		memset(&info, 0, sizeof(info));
		if (bpf_prog_get_info_by_fd(fd, &info, &len) < 0)
			continue;

		p = &out->progs[out->prog_count++];
		bench_sanitize_name(p->name, sizeof(p->name),
				    bpf_program__name(prog));
		p->run_ns = info.run_time_ns;
		p->run_cnt = info.run_cnt;
	}

	dirfd = open("/proc/self/fdinfo", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	out->memlock_ok = dirfd >= 0;
	bpf_object__for_each_map(map, ctx->obj) {
		uint64_t memlock;
		int fd = bpf_map__fd(map);

		if (fd < 0)
			continue;
		out->map_count++;
		if (dirfd < 0 || bench_read_memlock(dirfd, fd, &memlock) < 0)
			out->memlock_ok = false;
		else
			out->memlock += memlock;
	}
	if (dirfd >= 0)
		close(dirfd);
	return true;
}
