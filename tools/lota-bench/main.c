/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * lota-bench - what LOTA costs a game
 *
 * Samples the game's cgroup and the cgroups of the LOTA units side by side
 * and writes one result file. It needs no privilege, never stops or starts
 * the agent, and opens no network connection.
 */

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <linux/magic.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/vfs.h>
#include <time.h>
#include <unistd.h>

#include "cgroup.h"
#include "result.h"

#ifndef LOTA_BENCH_VERSION
#define LOTA_BENCH_VERSION "unknown"
#endif

#define EXIT_BENCH_USAGE 2

#define CGROUP_ROOT "/sys/fs/cgroup"

/* the LOTA units, under the cgroup root */
static const char *const unit_cgroups[BS_COUNT] = {
	[BS_LOTA_AGENT] = "system.slice/lota-agent.service",
	[BS_LOTA_ATTEST] = "system.slice/lota-attest.service",
};

/* <linux/ioprio.h> is missing from older uapi headers */
#define BENCH_IOPRIO_CLASS_IDLE 3
#define BENCH_IOPRIO_CLASS_SHIFT 13
#define BENCH_IOPRIO_WHO_PROCESS 1

static volatile sig_atomic_t stop_requested;

static void on_stop(int sig)
{
	(void)sig;
	stop_requested = 1;
}

static void usage(FILE *f)
{
	fprintf(f,
		"Usage: lota-bench sample --cgroup PATH --output FILE "
		"[--interval-ms N] [--duration-s N]\n"
		"       lota-bench --version\n"
		"\n"
		"sample  Sample the game's cgroup and the LOTA units' cgroups\n"
		"        until the duration runs out, the game's cgroup goes\n"
		"        away, or Ctrl+C.\n"
		"\n"
		"  --cgroup PATH     the game's cgroup: a path under " CGROUP_ROOT
		",\n"
		"                    or as systemctl show -p ControlGroup "
		"prints it\n"
		"  --output FILE     result file; never overwritten\n"
		"  --interval-ms N   %d..%d, default 1000\n"
		"  --duration-s N    stop after N seconds; default: run until "
		"stopped\n",
		BENCH_INTERVAL_MIN_MS, BENCH_INTERVAL_MAX_MS);
}

static int parse_uint(const char *s, unsigned long min, unsigned long max,
		      unsigned long *out)
{
	char *end;
	unsigned long v;

	if (*s < '0' || *s > '9')
		return -EINVAL;
	errno = 0;
	v = strtoul(s, &end, 10);
	if (errno || *end || v < min || v > max)
		return -EINVAL;
	*out = v;
	return 0;
}

static uint64_t ms_between(const struct timespec *a, const struct timespec *b)
{
	int64_t ns = (int64_t)(b->tv_sec - a->tv_sec) * 1000000000 +
		     (b->tv_nsec - a->tv_nsec);

	return ns > 0 ? (uint64_t)ns / 1000000 : 0;
}

static void advance(struct timespec *t, unsigned int ms)
{
	t->tv_sec += ms / 1000;
	t->tv_nsec += (long)(ms % 1000) * 1000000;
	if (t->tv_nsec >= 1000000000) {
		t->tv_sec++;
		t->tv_nsec -= 1000000000;
	}
}

/* the sampler is a guest on the game's machine */
static void step_aside(void)
{
	if (setpriority(PRIO_PROCESS, 0, 10))
		perror("lota-bench: setpriority");
	if (syscall(SYS_ioprio_set, BENCH_IOPRIO_WHO_PROCESS, 0,
		    BENCH_IOPRIO_CLASS_IDLE << BENCH_IOPRIO_CLASS_SHIFT))
		perror("lota-bench: ioprio_set");
}

static void catch_stop(void)
{
	struct sigaction sa;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = on_stop;
	/* no SA_RESTART: the sleep returns at once */
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);
}

static int open_game_cgroup(int root, const char *path)
{
	static const char prefix[] = CGROUP_ROOT "/";
	struct statfs sfs;
	const char *rel = path;
	int fd;

	/*
	 * systemctl show -p ControlGroup and /proc/<pid>/cgroup print the
	 * path from the cgroup root with a leading slash
	 */
	if (strncmp(path, prefix, sizeof(prefix) - 1) == 0)
		rel = path + sizeof(prefix) - 1;
	while (*rel == '/')
		rel++;
	if (!*rel) {
		fprintf(stderr, "lota-bench: the cgroup root is not a game\n");
		return -1;
	}
	fd = openat(root, rel, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (fd < 0) {
		fprintf(stderr, "lota-bench: cannot open cgroup %s: %s\n", path,
			strerror(errno));
		return -1;
	}
	if (fstatfs(fd, &sfs) || sfs.f_type != CGROUP2_SUPER_MAGIC) {
		fprintf(stderr, "lota-bench: %s is not a cgroup v2 directory\n",
			path);
		close(fd);
		return -1;
	}
	return fd;
}

/* NULL while the unit is not running: its cgroup exists only then */
static const struct bench_sample *read_unit(int root, enum bench_source src,
					    struct bench_sample *s)
{
	int fd, ret;

	fd = openat(root, unit_cgroups[src],
		    O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (fd < 0)
		return NULL;
	ret = bench_cgroup_read(fd, s);
	close(fd);
	return ret ? NULL : s;
}

static void self_cost(struct bench_self *self)
{
	struct rusage ru;

	memset(self, 0, sizeof(*self));
	if (getrusage(RUSAGE_SELF, &ru))
		return;
	self->cpu_user_usec = (uint64_t)ru.ru_utime.tv_sec * 1000000 +
			      (uint64_t)ru.ru_utime.tv_usec;
	self->cpu_system_usec = (uint64_t)ru.ru_stime.tv_sec * 1000000 +
				(uint64_t)ru.ru_stime.tv_usec;
	self->max_rss_bytes = (uint64_t)ru.ru_maxrss * 1024;
}

struct sample_opts {
	const char *cgroup;
	const char *output;
	unsigned int interval_ms;
	uint64_t duration_ms; /* 0: until stopped */
};

static int sample_loop(FILE *out, int root, int game,
		       const struct sample_opts *o, unsigned int *count,
		       enum bench_end *end)
{
	struct bench_sample s[BS_COUNT];
	struct timespec start, next, now;
	unsigned int i;
	int ret;

	clock_gettime(CLOCK_MONOTONIC, &start);
	next = start;

	for (i = 0;; i++) {
		const struct bench_sample *src[BS_COUNT];

		if (stop_requested) {
			*end = BE_INTERRUPTED;
			break;
		}
		ret = bench_cgroup_read(game, &s[BS_GAME]);
		if (ret == -ENOENT) {
			*end = BE_GAME_GONE;
			break;
		}
		if (ret) {
			fprintf(stderr, "lota-bench: reading %s: %s\n",
				o->cgroup, strerror(-ret));
			return ret;
		}
		src[BS_GAME] = &s[BS_GAME];
		src[BS_LOTA_AGENT] =
			read_unit(root, BS_LOTA_AGENT, &s[BS_LOTA_AGENT]);
		src[BS_LOTA_ATTEST] =
			read_unit(root, BS_LOTA_ATTEST, &s[BS_LOTA_ATTEST]);

		clock_gettime(CLOCK_MONOTONIC, &now);
		ret = bench_write_sample(out, i, ms_between(&start, &now), src);
		if (ret)
			return ret;

		if (i + 1 >= BENCH_MAX_SAMPLES) {
			i++;
			*end = BE_SAMPLE_CAP;
			break;
		}
		advance(&next, o->interval_ms);
		if (o->duration_ms &&
		    ms_between(&start, &next) > o->duration_ms) {
			i++;
			*end = BE_DURATION;
			break;
		}
		while (!stop_requested &&
		       clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &next,
				       NULL) == EINTR)
			;
	}
	*count = i;
	return 0;
}

static int cmd_sample(const struct sample_opts *o)
{
	struct bench_self self;
	enum bench_end end = BE_INTERRUPTED;
	unsigned int count = 0;
	int root, game, fd;
	int ret = 1;
	FILE *out;

	root = open(CGROUP_ROOT, O_PATH | O_DIRECTORY | O_CLOEXEC);
	if (root < 0) {
		perror("lota-bench: " CGROUP_ROOT);
		return 1;
	}
	game = open_game_cgroup(root, o->cgroup);
	if (game < 0)
		goto out_root;

	fd = open(o->output, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0644);
	if (fd < 0) {
		fprintf(stderr, "lota-bench: %s: %s\n", o->output,
			strerror(errno));
		goto out_game;
	}
	out = fdopen(fd, "w");
	if (!out) {
		perror("lota-bench: fdopen");
		close(fd);
		goto out_unlink;
	}

	step_aside();
	catch_stop();
	fprintf(stderr, "lota-bench: sampling every %u ms; Ctrl+C stops\n",
		o->interval_ms);

	if (bench_write_begin(out, o->interval_ms) ||
	    sample_loop(out, root, game, o, &count, &end))
		goto out_file;
	self_cost(&self);
	if (bench_write_end(out, end, &self))
		goto out_file;

	fprintf(stderr, "lota-bench: %u samples in %s (%s)\n", count, o->output,
		bench_end_names[end]);
	ret = 0;
out_file:
	if (fclose(out) && !ret) {
		perror("lota-bench: close");
		ret = 1;
	}
out_unlink:
	if (ret) {
		fprintf(stderr, "lota-bench: %s is incomplete, removed\n",
			o->output);
		unlink(o->output);
	}
out_game:
	close(game);
out_root:
	close(root);
	return ret;
}

static int main_sample(int argc, char **argv)
{
	static const struct option longopts[] = {
		{ "cgroup", required_argument, NULL, 'c' },
		{ "output", required_argument, NULL, 'o' },
		{ "interval-ms", required_argument, NULL, 'i' },
		{ "duration-s", required_argument, NULL, 'd' },
		{ "help", no_argument, NULL, 'h' },
		{ NULL, 0, NULL, 0 },
	};
	struct sample_opts o = { .interval_ms = 1000 };
	unsigned long v;
	int c;

	while ((c = getopt_long(argc, argv, "c:o:i:d:h", longopts, NULL)) !=
	       -1) {
		switch (c) {
		case 'c':
			o.cgroup = optarg;
			break;
		case 'o':
			o.output = optarg;
			break;
		case 'i':
			if (parse_uint(optarg, BENCH_INTERVAL_MIN_MS,
				       BENCH_INTERVAL_MAX_MS, &v)) {
				fprintf(stderr,
					"lota-bench: --interval-ms takes %d..%d\n",
					BENCH_INTERVAL_MIN_MS,
					BENCH_INTERVAL_MAX_MS);
				return EXIT_BENCH_USAGE;
			}
			o.interval_ms = (unsigned int)v;
			break;
		case 'd':
			/* a day is past any session BENCH_MAX_SAMPLES holds */
			if (parse_uint(optarg, 1, 86400, &v)) {
				fprintf(stderr,
					"lota-bench: --duration-s takes 1..86400\n");
				return EXIT_BENCH_USAGE;
			}
			o.duration_ms = (uint64_t)v * 1000;
			break;
		case 'h':
			usage(stdout);
			return 0;
		default:
			usage(stderr);
			return EXIT_BENCH_USAGE;
		}
	}
	if (optind != argc || !o.cgroup || !o.output) {
		usage(stderr);
		return EXIT_BENCH_USAGE;
	}
	return cmd_sample(&o);
}

int main(int argc, char **argv)
{
	if (argc < 2) {
		usage(stderr);
		return EXIT_BENCH_USAGE;
	}
	if (strcmp(argv[1], "--version") == 0) {
		printf("lota-bench %s\n", LOTA_BENCH_VERSION);
		return 0;
	}
	if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0) {
		usage(stdout);
		return 0;
	}
	if (strcmp(argv[1], "sample") == 0)
		return main_sample(argc - 1, argv + 1);

	fprintf(stderr, "lota-bench: unknown command '%s'\n", argv[1]);
	usage(stderr);
	return EXIT_BENCH_USAGE;
}
