/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * lota-bench run - take the next run of a session
 *
 * Each call takes one run and exits, so a session survives the reboots
 * that move LOTA between configurations. The game runs in a transient
 * scope its launch options start, which lota-bench finds by name: no PID
 * of the game or of the agent is ever looked up, and nothing under their
 * /proc is read. The agent is asked for its status only where the
 * configuration has it running, so a socket-activated agent is never
 * started by the meter that wants it stopped.
 */

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <linux/magic.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/vfs.h>
#include <time.h>
#include <unistd.h>

#include "../../include/lota.h"
#include "../../include/lota_ipc.h"
#include "../../src/agent/status_cmd.h"
#include "agentsnap.h"
#include "cgroup.h"
#include "field.h"
#include "frames.h"
#include "machine.h"
#include "result.h"
#include "run.h"
#include "validate.h"

#ifndef LOTA_BENCH_VERSION
#define LOTA_BENCH_VERSION "unknown"
#endif

#define CGROUP_ROOT "/sys/fs/cgroup"
#define PLAN_NAME "plan.json"
#define RESULT_NAME "result.json"
#define BOOT_NAME "boot_id"
#define BOOT_ID_PATH "/proc/sys/kernel/random/boot_id"
#define BOOT_ID_CAP 64
#define NAME_MAX_LEN 32

/* how often a wait looks again */
#define POLL_MS 500

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

static void catch_stop(void)
{
	struct sigaction sa;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = on_stop;
	/* no SA_RESTART: a sleep returns at once */
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);
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

static void nap(unsigned int ms)
{
	struct timespec ts = { ms / 1000, (long)(ms % 1000) * 1000000 };

	nanosleep(&ts, NULL);
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

/* --- files of the session --------------------------------------------- */

/*
 * @name in @dir, a regular file of at most @max bytes. NULL with errno
 * set; ELOOP for a link, EINVAL for anything else that is not a file.
 */
static char *read_at(int dir, const char *name, uint64_t max, size_t *len)
{
	struct stat st;
	size_t got = 0;
	char *buf;
	int fd, err;

	fd = openat(dir, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
	if (fd < 0)
		return NULL;
	if (fstat(fd, &st))
		goto fail;
	if (!S_ISREG(st.st_mode)) {
		errno = EINVAL;
		goto fail;
	}
	if ((uint64_t)st.st_size > max) {
		errno = EFBIG;
		goto fail;
	}
	buf = malloc((size_t)st.st_size + 1);
	if (!buf)
		goto fail;
	while (got < (size_t)st.st_size) {
		ssize_t n = read(fd, buf + got, (size_t)st.st_size - got);

		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0) {
			if (n == 0)
				errno = EIO;
			free(buf);
			goto fail;
		}
		got += (size_t)n;
	}
	close(fd);
	*len = got;
	return buf;
fail:
	err = errno;
	close(fd);
	errno = err;
	return NULL;
}

/* 1 when @name is in @dir, 0 when not, or negative errno */
static int present_at(int dir, const char *name)
{
	struct stat st;

	if (fstatat(dir, name, &st, AT_SYMLINK_NOFOLLOW) == 0)
		return 1;
	return errno == ENOENT ? 0 : -errno;
}

static void run_name(char *buf, unsigned int index)
{
	snprintf(buf, NAME_MAX_LEN, "run-%02u.json", index);
}

/* a file is written aside and named once it reads back */
static FILE *create_tmp(int dir, const char *tmp)
{
	FILE *f;
	int fd;

	if (unlinkat(dir, tmp, 0) && errno != ENOENT)
		return NULL;
	fd = openat(dir, tmp,
		    O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0644);
	if (fd < 0)
		return NULL;
	f = fdopen(fd, "w");
	if (!f)
		close(fd);
	return f;
}

/*
 * Read @tmp back as a @kind file, then give it @name, which must not
 * exist. @tmp is removed on failure.
 */
static int publish(int dir, const char *tmp, const char *name,
		   enum bench_kind kind, struct bench_doc *d)
{
	char err[256];
	size_t len;
	char *buf;
	int ret = -1;

	buf = read_at(dir, tmp, BENCH_RESULT_MAX_BYTES, &len);
	if (!buf) {
		fprintf(stderr, "lota-bench: %s: %s\n", tmp, strerror(errno));
		goto out;
	}
	if (bench_validate(buf, len, d, err, sizeof(err))) {
		fprintf(stderr, "lota-bench: %s does not read back: %s\n", name,
			err);
		goto out;
	}
	if (d->kind != kind) {
		fprintf(stderr, "lota-bench: %s reads back as a %s\n", name,
			bench_kind_names[d->kind]);
		goto out;
	}
	if (renameat2(dir, tmp, dir, name, RENAME_NOREPLACE)) {
		fprintf(stderr, "lota-bench: %s: %s\n", name, strerror(errno));
		goto out;
	}
	ret = 0;
out:
	if (ret)
		unlinkat(dir, tmp, 0);
	free(buf);
	return ret;
}

static int close_tmp(FILE *f, int ret)
{
	if (fclose(f) && !ret) {
		perror("lota-bench: close");
		return -EIO;
	}
	return ret;
}

/* --- the plan --------------------------------------------------------- */

struct plan_opts {
	const char *game;
	const char *proton;
	const char *version;
	const char *settings;
	unsigned long rounds;
	unsigned long settle_s;
	unsigned long duration_s;
	unsigned long interval_ms;
	bool any;
};

static void set_field(struct bench_field *f, const char *s)
{
	if (s)
		bench_field_set(f, s, strlen(s));
}

static int write_plan(int dir, const struct plan_opts *o,
		      const struct bench_machine *m, struct bench_doc *d)
{
	static const char tmp[] = ".plan.json.tmp";
	struct bench_plan p;
	uint64_t per_run, total;
	FILE *f;
	int ret;

	memset(&p, 0, sizeof(p));
	set_field(&p.version, LOTA_BENCH_VERSION);
	p.machine = *m;
	set_field(&p.game.title, o->game);
	set_field(&p.game.proton, o->proton);
	set_field(&p.game.version, o->version);
	set_field(&p.game.settings, o->settings);
	p.rounds = (unsigned int)o->rounds;
	p.settle_s = (unsigned int)o->settle_s;
	p.duration_s = (unsigned int)o->duration_s;
	p.interval_ms = (unsigned int)o->interval_ms;

	if (!p.game.title.set) {
		fprintf(stderr, "lota-bench: --game names no title\n");
		return -1;
	}
	per_run = bench_run_samples(&p);
	total = per_run * bench_session_runs(p.rounds);
	if (per_run > BENCH_MAX_SAMPLES || total > BENCH_SESSION_MAX_SAMPLES) {
		fprintf(stderr,
			"lota-bench: %llu samples a run, %llu a session; at "
			"most %d and %d: use a longer --interval-ms\n",
			(unsigned long long)per_run, (unsigned long long)total,
			BENCH_MAX_SAMPLES, BENCH_SESSION_MAX_SAMPLES);
		return -1;
	}

	f = create_tmp(dir, tmp);
	if (!f) {
		perror("lota-bench: " PLAN_NAME);
		return -1;
	}
	ret = close_tmp(f, bench_write_plan(f, &p));
	if (ret) {
		unlinkat(dir, tmp, 0);
		return -1;
	}
	return publish(dir, tmp, PLAN_NAME, BK_PLAN, d);
}

static int read_plan(int dir, struct bench_doc *d)
{
	char err[256];
	size_t len;
	char *buf;
	int ret = -1;

	buf = read_at(dir, PLAN_NAME, BENCH_RESULT_MAX_BYTES, &len);
	if (!buf) {
		fprintf(stderr, "lota-bench: " PLAN_NAME ": %s\n",
			errno == ENOENT ? "no session here; start one with "
					  "--game" :
					  strerror(errno));
		return -1;
	}
	if (bench_validate(buf, len, d, err, sizeof(err)))
		fprintf(stderr, "lota-bench: " PLAN_NAME ": invalid: %s\n",
			err);
	else if (d->kind != BK_PLAN)
		fprintf(stderr, "lota-bench: " PLAN_NAME " is a %s\n",
			bench_kind_names[d->kind]);
	else
		ret = 0;
	free(buf);
	return ret;
}

/* --- LOTA's state ----------------------------------------------------- */

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

static bool unit_running(int root, enum bench_source src)
{
	return present_at(root, unit_cgroups[src]) == 1;
}

/* LOTA is where run @index needs it; tells how to get there when not */
static bool lota_ready(int root, unsigned int index, enum bench_config c)
{
	bool agent = unit_running(root, BS_LOTA_AGENT);
	bool attest = unit_running(root, BS_LOTA_ATTEST);

	if (c == BC_A && (agent || attest)) {
		printf("Run %u is in A: LOTA stopped. Stop it with\n\n"
		       "  sudo systemctl stop lota-attest lota-agent.socket "
		       "lota-agent\n\n"
		       "and run lota-bench run again. The socket goes too, "
		       "or the next client starts the agent again.\n",
		       index);
		return false;
	}
	if (c != BC_A && !agent) {
		printf("Run %u is in %s: the agent running. Reboot, or "
		       "where PCR 14 does not bind the agent, start it with\n\n"
		       "  sudo systemctl start lota-agent.socket lota-agent\n\n"
		       "and run lota-bench run again. An agent stopped on a "
		       "host where PCR 14 binds it starts again only after a "
		       "reboot.\n",
		       index, bench_config_names[c]);
		return false;
	}
	return true;
}

static enum bench_mode mode_of(uint8_t mode)
{
	switch (mode) {
	case LOTA_MODE_MONITOR:
		return BMO_MONITOR;
	case LOTA_MODE_ENFORCE:
		return BMO_ENFORCE;
	default:
		return BMO_UNKNOWN;
	}
}

static int ask_agent(struct bench_run *r)
{
	struct lota_ipc_status st;
	int ret;

	ret = status_request(LOTA_IPC_SOCKET_PATH, &st);
	if (ret) {
		fprintf(stderr,
			"lota-bench: the agent does not answer on %s: %s\n",
			LOTA_IPC_SOCKET_PATH, strerror(-ret));
		return -1;
	}
	r->mode = mode_of(st.mode);
	r->agent_bench = (st.flags & LOTA_STATUS_BENCH) != 0;
	if (!r->agent_bench)
		fprintf(stderr,
			"lota-bench: the agent runs without --bench; this run "
			"has no agent figures%s\n",
			r->config == BC_C ? ", and whether the title was "
					    "protected cannot be checked" :
					    "");
	return 0;
}

/* --- the game's scope ------------------------------------------------- */

/*
 * systemd --user starts a transient scope under app.slice, older ones
 * straight under the manager
 */
static int open_scope(int root)
{
	static const char *const fmt[] = {
		"user.slice/user-%u.slice/user@%u.service/app.slice/%s.scope",
		"user.slice/user-%u.slice/user@%u.service/%s.scope",
	};
	unsigned int uid = (unsigned int)getuid();
	struct statfs sfs;
	char rel[256];
	int fd;

	for (size_t i = 0; i < sizeof(fmt) / sizeof(fmt[0]); i++) {
		snprintf(rel, sizeof(rel), fmt[i], uid, uid, BENCH_GAME_UNIT);
		fd = openat(root, rel, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
		if (fd < 0)
			continue;
		if (fstatfs(fd, &sfs) == 0 && sfs.f_type == CGROUP2_SUPER_MAGIC)
			return fd;
		close(fd);
	}
	return -1;
}

static bool scope_present(int root)
{
	int fd = open_scope(root);

	if (fd < 0)
		return false;
	close(fd);
	return true;
}

static void print_launch(const char *path, unsigned int index, bool warming,
			 const struct bench_plan *p)
{
	enum bench_config c = bench_run_config(index);
	const char *note = warming ? " (warm-up after a reboot, not kept)" :
			   index   ? "" :
				     " (warm-up)";

	printf("Run %u of %u, configuration %s%s. Set the game's launch "
	       "options to:\n\n"
	       "  MANGOHUD_CONFIG=output_folder=%s,autostart_log=%u,"
	       "log_duration=%u systemd-run --user --scope --unit=%s %s"
	       "mangohud %%command%%\n\n"
	       "start it, and be in the game within %u s, when the frame log "
	       "starts;\nplay as you would for %u s from there.\n"
	       "Waiting for the game; Ctrl+C gives up.\n",
	       index, bench_session_runs(p->rounds) - 1, bench_config_names[c],
	       note, path, p->settle_s, p->duration_s, BENCH_GAME_UNIT,
	       c == BC_C ? "lota-proton-hook " : "", p->settle_s,
	       p->duration_s);
	fflush(stdout);
}

/* the scope as it appears, or -1 on Ctrl+C */
static int wait_scope(int root)
{
	int fd;

	while ((fd = open_scope(root)) < 0) {
		if (stop_requested)
			return -1;
		nap(POLL_MS);
	}
	return fd;
}

/* 0 once the scope is gone, -1 on Ctrl+C */
static int wait_gone(int root)
{
	while (scope_present(root)) {
		if (stop_requested)
			return -1;
		nap(POLL_MS);
	}
	return 0;
}

/* --- sampling --------------------------------------------------------- */

/* the metric each total is accrued from */
static const enum bench_metric total_metric[BT_COUNT] = {
	[BT_CPU_USEC] = BM_CPU_USAGE_USEC,
	[BT_MEMORY_MAX_BYTES] = BM_MEMORY_CURRENT_BYTES,
	[BT_PGFAULT] = BM_PGFAULT,
	[BT_PGMAJFAULT] = BM_PGMAJFAULT,
	[BT_IO_READ_BYTES] = BM_IO_READ_BYTES,
	[BT_IO_WRITE_BYTES] = BM_IO_WRITE_BYTES,
};

struct accrual {
	bool seen; /* present in some sample */
	bool always; /* present in every sample */
	bool was; /* present in the sample before */
	struct bench_sample prev;
	struct bench_totals t;
};

/*
 * A counter accrues the difference between consecutive samples. A cgroup
 * that appears after the first sample is new, and so is one whose counter
 * went back: either holds all it counts.
 */
static void accrue(struct accrual *a, const struct bench_sample *s, bool first)
{
	if (first)
		a->always = true;
	if (!s) {
		a->always = false;
		a->was = false;
		return;
	}
	a->seen = true;
	a->t.present = true;
	for (int i = 0; i < BT_COUNT; i++) {
		enum bench_metric m = total_metric[i];
		struct bench_opt *o = &a->t.v[i];
		uint64_t v = s->v[m];

		if (!(s->have & (1u << m)))
			continue;
		if (i == BT_MEMORY_MAX_BYTES) {
			if (!o->set || v > o->v)
				o->v = v;
		} else if (a->was && (a->prev.have & (1u << m)) &&
			   v >= a->prev.v[m]) {
			o->v += v - a->prev.v[m];
		} else if (!first) {
			o->v += v;
		}
		o->set = true;
	}
	a->prev = *s;
	a->was = true;
}

struct snaps {
	bool any;
	struct bench_agent_snap first;
	struct bench_agent_snap last;
	struct bench_agent a;
	int err; /* why the last read failed */
};

static void snap_take(struct snaps *sn, int rundir)
{
	struct bench_agent_snap s;
	int ret;

	ret = bench_agent_snap_read(rundir, BENCH_AGENT_SNAP_NAME, &s);
	if (ret) {
		sn->err = ret;
		return;
	}
	if (!sn->any)
		sn->first = s;
	sn->any = true;
	sn->last = s;
	sn->a.present = true;
	if (s.memlock_set && (!sn->a.v[BA_MAPS_MEMLOCK_BYTES].set ||
			      s.memlock > sn->a.v[BA_MAPS_MEMLOCK_BYTES].v))
		sn->a.v[BA_MAPS_MEMLOCK_BYTES] =
			(struct bench_opt){ s.memlock, true };
	if (s.protected_set &&
	    (!sn->a.v[BA_PROTECTED_MAX].set ||
	     s.protected_count > sn->a.v[BA_PROTECTED_MAX].v))
		sn->a.v[BA_PROTECTED_MAX] =
			(struct bench_opt){ s.protected_count, true };
}

/* the BPF figures are what accrued between the first and last snapshot */
static void snap_finish(struct snaps *sn)
{
	const struct bench_agent_snap *f = &sn->first, *l = &sn->last;

	if (!sn->any || !f->bpf || !l->bpf || l->run_ns < f->run_ns ||
	    l->run_cnt < f->run_cnt)
		return;
	sn->a.v[BA_BPF_RUN_NS] =
		(struct bench_opt){ l->run_ns - f->run_ns, true };
	sn->a.v[BA_BPF_RUN_CNT] =
		(struct bench_opt){ l->run_cnt - f->run_cnt, true };
}

struct sampling {
	FILE *out;
	int root;
	int game;
	int rundir; /* -1 in A */
	unsigned int interval_ms;
	uint64_t duration_ms;
	struct accrual acc[BS_COUNT];
	struct snaps sn;
};

static int sample_loop(struct sampling *sp, struct bench_run *r)
{
	struct bench_sample s[BS_COUNT];
	struct timespec start, next, now;
	uint64_t t = 0;
	unsigned int i;
	int ret;

	clock_gettime(CLOCK_MONOTONIC, &start);
	next = start;
	r->end = BE_INTERRUPTED;

	for (i = 0;; i++) {
		const struct bench_sample *src[BS_COUNT];

		if (stop_requested)
			return -EINTR;
		ret = bench_cgroup_read(sp->game, &s[BS_GAME]);
		if (ret == -ENOENT && i) {
			r->end = BE_GAME_GONE;
			break;
		}
		if (ret) {
			fprintf(stderr, "lota-bench: reading the game: %s\n",
				strerror(-ret));
			return ret;
		}
		src[BS_GAME] = &s[BS_GAME];
		for (int u = BS_LOTA_AGENT; u < BS_COUNT; u++)
			src[u] = read_unit(sp->root, (enum bench_source)u,
					   &s[u]);
		if (sp->rundir >= 0)
			snap_take(&sp->sn, sp->rundir);

		clock_gettime(CLOCK_MONOTONIC, &now);
		t = ms_between(&start, &now);
		ret = bench_write_sample(sp->out, i, t, src);
		if (ret)
			return ret;
		for (int u = 0; u < BS_COUNT; u++)
			accrue(&sp->acc[u], src[u], i == 0);

		if (i + 1 >= BENCH_MAX_SAMPLES) {
			i++;
			r->end = BE_SAMPLE_CAP;
			break;
		}
		advance(&next, sp->interval_ms);
		if (ms_between(&start, &next) > sp->duration_ms) {
			i++;
			r->end = BE_DURATION;
			break;
		}
		while (!stop_requested &&
		       clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &next,
				       NULL) == EINTR)
			;
	}
	r->sample_count = i;
	r->wall_ms = t;
	return 0;
}

/* --- the frames ------------------------------------------------------- */

static bool ends_with(const char *s, const char *tail)
{
	size_t n = strlen(s), m = strlen(tail);

	return n >= m && strcmp(s + n - m, tail) == 0;
}

int bench_run_find_log(int dir, time_t since, char *name, size_t cap)
{
	struct dirent *e;
	time_t best = 0;
	struct stat st;
	DIR *d;
	int fd;

	fd = openat(dir, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (fd < 0)
		return -1;
	d = fdopendir(fd);
	if (!d) {
		close(fd);
		return -1;
	}
	name[0] = '\0';
	while ((e = readdir(d))) {
		if (!ends_with(e->d_name, ".csv") ||
		    strncmp(e->d_name, "frames-", 7) == 0 ||
		    strstr(e->d_name, "summary") || strlen(e->d_name) >= cap)
			continue;
		if (fstatat(dir, e->d_name, &st, AT_SYMLINK_NOFOLLOW) ||
		    !S_ISREG(st.st_mode) || st.st_mtime < since ||
		    st.st_mtime < best)
			continue;
		best = st.st_mtime;
		strcpy(name, e->d_name);
	}
	closedir(d);
	return name[0] ? 0 : -1;
}

/* summarise the run's log and keep it as frames-NN.csv */
static void take_frames(int dir, time_t since, unsigned int index,
			struct bench_run_frames *fr)
{
	struct bench_frames f;
	char name[NAME_MAX + 1], kept[NAME_MAX_LEN], err[256];
	size_t len;
	char *buf;
	int ret;

	if (bench_run_find_log(dir, since, name, sizeof(name))) {
		fprintf(stderr,
			"lota-bench: no MangoHud log in the session; this run "
			"has no frame times\n");
		return;
	}
	buf = read_at(dir, name, BENCH_FRAMES_LOG_MAX_BYTES, &len);
	if (!buf) {
		fprintf(stderr, "lota-bench: the MangoHud log: %s\n",
			strerror(errno));
		return;
	}
	ret = bench_frames_parse(buf, len, &f, err, sizeof(err));
	free(buf);
	if (ret) {
		fprintf(stderr, "lota-bench: the MangoHud log: %s\n", err);
	} else {
		bench_frame_stats(&f, &fr->s);
		fr->present = fr->s.frames > 0;
	}
	bench_frames_free(&f);

	/* one left by a run that was not kept goes */
	snprintf(kept, sizeof(kept), "frames-%02u.csv", index);
	if (renameat(dir, name, dir, kept))
		fprintf(stderr, "lota-bench: keeping the log as %s: %s\n", kept,
			strerror(errno));
}

/* --- the boot a session warmed up in ---------------------------------- */

static int read_boot(char *boot, size_t cap)
{
	FILE *f = fopen(BOOT_ID_PATH, "re");
	char *got;

	if (!f) {
		perror("lota-bench: " BOOT_ID_PATH);
		return -1;
	}
	got = fgets(boot, (int)cap, f);
	fclose(f);
	if (!got) {
		fprintf(stderr, "lota-bench: " BOOT_ID_PATH " is empty\n");
		return -1;
	}
	boot[strcspn(boot, "\n")] = '\0';
	return 0;
}

bool bench_run_warm(int dir, const char *boot)
{
	size_t len;
	char *buf;
	bool same;

	buf = read_at(dir, BOOT_NAME, BOOT_ID_CAP, &len);
	if (!buf)
		return false;
	buf[len] = '\0';
	buf[strcspn(buf, "\n")] = '\0';
	same = strcmp(buf, boot) == 0;
	free(buf);
	return same;
}

int bench_run_note_boot(int dir, const char *boot)
{
	static const char tmp[] = "." BOOT_NAME ".tmp";
	FILE *f = create_tmp(dir, tmp);

	if (f && !close_tmp(f, fprintf(f, "%s\n", boot) < 0 ? -1 : 0) &&
	    !renameat(dir, tmp, dir, BOOT_NAME))
		return 0;
	fprintf(stderr, "lota-bench: " BOOT_NAME ": %s\n", strerror(errno));
	unlinkat(dir, tmp, 0);
	return -1;
}

/* --- one run ---------------------------------------------------------- */

/* the run saw LOTA as its configuration has it; why not, or NULL */
static const char *run_mismatch(const struct sampling *sp,
				const struct bench_run *r)
{
	const struct bench_opt *prot = &r->agent.v[BA_PROTECTED_MAX];

	if (r->config == BC_A) {
		if (sp->acc[BS_LOTA_AGENT].seen || sp->acc[BS_LOTA_ATTEST].seen)
			return "LOTA started during an A run";
		return NULL;
	}
	if (!sp->acc[BS_LOTA_AGENT].always)
		return "the agent stopped during the run";
	if (r->config == BC_C && r->agent.present && (!prot->set || !prot->v))
		return "nothing was protected: is lota-proton-hook in the "
		       "launch options?";
	if (r->config == BC_B && prot->set && prot->v)
		return "the title was protected: take lota-proton-hook out "
		       "of the launch options";
	return NULL;
}

/* @warming: the same run, for what it leaves in memory; nothing is kept */
static int take_run(int dir, const char *path, const struct bench_plan *p,
		    unsigned int index, bool warming, struct bench_doc *d)
{
	char tmp[NAME_MAX_LEN + 8], name[NAME_MAX_LEN];
	struct sampling sp = { .rundir = -1 };
	struct bench_run r;
	const char *why;
	time_t since;
	int ret = -1;

	memset(&r, 0, sizeof(r));
	r.index = index;
	r.config = bench_run_config(index);
	r.warmup = index == 0;
	run_name(name, index);
	snprintf(tmp, sizeof(tmp), ".%s.tmp", name);

	sp.root = open(CGROUP_ROOT, O_PATH | O_DIRECTORY | O_CLOEXEC);
	if (sp.root < 0) {
		perror("lota-bench: " CGROUP_ROOT);
		return -1;
	}
	sp.game = -1;
	if (!lota_ready(sp.root, index, r.config))
		goto out;
	if (scope_present(sp.root)) {
		printf("A game is still running in %s.scope; quit it and run "
		       "lota-bench run again.\n",
		       BENCH_GAME_UNIT);
		goto out;
	}
	if (r.config != BC_A) {
		if (ask_agent(&r))
			goto out;
		sp.rundir = open(BENCH_AGENT_SNAP_DIR,
				 O_PATH | O_DIRECTORY | O_CLOEXEC);
	}

	catch_stop();
	print_launch(path, index, warming, p);
	sp.game = wait_scope(sp.root);
	if (sp.game < 0)
		goto out_stopped;
	since = time(NULL);
	{
		int rootfs = open("/", O_PATH | O_DIRECTORY | O_CLOEXEC);

		if (rootfs >= 0) {
			bench_power_read(rootfs, &r.power);
			close(rootfs);
		}
	}
	printf("The game is up; sampling every %u ms for %u s.\n",
	       p->interval_ms, p->settle_s + p->duration_s);
	fflush(stdout);
	step_aside();

	sp.out = create_tmp(dir, tmp);
	if (!sp.out) {
		fprintf(stderr, "lota-bench: %s: %s\n", tmp, strerror(errno));
		goto out;
	}
	sp.interval_ms = p->interval_ms;
	sp.duration_ms = (uint64_t)(p->settle_s + p->duration_s) * 1000;
	ret = bench_write_run_begin(sp.out, &r);
	if (!ret)
		ret = sample_loop(&sp, &r);
	if (ret) {
		fclose(sp.out);
		unlinkat(dir, tmp, 0);
		if (ret == -EINTR)
			goto out_stopped;
		ret = -1;
		goto out;
	}
	ret = -1;

	if (r.end == BE_GAME_GONE) {
		fclose(sp.out);
		unlinkat(dir, tmp, 0);
		fprintf(stderr,
			"lota-bench: the game quit %llu s into a %u s run; run "
			"%u is not kept, take it again\n",
			(unsigned long long)(r.wall_ms / 1000),
			p->settle_s + p->duration_s, index);
		goto out;
	}
	if (warming)
		printf("The warm-up is over. Quit the game.\n");
	else
		printf("Run %u is measured. Quit the game.\n", index);
	fflush(stdout);
	if (wait_gone(sp.root)) {
		fclose(sp.out);
		unlinkat(dir, tmp, 0);
		goto out_stopped;
	}

	for (int u = 0; u < BS_COUNT; u++)
		r.totals[u] = sp.acc[u].t;
	snap_finish(&sp.sn);
	r.agent = sp.sn.a;
	if (r.agent.present && !r.agent_bench)
		memset(&r.agent, 0, sizeof(r.agent));
	if (r.config != BC_A && r.agent_bench && !r.agent.present)
		fprintf(stderr,
			"lota-bench: cannot read " BENCH_AGENT_SNAP_DIR
			"/" BENCH_AGENT_SNAP_NAME ": %s\n",
			strerror(-sp.sn.err));

	why = run_mismatch(&sp, &r);
	if (why) {
		fclose(sp.out);
		unlinkat(dir, tmp, 0);
		fprintf(stderr, "lota-bench: run %u is not kept: %s\n", index,
			why);
		goto out;
	}
	if (warming) {
		char log[NAME_MAX + 1];

		fclose(sp.out);
		unlinkat(dir, tmp, 0);
		if (!bench_run_find_log(dir, since, log, sizeof(log)))
			unlinkat(dir, log, 0);
		printf("The warm-up is not kept; lota-bench run takes run %u "
		       "next.\n",
		       index);
		ret = 0;
		goto out;
	}
	take_frames(dir, since, index, &r.frames);
	self_cost(&r.self);
	if (close_tmp(sp.out, bench_write_run_end(sp.out, &r))) {
		unlinkat(dir, tmp, 0);
		goto out;
	}
	ret = publish(dir, tmp, name, BK_RUN, d);
	if (!ret)
		printf("Run %u is kept in %s.\n", index, name);
	goto out;

out_stopped:
	fprintf(stderr, "lota-bench: stopped; run %u is not kept\n", index);
out:
	if (sp.rundir >= 0)
		close(sp.rundir);
	if (sp.game >= 0)
		close(sp.game);
	close(sp.root);
	return ret;
}

/* --- the result ------------------------------------------------------- */

static int assemble(int dir, struct bench_doc *plan)
{
	static const char tmp[] = ".result.json.tmp";
	struct bench_doc *one = malloc(sizeof(*one));
	char *bufs[BENCH_MAX_RUNS] = { NULL };
	char name[NAME_MAX_LEN], err[256];
	unsigned int n = bench_session_runs(plan->plan.rounds);
	size_t len;
	int ret = -1;
	FILE *f;

	if (!one) {
		perror("lota-bench");
		return -1;
	}
	for (unsigned int i = 0; i < n; i++) {
		run_name(name, i);
		bufs[i] = read_at(dir, name, BENCH_RESULT_MAX_BYTES, &len);
		if (!bufs[i]) {
			fprintf(stderr, "lota-bench: %s: %s\n", name,
				strerror(errno));
			goto out;
		}
		if (bench_validate(bufs[i], len, one, err, sizeof(err))) {
			fprintf(stderr, "lota-bench: %s: invalid: %s\n", name,
				err);
			goto out;
		}
		if (one->kind != BK_RUN || one->runs[0].index != i) {
			fprintf(stderr, "lota-bench: %s is not run %u\n", name,
				i);
			goto out;
		}
		plan->runs[i] = one->runs[0];
	}
	plan->nruns = n;

	f = create_tmp(dir, tmp);
	if (!f) {
		perror("lota-bench: " RESULT_NAME);
		goto out;
	}
	if (close_tmp(f, bench_write_session(f, plan, BK_RESULT))) {
		unlinkat(dir, tmp, 0);
		goto out;
	}
	ret = publish(dir, tmp, RESULT_NAME, BK_RESULT, one);
	if (!ret)
		printf("The session is complete: " RESULT_NAME "\n");
out:
	for (unsigned int i = 0; i < n; i++)
		free(bufs[i]);
	free(one);
	return ret;
}

/* --- the command ------------------------------------------------------ */

static void run_usage(FILE *f)
{
	fprintf(f,
		"Usage: lota-bench run DIR [--game TITLE [--proton V] "
		"[--game-version V]\n"
		"                          [--settings TEXT] [--rounds N] "
		"[--duration-s N]\n"
		"                          [--settle-s N] [--interval-ms N]]\n"
		"\n"
		"Take the next run of the session in DIR. The first call "
		"starts the\n"
		"session and needs --game; every later one takes the options "
		"from it.\n"
		"\n"
		"  --rounds N        %d..%d rounds of A B C, default %d\n"
		"  --duration-s N    %d..%d seconds a run, default %d\n"
		"  --settle-s N      %d..%d seconds before the frame log, "
		"default %d\n"
		"  --interval-ms N   %d..%d, default %d\n",
		BENCH_ROUNDS_MIN, BENCH_ROUNDS_MAX, BENCH_ROUNDS_DEFAULT,
		BENCH_DURATION_MIN_S, BENCH_DURATION_MAX_S,
		BENCH_DURATION_DEFAULT_S, BENCH_SETTLE_MIN_S,
		BENCH_SETTLE_MAX_S, BENCH_SETTLE_DEFAULT_S,
		BENCH_INTERVAL_MIN_MS, BENCH_INTERVAL_MAX_MS,
		BENCH_INTERVAL_DEFAULT_MS);
}

static int parse_opts(int argc, char **argv, struct plan_opts *o)
{
	static const struct option longopts[] = {
		{ "game", required_argument, NULL, 'g' },
		{ "proton", required_argument, NULL, 'p' },
		{ "game-version", required_argument, NULL, 'v' },
		{ "settings", required_argument, NULL, 's' },
		{ "rounds", required_argument, NULL, 'r' },
		{ "duration-s", required_argument, NULL, 'd' },
		{ "interval-ms", required_argument, NULL, 'i' },
		{ "settle-s", required_argument, NULL, 'S' },
		{ "help", no_argument, NULL, 'h' },
		{ NULL, 0, NULL, 0 },
	};
	int c;

	while ((c = getopt_long(argc, argv, "h", longopts, NULL)) != -1) {
		int bad = 0;

		o->any = o->any || c != 'h';
		switch (c) {
		case 'g':
			o->game = optarg;
			break;
		case 'p':
			o->proton = optarg;
			break;
		case 'v':
			o->version = optarg;
			break;
		case 's':
			o->settings = optarg;
			break;
		case 'r':
			bad = parse_uint(optarg, BENCH_ROUNDS_MIN,
					 BENCH_ROUNDS_MAX, &o->rounds);
			break;
		case 'd':
			bad = parse_uint(optarg, BENCH_DURATION_MIN_S,
					 BENCH_DURATION_MAX_S, &o->duration_s);
			break;
		case 'S':
			bad = parse_uint(optarg, BENCH_SETTLE_MIN_S,
					 BENCH_SETTLE_MAX_S, &o->settle_s);
			break;
		case 'i':
			bad = parse_uint(optarg, BENCH_INTERVAL_MIN_MS,
					 BENCH_INTERVAL_MAX_MS,
					 &o->interval_ms);
			break;
		case 'h':
			run_usage(stdout);
			return 1;
		default:
			run_usage(stderr);
			return -1;
		}
		if (bad) {
			fprintf(stderr, "lota-bench: --%s out of range\n",
				longopts[c == 'r' ? 4 :
					 c == 'd' ? 5 :
					 c == 'S' ? 7 :
						    6]
					.name);
			return -1;
		}
	}
	return 0;
}

/*
 * The directory goes into MANGOHUD_CONFIG, which splits on ',' and '=',
 * and into launch options, which a shell reads
 */
static bool path_fits_launch(const char *p)
{
	for (; *p; p++) {
		if (!((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
		      (*p >= '0' && *p <= '9') || strchr("/._-+", *p)))
			return false;
	}
	return true;
}

static int open_session(const char *arg, bool create, char *path)
{
	int dir;

	if (!path_fits_launch(arg))
		goto bad_path;
	if (create && mkdir(arg, 0755) && errno != EEXIST) {
		fprintf(stderr, "lota-bench: %s: %s\n", arg, strerror(errno));
		return -1;
	}
	dir = open(arg, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (dir < 0) {
		fprintf(stderr, "lota-bench: %s: %s\n", arg, strerror(errno));
		return -1;
	}
	if (!realpath(arg, path) || !path_fits_launch(path)) {
		close(dir);
		goto bad_path;
	}
	return dir;
bad_path:
	fprintf(stderr,
		"lota-bench: %s: the session's path may hold only letters, "
		"digits and / . _ - +\n",
		arg);
	return -1;
}

static int machine_unchanged(const struct bench_plan *p)
{
	struct bench_machine m;
	const char *what;
	int root;

	root = open("/", O_PATH | O_DIRECTORY | O_CLOEXEC);
	if (root < 0) {
		perror("lota-bench: /");
		return -1;
	}
	bench_machine_read(root, &m);
	close(root);
	what = bench_machine_diff(&p->machine, &m);
	if (what) {
		fprintf(stderr,
			"lota-bench: the %s changed since the session began; "
			"start a new session\n",
			what);
		return -1;
	}
	return 0;
}

static int next_run(int dir, unsigned int nruns, unsigned int *index)
{
	char name[NAME_MAX_LEN];
	int ret;

	for (unsigned int i = 0; i < nruns; i++) {
		run_name(name, i);
		ret = present_at(dir, name);
		if (ret < 0) {
			fprintf(stderr, "lota-bench: %s: %s\n", name,
				strerror(-ret));
			return -1;
		}
		if (!ret) {
			*index = i;
			return 0;
		}
	}
	*index = nruns;
	return 0;
}

int bench_main_run(int argc, char **argv)
{
	struct plan_opts o = {
		.rounds = BENCH_ROUNDS_DEFAULT,
		.settle_s = BENCH_SETTLE_DEFAULT_S,
		.duration_s = BENCH_DURATION_DEFAULT_S,
		.interval_ms = BENCH_INTERVAL_DEFAULT_MS,
	};
	char path[PATH_MAX];
	struct bench_doc *d;
	unsigned int index, nruns;
	int dir, ret, status = 1;

	ret = parse_opts(argc, argv, &o);
	if (ret)
		return ret > 0 ? 0 : EXIT_BENCH_USAGE;
	if (optind + 1 != argc) {
		run_usage(stderr);
		return EXIT_BENCH_USAGE;
	}
	d = malloc(sizeof(*d));
	if (!d) {
		perror("lota-bench");
		return 1;
	}
	dir = open_session(argv[optind], o.any, path);
	if (dir < 0)
		goto out_doc;

	ret = present_at(dir, PLAN_NAME);
	if (ret < 0) {
		fprintf(stderr, "lota-bench: " PLAN_NAME ": %s\n",
			strerror(-ret));
		goto out;
	}
	if (o.any && ret) {
		fprintf(stderr,
			"lota-bench: %s already holds a session; its options "
			"are kept in " PLAN_NAME "\n",
			argv[optind]);
		status = EXIT_BENCH_USAGE;
		goto out;
	}
	if (o.any && !o.game) {
		fprintf(stderr, "lota-bench: a session starts with --game\n");
		status = EXIT_BENCH_USAGE;
		goto out;
	}
	if (o.any) {
		struct bench_machine m;
		int root = open("/", O_PATH | O_DIRECTORY | O_CLOEXEC);

		if (root < 0) {
			perror("lota-bench: /");
			goto out;
		}
		bench_machine_read(root, &m);
		close(root);
		if (write_plan(dir, &o, &m, d))
			goto out;
		printf("The session begins in %s: %u runs of %u s.\n", path,
		       bench_session_runs(d->plan.rounds), d->plan.duration_s);
	} else if (read_plan(dir, d)) {
		goto out;
	}

	ret = present_at(dir, RESULT_NAME);
	if (ret) {
		if (ret > 0)
			printf("The session in %s is complete: " RESULT_NAME
			       "\n",
			       path);
		status = ret > 0 ? 0 : 1;
		goto out;
	}
	nruns = bench_session_runs(d->plan.rounds);
	if (next_run(dir, nruns, &index))
		goto out;
	if (index < nruns) {
		struct bench_doc *run = malloc(sizeof(*run));
		char boot[BOOT_ID_CAP];
		bool warming;

		if (!run || machine_unchanged(&d->plan) ||
		    read_boot(boot, sizeof(boot))) {
			free(run);
			goto out;
		}
		warming = index > 0 && !bench_run_warm(dir, boot);
		ret = take_run(dir, path, &d->plan, index, warming, run);
		free(run);
		if (ret || bench_run_note_boot(dir, boot))
			goto out;
		if (warming || index + 1 < nruns) {
			status = 0;
			goto out;
		}
	}
	status = assemble(dir, d) ? 1 : 0;
out:
	close(dir);
out_doc:
	free(d);
	return status;
}
