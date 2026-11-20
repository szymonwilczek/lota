/* SPDX-License-Identifier: MIT */
/*
 * Unit tests for what --bench samples and writes.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "../src/agent/bench_bpf.h"
#include "../src/agent/bench_snapshot.h"

#include "test.h"

#define MS 1000000ULL

/* comm with a space and a paren, as a title may name its process */
static const char k_stat[] =
	"4242 (game) x) S 1 4242 4242 0 -1 4194560 120 0 3 0 250 40 0 0 "
	"20 0 4 0 100 2000000 500 18446744073709551615\n";

static const char k_status[] = "Name:\tgame\n"
			       "VmRSS:\t   3000 kB\n"
			       "Threads:\t4\n"
			       "voluntary_ctxt_switches:\t77\n"
			       "nonvoluntary_ctxt_switches:\t5\n";

static const char k_rollup[] =
	"55d0c0000000-7ffd00000000 ---p 00000000 00:00 0 [rollup]\n"
	"Rss:                2048 kB\n"
	"Pss:                1024 kB\n"
	"Pss_Anon:            900 kB\n"
	"Shared_Clean:        512 kB\n"
	"Private_Clean:       256 kB\n"
	"Private_Dirty:       128 kB\n";

static void test_parse_stat(void)
{
	struct bench_proc p = { 0 };

	TEST("stat parses");
	if (bench_parse_stat(k_stat, &p) != 0)
		FAIL("expected: bench_parse_stat(k_stat, &p) == 0");
	TEST("page faults read past comm");
	if (!(p.minflt == 120 && p.majflt == 3))
		FAIL("expected: p.minflt == 120 && p.majflt == 3");
	TEST("CPU ticks read past comm");
	if (!(p.utime == 250 && p.stime == 40))
		FAIL("expected: p.utime == 250 && p.stime == 40");
	TEST("start time read past negative fields");
	if (p.start != 100)
		FAIL("expected: p.start == 100");
	TEST("a stat without a closing paren is refused");
	if (bench_parse_stat("4242 (game S 1", &p) != -EINVAL)
		FAIL("expected: bench_parse_stat(\"4242 (game S 1\", &p) == "
		     "-EINVAL");
	TEST("a short stat is refused");
	if (bench_parse_stat("4242 (game) S 1 2 3\n", &p) != -EINVAL)
		FAIL("expected: bench_parse_stat(\"4242 (game) S 1 2 3\\n\", "
		     "&p) == -EINVAL");
}

static void test_parse_status(void)
{
	struct bench_proc p = { 0 };

	TEST("status parses");
	if (bench_parse_status(k_status, &p) != 0)
		FAIL("expected: bench_parse_status(k_status, &p) == 0");
	TEST("voluntary and involuntary switches are told apart");
	if (!(p.ctxt_vol == 77 && p.ctxt_invol == 5))
		FAIL("expected: p.ctxt_vol == 77 && p.ctxt_invol == 5");
	TEST("VmRSS is read from status");
	if (p.vm_rss_kb != 3000)
		FAIL("expected: p.vm_rss_kb == 3000");
	TEST("a status without switch counters is refused");
	if (bench_parse_status("Name:\tgame\n", &p) != -EINVAL)
		FAIL("expected: bench_parse_status(\"Name:\\tgame\\n\", &p) "
		     "== -EINVAL");
	TEST("a status without VmRSS reads as no resident pages");
	if (!(bench_parse_status("voluntary_ctxt_switches:\t1\n"
				 "nonvoluntary_ctxt_switches:\t2\n",
				 &p) == 0 &&
	      p.vm_rss_kb == 0))
		FAIL("expected: bench_parse_status(\"voluntary_ctxt_switches:\\t1\\n\" "
		     "\"nonvoluntary_ctxt_switches:\\t2\\n\", &p) == 0 && "
		     "p.vm_rss_kb == 0");
}

static void test_parse_rollup(void)
{
	struct bench_proc p = { 0 };

	TEST("smaps_rollup parses");
	if (bench_parse_rollup(k_rollup, &p) != 0)
		FAIL("expected: bench_parse_rollup(k_rollup, &p) == 0");
	TEST("Pss is not Pss_Anon");
	if (!(p.rss_kb == 2048 && p.pss_kb == 1024))
		FAIL("expected: p.rss_kb == 2048 && p.pss_kb == 1024");
	TEST("USS is the private pages");
	if (p.uss_kb != 384)
		FAIL("expected: p.uss_kb == 384");
	TEST("a rollup without Pss is refused");
	if (bench_parse_rollup("Rss: 1 kB\n", &p) != -EINVAL)
		FAIL("expected: bench_parse_rollup(\"Rss: 1 kB\\n\", &p) == "
		     "-EINVAL");
}

static int put(int dirfd, const char *name, const char *s)
{
	int fd = openat(dirfd, name, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC,
			0600);
	ssize_t n;

	if (fd < 0)
		return -1;
	n = write(fd, s, strlen(s));
	close(fd);
	return n == (ssize_t)strlen(s) ? 0 : -1;
}

static void test_read_proc(void)
{
	char dir[] = "/tmp/lota-bench-proc-XXXXXX";
	struct bench_proc p;
	int dirfd;

	if (!mkdtemp(dir)) {
		TEST("mkdtemp");
		if (!0)
			FAIL("expected: 0");
		return;
	}
	dirfd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	TEST("synthetic proc directory written");
	if (!(dirfd >= 0 && put(dirfd, "stat", k_stat) == 0 &&
	      put(dirfd, "status", k_status) == 0))
		FAIL("expected: dirfd >= 0 && put(dirfd, \"stat\", k_stat) == "
		     "0 && put(dirfd, \"status\", k_status) == 0");

	TEST("a missing smaps_rollup fails the read");
	if (bench_read_proc(dirfd, &p, true) != -ENOENT)
		FAIL("expected: bench_read_proc(dirfd, &p, true) == -ENOENT");
	TEST("without a rollup it is not opened");
	if (!(bench_read_proc(dirfd, &p, false) == 0 && p.utime == 250))
		FAIL("expected: bench_read_proc(dirfd, &p, false) == 0 && "
		     "p.utime == 250");

	TEST("smaps_rollup planted as a symlink");
	if (symlinkat("status", dirfd, "smaps_rollup") != 0)
		FAIL("expected: symlinkat(\"status\", dirfd, "
		     "\"smaps_rollup\") == 0");
	TEST("a symlinked proc file is not followed");
	if (bench_read_proc(dirfd, &p, true) != -ELOOP)
		FAIL("expected: bench_read_proc(dirfd, &p, true) == -ELOOP");
	unlinkat(dirfd, "smaps_rollup", 0);

	TEST("rollup written");
	if (put(dirfd, "smaps_rollup", k_rollup) != 0)
		FAIL("expected: put(dirfd, \"smaps_rollup\", k_rollup) == 0");
	TEST("all three files land in one sample");
	if (!(bench_read_proc(dirfd, &p, true) == 0 && p.utime == 250 &&
	      p.ctxt_vol == 77 && p.pss_kb == 1024))
		FAIL("expected: bench_read_proc(dirfd, &p, true) == 0 && "
		     "p.utime == 250 && p.ctxt_vol == 77 && p.pss_kb == 1024");

	unlinkat(dirfd, "stat", 0);
	unlinkat(dirfd, "status", 0);
	unlinkat(dirfd, "smaps_rollup", 0);
	close(dirfd);
	rmdir(dir);
}

static void test_read_self(void)
{
	struct bench_proc p = { 0 };
	int dirfd = open("/proc/self", O_RDONLY | O_DIRECTORY | O_CLOEXEC);

	TEST("the test's own counters read");
	if (!(dirfd >= 0 && bench_read_proc(dirfd, &p, true) == 0))
		FAIL("expected: dirfd >= 0 && bench_read_proc(dirfd, &p, "
		     "true) == 0");
	TEST("a live process has resident pages");
	if (!(p.rss_kb > 0 && p.pss_kb > 0))
		FAIL("expected: p.rss_kb > 0 && p.pss_kb > 0");
	if (dirfd >= 0)
		close(dirfd);
}

static void test_format(void)
{
	static struct bench_state st;
	struct bench_proc p = { .utime = 250, .stime = 40, .pss_kb = 1024 };

	bench_state_init(&st, getegid(), 10 * MS);
	st.clk_tck = 100;
	st.seq = 3;
	bench_format(&st, 3010 * MS, &p);
	bench_format_bpf(&st.w, NULL);
	bench_format_end(&st.w);
	TEST("the header carries version, sequence and uptime");
	if (strncmp(st.w.buf, "{\"version\":1,\"seq\":3,\"uptime_ms\":3000,",
		    38) != 0)
		FAIL("expected: strncmp(st.w.buf, "
		     "\"{\\\"version\\\":1,\\\"seq\\\":3,\\\"uptime_ms\\\":3000,\", "
		     "38) == 0");
	TEST("CPU ticks are written as nanoseconds");
	if (!(strstr(st.w.buf, "\"cpu_user_ns\":2500000000,") &&
	      strstr(st.w.buf, "\"cpu_sys_ns\":400000000,")))
		FAIL("expected: strstr(st.w.buf, "
		     "\"\\\"cpu_user_ns\\\":2500000000,\") && "
		     "strstr(st.w.buf, \"\\\"cpu_sys_ns\\\":400000000,\")");
	TEST("PSS is written");
	if (strstr(st.w.buf, "\"pss_kb\":1024,") == NULL)
		FAIL("expected: strstr(st.w.buf, \"\\\"pss_kb\\\":1024,\") != "
		     "NULL");
	TEST("the snapshot is one closed object on one line");
	if (!(strstr(st.w.buf, "},\"bpf\":null}\n") != NULL &&
	      st.w.buf[st.w.len - 1] == '\n'))
		FAIL("expected: strstr(st.w.buf, \"},\\\"bpf\\\":null}\\n\") "
		     "!= NULL && st.w.buf[st.w.len - 1] == '\\n'");

	bench_reset(&st.w);
	bench_format(&st, 3010 * MS, NULL);
	TEST("unreadable counters are written as null, not zero");
	if (strstr(st.w.buf, "\"agent\":null") == NULL)
		FAIL("expected: strstr(st.w.buf, \"\\\"agent\\\":null\") != "
		     "NULL");
}

static void test_format_bpf(void)
{
	static struct bench_state st;
	static struct bench_bpf b;
	size_t i;

	bench_state_init(&st, 0, 0);
	memset(&b, 0, sizeof(b));
	b.run_stats = true;
	b.map_count = 2;
	b.memlock_ok = true;
	b.memlock = 8192;
	b.prog_count = 2;
	strcpy(b.progs[0].name, "lota_bprm_check");
	b.progs[0].run_ns = 900;
	b.progs[0].run_cnt = 3;
	strcpy(b.progs[1].name, "lota_mmap");
	bench_format_bpf(&st.w, &b);
	TEST("programs are listed by name with run time and count");
	if (strcmp(st.w.buf,
		   ",\"bpf\":{\"run_stats\":true,\"maps\":2,"
		   "\"maps_memlock\":8192,\"progs_dropped\":0,\"progs\":["
		   "{\"name\":\"lota_bprm_check\",\"run_ns\":900,\"run_cnt\":3},"
		   "{\"name\":\"lota_mmap\",\"run_ns\":0,\"run_cnt\":0}]}") !=
	    0)
		FAIL("expected: strcmp(st.w.buf, "
		     "\",\\\"bpf\\\":{\\\"run_stats\\\":true,\\\"maps\\\":2,\" "
		     "\"\\\"maps_memlock\\\":8192,\\\"progs_dropped\\\":0,\\\"progs\\\":[\" "
		     "\"{\\\"name\\\":\\\"lota_bprm_check\\\",\\\"run_ns\\\":900,\\\"run_cnt\\\":3},\" "
		     "\"{\\\"name\\\":\\\"lota_mmap\\\",\\\"run_ns\\\":0,\\\"run_cnt\\\":0}]}\") "
		     "== 0");

	bench_reset(&st.w);
	b.memlock_ok = false;
	b.run_stats = false;
	bench_format_bpf(&st.w, &b);
	TEST("what was not read is written as null or false");
	if (!(strstr(st.w.buf, "\"run_stats\":false") &&
	      strstr(st.w.buf, "\"maps_memlock\":null")))
		FAIL("expected: strstr(st.w.buf, \"\\\"run_stats\\\":false\") "
		     "&& strstr(st.w.buf, \"\\\"maps_memlock\\\":null\")");

	/* the cap holds the worst case the daemon can produce */
	bench_reset(&st.w);
	b.prog_count = LOTA_BENCH_MAX_PROGS;
	for (i = 0; i < LOTA_BENCH_MAX_PROGS; i++) {
		memset(b.progs[i].name, 'x', LOTA_BENCH_NAME_MAX - 1);
		b.progs[i].name[LOTA_BENCH_NAME_MAX - 1] = '\0';
		b.progs[i].run_ns = UINT64_MAX;
		b.progs[i].run_cnt = UINT64_MAX;
	}
	b.memlock = UINT64_MAX;
	b.memlock_ok = true;
	{
		struct bench_proc p;

		memset(&p, 0xff, sizeof(p));
		st.seq = UINT64_MAX;
		st.w.skipped = UINT64_MAX;
		bench_format(&st, UINT64_MAX, &p);
	}
	bench_format_bpf(&st.w, &b);
	{
		struct bench_protected_sum sum;

		memset(&sum, 0xff, sizeof(sum));
		sum.pss_ok = true;
		bench_format_protected(&st, &sum);
	}
	bench_format_end(&st.w);
	TEST("the largest snapshot fits the cap");
	if (st.w.overflow)
		FAIL("expected: !st.w.overflow");
}

static void proc_at(struct bench_proc *p, uint64_t start, uint64_t cpu,
		    uint64_t flt, uint64_t pss)
{
	memset(p, 0, sizeof(*p));
	p->start = start;
	p->utime = cpu;
	p->minflt = flt;
	p->majflt = flt / 10;
	p->vm_rss_kb = 100;
	p->pss_kb = pss;
}

/* a BPF object of three loaded programs, the second without info */
struct bpf_program {
	int fd;
	const char *name;
};

struct bpf_object {
	struct bpf_program progs[3];
};

static struct bpf_object k_obj = { { { 3, "lota_bprm_check" },
				     { 4, "lota_file_open" },
				     { 5, "lota_mmap" } } };

struct bpf_program *bpf_object__next_program(const struct bpf_object *obj,
					     struct bpf_program *prog)
{
	struct bpf_program *first = (struct bpf_program *)obj->progs;

	if (!prog)
		return first;
	return prog + 1 < first + 3 ? prog + 1 : NULL;
}

int bpf_program__fd(const struct bpf_program *prog)
{
	return prog->fd;
}

const char *bpf_program__name(const struct bpf_program *prog)
{
	return prog->name;
}

int bpf_prog_get_info_by_fd(int prog_fd, struct bpf_prog_info *info,
			    __u32 *info_len)
{
	(void)info_len;
	if (prog_fd == 4) {
		errno = EPERM;
		return -EPERM;
	}
	info->run_time_ns = 100 * (__u64)prog_fd;
	info->run_cnt = prog_fd;
	return 0;
}

struct bpf_map *bpf_object__next_map(const struct bpf_object *obj,
				     const struct bpf_map *map)
{
	(void)obj;
	(void)map;
	return NULL;
}

int bpf_map__fd(const struct bpf_map *map)
{
	(void)map;
	return -1;
}

int bpf_enable_stats(enum bpf_stats_type type)
{
	(void)type;
	return -1;
}

int bpf_loader_protected_pids(const struct bpf_loader_ctx *ctx, uint32_t *pid,
			      uint64_t *start, size_t max)
{
	(void)ctx;
	(void)pid;
	(void)start;
	(void)max;
	return 0;
}

static void test_bpf_sample(void)
{
	static struct bpf_loader_ctx ctx;
	static struct bench_bpf b;

	ctx.loaded = true;
	ctx.obj = &k_obj;
	TEST("a program whose info cannot be read is counted as dropped");
	if (!(bench_bpf_sample(&ctx, true, &b) && b.prog_count == 2 &&
	      b.prog_dropped == 1 &&
	      !strcmp(b.progs[0].name, "lota_bprm_check") &&
	      !strcmp(b.progs[1].name, "lota_mmap") &&
	      b.progs[1].run_ns == 500 && b.progs[1].run_cnt == 5))
		FAIL("expected: bench_bpf_sample(&ctx, true, &b) && "
		     "b.prog_count == 2 && b.prog_dropped == 1 && "
		     "!strcmp(b.progs[0].name, \"lota_bprm_check\") && "
		     "!strcmp(b.progs[1].name, \"lota_mmap\") && "
		     "b.progs[1].run_ns == 500 && b.progs[1].run_cnt == 5");
}

static void test_protected_fold(void)
{
	static struct bench_protected bp;
	struct bench_protected_sum sum;
	struct bench_proc p;

	bench_protected_begin(&bp, &sum);
	proc_at(&p, 7, 100, 50, 40);
	bench_protected_add(&bp, &sum, 10, &p, true);
	proc_at(&p, 8, 200, 20, 0);
	bench_protected_add(&bp, &sum, 11, &p, false);
	bench_protected_end(&bp);
	TEST("both processes are summed");
	if (!(sum.count == 2 && sum.rss_kb == 200))
		FAIL("expected: sum.count == 2 && sum.rss_kb == 200");
	TEST("a process first seen is not charged its past");
	if (!(sum.cpu == 0 && sum.minflt == 0 && sum.majflt == 0))
		FAIL("expected: sum.cpu == 0 && sum.minflt == 0 && sum.majflt "
		     "== 0");
	TEST("PSS is unknown until each process had a rollup");
	if (sum.pss_ok)
		FAIL("expected: !sum.pss_ok");

	bench_protected_begin(&bp, &sum);
	proc_at(&p, 7, 130, 80, 0);
	bench_protected_add(&bp, &sum, 10, &p, false);
	proc_at(&p, 8, 205, 21, 60);
	bench_protected_add(&bp, &sum, 11, &p, true);
	bench_protected_end(&bp);
	TEST("the interval carries the deltas only");
	if (!(sum.cpu == 35 && sum.minflt == 31 && sum.majflt == 3))
		FAIL("expected: sum.cpu == 35 && sum.minflt == 31 && "
		     "sum.majflt == 3");
	TEST("PSS is carried between rollups");
	if (!(sum.pss_ok && sum.pss_kb == 100))
		FAIL("expected: sum.pss_ok && sum.pss_kb == 100");

	/* PID 10 is reused by another process, 11 has exited */
	bench_protected_begin(&bp, &sum);
	proc_at(&p, 9, 5, 5, 0);
	bench_protected_add(&bp, &sum, 10, &p, false);
	bench_protected_end(&bp);
	TEST("a reused PID starts over");
	if (!(sum.count == 1 && sum.cpu == 0 && sum.minflt == 0))
		FAIL("expected: sum.count == 1 && sum.cpu == 0 && sum.minflt "
		     "== 0");
	TEST("and has no PSS until its own rollup");
	if (sum.pss_ok)
		FAIL("expected: !sum.pss_ok");
	TEST("an exited process is dropped");
	if (bp.nprev != 1)
		FAIL("expected: bp.nprev == 1");

	bench_protected_begin(&bp, &sum);
	bench_protected_end(&bp);
	TEST("an empty set is zero, not unknown");
	if (!(sum.count == 0 && sum.pss_ok && sum.pss_kb == 0))
		FAIL("expected: sum.count == 0 && sum.pss_ok && sum.pss_kb == "
		     "0");
}

static void test_protected_sample(void)
{
	static struct bench_protected bp;
	struct bench_protected_sum sum;
	struct bench_pid pid;
	struct bench_proc self = { 0 };
	int dirfd = open("/proc/self", O_RDONLY | O_DIRECTORY | O_CLOEXEC);

	TEST("own start time read");
	if (!(dirfd >= 0 && bench_read_proc(dirfd, &self, false) == 0))
		FAIL("expected: dirfd >= 0 && bench_read_proc(dirfd, &self, "
		     "false) == 0");
	if (dirfd >= 0)
		close(dirfd);

	pid.pid = (uint32_t)getpid();
	pid.start = self.start;
	bench_protected_sample(&bp, &pid, 1, true, &sum);
	TEST("a live protected process is sampled");
	if (!(sum.count == 1 && sum.pss_ok && sum.pss_kb > 0))
		FAIL("expected: sum.count == 1 && sum.pss_ok && sum.pss_kb > 0");

	pid.start = self.start + 1;
	bench_protected_sample(&bp, &pid, 1, true, &sum);
	TEST("a start time mismatch is another process");
	if (sum.count != 0)
		FAIL("expected: sum.count == 0");

	pid.pid = 0;
	bench_protected_sample(&bp, &pid, 1, false, &sum);
	TEST("an unreadable PID is skipped");
	if (sum.count != 0)
		FAIL("expected: sum.count == 0");
}

static void test_format_protected(void)
{
	static struct bench_state st;
	struct bench_protected_sum sum = { .count = 2,
					   .cpu = 3,
					   .minflt = 4,
					   .majflt = 5,
					   .rss_kb = 6,
					   .pss_kb = 7,
					   .pss_ok = true };

	bench_state_init(&st, 0, 0);
	st.clk_tck = 100;
	bench_format_protected(&st, &sum);
	TEST("the protected set is one sum");
	if (strcmp(st.w.buf,
		   ",\"protected\":{\"count\":2,\"cpu_ns\":30000000,"
		   "\"minflt\":4,\"majflt\":5,\"rss_kb\":6,\"pss_kb\":7,"
		   "\"pss_every_ms\":5000}") != 0)
		FAIL("expected: strcmp(st.w.buf, "
		     "\",\\\"protected\\\":{\\\"count\\\":2,\\\"cpu_ns\\\":30000000,\" "
		     "\"\\\"minflt\\\":4,\\\"majflt\\\":5,\\\"rss_kb\\\":6,\\\"pss_kb\\\":7,\" "
		     "\"\\\"pss_every_ms\\\":5000}\") == 0");

	bench_reset(&st.w);
	sum.pss_ok = false;
	bench_format_protected(&st, &sum);
	TEST("an incomplete PSS is null");
	if (strstr(st.w.buf, "\"pss_kb\":null") == NULL)
		FAIL("expected: strstr(st.w.buf, \"\\\"pss_kb\\\":null\") != "
		     "NULL");

	bench_reset(&st.w);
	bench_format_protected(&st, NULL);
	TEST("an unreadable set is null");
	if (strcmp(st.w.buf, ",\"protected\":null") != 0)
		FAIL("expected: strcmp(st.w.buf, \",\\\"protected\\\":null\") "
		     "== 0");
}

static void test_sanitize(void)
{
	char out[LOTA_BENCH_NAME_MAX];

	bench_sanitize_name(out, sizeof(out), "lota_file.open");
	TEST("a plain name is kept");
	if (strcmp(out, "lota_file.open") != 0)
		FAIL("expected: strcmp(out, \"lota_file.open\") == 0");
	bench_sanitize_name(out, sizeof(out), "a\"b\\c/d\n");
	TEST("quotes, slashes and control bytes become underscores");
	if (strcmp(out, "a_b_c_d_") != 0)
		FAIL("expected: strcmp(out, \"a_b_c_d_\") == 0");
	bench_sanitize_name(out, 4, "abcdef");
	TEST("a long name is cut to the buffer");
	if (strcmp(out, "abc") != 0)
		FAIL("expected: strcmp(out, \"abc\") == 0");
}

static void test_memlock(void)
{
	uint64_t v = 0;

	TEST("memlock is read from a map's fdinfo");
	if (!(bench_parse_memlock("map_type:\t27\nmemlock:\t266240\n", &v) ==
		      0 &&
	      v == 266240))
		FAIL("expected: bench_parse_memlock(\"map_type:\\t27\\nmemlock:\\t266240\\n\", "
		     "&v) == 0 && v == 266240");
	TEST("an fdinfo without memlock is refused");
	if (bench_parse_memlock("map_type:\t27\n", &v) != -EINVAL)
		FAIL("expected: bench_parse_memlock(\"map_type:\\t27\\n\", "
		     "&v) == -EINVAL");
}

/* A file that fills the buffer to its last byte still fits */
static void test_memlock_at_buffer_size(void)
{
	char dir[] = "/tmp/lota-bench-fdinfo-XXXXXX";
	char body[4097];
	uint64_t v = 0;
	int dirfd;

	if (!mkdtemp(dir)) {
		TEST("mkdtemp");
		if (!0)
			FAIL("expected: 0");
		return;
	}
	dirfd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);

	memset(body, ' ', sizeof(body) - 1);
	memcpy(body, "memlock:\t7\n", 11);
	body[4095] = '\0';
	TEST("an fdinfo of one byte under the buffer is read");
	if (!(dirfd >= 0 && put(dirfd, "3", body) == 0 &&
	      bench_read_memlock(dirfd, 3, &v) == 0 && v == 7))
		FAIL("expected: dirfd >= 0 && put(dirfd, \"3\", body) == 0 && "
		     "bench_read_memlock(dirfd, 3, &v) == 0 && v == 7");

	body[4095] = ' ';
	body[4096] = '\0';
	TEST("an fdinfo the size of the buffer is refused");
	if (!(put(dirfd, "3", body) == 0 &&
	      bench_read_memlock(dirfd, 3, &v) == -EMSGSIZE))
		FAIL("expected: put(dirfd, \"3\", body) == 0 && "
		     "bench_read_memlock(dirfd, 3, &v) == -EMSGSIZE");

	unlinkat(dirfd, "3", 0);
	close(dirfd);
	rmdir(dir);
}

static void test_schedule(void)
{
	static struct bench_state st;

	bench_state_init(&st, 0, 100 * MS);
	TEST("the first one is due now");
	if (bench_timeout_ms(&st, 100 * MS) != 0)
		FAIL("expected: bench_timeout_ms(&st, 100 * MS) == 0");
	TEST("the first snapshot is taken");
	if (!bench_due(&st, 100 * MS))
		FAIL("expected: bench_due(&st, 100 * MS)");
	TEST("not again within the interval");
	if (bench_due(&st, 600 * MS))
		FAIL("expected: !bench_due(&st, 600 * MS)");
	TEST("the loop sleeps until the next one");
	if (bench_timeout_ms(&st, 600 * MS) != 500)
		FAIL("expected: bench_timeout_ms(&st, 600 * MS) == 500");
	TEST("a partial millisecond rounds up");
	if (bench_timeout_ms(&st, 1099 * MS + 1) != 1)
		FAIL("expected: bench_timeout_ms(&st, 1099 * MS + 1) == 1");
	TEST("due one interval later");
	if (!bench_due(&st, 1100 * MS))
		FAIL("expected: bench_due(&st, 1100 * MS)");

	TEST("a late loop takes one snapshot");
	if (!bench_due(&st, 9500 * MS))
		FAIL("expected: bench_due(&st, 9500 * MS)");
	TEST("and does not replay the missed ones");
	if (bench_due(&st, 9600 * MS))
		FAIL("expected: !bench_due(&st, 9600 * MS)");
	TEST("the schedule restarts from the late tick");
	if (bench_timeout_ms(&st, 9500 * MS) != 1000)
		FAIL("expected: bench_timeout_ms(&st, 9500 * MS) == 1000");
}

int main(void)
{
	test_begin("agent bench snapshot");

	test_parse_stat();
	test_parse_status();
	test_parse_rollup();
	test_read_proc();
	test_read_self();
	test_format();
	test_format_bpf();
	test_bpf_sample();
	test_protected_fold();
	test_protected_sample();
	test_format_protected();
	test_sanitize();
	test_memlock();
	test_memlock_at_buffer_size();
	test_schedule();

	return test_end();
}
