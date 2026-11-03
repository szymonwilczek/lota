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
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../src/agent/bench_snapshot.h"

static int g_failures;

#define CHECK(cond, msg)                                    \
	do {                                                \
		if (!(cond)) {                              \
			fprintf(stderr, "FAIL: %s\n", msg); \
			g_failures++;                       \
		} else {                                    \
			printf("PASS: %s\n", msg);          \
		}                                           \
	} while (0)

#define MS 1000000ULL

/* comm with a space and a paren, as a title may name its process */
static const char k_stat[] =
	"4242 (game) x) S 1 4242 4242 0 -1 4194560 120 0 3 0 250 40 0 0 "
	"20 0 4 0 100 2000000 500 18446744073709551615\n";

static const char k_status[] = "Name:\tgame\n"
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

	CHECK(bench_parse_stat(k_stat, &p) == 0, "stat parses");
	CHECK(p.minflt == 120 && p.majflt == 3, "page faults read past comm");
	CHECK(p.utime == 250 && p.stime == 40, "CPU ticks read past comm");
	CHECK(bench_parse_stat("4242 (game S 1", &p) == -EINVAL,
	      "a stat without a closing paren is refused");
	CHECK(bench_parse_stat("4242 (game) S 1 2 3\n", &p) == -EINVAL,
	      "a short stat is refused");
}

static void test_parse_status(void)
{
	struct bench_proc p = { 0 };

	CHECK(bench_parse_status(k_status, &p) == 0, "status parses");
	CHECK(p.ctxt_vol == 77 && p.ctxt_invol == 5,
	      "voluntary and involuntary switches are told apart");
	CHECK(bench_parse_status("Name:\tgame\n", &p) == -EINVAL,
	      "a status without switch counters is refused");
}

static void test_parse_rollup(void)
{
	struct bench_proc p = { 0 };

	CHECK(bench_parse_rollup(k_rollup, &p) == 0, "smaps_rollup parses");
	CHECK(p.rss_kb == 2048 && p.pss_kb == 1024, "Pss is not Pss_Anon");
	CHECK(p.uss_kb == 384, "USS is the private pages");
	CHECK(bench_parse_rollup("Rss: 1 kB\n", &p) == -EINVAL,
	      "a rollup without Pss is refused");
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
		CHECK(0, "mkdtemp");
		return;
	}
	dirfd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	CHECK(dirfd >= 0 && put(dirfd, "stat", k_stat) == 0 &&
		      put(dirfd, "status", k_status) == 0,
	      "synthetic proc directory written");

	CHECK(bench_read_proc(dirfd, &p) == -ENOENT,
	      "a missing smaps_rollup fails the read");

	CHECK(symlinkat("status", dirfd, "smaps_rollup") == 0,
	      "smaps_rollup planted as a symlink");
	CHECK(bench_read_proc(dirfd, &p) == -ELOOP,
	      "a symlinked proc file is not followed");
	unlinkat(dirfd, "smaps_rollup", 0);

	CHECK(put(dirfd, "smaps_rollup", k_rollup) == 0, "rollup written");
	CHECK(bench_read_proc(dirfd, &p) == 0 && p.utime == 250 &&
		      p.ctxt_vol == 77 && p.pss_kb == 1024,
	      "all three files land in one sample");

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

	CHECK(dirfd >= 0 && bench_read_proc(dirfd, &p) == 0,
	      "the test's own counters read");
	CHECK(p.rss_kb > 0 && p.pss_kb > 0,
	      "a live process has resident pages");
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
	CHECK(strncmp(st.w.buf, "{\"version\":1,\"seq\":3,\"uptime_ms\":3000,",
		      38) == 0,
	      "the header carries version, sequence and uptime");
	CHECK(strstr(st.w.buf, "\"cpu_user_ns\":2500000000,") &&
		      strstr(st.w.buf, "\"cpu_sys_ns\":400000000,"),
	      "CPU ticks are written as nanoseconds");
	CHECK(strstr(st.w.buf, "\"pss_kb\":1024,") != NULL, "PSS is written");
	CHECK(st.w.len > 0 && st.w.buf[st.w.len - 1] == '\n' &&
		      strstr(st.w.buf, "}}\n"),
	      "the snapshot is one closed object on one line");

	bench_reset(&st.w);
	bench_format(&st, 3010 * MS, NULL);
	CHECK(strstr(st.w.buf, "\"agent\":null}\n") != NULL,
	      "unreadable counters are written as null, not zero");
	CHECK(!st.w.overflow, "a full snapshot fits the cap");
}

static void test_schedule(void)
{
	static struct bench_state st;

	bench_state_init(&st, 0, 100 * MS);
	CHECK(bench_timeout_ms(&st, 100 * MS) == 0, "the first one is due now");
	CHECK(bench_due(&st, 100 * MS), "the first snapshot is taken");
	CHECK(!bench_due(&st, 600 * MS), "not again within the interval");
	CHECK(bench_timeout_ms(&st, 600 * MS) == 500,
	      "the loop sleeps until the next one");
	CHECK(bench_timeout_ms(&st, 1099 * MS + 1) == 1,
	      "a partial millisecond rounds up");
	CHECK(bench_due(&st, 1100 * MS), "due one interval later");

	CHECK(bench_due(&st, 9500 * MS), "a late loop takes one snapshot");
	CHECK(!bench_due(&st, 9600 * MS),
	      "and does not replay the missed ones");
	CHECK(bench_timeout_ms(&st, 9500 * MS) == 1000,
	      "the schedule restarts from the late tick");
}

int main(void)
{
	printf("=== agent bench snapshot tests ===\n\n");

	test_parse_stat();
	test_parse_status();
	test_parse_rollup();
	test_read_proc();
	test_read_self();
	test_format();
	test_schedule();

	printf("\n%s: %d failure(s)\n", g_failures ? "FAILED" : "OK",
	       g_failures);
	return g_failures ? 1 : 0;
}
