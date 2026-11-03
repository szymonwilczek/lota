/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * Unit tests for lota-bench's reader of the agent's bench snapshot.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "test.h"
#include "../tools/lota-bench/agentsnap.h"

static char dir[] = "/tmp/lota-bench-snap-XXXXXX";

/* the shape lota-agent --bench writes */
static const char full[] =
	"{\"version\":1,\"seq\":42,\"uptime_ms\":41003,\"interval_ms\":1000,"
	"\"skipped\":0,"
	"\"agent\":{\"cpu_user_ns\":1,\"cpu_sys_ns\":2,\"minflt\":3,"
	"\"majflt\":0,\"rss_kb\":4,\"pss_kb\":5,\"uss_kb\":6,\"ctxt_vol\":7,"
	"\"ctxt_invol\":8},"
	"\"bpf\":{\"run_stats\":true,\"maps\":17,\"maps_memlock\":65536,"
	"\"progs_dropped\":0,\"progs\":["
	"{\"name\":\"lota_file_open\",\"run_ns\":1000,\"run_cnt\":10},"
	"{\"name\":\"lota_ptrace\",\"run_ns\":500,\"run_cnt\":5}]},"
	"\"protected\":{\"count\":2,\"cpu_ns\":9,\"minflt\":1,\"majflt\":0,"
	"\"rss_kb\":100,\"pss_kb\":null,\"pss_every_ms\":5000}}\n";

static int parse(const char *s, struct bench_agent_snap *out)
{
	return bench_agent_snap_parse(s, strlen(s), out);
}

static void test_full(void)
{
	struct bench_agent_snap s;

	TEST("sums of a full snapshot");
	if (parse(full, &s) || s.seq != 42 || !s.bpf || s.run_ns != 1500 ||
	    s.run_cnt != 15 || !s.memlock_set || s.memlock != 65536 ||
	    !s.protected_set || s.protected_count != 2) {
		FAIL("wrong sums");
		return;
	}
	PASS();
}

static void test_nulls(void)
{
	struct bench_agent_snap s;

	TEST("null parts are reported as absent");
	if (parse("{\"seq\":1,\"agent\":null,\"bpf\":null,\"protected\":null}",
		  &s) ||
	    s.bpf || s.memlock_set || s.protected_set || s.seq != 1) {
		FAIL("absent part set");
		return;
	}
	if (parse("{\"bpf\":{\"maps_memlock\":null,\"progs\":[]}}", &s) ||
	    !s.bpf || s.memlock_set || s.run_ns) {
		FAIL("empty bpf");
		return;
	}
	PASS();
}

static void test_refused(void)
{
	static const char *const bad[] = {
		"",
		"[]",
		"{\"seq\":1",
		"{\"seq\":1,}",
		"{\"seq\":\"1\"}",
		"{\"bpf\":{\"progs\":[{\"run_ns\":null}]}}",
		"{\"protected\":{\"count\":-1}}",
		"{\"x\":[[[[[[1]]]]]]}",
		"{\"seq\":1} {}",
		"{\"seq\":1,\"seq\"}",
	};
	struct bench_agent_snap s;

	TEST("malformed snapshots are refused and leave zeros");
	for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
		if (parse(bad[i], &s) != -EINVAL || s.seq || s.run_ns) {
			FAIL(bad[i]);
			return;
		}
	}
	PASS();
}

static void put(const char *name, const char *body, size_t len)
{
	char path[256];
	FILE *f;
	int fd;

	snprintf(path, sizeof(path), "%s/%s", dir, name);
	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	f = fd < 0 ? NULL : fdopen(fd, "w");
	if (!f || fwrite(body, 1, len, f) != len) {
		perror(path);
		exit(1);
	}
	fclose(f);
}

static void test_read(void)
{
	struct bench_agent_snap s;
	char path[256], *big;
	int fd;

	TEST("read: file, missing, link and oversized");
	fd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	put("bench.json", full, strlen(full));
	if (bench_agent_snap_read(fd, "bench.json", &s) || s.seq != 42) {
		FAIL("file");
		goto out;
	}
	if (bench_agent_snap_read(fd, "missing.json", &s) != -ENOENT) {
		FAIL("missing");
		goto out;
	}
	snprintf(path, sizeof(path), "%s/link.json", dir);
	if (symlink("bench.json", path) ||
	    bench_agent_snap_read(fd, "link.json", &s) != -ELOOP) {
		FAIL("link followed");
		goto out;
	}
	big = malloc(BENCH_AGENT_SNAP_MAX);
	memset(big, ' ', BENCH_AGENT_SNAP_MAX);
	memcpy(big, full, strlen(full));
	put("big.json", big, BENCH_AGENT_SNAP_MAX);
	free(big);
	if (bench_agent_snap_read(fd, "big.json", &s) != -EFBIG) {
		FAIL("oversized");
		goto out;
	}
	PASS();
out:
	close(fd);
}

int main(void)
{
	char cmd[256];

	if (!mkdtemp(dir)) {
		perror("mkdtemp");
		return 1;
	}

	printf("lota-bench agent snapshot reader:\n");

	test_full();
	test_nulls();
	test_refused();
	test_read();

	snprintf(cmd, sizeof(cmd), "rm -rf -- '%s'", dir);
	if (system(cmd) != 0)
		fprintf(stderr, "cleanup of %s failed\n", dir);

	printf("%d/%d tests passed\n", tests_passed, tests_run);
	return tests_passed == tests_run ? 0 : 1;
}
