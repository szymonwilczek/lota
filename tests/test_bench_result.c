/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * Unit tests for lota-bench's result writer.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "test.h"
#include "../tools/lota-bench/result.h"

static const char expected[] =
	"{\n"
	"  \"schema_version\": 1,\n"
	"  \"tool\": \"lota-bench\",\n"
	"  \"interval_ms\": 250,\n"
	"  \"samples\": [\n"
	"    {\"t_ms\": 0, \"game\": {\"cpu_usage_usec\": 10, "
	"\"cpu_user_usec\": null, \"cpu_system_usec\": null, "
	"\"memory_current_bytes\": 4096, \"memory_peak_bytes\": null, "
	"\"memory_anon_bytes\": null, \"memory_file_bytes\": null, "
	"\"memory_kernel_bytes\": null, \"pgfault\": null, "
	"\"pgmajfault\": null, \"io_read_bytes\": null, "
	"\"io_write_bytes\": null, \"io_read_ops\": null, "
	"\"io_write_ops\": 18446744073709551615}, \"lota-agent\": null, "
	"\"lota-attest\": null},\n"
	"    {\"t_ms\": 250, \"game\": null, \"lota-agent\": "
	"{\"cpu_usage_usec\": 0, \"cpu_user_usec\": null, "
	"\"cpu_system_usec\": null, \"memory_current_bytes\": null, "
	"\"memory_peak_bytes\": null, \"memory_anon_bytes\": null, "
	"\"memory_file_bytes\": null, \"memory_kernel_bytes\": null, "
	"\"pgfault\": null, \"pgmajfault\": null, \"io_read_bytes\": null, "
	"\"io_write_bytes\": null, \"io_read_ops\": null, "
	"\"io_write_ops\": null}, \"lota-attest\": null}\n"
	"  ],\n"
	"  \"end\": \"game-gone\",\n"
	"  \"self\": {\"cpu_user_usec\": 1, \"cpu_system_usec\": 2, "
	"\"max_rss_bytes\": 3}\n"
	"}\n";

static void write_run(FILE *f, int *ret)
{
	struct bench_sample game = { .have = 0 }, agent = { .have = 0 };
	const struct bench_sample *src[BS_COUNT] = { NULL };
	struct bench_self self = { 1, 2, 3 };

	game.v[BM_CPU_USAGE_USEC] = 10;
	game.v[BM_MEMORY_CURRENT_BYTES] = 4096;
	game.v[BM_IO_WRITE_OPS] = UINT64_MAX;
	/* a value without its bit is not written */
	game.v[BM_PGFAULT] = 99;
	game.have = (1u << BM_CPU_USAGE_USEC) |
		    (1u << BM_MEMORY_CURRENT_BYTES) | (1u << BM_IO_WRITE_OPS);
	agent.have = 1u << BM_CPU_USAGE_USEC;

	ret[0] = bench_write_begin(f, 250);
	src[BS_GAME] = &game;
	ret[1] = bench_write_sample(f, 0, 0, src);
	src[BS_GAME] = NULL;
	src[BS_LOTA_AGENT] = &agent;
	ret[2] = bench_write_sample(f, 1, 250, src);
	ret[3] = bench_write_end(f, BE_GAME_GONE, &self);
}

static void test_layout(void)
{
	char *buf = NULL;
	size_t len = 0;
	int ret[4];
	FILE *f;

	TEST("a run is written byte for byte as documented");

	f = open_memstream(&buf, &len);
	if (!f) {
		FAIL("open_memstream");
		return;
	}
	write_run(f, ret);
	fclose(f);

	if (ret[0] || ret[1] || ret[2] || ret[3])
		FAIL("a write reported failure");
	else if (strcmp(buf, expected) != 0)
		FAIL("output differs from the documented layout");
	else
		PASS();
	free(buf);
}

static void test_full_device(void)
{
	int ret[4];
	FILE *f;
	int fd;

	TEST("a full device fails the run instead of truncating it");

	fd = open("/dev/full", O_WRONLY | O_CLOEXEC);
	f = fd < 0 ? NULL : fdopen(fd, "w");
	if (!f) {
		printf("SKIP (no /dev/full)\n");
		tests_run--;
		return;
	}
	write_run(f, ret);
	fclose(f);

	if (ret[3] != -EIO)
		FAIL("the end of a lost run is reported as written");
	else
		PASS();
}

static void test_names(void)
{
	int i;

	TEST("every source and end reason has a name");

	for (i = 0; i < BS_COUNT; i++) {
		if (!bench_source_names[i]) {
			FAIL("a source has no name");
			return;
		}
	}
	for (i = 0; i < BE_COUNT; i++) {
		if (!bench_end_names[i]) {
			FAIL("an end reason has no name");
			return;
		}
	}
	PASS();
}

int main(void)
{
	printf("lota-bench result writer:\n");

	test_layout();
	test_full_device();
	test_names();

	printf("%d/%d tests passed\n", tests_passed, tests_run);
	return tests_passed == tests_run ? 0 : 1;
}
