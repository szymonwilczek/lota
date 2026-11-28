/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * Unit tests for lota-bench run on the files of a session.
 *
 * Taking a run needs a game and LOTA in a given state, so these tests
 * stop short of it: they lay out a session whose runs are all taken and
 * check how lota-bench run joins them, and what it refuses.
 */

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "test.h"
#include "../tools/lota-bench/run.h"
#include "../tools/lota-bench/validate.h"

#define ROUNDS 2
#define NRUNS (1 + BC_COUNT * ROUNDS)

static char base[] = "/tmp/lota-bench-run-XXXXXX";
static struct bench_doc *doc;
static char *expected_result;

static void set(struct bench_field *f, const char *s)
{
	bench_field_set(f, s, strlen(s));
}

static void fill_plan(struct bench_plan *p)
{
	memset(p, 0, sizeof(*p));
	set(&p->version, "1.0.0");
	set(&p->machine.cpu_model, "Test CPU 8-Core");
	p->machine.cpu_threads = 16;
	p->machine.memory_bytes = 32ull << 30;
	set(&p->machine.kernel, "6.0.0-test");
	set(&p->machine.tpm, "none");
	set(&p->game.title, "Example Title");
	p->rounds = ROUNDS;
	p->settle_s = 30;
	p->duration_s = 600;
	p->interval_ms = 1000;
}

static void fill_run(struct bench_run *r, unsigned int i)
{
	memset(r, 0, sizeof(*r));
	r->index = i;
	r->config = bench_run_config(i);
	r->warmup = i == 0;
	r->wall_ms = 1000;
	r->sample_count = 2;
	r->end = BE_DURATION;
	r->totals[BS_GAME].present = true;
	r->totals[BS_GAME].v[BT_CPU_USEC] = (struct bench_opt){ 10, true };
	if (r->config == BC_A)
		return;
	r->mode = BMO_ENFORCE;
	r->agent_bench = true;
	r->totals[BS_LOTA_AGENT].present = true;
	r->agent.present = true;
	r->agent.v[BA_PROTECTED_MAX] =
		(struct bench_opt){ r->config == BC_C ? 1 : 0, true };
}

static char *write_run(unsigned int i)
{
	const struct bench_sample *src[BS_COUNT] = { NULL };
	struct bench_sample game = { .have = 1u << BM_CPU_USAGE_USEC };
	struct bench_run r;
	char *buf = NULL;
	size_t len = 0;
	FILE *f;

	f = open_memstream(&buf, &len);
	if (!f)
		return NULL;
	fill_run(&r, i);
	src[BS_GAME] = &game;
	bench_write_run_begin(f, &r);
	bench_write_sample(f, 0, 0, src);
	bench_write_sample(f, 1, 1000, src);
	bench_write_run_end(f, &r);
	fclose(f);
	return buf;
}

static int put(const char *dir, const char *name, const char *s)
{
	char path[256];
	FILE *f;
	int fd, ret;

	snprintf(path, sizeof(path), "%s/%s", dir, name);
	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	if (fd < 0)
		return -1;
	f = fdopen(fd, "w");
	if (!f) {
		close(fd);
		return -1;
	}
	ret = fputs(s, f) < 0;
	return fclose(f) || ret ? -1 : 0;
}

static char *get(const char *dir, const char *name)
{
	char path[256], *buf = NULL;
	size_t len = 0;
	FILE *f, *m;
	int c;

	snprintf(path, sizeof(path), "%s/%s", dir, name);
	f = fopen(path, "r");
	if (!f)
		return NULL;
	m = open_memstream(&buf, &len);
	if (m) {
		while ((c = fgetc(f)) != EOF)
			fputc(c, m);
		fclose(m);
	}
	fclose(f);
	return buf;
}

static bool exists(const char *dir, const char *name)
{
	char path[256];

	snprintf(path, sizeof(path), "%s/%s", dir, name);
	return access(path, F_OK) == 0;
}

/* a session in @name under the base whose runs are all taken */
static int lay_out(const char *name, char *dir, size_t cap)
{
	char *plan = NULL, file[32];
	size_t len = 0;
	FILE *f;

	snprintf(dir, cap, "%s/%s", base, name);
	if (mkdir(dir, 0755))
		return -1;
	f = open_memstream(&plan, &len);
	if (!f)
		return -1;
	bench_write_plan(f, &doc->plan);
	fclose(f);
	if (put(dir, "plan.json", plan)) {
		free(plan);
		return -1;
	}
	free(plan);
	for (unsigned int i = 0; i < NRUNS; i++) {
		char *run = write_run(i);
		int ret;

		snprintf(file, sizeof(file), "run-%02u.json", i);
		ret = !run || put(dir, file, run);
		free(run);
		if (ret)
			return -1;
	}
	return 0;
}

static int run_argv(int argc, char **argv)
{
	int fd, saved, ret;

	/* what it prints for a person is not under test */
	fflush(stdout);
	saved = dup(STDOUT_FILENO);
	fd = open("/dev/null", O_WRONLY);
	if (fd >= 0) {
		dup2(fd, STDOUT_FILENO);
		close(fd);
	}
	optind = 0;
	ret = bench_main_run(argc, argv);
	fflush(stdout);
	if (saved >= 0) {
		dup2(saved, STDOUT_FILENO);
		close(saved);
	}
	return ret;
}

static int run(const char *dir, const char *opt, const char *val)
{
	char *argv[5] = { "run", (char *)dir, (char *)opt, (char *)val, NULL };

	return run_argv(opt ? 4 : 2, argv);
}

static void test_assemble(void)
{
	char dir[128], *got;

	TEST("a session whose runs are taken joins into its result");

	if (lay_out("whole", dir, sizeof(dir))) {
		FAIL("laying out the session");
		return;
	}
	if (run(dir, NULL, NULL) != 0) {
		FAIL("lota-bench run failed");
		return;
	}
	got = get(dir, "result.json");
	if (!got)
		FAIL("no result.json");
	else if (strcmp(got, expected_result) != 0)
		FAIL("result.json is not the session's result");
	else if (exists(dir, ".result.json.tmp"))
		FAIL("the temporary file is left behind");
	else
		PASS();
	free(got);

	TEST("a complete session is left as it is");
	got = get(dir, "result.json");
	if (run(dir, NULL, NULL) != 0)
		FAIL("lota-bench run failed");
	else if (!got || !expected_result || strcmp(got, expected_result))
		FAIL("result.json changed");
	else
		PASS();
	free(got);
}

static void test_refusals(void)
{
	char dir[128], path[256], target[256];
	char *dense[] = { "run",
			  dir,
			  "--game",
			  "Example Title",
			  "--duration-s",
			  "3600",
			  "--interval-ms",
			  "100",
			  NULL };
	char *other;

	TEST("a run file under another run's name is refused");
	if (lay_out("swapped", dir, sizeof(dir))) {
		FAIL("laying out the session");
		return;
	}
	other = write_run(4);
	if (!other || put(dir, "run-01.json", other))
		FAIL("writing the run");
	else if (run(dir, NULL, NULL) != 1 || exists(dir, "result.json"))
		FAIL("joined a run under the wrong name");
	else
		PASS();
	free(other);

	TEST("a run file that is a link is refused");
	if (lay_out("linked", dir, sizeof(dir))) {
		FAIL("laying out the session");
		return;
	}
	snprintf(path, sizeof(path), "%s/run-02.json", dir);
	snprintf(target, sizeof(target), "%s/swapped/run-02.json", base);
	if (unlink(path) || symlink(target, path))
		FAIL("planting the link");
	else if (run(dir, NULL, NULL) != 1 || exists(dir, "result.json"))
		FAIL("followed the link");
	else
		PASS();

	TEST("options do not change a session that has begun");
	if (run(dir, "--game", "Other Title") != EXIT_BENCH_USAGE)
		FAIL("accepted --game on a session");
	else if (run(dir, "--rounds", "3") != EXIT_BENCH_USAGE)
		FAIL("accepted --rounds on a session");
	else
		PASS();

	TEST("a directory without a plan holds no session");
	snprintf(dir, sizeof(dir), "%s/empty", base);
	if (mkdir(dir, 0755) || run(dir, NULL, NULL) != 1)
		FAIL("took a run without a plan");
	else
		PASS();

	TEST("a path the launch options cannot carry is refused");
	snprintf(dir, sizeof(dir), "%s/a,b", base);
	if (run(dir, "--game", "Example Title") != 1 || exists(base, "a,b"))
		FAIL("began a session under a ','");
	else
		PASS();

	TEST("a session refused for its options leaves no directory");
	snprintf(dir, sizeof(dir), "%s/refused", base);
	if (run(dir, "--rounds", "3") != EXIT_BENCH_USAGE ||
	    exists(base, "refused"))
		FAIL("left the directory without --game");
	else if (run_argv(8, dense) != 1 || exists(base, "refused"))
		FAIL("left the directory past the sample limit");
	else if (mkdir(dir, 0755) ||
		 run(dir, "--rounds", "3") != EXIT_BENCH_USAGE ||
		 !exists(base, "refused"))
		FAIL("removed a directory it did not make");
	else
		PASS();
}

static int setup(void)
{
	struct bench_doc *one = malloc(sizeof(*one));
	char err[256], *runs[NRUNS] = { NULL };
	size_t len = 0;
	int ret = -1;
	FILE *f;

	doc = calloc(1, sizeof(*doc));
	if (!doc || !one || !mkdtemp(base))
		goto out;
	fill_plan(&doc->plan);
	for (unsigned int i = 0; i < NRUNS; i++) {
		runs[i] = write_run(i);
		if (!runs[i] || bench_validate(runs[i], strlen(runs[i]), one,
					       err, sizeof(err))) {
			printf("run %u: %s\n", i, runs[i] ? err : "write");
			goto out;
		}
		doc->runs[i] = one->runs[0];
	}
	doc->nruns = NRUNS;
	f = open_memstream(&expected_result, &len);
	if (!f)
		goto out;
	bench_write_session(f, doc, BK_RESULT);
	fclose(f);
	ret = 0;
out:
	for (unsigned int i = 0; i < NRUNS; i++)
		free(runs[i]);
	free(one);
	return ret;
}

static void cleanup(void)
{
	char cmd[sizeof(base) + 16];

	snprintf(cmd, sizeof(cmd), "rm -rf -- '%s'", base);
	if (strncmp(base, "/tmp/lota-bench-run-", 20) == 0 &&
	    !strchr(base, '\''))
		(void)!system(cmd);
}

static void test_find_log(void)
{
	char dir[sizeof(base) + 16], path[sizeof(dir) + 16], name[64];
	int fd, log;

	TEST("the log is found on every look at a session");
	snprintf(dir, sizeof(dir), "%s/logs", base);
	snprintf(path, sizeof(path), "%s/Title_1.csv", dir);
	fd = mkdir(dir, 0700) ? -1 : open(dir, O_RDONLY | O_DIRECTORY);
	log = fd < 0 ? -1 : open(path, O_WRONLY | O_CREAT, 0600);
	if (log < 0) {
		FAIL("session");
		goto out;
	}
	close(log);
	if (bench_run_find_log(fd, 0, name, sizeof(name)) ||
	    strcmp(name, "Title_1.csv")) {
		FAIL("first look");
		goto out;
	}
	if (bench_run_find_log(fd, 0, name, sizeof(name)) ||
	    strcmp(name, "Title_1.csv")) {
		FAIL("second look");
		goto out;
	}
	PASS();
out:
	if (fd >= 0)
		close(fd);
	unlink(path);
	rmdir(dir);
}

static void test_warm(void)
{
	char dir[sizeof(base) + 16], path[sizeof(dir) + 16];
	int fd;

	TEST("a session is warm only in the boot it warmed up in");
	snprintf(dir, sizeof(dir), "%s/boots", base);
	snprintf(path, sizeof(path), "%s/boot_id", dir);
	fd = mkdir(dir, 0700) ? -1 : open(dir, O_RDONLY | O_DIRECTORY);
	if (fd < 0) {
		FAIL("session");
		return;
	}
	if (bench_run_warm(fd, "boot-a")) {
		FAIL("warm before any run");
		goto out;
	}
	if (bench_run_note_boot(fd, "boot-a") ||
	    !bench_run_warm(fd, "boot-a")) {
		FAIL("cold in the boot it warmed up in");
		goto out;
	}
	if (bench_run_warm(fd, "boot-b")) {
		FAIL("warm after a reboot");
		goto out;
	}
	if (bench_run_note_boot(fd, "boot-b") ||
	    !bench_run_warm(fd, "boot-b") || bench_run_warm(fd, "boot-a")) {
		FAIL("the later boot does not replace the earlier");
		goto out;
	}
	if (exists(dir, ".boot_id.tmp")) {
		FAIL("the temporary file is left behind");
		goto out;
	}
	if (unlink(path) || symlink("boot-a", path)) {
		FAIL("planting the link");
		goto out;
	}
	if (bench_run_warm(fd, "boot-a")) {
		FAIL("followed a link");
		goto out;
	}
	PASS();
out:
	close(fd);
	unlink(path);
	rmdir(dir);
}

int main(void)
{
	printf("lota-bench run:\n");

	if (setup()) {
		printf("setup failed\n");
		cleanup();
		return 1;
	}
	test_assemble();
	test_refusals();
	test_warm();
	test_find_log();

	cleanup();
	free(expected_result);
	free(doc);
	printf("%d/%d tests passed\n", tests_passed, tests_run);
	return tests_passed == tests_run ? 0 : 1;
}
