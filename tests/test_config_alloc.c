/* SPDX-License-Identifier: MIT */
/*
 * Unit tests for the heap constructor pair, config_new/config_free,
 * and for the bounds of the fixed arrays that make struct lota_config
 * too large to hold in an automatic.
 *
 * The struct is over a megabyte, a megabyte of which is the fs-verity allow-list.
 * These tests pin the three properties a caller replacing a local with config_new()
 * depends on: the object it hands back carries exactly the defaults config_init()
 * writes, it parses a file the same way a local did, and it works on a thread
 * whose stack could never have held the local.
 *
 * The bound tests then walk each array to its last slot and one past it,
 * so the size that forces the allocation is also the size the parser enforces.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../src/agent/config.h"
#include "lota.h"

#include "test.h"

/* Write a config file and hand back its path in @path_out */
static int write_cfg(char *path_out, size_t path_size, const char *body)
{
	char path[] = "/tmp/lota_cfg_allocXXXXXX";
	int fd = mkstemp(path);
	FILE *fp;

	if (fd < 0)
		return -1;

	fp = fdopen(fd, "w");
	if (!fp) {
		close(fd);
		unlink(path);
		return -1;
	}
	fputs(body, fp);
	fclose(fp);

	snprintf(path_out, path_size, "%s", path);
	return 0;
}

/* Parse @body into a fresh config; returns config_load's result */
static int load_body(struct lota_config *cfg, const char *body)
{
	char path[PATH_MAX];
	int rc;

	if (write_cfg(path, sizeof(path), body) != 0)
		return -1;

	rc = config_load(cfg, path);
	unlink(path);
	return rc;
}

/*
 * Build a body repeating "<key> = <prefix><n>" @count times, numbering from @start.
 * protect_pid refuses zero, so the numbered lists start at one.
 */
static char *repeat_key(const char *key, const char *prefix, int count,
			int start)
{
	size_t cap = (size_t)count * 128u + 64u;
	char *buf = calloc(1, cap);
	size_t used = 0;
	int i;

	if (!buf)
		return NULL;

	for (i = 0; i < count; i++) {
		int n = snprintf(buf + used, cap - used, "%s = %s%d\n", key,
				 prefix, start + i);

		if (n < 0 || (size_t)n >= cap - used) {
			free(buf);
			return NULL;
		}
		used += (size_t)n;
	}
	return buf;
}

/*
 * The defaults must not depend on where the object lives.
 * Compared against a heap block config_init() filled directly, so the test does
 * not itself take the frame this API exists to avoid.
 */
static void test_defaults_match_config_init(void)
{
	struct lota_config *made = config_new();
	struct lota_config *ref = calloc(1, sizeof(*ref));

	TEST("config_new returns a config");
	if (made == NULL)
		FAIL("expected: made != NULL");
	TEST("reference block allocated");
	if (ref == NULL)
		FAIL("expected: ref != NULL");
	if (!made || !ref) {
		config_free(made);
		free(ref);
		return;
	}

	config_init(ref);
	TEST("every byte matches a config_init'd block");
	if (memcmp(made, ref, sizeof(*made)) != 0)
		FAIL("expected: memcmp(made, ref, sizeof(*made)) == 0");

	config_free(made);
	free(ref);
}

/* Returned config is a working config: it parses a file */
static void test_parses_a_file(void)
{
	struct lota_config *cfg = config_new();

	TEST("config_new returns a config");
	if (cfg == NULL)
		FAIL("expected: cfg != NULL");
	if (!cfg)
		return;

	TEST("config_load succeeds");
	if (load_body(cfg, "server = attest.example.org\nport = 4711\n") != 0)
		FAIL("expected: load_body(cfg, \"server = "
		     "attest.example.org\\nport = 4711\\n\") == 0");
	TEST("server parsed into the allocated config");
	if (strcmp(cfg->server, "attest.example.org") != 0)
		FAIL("expected: strcmp(cfg->server, \"attest.example.org\") "
		     "== 0");
	TEST("port parsed into the allocated config");
	if (cfg->port != 4711)
		FAIL("expected: cfg->port == 4711");

	config_free(cfg);
}

/*
 * Repeated construction must not hand back the same live block
 * or leave the previous one's contents behind
 */
static void test_each_config_is_independent(void)
{
	struct lota_config *a = config_new();
	struct lota_config *b;

	TEST("first config allocated");
	if (a == NULL)
		FAIL("expected: a != NULL");
	if (!a)
		return;

	snprintf(a->server, sizeof(a->server), "%s", "first.example.org");

	b = config_new();
	TEST("second config allocated");
	if (b == NULL)
		FAIL("expected: b != NULL");
	if (!b) {
		config_free(a);
		return;
	}

	TEST("the two configs are distinct objects");
	if (a == b)
		FAIL("expected: a != b");
	TEST("the second config does not carry the first one's writes");
	if (strcmp(b->server, "first.example.org") == 0)
		FAIL("expected: strcmp(b->server, \"first.example.org\") != 0");

	config_free(a);
	config_free(b);
}

/*
 * The reason the constructor exists.
 *
 * A thread gets this much stack -- far less than the struct -- so a local would
 * run off the end of it before config_init finished zeroing.
 * Allocating instead, the same work completes. The size is checked against the struct
 * at runtime so the test cannot quietly stop proving anything if the struct
 * is ever made small enough to hold in a frame again.
 */
#define SMALL_THREAD_STACK (512u * 1024u)

static void *load_on_small_stack(void *arg)
{
	int *ok = arg;
	struct lota_config *cfg = config_new();

	*ok = 0;
	if (!cfg)
		return NULL;

	if (load_body(cfg, "server = small.example.org\nport = 1234\n") == 0 &&
	    strcmp(cfg->server, "small.example.org") == 0 && cfg->port == 1234)
		*ok = 1;

	config_free(cfg);
	return NULL;
}

static void test_works_on_a_stack_smaller_than_the_struct(void)
{
	pthread_attr_t attr;
	pthread_t th;
	int ok = 0;

	TEST("the struct is larger than the whole thread stack");
	if (sizeof(struct lota_config) <= SMALL_THREAD_STACK)
		FAIL("expected: sizeof(struct lota_config) > "
		     "SMALL_THREAD_STACK");

	if (pthread_attr_init(&attr) != 0) {
		TEST("pthread_attr_init");
		if (!0)
			FAIL("expected: 0");
		return;
	}
	if (pthread_attr_setstacksize(&attr, SMALL_THREAD_STACK) != 0) {
		pthread_attr_destroy(&attr);
		TEST("pthread_attr_setstacksize");
		if (!0)
			FAIL("expected: 0");
		return;
	}
	if (pthread_create(&th, &attr, load_on_small_stack, &ok) != 0) {
		pthread_attr_destroy(&attr);
		TEST("pthread_create");
		if (!0)
			FAIL("expected: 0");
		return;
	}

	pthread_join(th, NULL);
	pthread_attr_destroy(&attr);

	TEST("config allocated and parsed on the small stack");
	if (ok != 1)
		FAIL("expected: ok == 1");
}

/*
 * Every fixed array is refused one entry past its last slot.
 * Each list is filled to exactly its bound, then to one more.
 */
static void test_list_bounds(const char *what, const char *key,
			     const char *prefix, int max, int start,
			     int (*count_of)(const struct lota_config *))
{
	struct lota_config *cfg;
	char name[TEST_NAME_MAX + 1];
	char *body;

	snprintf(name, sizeof(name), "%s: exactly %d entries parse", what, max);
	TEST(name);
	cfg = config_new();
	body = repeat_key(key, prefix, max, start);
	if (!cfg || !body)
		FAIL("allocation failed");
	else if (load_body(cfg, body) != 0)
		FAIL("load_body refused %d entries", max);
	else if (count_of(cfg) != max)
		FAIL("recorded %d entries, expected %d", count_of(cfg), max);
	free(body);
	config_free(cfg);

	snprintf(name, sizeof(name), "%s: entry %d is refused", what, max + 1);
	TEST(name);
	cfg = config_new();
	body = repeat_key(key, prefix, max + 1, start);
	if (!cfg || !body)
		FAIL("allocation failed");
	else if (load_body(cfg, body) == 0)
		FAIL("load_body accepted %d entries", max + 1);
	else if (count_of(cfg) > max)
		FAIL("recorded %d entries, max %d", count_of(cfg), max);
	free(body);
	config_free(cfg);
}

static int verity_count(const struct lota_config *c)
{
	return c->allow_verity_count;
}

static int lib_count(const struct lota_config *c)
{
	return c->trust_lib_count;
}

static int pid_count(const struct lota_config *c)
{
	return c->protect_pid_count;
}

static int listener_count(const struct lota_config *c)
{
	return c->container_listener_uid_count;
}

/*
 * A value longer than the cell it lands in must be truncated, not written past.
 * The parser caps a line at LOTA_CONFIG_MAX_LINE, so the longest value that can
 * reach a PATH_MAX cell is already shorter than it -- this pins that the shorter
 * cells behind the same path are bounded too.
 */
static void test_overlong_value_is_bounded(void)
{
	struct lota_config *cfg = config_new();
	char body[LOTA_CONFIG_MAX_LINE * 2];
	size_t fill = sizeof(body) / 2;
	size_t i;

	TEST("config allocated");
	if (cfg == NULL)
		FAIL("expected: cfg != NULL");
	if (!cfg)
		return;

	memcpy(body, "server = ", 9);
	for (i = 9; i < fill; i++)
		body[i] = 'a';
	body[fill] = '\n';
	body[fill + 1] = '\0';

	/* Parsing may accept or reject; neither may write past the field */
	(void)load_body(cfg, body);
	TEST("server stays within its cell");
	if (strlen(cfg->server) >= sizeof(cfg->server))
		FAIL("expected: strlen(cfg->server) < sizeof(cfg->server)");
	TEST("server is still terminated");
	if (cfg->server[sizeof(cfg->server) - 1] != '\0')
		FAIL("expected: cfg->server[sizeof(cfg->server) - 1] == '\\0'");

	config_free(cfg);
}

int main(void)
{
	test_begin("config alloc");

	test_defaults_match_config_init();
	test_parses_a_file();
	test_each_config_is_independent();
	test_works_on_a_stack_smaller_than_the_struct();

	test_list_bounds("allow_verity", "allow_verity", "/opt/lota/f",
			 LOTA_CONFIG_MAX_VERITY, 0, verity_count);
	test_list_bounds("trust_lib", "trust_lib", "/opt/lota/lib",
			 LOTA_CONFIG_MAX_LIBS, 0, lib_count);
	test_list_bounds("protect_pid", "protect_pid", "",
			 LOTA_MAX_PROTECTED_PIDS, 1, pid_count);
	test_list_bounds("container_listener_uid", "container_listener_uid", "",
			 LOTA_CONFIG_MAX_CONTAINER_LISTENERS, 0,
			 listener_count);

	test_overlong_value_is_bounded();

	return test_end();
}
