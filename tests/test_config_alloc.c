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

static int failures;

#define CHECK(cond, msg)                                              \
	do {                                                          \
		if (!(cond)) {                                        \
			printf("  FAIL: %s (%s:%d)\n", msg, __FILE__, \
			       __LINE__);                             \
			failures++;                                   \
		} else {                                              \
			printf("  ok: %s\n", msg);                    \
		}                                                     \
	} while (0)

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

	printf("test: config_new applies the same defaults as config_init\n");

	CHECK(made != NULL, "config_new returns a config");
	CHECK(ref != NULL, "reference block allocated");
	if (!made || !ref) {
		config_free(made);
		free(ref);
		return;
	}

	config_init(ref);
	CHECK(memcmp(made, ref, sizeof(*made)) == 0,
	      "every byte matches a config_init'd block");

	config_free(made);
	free(ref);
}

/* Returned config is a working config: it parses a file */
static void test_parses_a_file(void)
{
	struct lota_config *cfg = config_new();

	printf("test: a config_new config loads a file\n");

	CHECK(cfg != NULL, "config_new returns a config");
	if (!cfg)
		return;

	CHECK(load_body(cfg, "server = attest.example.org\nport = 4711\n") == 0,
	      "config_load succeeds");
	CHECK(strcmp(cfg->server, "attest.example.org") == 0,
	      "server parsed into the allocated config");
	CHECK(cfg->port == 4711, "port parsed into the allocated config");

	config_free(cfg);
}

/* free(NULL) is a no-op, and so is this */
static void test_free_null_is_a_noop(void)
{
	printf("test: config_free tolerates NULL\n");
	config_free(NULL);
	CHECK(1, "config_free(NULL) returned");
}

/*
 * Repeated construction must not hand back the same live block
 * or leave the previous one's contents behind
 */
static void test_each_config_is_independent(void)
{
	struct lota_config *a = config_new();
	struct lota_config *b;

	printf("test: each config_new is a fresh, independent object\n");

	CHECK(a != NULL, "first config allocated");
	if (!a)
		return;

	snprintf(a->server, sizeof(a->server), "%s", "first.example.org");

	b = config_new();
	CHECK(b != NULL, "second config allocated");
	if (!b) {
		config_free(a);
		return;
	}

	CHECK(a != b, "the two configs are distinct objects");
	CHECK(strcmp(b->server, "first.example.org") != 0,
	      "the second config does not carry the first one's writes");

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

	printf("test: the config path runs on a %u KiB stack\n",
	       SMALL_THREAD_STACK / 1024u);

	CHECK(sizeof(struct lota_config) > SMALL_THREAD_STACK,
	      "the struct is larger than the whole thread stack");

	if (pthread_attr_init(&attr) != 0) {
		CHECK(0, "pthread_attr_init");
		return;
	}
	if (pthread_attr_setstacksize(&attr, SMALL_THREAD_STACK) != 0) {
		pthread_attr_destroy(&attr);
		CHECK(0, "pthread_attr_setstacksize");
		return;
	}
	if (pthread_create(&th, &attr, load_on_small_stack, &ok) != 0) {
		pthread_attr_destroy(&attr);
		CHECK(0, "pthread_create");
		return;
	}

	pthread_join(th, NULL);
	pthread_attr_destroy(&attr);

	CHECK(ok == 1, "config allocated and parsed on the small stack");
}

/*
 * Every fixed array is refused one entry past its last slot.
 * Each list is filled to exactly its bound, then to one more.
 */
static void test_list_bounds(const char *what, const char *key,
			     const char *prefix, int max, int start,
			     int (*count_of)(const struct lota_config *))
{
	struct lota_config *cfg = config_new();
	char *body;

	printf("test: %s stops at %d entries\n", what, max);

	CHECK(cfg != NULL, "config allocated");
	if (!cfg)
		return;

	body = repeat_key(key, prefix, max, start);
	CHECK(body != NULL, "full-length body built");
	if (body) {
		CHECK(load_body(cfg, body) == 0, "exactly max entries parse");
		CHECK(count_of(cfg) == max, "all max entries are recorded");
		free(body);
	}

	config_free(cfg);
	cfg = config_new();
	if (!cfg)
		return;

	body = repeat_key(key, prefix, max + 1, start);
	CHECK(body != NULL, "over-length body built");
	if (body) {
		CHECK(load_body(cfg, body) != 0,
		      "one entry past max is refused");
		CHECK(count_of(cfg) <= max, "the count never exceeds max");
		free(body);
	}

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

	printf("test: an over-long value cannot run past its cell\n");

	CHECK(cfg != NULL, "config allocated");
	if (!cfg)
		return;

	memcpy(body, "server = ", 9);
	for (i = 9; i < fill; i++)
		body[i] = 'a';
	body[fill] = '\n';
	body[fill + 1] = '\0';

	/* Parsing may accept or reject; neither may write past the field */
	(void)load_body(cfg, body);
	CHECK(strlen(cfg->server) < sizeof(cfg->server),
	      "server stays within its cell");
	CHECK(cfg->server[sizeof(cfg->server) - 1] == '\0',
	      "server is still terminated");

	config_free(cfg);
}

int main(void)
{
	printf("=== config_new / config_free ===\n\n");

	test_defaults_match_config_init();
	test_parses_a_file();
	test_free_null_is_a_noop();
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

	printf("\n%s\n", failures == 0 ? "ALL TESTS PASSED" : "TESTS FAILED");
	return failures == 0 ? 0 : 1;
}
