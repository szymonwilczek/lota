/* SPDX-License-Identifier: MIT */
/*
 * Unit tests for the enrollment state record (enroll_state.c).
 *
 * The record lets --reenroll reuse a saved CA endpoint and lets the daemon
 * tell when a local AIK rotation has outdated the issued certificate, so
 * the round-trip and the fail-closed guards are pinned here.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>

#include "../src/agent/enroll.h"

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

static const char *tmp_path(void)
{
	static char path[256];
	snprintf(path, sizeof(path), "/tmp/lota-enroll-state-test.%d",
		 getpid());
	return path;
}

static void test_roundtrip(void)
{
	const char *path = tmp_path();
	struct enroll_state in, out;

	memset(&in, 0, sizeof(in));
	in.aik_generation = 7;
	in.ca_port = 8444;
	in.no_verify_tls = 0;
	in.has_pin = 1;
	for (size_t i = 0; i < sizeof(in.pin_sha256); i++)
		in.pin_sha256[i] = (uint8_t)i;
	snprintf(in.ca_server, sizeof(in.ca_server), "ca.example");
	snprintf(in.ca_cert, sizeof(in.ca_cert), "/etc/lota/ca-tls.crt");
	snprintf(in.enroll_token, sizeof(in.enroll_token), "game-alpha-token");

	CHECK(enroll_state_save_path(path, &in) == 0, "save state");

	memset(&out, 0, sizeof(out));
	CHECK(enroll_state_load_path(path, &out) == 0, "load state");

	CHECK(out.aik_generation == 7, "generation round-trips");
	CHECK(out.ca_port == 8444, "port round-trips");
	CHECK(out.has_pin == 1, "has_pin round-trips");
	CHECK(memcmp(out.pin_sha256, in.pin_sha256, sizeof(in.pin_sha256)) == 0,
	      "pin round-trips");
	CHECK(strcmp(out.ca_server, "ca.example") == 0, "server round-trips");
	CHECK(strcmp(out.ca_cert, "/etc/lota/ca-tls.crt") == 0,
	      "ca_cert round-trips");
	CHECK(strcmp(out.enroll_token, "game-alpha-token") == 0,
	      "enrollment token round-trips");

	unlink(path);
}

static void test_missing_is_enoent(void)
{
	struct enroll_state out;
	int ret = enroll_state_load_path("/tmp/lota-enroll-state-absent.XXXXXX",
					 &out);
	CHECK(ret == -ENOENT, "absent state load returns -ENOENT");
}

static void test_rejects_v1_record(void)
{
	/* record written before the token field existed:
	 * version 1, ending where enroll_token begins
	 * loader requires the current record,
	 * so the host re-enrolls instead of running on state it cannot fully read */
	const size_t v1_size = offsetof(struct enroll_state, enroll_token);
	const char *path = tmp_path();
	struct enroll_state in, out;
	int fd;

	memset(&in, 0, sizeof(in));
	in.magic = LOTA_ENROLL_STATE_MAGIC;
	in.version = 1;
	in.ca_port = 8444;
	snprintf(in.ca_server, sizeof(in.ca_server), "ca.example");

	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	CHECK(fd >= 0, "open v1 record");
	if (fd >= 0) {
		CHECK(write(fd, &in, v1_size) == (ssize_t)v1_size,
		      "write v1 record");
		close(fd);
	}

	memset(&out, 0xFF, sizeof(out));
	CHECK(enroll_state_load_path(path, &out) == -EINVAL,
	      "v1 record rejected");

	/* short record claiming the current version is refused too */
	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	CHECK(fd >= 0, "reopen for short current-version record");
	if (fd >= 0) {
		in.version = LOTA_ENROLL_STATE_VERSION;
		CHECK(write(fd, &in, v1_size) == (ssize_t)v1_size,
		      "write truncated current record");
		close(fd);
	}
	CHECK(enroll_state_load_path(path, &out) == -EINVAL,
	      "truncated current record rejected");

	unlink(path);
}

static void test_rejects_bad_magic(void)
{
	const char *path = tmp_path();
	struct enroll_state in, out;
	FILE *f;

	memset(&in, 0, sizeof(in));
	in.ca_port = 8444;
	CHECK(enroll_state_save_path(path, &in) == 0, "save for corruption");

	/* corrupt the magic in place; the load must fail closed */
	f = fopen(path, "r+b");
	CHECK(f != NULL, "reopen state");
	if (f) {
		uint32_t bad = 0xDEADBEEF;
		fwrite(&bad, sizeof(bad), 1, f);
		fclose(f);
	}
	CHECK(enroll_state_load_path(path, &out) == -EINVAL,
	      "bad magic rejected");

	unlink(path);
}

static void test_rejects_truncated(void)
{
	const char *path = tmp_path();
	struct enroll_state out;
	int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);

	CHECK(fd >= 0, "open truncated");
	if (fd >= 0) {
		uint8_t half[8] = { 0 };
		CHECK(write(fd, half, sizeof(half)) == (ssize_t)sizeof(half),
		      "write truncated");
		close(fd);
	}
	CHECK(enroll_state_load_path(path, &out) == -EINVAL,
	      "short file rejected");

	unlink(path);
}

static void test_null_args(void)
{
	struct enroll_state st;
	memset(&st, 0, sizeof(st));
	CHECK(enroll_state_save_path(NULL, &st) == -EINVAL, "save NULL path");
	CHECK(enroll_state_save_path("/tmp/x", NULL) == -EINVAL,
	      "save NULL st");
	CHECK(enroll_state_load_path(NULL, &st) == -EINVAL, "load NULL path");
	CHECK(enroll_state_load_path("/tmp/x", NULL) == -EINVAL,
	      "load NULL out");
}

int main(void)
{
	test_roundtrip();
	test_rejects_v1_record();
	test_missing_is_enoent();
	test_rejects_bad_magic();
	test_rejects_truncated();
	test_null_args();

	if (g_failures) {
		fprintf(stderr, "\n%d test(s) failed\n", g_failures);
		return 1;
	}
	printf("\nAll enroll_state tests passed\n");
	return 0;
}
