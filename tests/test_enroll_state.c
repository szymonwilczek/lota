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
	 * version 1, ending where enroll_token begins */
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
	/* -ENOTSUP, not -ENOENT: re-enrolling would overwrite the certificate */
	CHECK(enroll_state_load_path(path, &out) == -ENOTSUP,
	      "a record at a version this build does not read says so");

	/* short record claiming the current version is refused too */
	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	CHECK(fd >= 0, "reopen for short current-version record");
	if (fd >= 0) {
		in.version = LOTA_ENROLL_STATE_VERSION;
		CHECK(write(fd, &in, v1_size) == (ssize_t)v1_size,
		      "write truncated current record");
		close(fd);
	}
	CHECK(enroll_state_load_path(path, &out) == -EIO,
	      "a record shorter than the record says so");

	unlink(path);
}

static void test_record_presence(void)
{
	/* a missing file is the only answer that means "nothing is there" */
	CHECK(enroll_state_record_present(-ENOENT) == 0,
	      "no file means no record");
	CHECK(enroll_state_record_present(0) == 1,
	      "a record that loads is one");
	CHECK(enroll_state_record_present(-ENOTSUP) == 1,
	      "a version this build cannot read is still a record");
	CHECK(enroll_state_record_present(-EIO) == 1,
	      "a short record is still a record");
	CHECK(enroll_state_record_present(-EINVAL) == 1,
	      "bytes that are not the record are still on disk");
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

/*
 * A renewal has two candidate anchors:
 * The one this profile is configured with, and the one recorded when it enrolled.
 * They name the same publisher -- the profile is derived from the anchor -- but
 * only the configured one is guaranteed to still be readable by the daemon,
 * which runs with its own /tmp and /var/tmp.
 * Preferring the recorded path lets an enrollment driven from a staging directory
 * make every later renewal fail.
 */
static void test_renew_anchor_prefers_the_configured_one(void)
{
	const char *chosen = NULL;

	CHECK(enroll_renew_anchor("/etc/lota/publisher-ca.crt",
				  "/var/tmp/rig/ca.crt", &chosen) == 0 &&
		      strcmp(chosen, "/etc/lota/publisher-ca.crt") == 0,
	      "configured anchor wins over the recorded one");

	chosen = NULL;
	CHECK(enroll_renew_anchor(NULL, "/var/tmp/rig/ca.crt", &chosen) == 0 &&
		      strcmp(chosen, "/var/tmp/rig/ca.crt") == 0,
	      "recorded anchor carries a target with none configured");

	chosen = NULL;
	CHECK(enroll_renew_anchor("", "/var/tmp/rig/ca.crt", &chosen) == 0 &&
		      strcmp(chosen, "/var/tmp/rig/ca.crt") == 0,
	      "empty configured anchor is not an anchor");

	chosen = NULL;
	CHECK(enroll_renew_anchor("", "", &chosen) == -ENOENT && !chosen,
	      "no anchor at all is reported, not guessed");

	CHECK(enroll_renew_anchor("/etc/lota/publisher-ca.crt",
				  "/var/tmp/rig/ca.crt", NULL) == -EINVAL,
	      "NULL output is refused");
}

static void test_nothing_given_keeps_the_recorded_endpoint(void)
{
	CHECK(enroll_endpoint_source(NULL, 0) == ENROLL_ENDPOINT_FROM_RECORD,
	      "a bare --reenroll dials the recorded endpoint");
	CHECK(strcmp(enroll_endpoint_server("ca.example", NULL),
		     "ca.example") == 0,
	      "the recorded host stands when none was given");
	CHECK(enroll_endpoint_port(8545, 0) == 8545,
	      "the recorded port stands when none was given");
	CHECK(enroll_endpoint_source("", 0) == ENROLL_ENDPOINT_FROM_RECORD,
	      "an empty host is not a host that was named");
	CHECK(strcmp(enroll_endpoint_server("ca.example", ""), "ca.example") ==
		      0,
	      "an empty host does not displace the recorded one");
}

static void test_a_given_endpoint_wins(void)
{
	CHECK(enroll_endpoint_source("ca.new", 9000) ==
		      ENROLL_ENDPOINT_FROM_COMMAND_LINE,
	      "a host and port on the command line are what the run dials");
	CHECK(strcmp(enroll_endpoint_server("ca.old", "ca.new"), "ca.new") == 0,
	      "the given host displaces the recorded one");
	CHECK(enroll_endpoint_port(8546, 8545) == 8545,
	      "the given port displaces the recorded one");
}

/* A field not given keeps the recorded value. */
static void test_either_field_alone_is_an_endpoint(void)
{
	CHECK(enroll_endpoint_source(NULL, 8545) ==
		      ENROLL_ENDPOINT_FROM_COMMAND_LINE,
	      "a port alone is an endpoint the command line named");
	CHECK(enroll_endpoint_source("ca.new", 0) ==
		      ENROLL_ENDPOINT_FROM_COMMAND_LINE,
	      "a host alone is an endpoint the command line named");
	CHECK(strcmp(enroll_endpoint_server("ca.old", NULL), "ca.old") == 0 &&
		      enroll_endpoint_port(8546, 8545) == 8545,
	      "a port alone keeps the recorded host");
	CHECK(strcmp(enroll_endpoint_server("ca.old", "ca.new"), "ca.new") ==
			      0 &&
		      enroll_endpoint_port(8546, 0) == 8546,
	      "a host alone keeps the recorded port");
}

int main(void)
{
	test_nothing_given_keeps_the_recorded_endpoint();
	test_a_given_endpoint_wins();
	test_either_field_alone_is_an_endpoint();
	test_renew_anchor_prefers_the_configured_one();
	test_roundtrip();
	test_rejects_v1_record();
	test_missing_is_enoent();
	test_record_presence();
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
