/* SPDX-License-Identifier: MIT */
/*
 * Unit tests for the enrollment state record (enroll_state.c).
 *
 * The record lets --reenroll reuse a saved CA endpoint, so the round-trip
 * and the fail-closed guards are pinned here.
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

#include "test.h"

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
	in.ca_port = 8444;
	in.no_verify_tls = 0;
	in.has_pin = 1;
	for (size_t i = 0; i < sizeof(in.pin_sha256); i++)
		in.pin_sha256[i] = (uint8_t)i;
	snprintf(in.ca_server, sizeof(in.ca_server), "ca.example");
	snprintf(in.ca_cert, sizeof(in.ca_cert), "/etc/lota/ca-tls.crt");
	snprintf(in.enroll_token, sizeof(in.enroll_token), "game-alpha-token");

	TEST("save state");
	if (enroll_state_save_path(path, &in) != 0)
		FAIL("expected: enroll_state_save_path(path, &in) == 0");

	memset(&out, 0, sizeof(out));
	TEST("load state");
	if (enroll_state_load_path(path, &out) != 0)
		FAIL("expected: enroll_state_load_path(path, &out) == 0");

	TEST("port round-trips");
	if (out.ca_port != 8444)
		FAIL("expected: out.ca_port == 8444");
	TEST("has_pin round-trips");
	if (out.has_pin != 1)
		FAIL("expected: out.has_pin == 1");
	TEST("pin round-trips");
	if (memcmp(out.pin_sha256, in.pin_sha256, sizeof(in.pin_sha256)) != 0)
		FAIL("expected: memcmp(out.pin_sha256, in.pin_sha256, "
		     "sizeof(in.pin_sha256)) == 0");
	TEST("server round-trips");
	if (strcmp(out.ca_server, "ca.example") != 0)
		FAIL("expected: strcmp(out.ca_server, \"ca.example\") == 0");
	TEST("ca_cert round-trips");
	if (strcmp(out.ca_cert, "/etc/lota/ca-tls.crt") != 0)
		FAIL("expected: strcmp(out.ca_cert, \"/etc/lota/ca-tls.crt\") "
		     "== 0");
	TEST("enrollment token round-trips");
	if (strcmp(out.enroll_token, "game-alpha-token") != 0)
		FAIL("expected: strcmp(out.enroll_token, "
		     "\"game-alpha-token\") == 0");

	unlink(path);
}

static void test_missing_is_enoent(void)
{
	struct enroll_state out;
	int ret = enroll_state_load_path("/tmp/lota-enroll-state-absent.XXXXXX",
					 &out);
	TEST("absent state load returns -ENOENT");
	if (ret != -ENOENT)
		FAIL("expected: ret == -ENOENT");
}

static void test_rejects_other_version_record(void)
{
	/* a record at another version need not match this layout */
	const size_t short_size = offsetof(struct enroll_state, enroll_token);
	const char *path = tmp_path();
	struct enroll_state in, out;
	int fd;

	memset(&in, 0, sizeof(in));
	in.magic = LOTA_ENROLL_STATE_MAGIC;
	in.version = LOTA_ENROLL_STATE_VERSION + 1;
	in.ca_port = 8444;
	snprintf(in.ca_server, sizeof(in.ca_server), "ca.example");

	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	TEST("open other-version record");
	if (fd < 0)
		FAIL("expected: fd >= 0");
	if (fd >= 0) {
		TEST("write other-version record");
		if (write(fd, &in, short_size) != (ssize_t)short_size)
			FAIL("expected: write(fd, &in, short_size) == "
			     "(ssize_t)short_size");
		close(fd);
	}

	memset(&out, 0xFF, sizeof(out));
	/* -ENOTSUP, not -ENOENT: re-enrolling would overwrite the certificate */
	TEST("a record at a version this build does not read says so");
	if (enroll_state_load_path(path, &out) != -ENOTSUP)
		FAIL("expected: enroll_state_load_path(path, &out) == -ENOTSUP");

	/* short record claiming the current version is refused too */
	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	TEST("reopen for short current-version record");
	if (fd < 0)
		FAIL("expected: fd >= 0");
	if (fd >= 0) {
		in.version = LOTA_ENROLL_STATE_VERSION;
		TEST("write truncated current record");
		if (write(fd, &in, short_size) != (ssize_t)short_size)
			FAIL("expected: write(fd, &in, short_size) == "
			     "(ssize_t)short_size");
		close(fd);
	}
	TEST("a record shorter than the record says so");
	if (enroll_state_load_path(path, &out) != -EIO)
		FAIL("expected: enroll_state_load_path(path, &out) == -EIO");

	unlink(path);
}

static void test_record_presence(void)
{
	/* a missing file is the only answer that means "nothing is there" */
	TEST("no file means no record");
	if (enroll_state_record_present(-ENOENT) != 0)
		FAIL("expected: enroll_state_record_present(-ENOENT) == 0");
	TEST("a record that loads is one");
	if (enroll_state_record_present(0) != 1)
		FAIL("expected: enroll_state_record_present(0) == 1");
	TEST("a version this build cannot read is still a record");
	if (enroll_state_record_present(-ENOTSUP) != 1)
		FAIL("expected: enroll_state_record_present(-ENOTSUP) == 1");
	TEST("a short record is still a record");
	if (enroll_state_record_present(-EIO) != 1)
		FAIL("expected: enroll_state_record_present(-EIO) == 1");
	TEST("bytes that are not the record are still on disk");
	if (enroll_state_record_present(-EINVAL) != 1)
		FAIL("expected: enroll_state_record_present(-EINVAL) == 1");
}

static void test_rejects_bad_magic(void)
{
	const char *path = tmp_path();
	struct enroll_state in, out;
	FILE *f;

	memset(&in, 0, sizeof(in));
	in.ca_port = 8444;
	TEST("save for corruption");
	if (enroll_state_save_path(path, &in) != 0)
		FAIL("expected: enroll_state_save_path(path, &in) == 0");

	/* corrupt the magic in place; the load must fail closed */
	f = fopen(path, "r+b");
	TEST("reopen state");
	if (f == NULL)
		FAIL("expected: f != NULL");
	if (f) {
		uint32_t bad = 0xDEADBEEF;
		fwrite(&bad, sizeof(bad), 1, f);
		fclose(f);
	}
	TEST("bad magic rejected");
	if (enroll_state_load_path(path, &out) != -EINVAL)
		FAIL("expected: enroll_state_load_path(path, &out) == -EINVAL");

	unlink(path);
}

static void test_rejects_truncated(void)
{
	const char *path = tmp_path();
	struct enroll_state out;
	int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);

	TEST("open truncated");
	if (fd < 0)
		FAIL("expected: fd >= 0");
	if (fd >= 0) {
		uint8_t half[8] = { 0 };
		TEST("write truncated");
		if (write(fd, half, sizeof(half)) != (ssize_t)sizeof(half))
			FAIL("expected: write(fd, half, sizeof(half)) == "
			     "(ssize_t)sizeof(half)");
		close(fd);
	}
	TEST("short file rejected");
	if (enroll_state_load_path(path, &out) != -EINVAL)
		FAIL("expected: enroll_state_load_path(path, &out) == -EINVAL");

	unlink(path);
}

static void test_null_args(void)
{
	struct enroll_state st;
	memset(&st, 0, sizeof(st));
	TEST("save NULL path");
	if (enroll_state_save_path(NULL, &st) != -EINVAL)
		FAIL("expected: enroll_state_save_path(NULL, &st) == -EINVAL");
	TEST("save NULL st");
	if (enroll_state_save_path("/tmp/x", NULL) != -EINVAL)
		FAIL("expected: enroll_state_save_path(\"/tmp/x\", NULL) == "
		     "-EINVAL");
	TEST("load NULL path");
	if (enroll_state_load_path(NULL, &st) != -EINVAL)
		FAIL("expected: enroll_state_load_path(NULL, &st) == -EINVAL");
	TEST("load NULL out");
	if (enroll_state_load_path("/tmp/x", NULL) != -EINVAL)
		FAIL("expected: enroll_state_load_path(\"/tmp/x\", NULL) == "
		     "-EINVAL");
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

	TEST("configured anchor wins over the recorded one");
	if (!(enroll_renew_anchor("/etc/lota/publisher-ca.crt",
				  "/var/tmp/rig/ca.crt", &chosen) == 0 &&
	      strcmp(chosen, "/etc/lota/publisher-ca.crt") == 0))
		FAIL("expected: enroll_renew_anchor(\"/etc/lota/publisher-ca.crt\", "
		     "\"/var/tmp/rig/ca.crt\", &chosen) == 0 && "
		     "strcmp(chosen, \"/etc/lota/publisher-ca.crt\") == 0");

	chosen = NULL;
	TEST("recorded anchor carries a target with none configured");
	if (!(enroll_renew_anchor(NULL, "/var/tmp/rig/ca.crt", &chosen) == 0 &&
	      strcmp(chosen, "/var/tmp/rig/ca.crt") == 0))
		FAIL("expected: enroll_renew_anchor(NULL, "
		     "\"/var/tmp/rig/ca.crt\", &chosen) == 0 && "
		     "strcmp(chosen, \"/var/tmp/rig/ca.crt\") == 0");

	chosen = NULL;
	TEST("empty configured anchor is not an anchor");
	if (!(enroll_renew_anchor("", "/var/tmp/rig/ca.crt", &chosen) == 0 &&
	      strcmp(chosen, "/var/tmp/rig/ca.crt") == 0))
		FAIL("expected: enroll_renew_anchor(\"\", "
		     "\"/var/tmp/rig/ca.crt\", &chosen) == 0 && "
		     "strcmp(chosen, \"/var/tmp/rig/ca.crt\") == 0");

	chosen = NULL;
	TEST("no anchor at all is reported, not guessed");
	if (!(enroll_renew_anchor("", "", &chosen) == -ENOENT && !chosen))
		FAIL("expected: enroll_renew_anchor(\"\", \"\", &chosen) == "
		     "-ENOENT && !chosen");

	TEST("NULL output is refused");
	if (enroll_renew_anchor("/etc/lota/publisher-ca.crt",
				"/var/tmp/rig/ca.crt", NULL) != -EINVAL)
		FAIL("expected: enroll_renew_anchor(\"/etc/lota/publisher-ca.crt\", "
		     "\"/var/tmp/rig/ca.crt\", NULL) == -EINVAL");
}

static void test_nothing_given_keeps_the_recorded_endpoint(void)
{
	TEST("a bare --reenroll dials the recorded endpoint");
	if (enroll_endpoint_source(NULL, 0) != ENROLL_ENDPOINT_FROM_RECORD)
		FAIL("expected: enroll_endpoint_source(NULL, 0) == "
		     "ENROLL_ENDPOINT_FROM_RECORD");
	TEST("the recorded host stands when none was given");
	if (strcmp(enroll_endpoint_server("ca.example", NULL), "ca.example") !=
	    0)
		FAIL("expected: strcmp(enroll_endpoint_server(\"ca.example\", "
		     "NULL), \"ca.example\") == 0");
	TEST("the recorded port stands when none was given");
	if (enroll_endpoint_port(8545, 0) != 8545)
		FAIL("expected: enroll_endpoint_port(8545, 0) == 8545");
	TEST("an empty host is not a host that was named");
	if (enroll_endpoint_source("", 0) != ENROLL_ENDPOINT_FROM_RECORD)
		FAIL("expected: enroll_endpoint_source(\"\", 0) == "
		     "ENROLL_ENDPOINT_FROM_RECORD");
	TEST("an empty host does not displace the recorded one");
	if (strcmp(enroll_endpoint_server("ca.example", ""), "ca.example") != 0)
		FAIL("expected: strcmp(enroll_endpoint_server(\"ca.example\", "
		     "\"\"), \"ca.example\") == 0");
}

static void test_a_given_endpoint_wins(void)
{
	TEST("a host and port on the command line are what the run dials");
	if (enroll_endpoint_source("ca.new", 9000) !=
	    ENROLL_ENDPOINT_FROM_COMMAND_LINE)
		FAIL("expected: enroll_endpoint_source(\"ca.new\", 9000) == "
		     "ENROLL_ENDPOINT_FROM_COMMAND_LINE");
	TEST("the given host displaces the recorded one");
	if (strcmp(enroll_endpoint_server("ca.old", "ca.new"), "ca.new") != 0)
		FAIL("expected: strcmp(enroll_endpoint_server(\"ca.old\", "
		     "\"ca.new\"), \"ca.new\") == 0");
	TEST("the given port displaces the recorded one");
	if (enroll_endpoint_port(8546, 8545) != 8545)
		FAIL("expected: enroll_endpoint_port(8546, 8545) == 8545");
}

/* A field not given keeps the recorded value. */
static void test_either_field_alone_is_an_endpoint(void)
{
	TEST("a port alone is an endpoint the command line named");
	if (enroll_endpoint_source(NULL, 8545) !=
	    ENROLL_ENDPOINT_FROM_COMMAND_LINE)
		FAIL("expected: enroll_endpoint_source(NULL, 8545) == "
		     "ENROLL_ENDPOINT_FROM_COMMAND_LINE");
	TEST("a host alone is an endpoint the command line named");
	if (enroll_endpoint_source("ca.new", 0) !=
	    ENROLL_ENDPOINT_FROM_COMMAND_LINE)
		FAIL("expected: enroll_endpoint_source(\"ca.new\", 0) == "
		     "ENROLL_ENDPOINT_FROM_COMMAND_LINE");
	TEST("a port alone keeps the recorded host");
	if (!(strcmp(enroll_endpoint_server("ca.old", NULL), "ca.old") == 0 &&
	      enroll_endpoint_port(8546, 8545) == 8545))
		FAIL("expected: strcmp(enroll_endpoint_server(\"ca.old\", "
		     "NULL), \"ca.old\") == 0 && enroll_endpoint_port(8546, "
		     "8545) == 8545");
	TEST("a host alone keeps the recorded port");
	if (!(strcmp(enroll_endpoint_server("ca.old", "ca.new"), "ca.new") ==
		      0 &&
	      enroll_endpoint_port(8546, 0) == 8546))
		FAIL("expected: strcmp(enroll_endpoint_server(\"ca.old\", "
		     "\"ca.new\"), \"ca.new\") == 0 && "
		     "enroll_endpoint_port(8546, 0) == 8546");
}

/* an empty handle holds no key at all, not someone else's */
static void test_forget_key_plan(void)
{
	TEST("forget: an empty handle is neither evicted nor foreign");
	if (forget_key_plan(0, 0) != FORGET_KEY_NONE)
		FAIL("expected: forget_key_plan(0, 0) == FORGET_KEY_NONE");
	TEST("forget: the publisher's own key is evicted");
	if (forget_key_plan(1, 1) != FORGET_KEY_EVICT)
		FAIL("expected: forget_key_plan(1, 1) == FORGET_KEY_EVICT");
	TEST("forget: another object at the handle is left alone");
	if (forget_key_plan(1, 0) != FORGET_KEY_FOREIGN)
		FAIL("expected: forget_key_plan(1, 0) == FORGET_KEY_FOREIGN");
	TEST("forget: a handle that cannot be checked removes nothing");
	if (!(forget_key_plan(-EIO, 0) == FORGET_KEY_UNKNOWN &&
	      forget_key_plan(1, -EIO) == FORGET_KEY_UNKNOWN))
		FAIL("expected: forget_key_plan(-EIO, 0) == "
		     "FORGET_KEY_UNKNOWN && forget_key_plan(1, -EIO) == "
		     "FORGET_KEY_UNKNOWN");
}

int main(void)
{
	test_begin("enroll state");
	test_forget_key_plan();
	test_nothing_given_keeps_the_recorded_endpoint();
	test_a_given_endpoint_wins();
	test_either_field_alone_is_an_endpoint();
	test_renew_anchor_prefers_the_configured_one();
	test_roundtrip();
	test_rejects_other_version_record();
	test_missing_is_enoent();
	test_record_presence();
	test_rejects_bad_magic();
	test_rejects_truncated();
	test_null_args();

	return test_end();
}
