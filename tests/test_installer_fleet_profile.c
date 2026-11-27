/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * tests/test_installer_fleet_profile.c
 *
 * A fleet install enrolls with the operator's CA. Unless it also records that
 * CA as a publisher profile in lota.conf, the loop has nothing to report to
 * after the reboot, and the daemon does not know the publisher it enrolled with.
 * The self-check waits for a report to every profile that reports
 * continuously.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include "test.h"
#include "../installer/install.h"
#include "../src/agent/config.h"

static char dir[] = "/tmp/lota-fleet-profile-XXXXXX";
static char anchor[256];
static char anchor_copy[256];
static char other[256];
static char conf[256];

static FILE *open_private(const char *path)
{
	int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	FILE *f;

	if (fd < 0)
		return NULL;
	f = fdopen(fd, "w");
	if (!f)
		close(fd);
	return f;
}

static int write_anchor(const char *path, EVP_PKEY *pkey, const char *cn)
{
	X509 *x = X509_new();
	FILE *f;
	int ok = 0;

	if (!x)
		return -1;
	X509_set_version(x, 2);
	ASN1_INTEGER_set(X509_get_serialNumber(x), 1);
	X509_gmtime_adj(X509_getm_notBefore(x), 0);
	X509_gmtime_adj(X509_getm_notAfter(x), 3600);
	X509_set_pubkey(x, pkey);
	X509_NAME_add_entry_by_txt(X509_get_subject_name(x), "CN", MBSTRING_ASC,
				   (const unsigned char *)cn, -1, -1, 0);
	X509_set_issuer_name(x, X509_get_subject_name(x));
	if (X509_sign(x, pkey, EVP_sha256())) {
		f = open_private(path);
		if (f) {
			ok = PEM_write_X509(f, x);
			fclose(f);
		}
	}
	X509_free(x);
	return ok == 1 ? 0 : -1;
}

static int write_conf(const char *text)
{
	FILE *f = open_private(conf);

	if (!f)
		return -1;
	fputs(text, f);
	fclose(f);
	return 0;
}

static void test_recorded(void)
{
	char text[1024];

	TEST("no lota.conf records nothing");
	unlink(conf);
	if (installer_profile_recorded(conf, anchor) != 0) {
		FAIL("missing file read as recorded");
		return;
	}
	PASS();

	TEST("a top-level ca_cert is not a publisher profile");
	snprintf(text, sizeof(text), "ca_cert = %s\n", anchor);
	if (write_conf(text) < 0 ||
	    installer_profile_recorded(conf, anchor) != 0) {
		FAIL("top-level anchor read as a profile");
		return;
	}
	PASS();

	TEST("another publisher's profile does not record this one");
	snprintf(text, sizeof(text),
		 "[profile \"other\"]\nca = ca.other.example\n"
		 "ca_cert = %s\nverifier = none\n",
		 other);
	if (write_conf(text) < 0 ||
	    installer_profile_recorded(conf, anchor) != 0) {
		FAIL("a different key read as the same publisher");
		return;
	}
	PASS();

	/* a publisher is its key, not the path its anchor was copied to */
	TEST("the same key under another path is recorded");
	snprintf(text, sizeof(text),
		 "[profile \"other\"]\nca = ca.other.example\n"
		 "ca_cert = %s\nverifier = none\n"
		 "[profile \"fleet\"]\nca = ca.fleet.example\n"
		 "ca_cert = %s\nverifier = none\n",
		 other, anchor_copy);
	if (write_conf(text) < 0 ||
	    installer_profile_recorded(conf, anchor) != 1) {
		FAIL("the recorded profile was not found");
		return;
	}
	PASS();

	/* the installer reads as much of lota.conf as the agent writes */
	TEST("a profile 64 KiB into lota.conf is found");
	{
		char *big = malloc(70000);
		size_t n = 65536;
		int bad;

		if (!big) {
			FAIL("out of memory");
			return;
		}
		memset(big, '#', n);
		big[n - 1] = '\n';
		n += snprintf(big + n, 70000 - n,
			      "[profile \"fleet\"]\nca = ca.fleet.example\n"
			      "ca_cert = %s\nverifier = none\n",
			      anchor);
		big[n] = '\0';
		bad = write_conf(big) < 0 ||
		      installer_profile_recorded(conf, anchor) != 1;
		free(big);
		if (bad) {
			FAIL("a profile past 16 KiB was not read");
			return;
		}
	}
	PASS();

	/* a profile past the reader's buffer is not "no profile" */
	TEST("a lota.conf too large to read whole is an error");
	{
		const size_t cap = LOTA_CONFIG_MAX_FILE + 1024;
		char *big = malloc(cap);
		size_t n;
		int bad;

		if (!big) {
			FAIL("out of memory");
			return;
		}
		/* config_profile_append() refuses one this large as well */
		memset(big, '#', LOTA_CONFIG_MAX_FILE);
		big[LOTA_CONFIG_MAX_FILE - 1] = '\n';
		n = LOTA_CONFIG_MAX_FILE;
		n += snprintf(big + n, cap - n,
			      "[profile \"fleet\"]\nca = ca.fleet.example\n"
			      "ca_cert = %s\nverifier = none\n",
			      anchor);
		big[n] = '\0';
		bad = write_conf(big) < 0 ||
		      installer_profile_recorded(conf, anchor) != -EFBIG;
		free(big);
		if (bad) {
			FAIL("an oversized file read as no profile");
			return;
		}
	}
	PASS();

	TEST("a lota.conf that cannot be read is an error");
	unlink(conf);
	if (mkdir(conf, 0700) < 0 ||
	    installer_profile_recorded(conf, anchor) >= 0) {
		rmdir(conf);
		FAIL("an unreadable file read as no profile");
		return;
	}
	rmdir(conf);
	PASS();
}

static int argv_has(const char *const *argv, const char *a, const char *b)
{
	for (int i = 0; argv[i]; i++) {
		if (strcmp(argv[i], a) != 0)
			continue;
		if (!b)
			return 1;
		return argv[i + 1] && strcmp(argv[i + 1], b) == 0;
	}
	return 0;
}

static void test_loop_expected(void)
{
	TEST("the loop wait expects a report per continuous profile");
	if (write_conf("[profile \"fleet\"]\nreporting = continuous\n"
		       "verifier = v.fleet.example\n"
		       "[profile \"fleet2\"]\nreporting = continuous\n"
		       "verifier = v.fleet2.example\n") < 0 ||
	    installer_loop_reports_expected(conf) != 2) {
		FAIL("profiles in lota.conf not counted");
		return;
	}
	PASS();

	TEST("the loop wait expects one report without lota.conf");
	unlink(conf);
	if (installer_loop_reports_expected(conf) != 1) {
		FAIL("a missing lota.conf is not one report");
		return;
	}
	PASS();
}

static void test_add_publisher_argv(void)
{
	struct install_opts o;
	const char *argv[INSTALLER_ADD_PUBLISHER_ARGC];

	memset(&o, 0, sizeof(o));
	o.ca_server = "ca.fleet.example";
	o.ca_port = "8564";
	o.ca_cert = anchor;
	o.verifier = "verifier.fleet.example";
	o.verifier_port = "9443";

	TEST("the fleet verifier is written to report continuously");
	installer_add_publisher_argv(&o, argv);
	if (!argv_has(argv, "--add-publisher", "ca.fleet.example") ||
	    !argv_has(argv, "--ca-port", "8564") ||
	    !argv_has(argv, "--ca-cert", anchor) ||
	    !argv_has(argv, "--server", "verifier.fleet.example") ||
	    !argv_has(argv, "--port", "9443") ||
	    !argv_has(argv, "--reporting", "continuous")) {
		FAIL("the profile would not name the fleet's verifier");
		return;
	}
	PASS();

	TEST("no verifier writes a publisher that runs none");
	o.verifier = NULL;
	installer_add_publisher_argv(&o, argv);
	if (argv_has(argv, "--server", NULL) ||
	    argv_has(argv, "--port", NULL) ||
	    !argv_has(argv, "--add-publisher", "ca.fleet.example")) {
		FAIL("a verifier was named that nobody gave");
		return;
	}
	PASS();

	TEST("an unset CA port is left to the agent's default");
	o.ca_port = NULL;
	installer_add_publisher_argv(&o, argv);
	if (argv_has(argv, "--ca-port", NULL)) {
		FAIL("a CA port was named that nobody gave");
		return;
	}
	PASS();
}

int main(void)
{
	EVP_PKEY *a;
	EVP_PKEY *b;

	printf("=== installer fleet profile ===\n");

	if (!mkdtemp(dir))
		return 1;
	snprintf(anchor, sizeof(anchor), "%s/fleet.pem", dir);
	snprintf(anchor_copy, sizeof(anchor_copy), "%s/fleet-copy.pem", dir);
	snprintf(other, sizeof(other), "%s/other.pem", dir);
	snprintf(conf, sizeof(conf), "%s/lota.conf", dir);

	a = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256");
	b = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256");
	if (!a || !b || write_anchor(anchor, a, "fleet") < 0 ||
	    write_anchor(anchor_copy, a, "fleet") < 0 ||
	    write_anchor(other, b, "other") < 0) {
		fprintf(stderr, "cannot mint anchors\n");
		return 1;
	}
	EVP_PKEY_free(a);
	EVP_PKEY_free(b);

	test_recorded();
	test_loop_expected();
	test_add_publisher_argv();

	unlink(anchor);
	unlink(anchor_copy);
	unlink(other);
	unlink(conf);
	rmdir(dir);

	printf("\nPassed: %d / %d\n", tests_passed, tests_run);
	return tests_passed == tests_run ? 0 : 1;
}
