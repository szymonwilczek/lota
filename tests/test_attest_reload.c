/* SPDX-License-Identifier: MIT */
/*
 * Unit tests for rebuilding the attestation target list while the loop runs.
 *
 * A game's installer registers its publisher with --add-publisher on a host
 * that is already running. The daemon that answers titles re-reads the list
 * on SIGHUP; the loop that *reports* enumerated its targets at startup
 * and never looked again, so the new publisher's verifier heard nothing until
 * somebody restarted a unit. The only symptom is absence.
 *
 * A reload therefore has to pick up what the file now says without disturbing
 * what the loop already knows: a publisher that is still configured keeps its
 * schedule, its failure state and the session count the IPC layer maintains,
 * because dropping those would re-report every publisher on every reload
 * and silence a session-gated one until the next sync.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

#include "../src/agent/attest_targets.h"
#include "../src/agent/config.h"

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

/* self-signed anchor, so a target resolves a real publisher identity */
static int write_anchor(const char *path)
{
	EVP_PKEY *pkey = EVP_EC_gen("P-256");
	uint8_t *der = NULL;
	X509_NAME *name;
	X509 *x = NULL;
	int len, fd, ret = -1;

	if (!pkey)
		goto out;
	x = X509_new();
	if (!x)
		goto out;

	X509_set_version(x, 2);
	ASN1_INTEGER_set(X509_get_serialNumber(x), 1);
	X509_gmtime_adj(X509_getm_notBefore(x), 0);
	X509_gmtime_adj(X509_getm_notAfter(x), 3600);
	X509_set_pubkey(x, pkey);
	name = X509_get_subject_name(x);
	X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
				   (const unsigned char *)"lota-reload", -1, -1,
				   0);
	X509_set_issuer_name(x, name);
	if (!X509_sign(x, pkey, EVP_sha256()))
		goto out;

	len = i2d_X509(x, &der);
	if (len <= 0)
		goto out;

	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	if (fd < 0)
		goto out;
	if (write(fd, der, (size_t)len) == (ssize_t)len)
		ret = 0;
	close(fd);

out:
	OPENSSL_free(der);
	X509_free(x);
	EVP_PKEY_free(pkey);
	return ret;
}

static int write_file(const char *path, const char *text)
{
	int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);

	if (fd < 0)
		return -errno;
	if (write(fd, text, strlen(text)) != (ssize_t)strlen(text)) {
		close(fd);
		return -EIO;
	}
	close(fd);
	return 0;
}

int main(void)
{
	char anchor_a[128], anchor_b[128], conf[128];
	char text[2048];
	struct attest_target *targets;
	struct lota_config *cfg;
	size_t count = 0;
	int rc;

	printf("=== attestation target reload tests ===\n\n");

	snprintf(anchor_a, sizeof(anchor_a), "/tmp/lota-reload-a.%d.der",
		 (int)getpid());
	snprintf(anchor_b, sizeof(anchor_b), "/tmp/lota-reload-b.%d.der",
		 (int)getpid());
	snprintf(conf, sizeof(conf), "/tmp/lota-reload.%d.conf", (int)getpid());

	if (write_anchor(anchor_a) != 0 || write_anchor(anchor_b) != 0) {
		fprintf(stderr, "FAIL: could not write the test anchors\n");
		return 1;
	}

	targets = calloc(LOTA_CONFIG_MAX_PROFILES, sizeof(*targets));
	cfg = config_new();
	if (!targets || !cfg) {
		fprintf(stderr, "FAIL: allocation\n");
		config_free(cfg);
		free(targets);
		return 1;
	}

	snprintf(text, sizeof(text),
		 "[profile \"alpha\"]\n"
		 "ca = ca.alpha.example\n"
		 "ca_cert = %s\n"
		 "verifier = v.alpha.example\n"
		 "verifier_port = 8573\n",
		 anchor_a);
	if (write_file(conf, text) < 0) {
		fprintf(stderr, "FAIL: could not write the config\n");
		config_free(cfg);
		free(targets);
		return 1;
	}

	rc = attest_targets_reload(conf, cfg, NULL, 0, NULL, 300, targets,
				   LOTA_CONFIG_MAX_PROFILES, &count);
	CHECK(rc == 0 && count == 1, "the configured publisher is a target");

	/* what the running loop knows about that publisher */
	targets[0].sessions = 2;
	targets[0].next_due_ms = 123456;
	targets[0].consecutive_failures = 3;
	targets[0].backoff_sec = 40;
	targets[0].attested = true;

	snprintf(text, sizeof(text),
		 "[profile \"alpha\"]\n"
		 "ca = ca.alpha.example\n"
		 "ca_cert = %s\n"
		 "verifier = v.alpha.example\n"
		 "verifier_port = 8573\n"
		 "\n"
		 "[profile \"beta\"]\n"
		 "ca = ca.beta.example\n"
		 "ca_cert = %s\n"
		 "verifier = v.beta.example\n"
		 "verifier_port = 8583\n",
		 anchor_a, anchor_b);
	if (write_file(conf, text) < 0) {
		fprintf(stderr, "FAIL: could not rewrite the config\n");
		config_free(cfg);
		free(targets);
		return 1;
	}

	rc = attest_targets_reload(conf, cfg, NULL, 0, NULL, 300, targets,
				   LOTA_CONFIG_MAX_PROFILES, &count);
	CHECK(rc == 0 && count == 2,
	      "a publisher added while the loop runs becomes a target");
	CHECK(count == 2 && strcmp(targets[1].server, "v.beta.example") == 0,
	      "the new publisher's verifier is the one the file names");
	CHECK(targets[0].sessions == 2 && targets[0].next_due_ms == 123456,
	      "a publisher that is still configured keeps its schedule and "
	      "sessions");
	CHECK(targets[0].consecutive_failures == 3 &&
		      targets[0].backoff_sec == 40 && targets[0].attested,
	      "and keeps its failure state, so a reload is not a way to clear "
	      "a backoff");
	CHECK(targets[1].next_due_ms == 0,
	      "the new publisher is due now rather than one interval from now");

	/* A file that does not parse is the installer's half-written config
	 * or a hand edit; answering titles and reporting from the previous
	 * list beats reporting to nobody */
	if (write_file(conf, "[profile \"broken\"]\n") == 0) {
		size_t before = count;

		rc = attest_targets_reload(conf, cfg, NULL, 0, NULL, 300,
					   targets, LOTA_CONFIG_MAX_PROFILES,
					   &count);
		CHECK(rc < 0, "a config that does not load is refused");
		CHECK(count == before &&
			      strcmp(targets[1].server, "v.beta.example") == 0,
		      "and the list the loop is using is left alone");
	}

	CHECK(attest_targets_reload(NULL, cfg, NULL, 0, NULL, 300, targets,
				    LOTA_CONFIG_MAX_PROFILES, &count) < 0,
	      "a reload without a config path is refused");

	unlink(anchor_a);
	unlink(anchor_b);
	unlink(conf);
	config_free(cfg);
	free(targets);

	printf("\n%s\n", g_failures ? "FAILURES" : "All tests passed");
	return g_failures ? 1 : 0;
}
