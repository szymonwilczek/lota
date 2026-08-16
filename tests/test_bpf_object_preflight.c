/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * Tests for the enforcement object's pre-flight check.
 *
 * bpf_loader_verify_object() answers whether the object, the detached signature
 * beside it and the configured public key agree. The answer needs no TPM and
 * no kernel, so the agent can refuse a mis-signed object before it extends
 * PCR 14 -- a boot commitment is spendable once per boot, and a configuration
 * mistake must not cost it.
 *
 * The signature primitive is interposed with --wrap so the test needs no real
 * key: what is asserted here is the file handling and the verdict it produces,
 * which is what decides whether the agent starts.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../src/agent/bpf_loader.h"
#include "../src/agent/policy_sign.h"

static int g_failures;
static int g_verify_verdict;
static int g_verify_calls;

#define CHECK(cond, msg)                                    \
	do {                                                \
		if (!(cond)) {                              \
			fprintf(stderr, "FAIL: %s\n", msg); \
			g_failures++;                       \
		} else {                                    \
			printf("PASS: %s\n", msg);          \
		}                                           \
	} while (0)

/* --wrap targets need external linkage */
int __wrap_policy_verify_buffer(const uint8_t *data, size_t data_len,
				const char *pubkey_pem_path,
				const uint8_t *sig);

int __wrap_policy_verify_buffer(const uint8_t *data, size_t data_len,
				const char *pubkey_pem_path, const uint8_t *sig)
{
	(void)data;
	(void)data_len;
	(void)pubkey_pem_path;
	(void)sig;
	g_verify_calls++;
	return g_verify_verdict;
}

static void write_file(const char *path, const void *data, size_t len)
{
	int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	FILE *f;

	if (fd < 0) {
		fprintf(stderr, "FAIL: open %s: %s\n", path, strerror(errno));
		exit(1);
	}
	f = fdopen(fd, "wb");
	if (!f) {
		fprintf(stderr, "FAIL: fdopen %s: %s\n", path, strerror(errno));
		close(fd);
		exit(1);
	}
	if (len && fwrite(data, 1, len, f) != len) {
		fprintf(stderr, "FAIL: fwrite %s\n", path);
		fclose(f);
		exit(1);
	}
	fclose(f);
}

static const char g_obj_path[] = "/tmp/lota_test_preflight.o";
static const char g_sig_path[] = "/tmp/lota_test_preflight.o.sig";
static const char g_pubkey[] = "dummy-pubkey.pem";
static const char g_obj_bytes[] = "ENFORCEMENT-OBJECT-BYTES";

static void write_object(void)
{
	write_file(g_obj_path, g_obj_bytes, sizeof(g_obj_bytes) - 1);
}

static void write_signature(size_t len)
{
	uint8_t sig[POLICY_SIG_SIZE] = { 0 };

	write_file(g_sig_path, sig, len);
}

/*
 * The accept path.
 * An object whose signature verifies is reported as one the agent may go on
 * to load, and the primitive was actually consulted -- a pre-flight that answers
 * without checking anything would pass this too.
 */
static void test_a_signed_object_is_accepted(void)
{
	write_object();
	write_signature(POLICY_SIG_SIZE);
	g_verify_verdict = 0;
	g_verify_calls = 0;

	CHECK(bpf_loader_verify_object(g_obj_path, g_pubkey) == 0,
	      "an object whose signature verifies is accepted");
	CHECK(g_verify_calls == 1,
	      "the verdict came from the signature primitive, once");
}

/*
 * Object and signature are both present and well-formed, but the signature
 * does not verify under the configured key: the pre-flight must refuse it.
 */
static void test_a_bad_signature_is_refused(void)
{
	write_object();
	write_signature(POLICY_SIG_SIZE);
	g_verify_verdict = -EPERM;

	CHECK(bpf_loader_verify_object(g_obj_path, g_pubkey) < 0,
	      "an object signed by another key is refused");
}

/*
 * Every way the three files can fail to be there.
 * Each is an ordinary misconfiguration -- a package that shipped an object
 * without its signature, a fleet key that was never installed, a path typo
 * -- and each must be answerable without the TPM.
 */
static void test_missing_material_is_refused(void)
{
	g_verify_verdict = 0;

	write_object();
	unlink(g_sig_path);
	CHECK(bpf_loader_verify_object(g_obj_path, g_pubkey) < 0,
	      "an object with no signature beside it is refused");

	unlink(g_obj_path);
	write_signature(POLICY_SIG_SIZE);
	CHECK(bpf_loader_verify_object(g_obj_path, g_pubkey) < 0,
	      "a signature with no object is refused");

	write_object();
	write_signature(POLICY_SIG_SIZE - 1);
	CHECK(bpf_loader_verify_object(g_obj_path, g_pubkey) < 0,
	      "a signature shorter than Ed25519's is refused");
}

/*
 * No key configured is a refusal, not a skip.
 * A pre-flight that treated an unset key as "nothing to check" would report
 * an unsigned object healthy and let the load be the first to notice
 * -- after the extend, which is the whole defect.
 */
static void test_no_key_is_refused_not_skipped(void)
{
	write_object();
	write_signature(POLICY_SIG_SIZE);
	g_verify_verdict = 0;
	g_verify_calls = 0;

	CHECK(bpf_loader_verify_object(g_obj_path, NULL) == -EINVAL,
	      "an unset public key is refused");
	CHECK(bpf_loader_verify_object(g_obj_path, "") == -EINVAL,
	      "an empty public key path is refused");
	CHECK(bpf_loader_verify_object(NULL, g_pubkey) == -EINVAL,
	      "an unset object path is refused");
	CHECK(g_verify_calls == 0,
	      "none of those reached the signature primitive");
}

int main(void)
{
	printf("=== enforcement object pre-flight tests ===\n");
	test_a_signed_object_is_accepted();
	test_a_bad_signature_is_refused();
	test_missing_material_is_refused();
	test_no_key_is_refused_not_skipped();

	unlink(g_obj_path);
	unlink(g_sig_path);

	if (g_failures) {
		fprintf(stderr, "\n%d test(s) failed\n", g_failures);
		return 1;
	}
	printf("\nAll enforcement object pre-flight tests passed\n");
	return 0;
}
