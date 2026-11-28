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

#include "test.h"

static int g_verify_verdict;
static int g_verify_calls;

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
		FAIL("open %s: %s", path, strerror(errno));
		exit(1);
	}
	f = fdopen(fd, "wb");
	if (!f) {
		FAIL("fdopen %s: %s", path, strerror(errno));
		close(fd);
		exit(1);
	}
	if (len && fwrite(data, 1, len, f) != len) {
		FAIL("fwrite %s", path);
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

	TEST("an object whose signature verifies is accepted");
	if (bpf_loader_verify_object(g_obj_path, g_pubkey) != 0)
		FAIL("expected: bpf_loader_verify_object(g_obj_path, "
		     "g_pubkey) == 0");
	TEST("the verdict came from the signature primitive, once");
	if (g_verify_calls != 1)
		FAIL("expected: g_verify_calls == 1");
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

	TEST("an object signed by another key is refused");
	if (bpf_loader_verify_object(g_obj_path, g_pubkey) >= 0)
		FAIL("expected: bpf_loader_verify_object(g_obj_path, "
		     "g_pubkey) < 0");
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
	TEST("an object with no signature beside it is refused");
	if (bpf_loader_verify_object(g_obj_path, g_pubkey) >= 0)
		FAIL("expected: bpf_loader_verify_object(g_obj_path, "
		     "g_pubkey) < 0");

	unlink(g_obj_path);
	write_signature(POLICY_SIG_SIZE);
	TEST("a signature with no object is refused");
	if (bpf_loader_verify_object(g_obj_path, g_pubkey) >= 0)
		FAIL("expected: bpf_loader_verify_object(g_obj_path, "
		     "g_pubkey) < 0");

	write_object();
	write_signature(POLICY_SIG_SIZE - 1);
	TEST("a signature shorter than Ed25519's is refused");
	if (bpf_loader_verify_object(g_obj_path, g_pubkey) >= 0)
		FAIL("expected: bpf_loader_verify_object(g_obj_path, "
		     "g_pubkey) < 0");
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

	TEST("an unset public key is refused");
	if (bpf_loader_verify_object(g_obj_path, NULL) != -EINVAL)
		FAIL("expected: bpf_loader_verify_object(g_obj_path, NULL) == "
		     "-EINVAL");
	TEST("an empty public key path is refused");
	if (bpf_loader_verify_object(g_obj_path, "") != -EINVAL)
		FAIL("expected: bpf_loader_verify_object(g_obj_path, \"\") == "
		     "-EINVAL");
	TEST("an unset object path is refused");
	if (bpf_loader_verify_object(NULL, g_pubkey) != -EINVAL)
		FAIL("expected: bpf_loader_verify_object(NULL, g_pubkey) == "
		     "-EINVAL");
	TEST("none of those reached the signature primitive");
	if (g_verify_calls != 0)
		FAIL("expected: g_verify_calls == 0");
}

int main(void)
{
	test_begin("bpf object preflight");
	test_a_signed_object_is_accepted();
	test_a_bad_signature_is_refused();
	test_missing_material_is_refused();
	test_no_key_is_refused_not_skipped();

	unlink(g_obj_path);
	unlink(g_sig_path);

	return test_end();
}
