/* SPDX-License-Identifier: MIT */
/*
 * Unit tests for the initramfs PCR14 lock helper's pure derivation.
 * Hardware TPM behaviour is covered by the production helper and
 * test-hardware; these tests keep the tag/endian contract pinned in
 * normal unit-test runs.
 */

#include <errno.h>
#include <openssl/evp.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <openssl/types.h>

#define HASH_SIZE 32

int lota_initramfs_lock_commit(uint32_t reset_count, uint32_t restart_count,
			       uint8_t out_digest[HASH_SIZE]);

static int tests_run;
static int tests_passed;

#define TEST(name)                                                             \
	do {                                                                   \
		tests_run++;                                                   \
		printf("  [%2d] %-55s ", tests_run, name);                     \
	} while (0)

#define PASS()                                                                 \
	do {                                                                   \
		tests_passed++;                                                \
		printf("PASS\n");                                              \
	} while (0)

#define FAIL(msg)                                                              \
	do {                                                                   \
		printf("FAIL: %s\n", msg);                                     \
	} while (0)

static int reference_commit(uint32_t reset_count, uint32_t restart_count,
			    uint8_t out[HASH_SIZE])
{
	static const char tag[] = "LOTA-PCR14-INITRAMFS-LOCK-v1";
	EVP_MD_CTX *md;
	int ok;

	(void)reset_count;
	(void)restart_count;

	md = EVP_MD_CTX_new();
	if (!md)
		return -ENOMEM;

	ok = EVP_DigestInit_ex(md, EVP_sha256(), NULL) == 1 &&
	     EVP_DigestUpdate(md, tag, sizeof(tag) - 1) == 1 &&
	     EVP_DigestFinal_ex(md, out, NULL) == 1;
	EVP_MD_CTX_free(md);
	return ok ? 0 : -EIO;
}

static void test_commit_matches_reference(void)
{
	uint8_t got[HASH_SIZE];
	uint8_t want[HASH_SIZE];

	TEST("initramfs lock commit matches reference derivation");
	memset(got, 0, sizeof(got));
	memset(want, 0, sizeof(want));

	if (lota_initramfs_lock_commit(0x10203040U, 0x50607080U, got) != 0) {
		FAIL("helper derivation failed");
		return;
	}
	if (reference_commit(0x10203040U, 0x50607080U, want) != 0) {
		FAIL("reference derivation failed");
		return;
	}
	if (memcmp(got, want, HASH_SIZE) != 0) {
		FAIL("digest mismatch");
		return;
	}

	PASS();
}

static void test_commit_ignores_clock_counters(void)
{
	uint8_t first[HASH_SIZE];
	uint8_t second[HASH_SIZE];

	TEST("initramfs lock commit ignores TPM clock counters");
	memset(first, 0, sizeof(first));
	memset(second, 0, sizeof(second));

	if (lota_initramfs_lock_commit(0, 0, first) != 0 ||
	    lota_initramfs_lock_commit(0xAABBCCDDU, 0x01020304U, second) != 0) {
		FAIL("helper derivation failed");
		return;
	}
	if (memcmp(first, second, HASH_SIZE) != 0) {
		FAIL("clock counters changed initramfs lock digest");
		return;
	}

	PASS();
}

static void test_commit_rejects_null_output(void)
{
	TEST("initramfs lock commit rejects NULL output");
	if (lota_initramfs_lock_commit(1, 2, NULL) != -EINVAL) {
		FAIL("expected -EINVAL");
		return;
	}
	PASS();
}

int main(void)
{
	printf("=== initramfs lock tests ===\n");
	test_commit_matches_reference();
	test_commit_ignores_clock_counters();
	test_commit_rejects_null_output();

	printf("\nResult: %d/%d tests passed\n", tests_passed, tests_run);
	return tests_passed == tests_run ? 0 : 1;
}
