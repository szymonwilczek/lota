/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * Unit tests for the initramfs PCR14 lock helper's pure derivation.
 * Hardware TPM behaviour is covered by the production helper and
 * test-hardware; these tests keep the tag pinned in normal unit-test
 * runs.
 */

#include <errno.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <openssl/types.h>

#include "test.h"

#define HASH_SIZE 32

int lota_initramfs_lock_commit(uint8_t out_digest[HASH_SIZE]);
int lota_initramfs_lock_read_baseline(const char *path, uint8_t out[HASH_SIZE]);

static int reference_commit(uint8_t out[HASH_SIZE])
{
	static const char tag[] = "LOTA-PCR14-INITRAMFS-LOCK-v1";
	EVP_MD_CTX *md;
	int ok;

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

	if (lota_initramfs_lock_commit(got) != 0) {
		FAIL("helper derivation failed");
		return;
	}
	if (reference_commit(want) != 0) {
		FAIL("reference derivation failed");
		return;
	}
	if (memcmp(got, want, HASH_SIZE) != 0) {
		FAIL("digest mismatch");
		return;
	}
}

static void test_commit_rejects_null_output(void)
{
	TEST("initramfs lock commit rejects NULL output");
	if (lota_initramfs_lock_commit(NULL) != -EINVAL) {
		FAIL("expected -EINVAL");
		return;
	}
}

static void test_baseline_read_takes_exactly_one_digest(void)
{
	static const size_t lens[] = { HASH_SIZE, HASH_SIZE - 1,
				       HASH_SIZE + 1 };
	static const int want[] = { 1, 0, 0 };
	uint8_t buf[HASH_SIZE + 1];
	uint8_t out[HASH_SIZE];
	char path[64];

	TEST("a saved baseline is read only at exactly 32 bytes");
	snprintf(path, sizeof(path), "/tmp/lota-lock-base.%d", (int)getpid());
	memset(buf, 0x5a, sizeof(buf));
	for (size_t i = 0; i < sizeof(lens) / sizeof(lens[0]); i++) {
		int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC,
			      0600);

		if (fd < 0 || write(fd, buf, lens[i]) != (ssize_t)lens[i]) {
			if (fd >= 0)
				close(fd);
			unlink(path);
			FAIL("could not write the fixture");
			return;
		}
		close(fd);
		memset(out, 0, sizeof(out));
		if (lota_initramfs_lock_read_baseline(path, out) != want[i]) {
			unlink(path);
			FAIL("a baseline of the wrong length was taken");
			return;
		}
		if (want[i] && memcmp(out, buf, HASH_SIZE) != 0) {
			unlink(path);
			FAIL("the baseline bytes were not copied");
			return;
		}
	}
	unlink(path);
	if (lota_initramfs_lock_read_baseline("/nonexistent/lota-base", out) !=
	    0) {
		FAIL("a missing baseline was not read as absent");
		return;
	}
}

int main(void)
{
	test_begin("initramfs lock");
	test_commit_matches_reference();
	test_commit_rejects_null_output();
	test_baseline_read_takes_exactly_one_digest();

	return test_end();
}
