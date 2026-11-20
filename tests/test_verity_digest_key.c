/* SPDX-License-Identifier: MIT */
/*
 * bpf_get_fsverity_digest() reports success as 0 and writes a struct
 * fsverity_digest -- a four-byte header, then the digest -- into the buffer
 * the caller hands it. A caller that reads the return value as a length,
 * or the buffer as a bare digest, builds a key that matches nothing:
 * the allowlist then rejects the very file it was given.
 *
 * The layout below was read off a live kernel (Fedora 7.1.8, fs-verity
 * on btrfs): for a SHA-256 file the buffer began 01 00 20 00 and the digest
 * followed at offset 4.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#include <string.h>

#include "../include/lota.h"

#include "test.h"

/* Fill @buf the way the kernel does: header, then @len digest bytes */
static void make_kernel_buf(unsigned char *buf, unsigned short alg,
			    unsigned short len, unsigned char first)
{
	struct lota_fsverity_digest_hdr hdr;
	unsigned short i;

	memset(buf, 0, LOTA_FSVERITY_DIGEST_BUF_SIZE);
	hdr.digest_algorithm = alg;
	hdr.digest_size = len;
	memcpy(buf, &hdr, sizeof(hdr));

	for (i = 0; i < len; i++)
		buf[LOTA_FSVERITY_DIGEST_HDR_SIZE + i] =
			(unsigned char)(first + i);
}

static void test_sha256_key(void)
{
	unsigned char buf[LOTA_FSVERITY_DIGEST_BUF_SIZE];
	struct lota_verity_digest_key key;
	unsigned int i;
	int tail_zero = 1;

	make_kernel_buf(buf, 1, LOTA_VERITY_DIGEST_SHA256_SIZE, 0x0f);
	memset(&key, 0xAA, sizeof(key));

	TEST("a SHA-256 digest buffer parses");
	if (lota_verity_key_from_digest_buf(buf, &key) != 0)
		FAIL("expected: lota_verity_key_from_digest_buf(buf, &key) == "
		     "0");
	TEST("length comes from the header, not from the return value");
	if (key.len != LOTA_VERITY_DIGEST_SHA256_SIZE)
		FAIL("expected: key.len == LOTA_VERITY_DIGEST_SHA256_SIZE");
	TEST("the digest starts after the header, not at offset 0");
	if (key.digest[0] != 0x0f)
		FAIL("expected: key.digest[0] == 0x0f");
	TEST("the whole digest is copied");
	if (key.digest[LOTA_VERITY_DIGEST_SHA256_SIZE - 1] !=
	    (unsigned char)(0x0f + LOTA_VERITY_DIGEST_SHA256_SIZE - 1))
		FAIL("expected: key.digest[LOTA_VERITY_DIGEST_SHA256_SIZE - "
		     "1] == (unsigned char)(0x0f + "
		     "LOTA_VERITY_DIGEST_SHA256_SIZE - 1)");

	for (i = LOTA_VERITY_DIGEST_SHA256_SIZE;
	     i < LOTA_VERITY_DIGEST_MAX_SIZE; i++)
		if (key.digest[i] != 0)
			tail_zero = 0;
	TEST("the tail past len is zeroed so one map holds both sizes");
	if (!tail_zero)
		FAIL("expected: tail_zero");
}

static void test_sha512_key(void)
{
	unsigned char buf[LOTA_FSVERITY_DIGEST_BUF_SIZE];
	struct lota_verity_digest_key key;

	make_kernel_buf(buf, 2, LOTA_VERITY_DIGEST_SHA512_SIZE, 0x20);
	memset(&key, 0xAA, sizeof(key));

	TEST("a SHA-512 digest buffer parses");
	if (lota_verity_key_from_digest_buf(buf, &key) != 0)
		FAIL("expected: lota_verity_key_from_digest_buf(buf, &key) == "
		     "0");
	TEST("SHA-512 length is taken from the header");
	if (key.len != LOTA_VERITY_DIGEST_SHA512_SIZE)
		FAIL("expected: key.len == LOTA_VERITY_DIGEST_SHA512_SIZE");
	TEST("the whole SHA-512 digest is copied");
	if (!(key.digest[0] == 0x20 &&
	      key.digest[LOTA_VERITY_DIGEST_SHA512_SIZE - 1] ==
		      (unsigned char)(0x20 + LOTA_VERITY_DIGEST_SHA512_SIZE -
				      1)))
		FAIL("expected: key.digest[0] == 0x20 && "
		     "key.digest[LOTA_VERITY_DIGEST_SHA512_SIZE - 1] == "
		     "(unsigned char)(0x20 + LOTA_VERITY_DIGEST_SHA512_SIZE - "
		     "1)");
}

static void test_unsupported_size_refused(void)
{
	unsigned char buf[LOTA_FSVERITY_DIGEST_BUF_SIZE];
	struct lota_verity_digest_key key;

	/* a size no policy enforces: refused rather than truncated */
	make_kernel_buf(buf, 1, 20, 0x01);
	memset(&key, 0, sizeof(key));
	TEST("a digest size policy does not enforce is refused");
	if (lota_verity_key_from_digest_buf(buf, &key) == 0)
		FAIL("expected: lota_verity_key_from_digest_buf(buf, &key) != "
		     "0");

	/* a zero size is what a caller sees when it mistakes the kernel's
	 * success return for a length */
	make_kernel_buf(buf, 1, 0, 0x01);
	TEST("a zero size is refused");
	if (lota_verity_key_from_digest_buf(buf, &key) == 0)
		FAIL("expected: lota_verity_key_from_digest_buf(buf, &key) != "
		     "0");
}

static void test_matches_the_loader_key(void)
{
	unsigned char buf[LOTA_FSVERITY_DIGEST_BUF_SIZE];
	struct lota_verity_digest_key from_kernel;
	struct lota_verity_digest_key from_loader;

	/*
	 * The loader measures with FS_IOC_MEASURE_VERITY and fills the key
	 * directly.
	 * Both keys index the same map, so for one file they have to be
	 * byte-identical -- this is the equality the allowlist rests on.
	 */
	make_kernel_buf(buf, 1, LOTA_VERITY_DIGEST_SHA256_SIZE, 0x0f);
	TEST("kernel-side key builds");
	if (lota_verity_key_from_digest_buf(buf, &from_kernel) != 0)
		FAIL("expected: lota_verity_key_from_digest_buf(buf, "
		     "&from_kernel) == 0");

	memset(&from_loader, 0, sizeof(from_loader));
	from_loader.len = LOTA_VERITY_DIGEST_SHA256_SIZE;
	memcpy(from_loader.digest, buf + LOTA_FSVERITY_DIGEST_HDR_SIZE,
	       LOTA_VERITY_DIGEST_SHA256_SIZE);

	TEST("the enforcement key equals the key the loader installs");
	if (memcmp(&from_kernel, &from_loader, sizeof(from_kernel)) != 0)
		FAIL("expected: memcmp(&from_kernel, &from_loader, "
		     "sizeof(from_kernel)) == 0");
}

int main(void)
{
	test_begin("verity digest key");
	test_sha256_key();
	test_sha512_key();
	test_unsupported_size_refused();
	test_matches_the_loader_key();

	return test_end();
}
