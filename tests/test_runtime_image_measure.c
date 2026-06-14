/* SPDX-License-Identifier: MIT */
/*
 * LOTA per-process runtime image measurement - Unit Tests
 *
 * Exercises lota_compute_runtime_image_digest() and its canonical-order
 * validator. The fold binds the kernel-computed fs-verity digest of every
 * file-backed executable object mapped into a process; these tests pin the
 * documented byte layout, the canonical-order contract, and the sensitivity
 * of the digest to soname, verity digest, and module count.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <errno.h>
#include <openssl/types.h>

#include "lota_endian.h"
#include "lota_runtime_image_measure.h"
#include "lota.h"

static int tests_run;
static int tests_passed;

#define TEST(name)                                                             \
	do {                                                                   \
		tests_run++;                                                   \
		printf("  [%2d] %-55s", tests_run, name);                      \
	} while (0)

#define PASS()                                                                 \
	do {                                                                   \
		tests_passed++;                                                \
		printf("PASS\n");                                              \
	} while (0)

#define FAIL(reason)                                                           \
	do {                                                                   \
		printf("FAIL (%s)\n", reason);                                 \
	} while (0)

/* fill a module with a soname and a verity digest of byte value `fill` */
static void make_module(struct lota_runtime_image_module *m, const char *soname,
			uint8_t fill)
{
	memset(m, 0, sizeof(*m));
	strncpy(m->soname, soname, LOTA_RUNTIME_IMAGE_SONAME_MAX - 1);
	m->verity.len = LOTA_VERITY_DIGEST_SHA512_SIZE;
	memset(m->verity.digest, fill, LOTA_VERITY_DIGEST_SHA512_SIZE);
}

/*
 * Independent reference fold mirroring the documented byte layout, so the
 * test catches any drift in lota_compute_runtime_image_digest()'s wire
 * format instead of merely re-deriving it
 */
static int reference_digest(const struct lota_runtime_image_module *modules,
			    uint32_t count, uint8_t out[32])
{
	static const char domain[] = "lota-runtime-image-measure:v1\0";
	EVP_MD_CTX *ctx = EVP_MD_CTX_new();
	unsigned int len = 0;
	uint8_t le[4];

	if (!ctx)
		return -1;
	if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1 ||
	    EVP_DigestUpdate(ctx, domain, sizeof(domain) - 1) != 1)
		goto fail;
	lota__write_le32(le, count);
	if (EVP_DigestUpdate(ctx, le, 4) != 1)
		goto fail;
	for (uint32_t i = 0; i < count; i++) {
		uint32_t slen = (uint32_t)strlen(modules[i].soname);
		lota__write_le32(le, slen);
		if (EVP_DigestUpdate(ctx, le, 4) != 1 ||
		    EVP_DigestUpdate(ctx, modules[i].soname, slen) != 1)
			goto fail;
		lota__write_le32(le, modules[i].verity.len);
		if (EVP_DigestUpdate(ctx, le, 4) != 1 ||
		    EVP_DigestUpdate(ctx, modules[i].verity.digest,
				     modules[i].verity.len) != 1)
			goto fail;
	}
	if (EVP_DigestFinal_ex(ctx, out, &len) != 1 || len != 32)
		goto fail;
	EVP_MD_CTX_free(ctx);
	return 0;
fail:
	EVP_MD_CTX_free(ctx);
	return -1;
}

int main(void)
{
	struct lota_runtime_image_module mods[3];
	uint8_t a[32], b[32], ref[32];

	printf("Runtime image measurement tests:\n");

	/* a.out then libc.so, canonically ordered */
	make_module(&mods[0], "a.out", 0x11);
	make_module(&mods[1], "libc.so.6", 0x22);

	TEST("digest matches independent reference layout");
	if (lota_compute_runtime_image_digest(mods, 2, a) == 0 &&
	    reference_digest(mods, 2, ref) == 0 && memcmp(a, ref, 32) == 0)
		PASS();
	else
		FAIL("layout drift");

	TEST("digest is deterministic");
	if (lota_compute_runtime_image_digest(mods, 2, b) == 0 &&
	    memcmp(a, b, 32) == 0)
		PASS();
	else
		FAIL("non-deterministic");

	TEST("soname change alters digest");
	make_module(&mods[1], "libc.so.7", 0x22);
	if (lota_compute_runtime_image_digest(mods, 2, b) == 0 &&
	    memcmp(a, b, 32) != 0)
		PASS();
	else
		FAIL("soname not bound");

	TEST("verity digest change alters digest");
	make_module(&mods[1], "libc.so.6", 0x23);
	if (lota_compute_runtime_image_digest(mods, 2, b) == 0 &&
	    memcmp(a, b, 32) != 0)
		PASS();
	else
		FAIL("verity digest not bound");

	TEST("module count change alters digest");
	if (lota_compute_runtime_image_digest(mods, 1, b) == 0 &&
	    memcmp(a, b, 32) != 0)
		PASS();
	else
		FAIL("count not bound");

	TEST("empty set yields a defined digest");
	if (lota_compute_runtime_image_digest(NULL, 0, b) == 0 &&
	    reference_digest(NULL, 0, ref) == 0 && memcmp(b, ref, 32) == 0)
		PASS();
	else
		FAIL("empty set rejected");

	/* reset to canonical pair for the validator tests */
	make_module(&mods[0], "a.out", 0x11);
	make_module(&mods[1], "libc.so.6", 0x22);

	TEST("validator accepts canonical order");
	if (lota_validate_runtime_image_modules(mods, 2) == 0)
		PASS();
	else
		FAIL("rejected valid set");

	TEST("validator rejects unsorted order");
	make_module(&mods[0], "libc.so.6", 0x22);
	make_module(&mods[1], "a.out", 0x11);
	if (lota_validate_runtime_image_modules(mods, 2) == -EINVAL &&
	    lota_compute_runtime_image_digest(mods, 2, b) == -EINVAL)
		PASS();
	else
		FAIL("accepted unsorted");

	TEST("validator rejects duplicate module");
	make_module(&mods[0], "libc.so.6", 0x22);
	make_module(&mods[1], "libc.so.6", 0x22);
	if (lota_validate_runtime_image_modules(mods, 2) == -EINVAL)
		PASS();
	else
		FAIL("accepted duplicate");

	TEST("validator rejects non-SHA-512 verity length");
	make_module(&mods[0], "a.out", 0x11);
	mods[0].verity.len = 32;
	if (lota_validate_runtime_image_modules(mods, 1) == -EINVAL)
		PASS();
	else
		FAIL("accepted short verity digest");

	TEST("validator rejects empty soname");
	make_module(&mods[0], "a.out", 0x11);
	mods[0].soname[0] = '\0';
	if (lota_validate_runtime_image_modules(mods, 1) == -EINVAL)
		PASS();
	else
		FAIL("accepted empty soname");

	TEST("validator rejects NULL set with non-zero count");
	if (lota_validate_runtime_image_modules(NULL, 1) == -EINVAL)
		PASS();
	else
		FAIL("accepted NULL set");

	printf("\n%d/%d runtime image measurement tests passed\n", tests_passed,
	       tests_run);
	return tests_passed == tests_run ? 0 : 1;
}
