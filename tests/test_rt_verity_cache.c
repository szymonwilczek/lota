/* SPDX-License-Identifier: MIT */
/*
 * LOTA fs-verity digest cache - Unit Tests
 *
 * Cache exists to keep a heartbeating title from re-reading the same unchanged
 * libraries every few seconds.
 * Serving digest for an inode that is no longer the inode measured would be worse
 * than any saving, so these tests pin what counts as the same object.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../src/agent/rt_verity_cache.h"

static int tests_run;
static int tests_passed;

#define TEST(name)                                        \
	do {                                              \
		tests_run++;                              \
		printf("  [%2d] %-55s", tests_run, name); \
	} while (0)

#define PASS()                    \
	do {                      \
		tests_passed++;   \
		printf("PASS\n"); \
	} while (0)

#define FAIL(reason)                           \
	do {                                   \
		printf("FAIL (%s)\n", reason); \
	} while (0)

static struct lota_rt_verity_key make_key(uint64_t dev, uint64_t ino,
					  uint64_t size, int64_t sec,
					  int64_t nsec)
{
	struct lota_rt_verity_key k = { 0 };

	k.dev = dev;
	k.ino = ino;
	k.size = size;
	k.mtime_sec = sec;
	k.mtime_nsec = nsec;
	return k;
}

static struct lota_verity_digest_key make_digest(uint8_t fill, uint32_t len)
{
	struct lota_verity_digest_key d = { 0 };

	d.len = len;
	memset(d.digest, fill, len);
	return d;
}

int main(void)
{
	static struct lota_rt_verity_cache cache;
	struct lota_verity_digest_key got;
	struct lota_rt_verity_key key;

	printf("fs-verity digest cache tests:\n");

	lota_rt_verity_cache_clear(&cache);
	key = make_key(64, 1000, 4096, 100, 200);

	TEST("an unknown object misses");
	if (lota_rt_verity_cache_get(&cache, &key, &got) == 0)
		PASS();
	else
		FAIL("hit on an empty cache");

	TEST("a stored digest is served back");
	lota_rt_verity_cache_put(&cache, &key,
				 &(struct lota_verity_digest_key){
					 .len = LOTA_VERITY_DIGEST_SHA256_SIZE });
	{
		struct lota_verity_digest_key d =
			make_digest(0xAB, LOTA_VERITY_DIGEST_SHA512_SIZE);
		lota_rt_verity_cache_put(&cache, &key, &d);
	}
	memset(&got, 0, sizeof(got));
	if (lota_rt_verity_cache_get(&cache, &key, &got) == 1 &&
	    got.len == LOTA_VERITY_DIGEST_SHA512_SIZE && got.digest[0] == 0xAB)
		PASS();
	else
		FAIL("stored digest not served");

	/* every identity field has to be part of what "the same object" means */
	TEST("a different inode misses");
	{
		struct lota_rt_verity_key other = make_key(64, 1001, 4096, 100, 200);
		if (lota_rt_verity_cache_get(&cache, &other, &got) == 0)
			PASS();
		else
			FAIL("served another inode's digest");
	}

	TEST("a different device misses");
	{
		struct lota_rt_verity_key other = make_key(65, 1000, 4096, 100, 200);
		if (lota_rt_verity_cache_get(&cache, &other, &got) == 0)
			PASS();
		else
			FAIL("served another filesystem's digest");
	}

	TEST("a changed size misses");
	{
		struct lota_rt_verity_key other = make_key(64, 1000, 8192, 100, 200);
		if (lota_rt_verity_cache_get(&cache, &other, &got) == 0)
			PASS();
		else
			FAIL("served a digest across a size change");
	}

	TEST("a changed mtime misses");
	{
		struct lota_rt_verity_key other = make_key(64, 1000, 4096, 101, 200);
		struct lota_rt_verity_key ns = make_key(64, 1000, 4096, 100, 201);
		if (lota_rt_verity_cache_get(&cache, &other, &got) == 0 &&
		    lota_rt_verity_cache_get(&cache, &ns, &got) == 0)
			PASS();
		else
			FAIL("served a digest across an mtime change");
	}

	TEST("a re-put replaces the digest for the same key");
	{
		struct lota_verity_digest_key d =
			make_digest(0xCD, LOTA_VERITY_DIGEST_SHA256_SIZE);
		lota_rt_verity_cache_put(&cache, &key, &d);
		memset(&got, 0, sizeof(got));
		if (lota_rt_verity_cache_get(&cache, &key, &got) == 1 &&
		    got.len == LOTA_VERITY_DIGEST_SHA256_SIZE &&
		    got.digest[0] == 0xCD)
			PASS();
		else
			FAIL("kept the superseded digest");
	}

	TEST("a digest of unsupported length is not stored");
	{
		struct lota_rt_verity_key bad = make_key(64, 2000, 4096, 100, 200);
		struct lota_verity_digest_key d = make_digest(0xEE, 48);
		d.len = 48;
		lota_rt_verity_cache_put(&cache, &bad, &d);
		if (lota_rt_verity_cache_get(&cache, &bad, &got) == 0)
			PASS();
		else
			FAIL("cached an unsupported digest length");
	}

	TEST("the cache stays bounded under pressure");
	{
		int served = 0;

		lota_rt_verity_cache_clear(&cache);
		for (uint64_t i = 0; i < LOTA_RT_VERITY_CACHE_ENTRIES * 4; i++) {
			struct lota_rt_verity_key k =
				make_key(64, 5000 + i, 4096, 100, 200);
			struct lota_verity_digest_key d = make_digest(
				(uint8_t)i, LOTA_VERITY_DIGEST_SHA256_SIZE);
			lota_rt_verity_cache_put(&cache, &k, &d);
		}
		for (uint64_t i = 0; i < LOTA_RT_VERITY_CACHE_ENTRIES * 4; i++) {
			struct lota_rt_verity_key k =
				make_key(64, 5000 + i, 4096, 100, 200);
			if (lota_rt_verity_cache_get(&cache, &k, &got) == 1)
				served++;
		}
		/* eviction is expected; serving a wrong digest is not */
		if (served > 0 && served <= LOTA_RT_VERITY_CACHE_ENTRIES)
			PASS();
		else
			FAIL("cache grew past its bound");
	}

	TEST("a NULL cache is safe");
	lota_rt_verity_cache_put(NULL, &key, &got);
	if (lota_rt_verity_cache_get(NULL, &key, &got) == 0)
		PASS();
	else
		FAIL("hit on a NULL cache");

	printf("\n%d/%d fs-verity digest cache tests passed\n", tests_passed,
	       tests_run);
	return tests_passed == tests_run ? 0 : 1;
}
