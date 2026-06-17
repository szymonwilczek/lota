// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
// LOTA - constant-time secret comparison test
//
// Two things are proven here:
//   1. Functional: CRYPTO_memcmp reports equal only when every bit matches --
//      single flipped bit anywhere in the buffer is detected.
//      This guards the accept/reject decision of every converted call site.
//   2. Data-independence: plain memcmp returns at the first differing byte,
//      so its run time depends on how many leading bytes matched -- timing side
//      channel.
//      CRYPTO_memcmp scans the whole buffer regardless. On a large buffer the
//      difference is large and stable: memcmp is far faster when the
//      mismatch is early, CRYPTO_memcmp is not.
//      That is the property that makes the conversion the better choice for
//      secret-gating comparisons.
//
// Timing assertions are skipped under ASan/TSan (instrumentation distorts
// timing); the functional assertions always run.

#include <openssl/crypto.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#if defined(__SANITIZE_ADDRESS__) || defined(__SANITIZE_THREAD__)
#define CT_INSTRUMENTED 1
#elif defined(__has_feature)
#if __has_feature(address_sanitizer) || __has_feature(thread_sanitizer)
#define CT_INSTRUMENTED 1
#endif
#endif

#define DIGEST_LEN 32

static void fail(const char *msg)
{
	fprintf(stderr, "FAIL: %s\n", msg);
	exit(1);
}

// CRYPTO_memcmp must see equal buffers as equal and any single-bit difference
// as unequal, at every bit position
static void test_functional(void)
{
	uint8_t ref[DIGEST_LEN];
	uint8_t cmp[DIGEST_LEN];

	memset(ref, 0x5A, sizeof(ref));
	memcpy(cmp, ref, sizeof(cmp));

	if (CRYPTO_memcmp(ref, cmp, sizeof(ref)) != 0)
		fail("equal buffers reported as different");

	for (size_t bit = 0; bit < DIGEST_LEN * 8; bit++) {
		cmp[bit / 8] ^= (uint8_t)(1u << (bit % 8));
		if (CRYPTO_memcmp(ref, cmp, sizeof(ref)) == 0)
			fail("single flipped bit not detected");
		cmp[bit / 8] ^= (uint8_t)(1u << (bit % 8)); // restore
	}

	printf("functional: equal match + all %d single-bit flips detected\n",
	       DIGEST_LEN * 8);
}

#ifndef CT_INSTRUMENTED

#define TIMING_BUF (64u * 1024u)
#define TIMING_BATCH 400u
#define TIMING_REPS 9u

static volatile int g_sink;

static uint64_t now_ns(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static int cmp_u64(const void *a, const void *b)
{
	uint64_t x = *(const uint64_t *)a;
	uint64_t y = *(const uint64_t *)b;
	return (x > y) - (x < y);
}

// Median ns over a batch of comparisons of ref against buf.
// use_ct picks CRYPTO_memcmp (constant time) vs memcmp (early exit)
static uint64_t median_ns(const uint8_t *ref, const uint8_t *buf, size_t len,
			  int use_ct)
{
	uint64_t samples[TIMING_REPS];

	for (unsigned r = 0; r < TIMING_REPS; r++) {
		uint64_t t0 = now_ns();
		for (unsigned i = 0; i < TIMING_BATCH; i++) {
			if (use_ct)
				g_sink += CRYPTO_memcmp(ref, buf, len);
			else
				g_sink += memcmp(ref, buf, len);
		}
		uint64_t dt = now_ns() - t0;
		samples[r] = dt ? dt : 1;
	}
	qsort(samples, TIMING_REPS, sizeof(samples[0]), cmp_u64);
	return samples[TIMING_REPS / 2];
}

// Demonstrate the timing property on a large buffer:
// build one copy that differs at byte 0 (early mismatch) and one that differs
// at the last byte (late mismatch), and compare the late/early time ratio for
// each function.
static void test_timing(void)
{
	uint8_t *ref = malloc(TIMING_BUF);
	uint8_t *early = malloc(TIMING_BUF);
	uint8_t *late = malloc(TIMING_BUF);

	if (!ref || !early || !late)
		fail("allocation");

	memset(ref, 0x5A, TIMING_BUF);
	memcpy(early, ref, TIMING_BUF);
	memcpy(late, ref, TIMING_BUF);
	early[0] ^= 0xFF; // mismatch at the first byte
	late[TIMING_BUF - 1] ^= 0xFF; // mismatch at the last byte

	double mc_early = (double)median_ns(ref, early, TIMING_BUF, 0);
	double mc_late = (double)median_ns(ref, late, TIMING_BUF, 0);
	double ct_early = (double)median_ns(ref, early, TIMING_BUF, 1);
	double ct_late = (double)median_ns(ref, late, TIMING_BUF, 1);

	double mc_ratio = mc_late / mc_early;
	double ct_ratio = ct_late / ct_early;

	printf("timing (late/early over %u bytes): memcmp=%.1fx CRYPTO_memcmp=%.2fx\n",
	       TIMING_BUF, mc_ratio, ct_ratio);

	free(ref);
	free(early);
	free(late);

	// memcmp is data-dependent:
	// late mismatch costs far more than an early one.
	// CRYPTO_memcmp stays flat.
	// Generous bounds keep the check robust to scheduling noise while still
	// proving the qualitative difference.
	if (mc_ratio < 2.0)
		fail("memcmp did not show data-dependent timing (test setup?)");
	if (ct_ratio > 4.0)
		fail("CRYPTO_memcmp timing depended on mismatch position");
}

#endif /* !CT_INSTRUMENTED */

int main(void)
{
	test_functional();

#ifdef CT_INSTRUMENTED
	printf("timing: skipped under sanitizer instrumentation\n");
#else
	test_timing();
#endif

	printf("PASS\n");
	return 0;
}
