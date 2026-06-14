/* SPDX-License-Identifier: MIT */
/*
 * LOTA sealed keys - TPM-side unit tests.
 *
 * Like the other tpm.c unit tests, these exercise only the paths that run
 * before any Esys call: the PCR-mask -> selection conversion and the
 * argument validation guards of tpm_seal_secret() / tpm_unseal_secret().
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <tss2/tss2_tpm2_types.h>

#include "../src/agent/agent_internal.h" // IWYU pragma: keep (defines LOTA_TPM_TESTING)
#include "lota_seal.h"

static int tests_run;
static int tests_passed;

#define TEST(name)                                                             \
	do {                                                                   \
		tests_run++;                                                   \
		printf("  [%2d] %-58s", tests_run, name);                      \
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

static void test_mask_selection_default(void)
{
	uint8_t sel[3];
	uint32_t count = 0;

	TEST("mask->selection: default mask sets PCR 0-7 and PCR14");
	if (tpm_test_pcr_mask_to_selection(LOTA_SEAL_DEFAULT_PCR_MASK, sel,
					   &count) != 0) {
		FAIL("call");
		return;
	}
	/* PCR 0-7 -> byte0 = 0xFF; PCR14 -> byte1 bit6 = 0x40; byte2 = 0 */
	if (count != 1 || sel[0] != 0xFF || sel[1] != 0x40 || sel[2] != 0x00) {
		FAIL("bitmap mismatch");
		return;
	}
	PASS();
}

static void test_mask_selection_edges(void)
{
	uint8_t sel[3];
	uint32_t count = 0;

	TEST("mask->selection: PCR0, PCR14, PCR23 map to the right bits");
	tpm_test_pcr_mask_to_selection(1u << 0, sel, &count);
	if (sel[0] != 0x01 || sel[1] != 0 || sel[2] != 0) {
		FAIL("PCR0");
		return;
	}
	tpm_test_pcr_mask_to_selection(1u << 14, sel, &count);
	if (sel[0] != 0 || sel[1] != 0x40 || sel[2] != 0) {
		FAIL("PCR14");
		return;
	}
	tpm_test_pcr_mask_to_selection(1u << 23, sel, &count);
	if (sel[0] != 0 || sel[1] != 0 || sel[2] != 0x80) {
		FAIL("PCR23");
		return;
	}
	PASS();
}

static void test_mask_selection_ignores_out_of_range(void)
{
	uint8_t sel[3];
	uint32_t count = 0;

	TEST("mask->selection: bits above PCR23 contribute nothing");
	tpm_test_pcr_mask_to_selection((1u << 24) | (1u << 31), sel, &count);
	if (sel[0] != 0 || sel[1] != 0 || sel[2] != 0) {
		FAIL("out-of-range bit leaked into selection");
		return;
	}
	PASS();
}

static void test_mask_selection_null_args(void)
{
	uint8_t sel[3];
	uint32_t count = 0;

	TEST("mask->selection: NULL outputs rejected");
	if (tpm_test_pcr_mask_to_selection(1u << 0, NULL, &count) != -EINVAL) {
		FAIL("NULL select");
		return;
	}
	if (tpm_test_pcr_mask_to_selection(1u << 0, sel, NULL) != -EINVAL) {
		FAIL("NULL count");
		return;
	}
	PASS();
}

static void test_seal_arg_validation(void)
{
	uint8_t secret[16] = {0};
	uint8_t big[LOTA_SEAL_MAX_SECRET + 1] = {0};
	uint8_t out[LOTA_SEAL_MAX_BLOB];
	size_t out_len = 0;

	TEST("seal: NULL ctx and bad lengths rejected before any TPM call");
	/* NULL context: returns before touching the TPM */
	if (tpm_seal_secret(NULL, secret, sizeof(secret), 0, out, sizeof(out),
			    &out_len) != -EINVAL) {
		FAIL("NULL ctx");
		return;
	}
	/*
	 * zeroed context has esys_ctx == NULL and initialized == false, so
	 * the guard rejects it before any Esys call -- safe without a TPM
	 */
	struct tpm_context ctx;
	memset(&ctx, 0, sizeof(ctx));
	if (tpm_seal_secret(&ctx, secret, sizeof(secret), 0, out, sizeof(out),
			    &out_len) != -EINVAL) {
		FAIL("uninit ctx");
		return;
	}
	if (tpm_seal_secret(&ctx, secret, 0, 0, out, sizeof(out), &out_len) !=
	    -EINVAL) {
		FAIL("zero len");
		return;
	}
	if (tpm_seal_secret(&ctx, big, sizeof(big), 0, out, sizeof(out),
			    &out_len) != -EINVAL) {
		FAIL("oversize secret");
		return;
	}
	if (tpm_seal_secret(&ctx, NULL, 8, 0, out, sizeof(out), &out_len) !=
	    -EINVAL) {
		FAIL("NULL secret");
		return;
	}
	PASS();
}

static void test_unseal_arg_validation(void)
{
	uint8_t blob[LOTA_SEAL_MAX_BLOB] = {0};
	uint8_t out[LOTA_SEAL_MAX_SECRET];
	size_t out_len = 0;

	TEST("unseal: NULL ctx and NULL args rejected before any TPM call");
	if (tpm_unseal_secret(NULL, blob, sizeof(blob), out, sizeof(out),
			      &out_len) != -EINVAL) {
		FAIL("NULL ctx");
		return;
	}
	struct tpm_context ctx;
	memset(&ctx, 0, sizeof(ctx));
	if (tpm_unseal_secret(&ctx, NULL, 0, out, sizeof(out), &out_len) !=
	    -EINVAL) {
		FAIL("NULL blob");
		return;
	}
	if (tpm_unseal_secret(&ctx, blob, sizeof(blob), out, sizeof(out),
			      NULL) != -EINVAL) {
		FAIL("NULL out_len");
		return;
	}
	PASS();
}

static void test_policy_fail_maps_clean(void)
{
	TEST("PolicyPCR mismatch maps to the dedicated policy-fail code");
	/*
	 * PCR-bound unseal in the wrong boot state returns TPM2_RC_POLICY_FAIL.
	 * It must surface as the dedicated LOTA code, not -EIO.
	 */
	if (tpm_test_rc_to_errno(TPM2_RC_POLICY_FAIL) !=
	    -LOTA_ERR_TPM_POLICY_FAIL) {
		FAIL("POLICY_FAIL not mapped");
		return;
	}
	if (tpm_test_rc_to_errno(TPM2_RC_PCR_CHANGED) !=
	    -LOTA_ERR_TPM_POLICY_FAIL) {
		FAIL("PCR_CHANGED not mapped");
		return;
	}
	PASS();
}

int main(void)
{
	printf("Running LOTA sealed-keys TPM-side tests...\n\n");

	test_mask_selection_default();
	test_mask_selection_edges();
	test_mask_selection_ignores_out_of_range();
	test_mask_selection_null_args();
	test_seal_arg_validation();
	test_unseal_arg_validation();
	test_policy_fail_maps_clean();

	printf("\n%d/%d tests passed\n", tests_passed, tests_run);
	return tests_passed == tests_run ? 0 : 1;
}
