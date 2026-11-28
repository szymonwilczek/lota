/* SPDX-License-Identifier: MIT */
/*
 * Which PCR carries the booted kernel depends on how the host booted,
 * and a register that exists is not a register that was extended: every TPM
 * answers for PCR 11 whether or not anything measured a unified kernel image
 * into it.
 * Taking the first readable one therefore reported thirty-two zero bytes
 * on every GRUB host, with the flag saying the measurement was good.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#include <errno.h>
#include <stdint.h>
#include <string.h>

#include "../src/agent/kernel_measure.h"

#include "test.h"

/* a machine's registers: value per PCR, and whether the read succeeds */
struct fake_tpm {
	uint8_t value[24][LOTA_HASH_SIZE];
	int readable[24];
	int reads;
};

static int fake_read(void *ctx, int pcr, uint8_t out[LOTA_HASH_SIZE])
{
	struct fake_tpm *tpm = ctx;

	if (pcr < 0 || pcr >= 24)
		return -EINVAL;

	tpm->reads++;
	if (!tpm->readable[pcr])
		return -EIO;

	memcpy(out, tpm->value[pcr], LOTA_HASH_SIZE);
	return 0;
}

static void set_pcr(struct fake_tpm *tpm, int pcr, uint8_t fill)
{
	memset(tpm->value[pcr], fill, LOTA_HASH_SIZE);
	tpm->readable[pcr] = 1;
}

static void all_readable(struct fake_tpm *tpm)
{
	memset(tpm, 0, sizeof(*tpm));
	for (int i = 0; i < 24; i++)
		tpm->readable[i] = 1;
}

/*
 * The shape this was found in: Fedora on GRUB, PCR 11 never extended,
 * the kernel and initrd measured into PCR 9.
 */
static void test_grub_host_takes_pcr9(void)
{
	struct fake_tpm tpm;
	uint8_t out[LOTA_HASH_SIZE];
	int pcr = -1;

	all_readable(&tpm);
	set_pcr(&tpm, 9, 0x3c);
	set_pcr(&tpm, 8, 0x91);
	set_pcr(&tpm, 4, 0x97);

	TEST("a host with an unextended PCR 11 still has a measurement");
	if (kernel_measurement_select(fake_read, &tpm, out, &pcr) != 0)
		FAIL("expected: kernel_measurement_select(fake_read, &tpm, "
		     "out, &pcr) == 0");
	TEST("the GRUB kernel measurement comes from PCR 9");
	if (pcr != 9)
		FAIL("expected: pcr == 9");
	TEST("the value is the one PCR 9 holds");
	if (out[0] != 0x3c)
		FAIL("expected: out[0] == 0x3c");
}

/* a unified kernel image is measured into PCR 11, and it still wins */
static void test_uki_host_takes_pcr11(void)
{
	struct fake_tpm tpm;
	uint8_t out[LOTA_HASH_SIZE];
	int pcr = -1;

	all_readable(&tpm);
	set_pcr(&tpm, 11, 0xab);
	set_pcr(&tpm, 9, 0x3c);

	TEST("a UKI host keeps reporting PCR 11");
	if (!(kernel_measurement_select(fake_read, &tpm, out, &pcr) == 0 &&
	      pcr == 11 && out[0] == 0xab))
		FAIL("expected: kernel_measurement_select(fake_read, &tpm, "
		     "out, &pcr) == 0 && pcr == 11 && out[0] == 0xab");
}

/*
 * When nothing carries a measurement the answer is "none", not a digest of zeros:
 * the caller sets the report flag on success, and a zero digest that claims
 * to be a kernel hash is what an allow-list would then admit everywhere.
 */
static void test_no_measurement_is_not_zeros(void)
{
	struct fake_tpm tpm;
	uint8_t out[LOTA_HASH_SIZE];
	int pcr = 7;

	all_readable(&tpm);

	TEST("a host with no kernel measurement reports none");
	if (kernel_measurement_select(fake_read, &tpm, out, &pcr) != -ENOENT)
		FAIL("expected: kernel_measurement_select(fake_read, &tpm, "
		     "out, &pcr) == -ENOENT");
	TEST("and names no register");
	if (pcr != -1)
		FAIL("expected: pcr == -1");
}

/* a register that cannot be read is skipped, not treated as empty */
static void test_unreadable_register_is_skipped(void)
{
	struct fake_tpm tpm;
	uint8_t out[LOTA_HASH_SIZE];
	int pcr = -1;

	all_readable(&tpm);
	tpm.readable[11] = 0;
	set_pcr(&tpm, 9, 0x3c);

	TEST("an unreadable register does not stop the search");
	if (!(kernel_measurement_select(fake_read, &tpm, out, &pcr) == 0 &&
	      pcr == 9))
		FAIL("expected: kernel_measurement_select(fake_read, &tpm, "
		     "out, &pcr) == 0 && pcr == 9");
}

static void test_rejects_bad_arguments(void)
{
	struct fake_tpm tpm;
	uint8_t out[LOTA_HASH_SIZE];

	all_readable(&tpm);
	TEST("no reader is an invalid argument");
	if (kernel_measurement_select(NULL, &tpm, out, NULL) != -EINVAL)
		FAIL("expected: kernel_measurement_select(NULL, &tpm, out, "
		     "NULL) == -EINVAL");
	TEST("nowhere to put the digest is an invalid argument");
	if (kernel_measurement_select(fake_read, &tpm, NULL, NULL) != -EINVAL)
		FAIL("expected: kernel_measurement_select(fake_read, &tpm, "
		     "NULL, NULL) == -EINVAL");
}

int main(void)
{
	test_begin("kernel measure");
	test_grub_host_takes_pcr9();
	test_uki_host_takes_pcr11();
	test_no_measurement_is_not_zeros();
	test_unreadable_register_is_skipped();
	test_rejects_bad_arguments();

	return test_end();
}
