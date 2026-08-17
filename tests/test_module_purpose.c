/* SPDX-License-Identifier: MIT */
/*
 * Unit tests for what the module gate counts as a module load (include/lota.h).
 *
 * A module reaches the kernel in one of two forms, and the kernel says which:
 * the image itself, or the compressed file handed to
 * finit_module(MODULE_INIT_COMPRESSED_FILE) for the kernel to expand.
 * Every distribution that ships .ko.xz or .ko.zst uses the second, so on such
 * a host the plain purpose never appears and a gate that recognises only it
 * refuses nothing while reporting itself armed.
 *
 * The purposes are written here as the numbers the kernel sends rather than
 * as the object's own constants: the question these ask is whether the object
 * covers what arrives, so borrowing its answer would make them agree with it
 * by construction.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#include <stdio.h>

#include "../include/lota.h"

/*
 * enum kernel_read_file_id and enum kernel_load_data_id, read off the BTF of
 * the kernel under validation (7.1.8-200.fc44.x86_64).
 * The two enums are generated from one list and carry the same values.
 */
#define KERNEL_PURPOSE_UNKNOWN 0u
#define KERNEL_PURPOSE_FIRMWARE 1u
#define KERNEL_PURPOSE_MODULE 2u
#define KERNEL_PURPOSE_KEXEC_IMAGE 3u
#define KERNEL_PURPOSE_KEXEC_INITRAMFS 4u
#define KERNEL_PURPOSE_POLICY 5u
#define KERNEL_PURPOSE_X509_CERTIFICATE 6u
#define KERNEL_PURPOSE_MODULE_COMPRESSED 7u

static int g_failures;

#define CHECK(cond, msg)                                    \
	do {                                                \
		if (!(cond)) {                              \
			fprintf(stderr, "FAIL: %s\n", msg); \
			g_failures++;                       \
		} else {                                    \
			printf("PASS: %s\n", msg);          \
		}                                           \
	} while (0)

/*
 * The uncompressed form, which is what insmod of a plain .ko produces
 * and what the gate has always covered.
 */
static void test_plain_module_is_a_module(void)
{
	CHECK(lota_kread_is_module(KERNEL_PURPOSE_MODULE),
	      "an uncompressed module image counts as a module load");
}

/*
 * The compressed form, which is what modprobe produces on Fedora, RHEL, Debian
 * and every other distribution that compresses its modules.
 * It is the only form a stock host ever presents.
 */
static void test_compressed_module_is_a_module(void)
{
	CHECK(lota_kread_is_module(KERNEL_PURPOSE_MODULE_COMPRESSED),
	      "a compressed module file counts as a module load");
}

/*
 * The purposes that are not modules stay outside the gate: firmware and kexec
 * have their own rules in the hook, and a policy or certificate read is not
 * something strict module loading has an opinion about.
 */
static void test_other_purposes_are_not_modules(void)
{
	CHECK(!lota_kread_is_module(KERNEL_PURPOSE_UNKNOWN),
	      "an unstated purpose is not a module load");
	CHECK(!lota_kread_is_module(KERNEL_PURPOSE_FIRMWARE),
	      "firmware is not a module load");
	CHECK(!lota_kread_is_module(KERNEL_PURPOSE_KEXEC_IMAGE),
	      "a kexec image is not a module load");
	CHECK(!lota_kread_is_module(KERNEL_PURPOSE_KEXEC_INITRAMFS),
	      "a kexec initramfs is not a module load");
	CHECK(!lota_kread_is_module(KERNEL_PURPOSE_POLICY),
	      "a policy read is not a module load");
	CHECK(!lota_kread_is_module(KERNEL_PURPOSE_X509_CERTIFICATE),
	      "a certificate read is not a module load");
}

int main(void)
{
	printf("=== module purpose coverage ===\n");

	test_plain_module_is_a_module();
	test_compressed_module_is_a_module();
	test_other_purposes_are_not_modules();

	if (g_failures) {
		fprintf(stderr, "\n%d check(s) failed\n", g_failures);
		return 1;
	}

	printf("\nAll module purpose checks passed\n");
	return 0;
}
