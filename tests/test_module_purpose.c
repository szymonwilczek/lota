/* SPDX-License-Identifier: MIT */
/*
 * Unit tests for what the module gate counts as a module load, and for its
 * verdict (include/lota.h).
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

#include "../include/lota.h"

#include "test.h"

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

/*
 * The uncompressed form, which is what insmod of a plain .ko produces
 * and what the gate has always covered.
 */
static void test_plain_module_is_a_module(void)
{
	TEST("an uncompressed module image counts as a module load");
	if (!lota_kread_is_module(KERNEL_PURPOSE_MODULE))
		FAIL("expected: lota_kread_is_module(KERNEL_PURPOSE_MODULE)");
}

/*
 * The compressed form, which is what modprobe produces on Fedora, RHEL, Debian
 * and every other distribution that compresses its modules.
 * It is the only form a stock host ever presents.
 */
static void test_compressed_module_is_a_module(void)
{
	TEST("a compressed module file counts as a module load");
	if (!lota_kread_is_module(KERNEL_PURPOSE_MODULE_COMPRESSED))
		FAIL("expected: lota_kread_is_module(KERNEL_PURPOSE_MODULE_COMPRESSED)");
}

/*
 * The purposes that are not modules stay outside the gate: firmware and kexec
 * have their own rules in the hook, and a policy or certificate read is not
 * something strict module loading has an opinion about.
 */
static void test_other_purposes_are_not_modules(void)
{
	TEST("an unstated purpose is not a module load");
	if (lota_kread_is_module(KERNEL_PURPOSE_UNKNOWN))
		FAIL("expected: !lota_kread_is_module(KERNEL_PURPOSE_UNKNOWN)");
	TEST("firmware is not a module load");
	if (lota_kread_is_module(KERNEL_PURPOSE_FIRMWARE))
		FAIL("expected: !lota_kread_is_module(KERNEL_PURPOSE_FIRMWARE)");
	TEST("a kexec image is not a module load");
	if (lota_kread_is_module(KERNEL_PURPOSE_KEXEC_IMAGE))
		FAIL("expected: !lota_kread_is_module(KERNEL_PURPOSE_KEXEC_IMAGE)");
	TEST("a kexec initramfs is not a module load");
	if (lota_kread_is_module(KERNEL_PURPOSE_KEXEC_INITRAMFS))
		FAIL("expected: !lota_kread_is_module(KERNEL_PURPOSE_KEXEC_INITRAMFS)");
	TEST("a policy read is not a module load");
	if (lota_kread_is_module(KERNEL_PURPOSE_POLICY))
		FAIL("expected: !lota_kread_is_module(KERNEL_PURPOSE_POLICY)");
	TEST("a certificate read is not a module load");
	if (lota_kread_is_module(KERNEL_PURPOSE_X509_CERTIFICATE))
		FAIL("expected: !lota_kread_is_module(KERNEL_PURPOSE_X509_CERTIFICATE)");
}

/*
 * The purposes the kernel under validation can send are all recognised,
 * so a host running it is never refused a load the gate has a rule for.
 */
static void test_every_purpose_this_kernel_sends_is_known(void)
{
	TEST("every purpose this kernel sends is one the gate recognises");
	if (!(lota_kread_is_known(KERNEL_PURPOSE_UNKNOWN) &&
	      lota_kread_is_known(KERNEL_PURPOSE_FIRMWARE) &&
	      lota_kread_is_known(KERNEL_PURPOSE_MODULE) &&
	      lota_kread_is_known(KERNEL_PURPOSE_KEXEC_IMAGE) &&
	      lota_kread_is_known(KERNEL_PURPOSE_KEXEC_INITRAMFS) &&
	      lota_kread_is_known(KERNEL_PURPOSE_POLICY) &&
	      lota_kread_is_known(KERNEL_PURPOSE_X509_CERTIFICATE) &&
	      lota_kread_is_known(KERNEL_PURPOSE_MODULE_COMPRESSED)))
		FAIL("expected: lota_kread_is_known(KERNEL_PURPOSE_UNKNOWN) "
		     "&& lota_kread_is_known(KERNEL_PURPOSE_FIRMWARE) && "
		     "lota_kread_is_known(KERNEL_PURPOSE_MODULE) && "
		     "lota_kread_is_known(KERNEL_PURPOSE_KEXEC_IMAGE) && "
		     "lota_kread_is_known(KERNEL_PURPOSE_KEXEC_INITRAMFS) && "
		     "lota_kread_is_known(KERNEL_PURPOSE_POLICY) && "
		     "lota_kread_is_known(KERNEL_PURPOSE_X509_CERTIFICATE) && "
		     "lota_kread_is_known(KERNEL_PURPOSE_MODULE_COMPRESSED)");
}

/*
 * A purpose above the list is what a later kernel adds, and it is the shape
 * this arrived in.
 * The gate has to be able to tell that it does not know one, so that it can
 * refuse.
 */
static void test_a_later_purpose_is_not_known(void)
{
	TEST("the next purpose a kernel adds is not recognised");
	if (lota_kread_is_known(KERNEL_PURPOSE_MODULE_COMPRESSED + 1))
		FAIL("expected: !lota_kread_is_known(KERNEL_PURPOSE_MODULE_COMPRESSED "
		     "+ 1)");
	TEST("a purpose well above the list is not recognised");
	if (lota_kread_is_known(KERNEL_PURPOSE_MODULE_COMPRESSED + 9))
		FAIL("expected: !lota_kread_is_known(KERNEL_PURPOSE_MODULE_COMPRESSED "
		     "+ 9)");
	TEST("an unrecognised purpose is not claimed as a module load");
	if (lota_kread_is_module(KERNEL_PURPOSE_MODULE_COMPRESSED + 1))
		FAIL("expected: !lota_kread_is_module(KERNEL_PURPOSE_MODULE_COMPRESSED "
		     "+ 1)");
}

/* (purpose, enforce, strict_modules, baseline, verity) */
#define FROM_FILE(id, on, strict, base, verity) \
	lota_kread_denied((id), 1, (on), (strict), (base), (verity), 0)
#define FROM_MEMORY(id, on, strict, base) \
	lota_kread_denied((id), 0, (on), (strict), (base), 0, 0)

/* Kernel integrity is not policy: it holds in monitor too */
static void test_kernel_integrity_holds_in_every_mode(void)
{
	TEST("kexec of a file is refused in monitor");
	if (!FROM_FILE(KERNEL_PURPOSE_KEXEC_IMAGE, 0, 0, 1, 1))
		FAIL("expected: FROM_FILE(KERNEL_PURPOSE_KEXEC_IMAGE, 0, 0, "
		     "1, 1)");
	TEST("kexec from memory is refused in monitor");
	if (!FROM_MEMORY(KERNEL_PURPOSE_KEXEC_INITRAMFS, 0, 0, 1))
		FAIL("expected: FROM_MEMORY(KERNEL_PURPOSE_KEXEC_INITRAMFS, "
		     "0, 0, 1)");
	TEST("a module without the integrity baseline is refused in monitor");
	if (!FROM_FILE(KERNEL_PURPOSE_MODULE_COMPRESSED, 0, 0, 0, 1))
		FAIL("expected: FROM_FILE(KERNEL_PURPOSE_MODULE_COMPRESSED, "
		     "0, 0, 0, 1)");
	TEST("firmware without the integrity baseline is refused in monitor");
	if (!FROM_FILE(KERNEL_PURPOSE_FIRMWARE, 0, 0, 0, 1))
		FAIL("expected: FROM_FILE(KERNEL_PURPOSE_FIRMWARE, 0, 0, 0, 1)");
	TEST("a module from a foreign user namespace is refused in monitor");
	if (!lota_kread_denied(KERNEL_PURPOSE_MODULE, 1, 0, 0, 1, 1, 1))
		FAIL("expected: lota_kread_denied(KERNEL_PURPOSE_MODULE, 1, "
		     "0, 0, 1, 1, 1)");
	TEST("a certificate from a foreign user namespace is refused");
	if (!lota_kread_denied(KERNEL_PURPOSE_X509_CERTIFICATE, 0, 0, 0, 1, 0,
			       1))
		FAIL("expected: lota_kread_denied(KERNEL_PURPOSE_X509_CERTIFICATE, "
		     "0, 0, 0, 1, 0, 1)");
}

/* With the baseline met and strict_modules off, firmware is the kernel's */
static void test_firmware_is_policy(void)
{
	TEST("enforce takes firmware outside the allowlist without strict_modules");
	if (FROM_FILE(KERNEL_PURPOSE_FIRMWARE, 1, 0, 1, 0))
		FAIL("expected: !FROM_FILE(KERNEL_PURPOSE_FIRMWARE, 1, 0, 1, "
		     "0)");
	TEST("enforce takes firmware from memory without strict_modules");
	if (FROM_MEMORY(KERNEL_PURPOSE_FIRMWARE, 1, 0, 1))
		FAIL("expected: !FROM_MEMORY(KERNEL_PURPOSE_FIRMWARE, 1, 0, 1)");
	TEST("strict_modules refuses firmware outside the allowlist");
	if (!FROM_FILE(KERNEL_PURPOSE_FIRMWARE, 1, 1, 1, 0))
		FAIL("expected: FROM_FILE(KERNEL_PURPOSE_FIRMWARE, 1, 1, 1, 0)");
	TEST("strict_modules takes allowlisted firmware");
	if (FROM_FILE(KERNEL_PURPOSE_FIRMWARE, 1, 1, 1, 1))
		FAIL("expected: !FROM_FILE(KERNEL_PURPOSE_FIRMWARE, 1, 1, 1, "
		     "1)");
	TEST("strict_modules refuses firmware from memory");
	if (!FROM_MEMORY(KERNEL_PURPOSE_FIRMWARE, 1, 1, 1))
		FAIL("expected: FROM_MEMORY(KERNEL_PURPOSE_FIRMWARE, 1, 1, 1)");
}

static void test_strict_modules_is_policy(void)
{
	TEST("strict_modules refuses a module outside the allowlist");
	if (!FROM_FILE(KERNEL_PURPOSE_MODULE_COMPRESSED, 1, 1, 1, 0))
		FAIL("expected: FROM_FILE(KERNEL_PURPOSE_MODULE_COMPRESSED, "
		     "1, 1, 1, 0)");
	TEST("strict_modules takes an allowlisted module");
	if (FROM_FILE(KERNEL_PURPOSE_MODULE_COMPRESSED, 1, 1, 1, 1))
		FAIL("expected: !FROM_FILE(KERNEL_PURPOSE_MODULE_COMPRESSED, "
		     "1, 1, 1, 1)");
	TEST("strict_modules refuses a module from memory");
	if (!FROM_MEMORY(KERNEL_PURPOSE_MODULE, 1, 1, 1))
		FAIL("expected: FROM_MEMORY(KERNEL_PURPOSE_MODULE, 1, 1, 1)");
	TEST("monitor lifts strict_modules");
	if (FROM_FILE(KERNEL_PURPOSE_MODULE_COMPRESSED, 0, 1, 1, 0))
		FAIL("expected: !FROM_FILE(KERNEL_PURPOSE_MODULE_COMPRESSED, "
		     "0, 1, 1, 0)");
	TEST("strict_modules refuses a purpose it does not know");
	if (!FROM_FILE(KERNEL_PURPOSE_MODULE_COMPRESSED + 1, 1, 1, 1, 1))
		FAIL("expected: FROM_FILE(KERNEL_PURPOSE_MODULE_COMPRESSED + "
		     "1, 1, 1, 1, 1)");
	TEST("monitor takes a purpose it does not know");
	if (FROM_FILE(KERNEL_PURPOSE_MODULE_COMPRESSED + 1, 0, 1, 1, 1))
		FAIL("expected: !FROM_FILE(KERNEL_PURPOSE_MODULE_COMPRESSED + "
		     "1, 0, 1, 1, 1)");
}

/* What the gate does not rule on */
static void test_purposes_outside_the_gate(void)
{
	TEST("an IMA policy read from a file is always taken");
	if (FROM_FILE(KERNEL_PURPOSE_POLICY, 1, 1, 0, 0))
		FAIL("expected: !FROM_FILE(KERNEL_PURPOSE_POLICY, 1, 1, 0, 0)");
	TEST("a certificate read from a file is not ruled on");
	if (FROM_FILE(KERNEL_PURPOSE_X509_CERTIFICATE, 1, 1, 0, 0))
		FAIL("expected: !FROM_FILE(KERNEL_PURPOSE_X509_CERTIFICATE, "
		     "1, 1, 0, 0)");
	TEST("the unknown purpose the kernel names is not ruled on");
	if (FROM_FILE(KERNEL_PURPOSE_UNKNOWN, 1, 1, 0, 0))
		FAIL("expected: !FROM_FILE(KERNEL_PURPOSE_UNKNOWN, 1, 1, 0, 0)");
}

int main(void)
{
	test_begin("module purpose");

	test_plain_module_is_a_module();
	test_compressed_module_is_a_module();
	test_other_purposes_are_not_modules();
	test_every_purpose_this_kernel_sends_is_known();
	test_a_later_purpose_is_not_known();
	test_kernel_integrity_holds_in_every_mode();
	test_firmware_is_policy();
	test_strict_modules_is_policy();
	test_purposes_outside_the_gate();

	return test_end();
}
