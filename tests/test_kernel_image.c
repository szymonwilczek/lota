/* SPDX-License-Identifier: MIT */
/*
 * The exporter has to write the value the verifier compares, and the verifier
 * compares the bootloader's measurement of the kernel image -- not the PCR 9
 * register, which folds in grubenv and therefore differs between two boots of
 * one kernel. These cases hold this reader to the rules
 * ExtractKernelImageDigest keeps on the other side of the wire.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../src/agent/kernel_image.h"

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

#define LOG_MAX 4096

struct log_builder {
	uint8_t buf[LOG_MAX];
	size_t len;
};

static void put_u16(struct log_builder *b, uint16_t v)
{
	b->buf[b->len++] = (uint8_t)(v & 0xff);
	b->buf[b->len++] = (uint8_t)(v >> 8);
}

static void put_u32(struct log_builder *b, uint32_t v)
{
	b->buf[b->len++] = (uint8_t)(v & 0xff);
	b->buf[b->len++] = (uint8_t)((v >> 8) & 0xff);
	b->buf[b->len++] = (uint8_t)((v >> 16) & 0xff);
	b->buf[b->len++] = (uint8_t)((v >> 24) & 0xff);
}

static void put_bytes(struct log_builder *b, const void *p, size_t n)
{
	memcpy(b->buf + b->len, p, n);
	b->len += n;
}

/* Legacy TCG_PCR_EVENT the crypto-agile log opens with */
static void begin_log(struct log_builder *b)
{
	static const char spec[] = "Spec ID Event03";
	uint8_t sha1[20] = { 0 };

	b->len = 0;
	put_u32(b, 0); /* PCR 0 */
	put_u32(b, 0x00000003); /* EV_NO_ACTION */
	put_bytes(b, sha1, sizeof(sha1));
	put_u32(b, (uint32_t)sizeof(spec));
	put_bytes(b, spec, sizeof(spec));
}

/* One crypto-agile record carrying a single SHA-256 digest */
static void add_event(struct log_builder *b, uint32_t pcr, uint32_t type,
		      uint8_t fill, const char *data)
{
	uint8_t digest[LOTA_HASH_SIZE];

	memset(digest, fill, sizeof(digest));
	put_u32(b, pcr);
	put_u32(b, type);
	put_u32(b, 1); /* digest count */
	put_u16(b, 0x000B); /* SHA-256 */
	put_bytes(b, digest, sizeof(digest));
	put_u32(b, (uint32_t)(strlen(data) + 1));
	put_bytes(b, data, strlen(data) + 1);
}

/* The same record with a SHA-1 digest only, which is what a log written by
 * a firmware that never enabled SHA-256 looks like */
static void add_sha1_event(struct log_builder *b, uint32_t pcr, uint32_t type,
			   const char *data)
{
	uint8_t digest[20];

	memset(digest, 0x11, sizeof(digest));
	put_u32(b, pcr);
	put_u32(b, type);
	put_u32(b, 1);
	put_u16(b, 0x0004); /* SHA-1 */
	put_bytes(b, digest, sizeof(digest));
	put_u32(b, (uint32_t)(strlen(data) + 1));
	put_bytes(b, data, strlen(data) + 1);
}

/*
 * A GRUB boot: the bootloader reads its own files, then the kernel,
 * then the initrd.
 * @env_fill stands in for grubenv, which changes on every boot.
 */
static void grub_boot_log(struct log_builder *b, uint8_t env_fill)
{
	begin_log(b);
	add_event(b, 9, 0x0000000D, env_fill, "(hd0,gpt2)/grub2/grubenv");
	add_event(b, 9, 0x0000000D, 0x51, "(hd0,gpt2)/vmlinuz-6.19.4-200.fc44");
	add_event(b, 9, 0x0000000D, 0x77, "(hd0,gpt2)/initramfs-6.19.4.img");
	add_event(b, 8, 0x0000000D, 0x33, "kernel_cmdline: ro quiet");
}

static void test_kernel_digest_survives_a_reboot(void)
{
	struct log_builder first, second;
	struct kernel_image a, s;

	grub_boot_log(&first, 0x01);
	grub_boot_log(&second, 0xfe);

	CHECK(kernel_image_from_event_log(first.buf, first.len, &a) == 0,
	      "a GRUB log yields the kernel image");
	CHECK(kernel_image_from_event_log(second.buf, second.len, &s) == 0,
	      "the next boot of the same kernel yields it too");
	CHECK(memcmp(a.digest, s.digest, LOTA_HASH_SIZE) == 0,
	      "the kernel digest is the same across two boots");
	CHECK(strcmp(a.path, "(hd0,gpt2)/vmlinuz-6.19.4-200.fc44") == 0,
	      "the path is the one the bootloader wrote");
}

static void test_no_kernel_image_is_not_a_zero_digest(void)
{
	struct log_builder b;
	struct kernel_image img;

	begin_log(&b);
	add_event(&b, 9, 0x0000000D, 0x01, "(hd0,gpt2)/grub2/grubenv");
	add_event(&b, 9, 0x0000000D, 0x02, "(hd0,gpt2)/initramfs-6.19.4.img");

	CHECK(kernel_image_from_event_log(b.buf, b.len, &img) == -ENOENT,
	      "a log measuring no kernel says so rather than answering zeros");
}

static void test_two_kernels_are_refused(void)
{
	struct log_builder b;
	struct kernel_image img;

	begin_log(&b);
	add_event(&b, 9, 0x0000000D, 0x51, "(hd0,gpt2)/vmlinuz-6.19.4");
	add_event(&b, 9, 0x0000000D, 0x52, "(hd0,gpt2)/vmlinuz-6.18.9");

	CHECK(kernel_image_from_event_log(b.buf, b.len, &img) == -EEXIST,
	      "two different kernel images are refused, not resolved");
}

static void test_one_kernel_measured_twice_is_one_answer(void)
{
	struct log_builder b;
	struct kernel_image img;

	begin_log(&b);
	add_event(&b, 9, 0x0000000D, 0x51, "(hd0,gpt2)/vmlinuz-6.19.4");
	add_event(&b, 9, 0x0000000D, 0x51, "(hd0,gpt2)/vmlinuz-6.19.4");

	CHECK(kernel_image_from_event_log(b.buf, b.len, &img) == 0,
	      "the same image measured twice is not a conflict");
}

static void test_kernel_outside_pcr9_is_not_the_answer(void)
{
	struct log_builder b;
	struct kernel_image img;

	begin_log(&b);
	/* PCR 4 carries the firmware's own measurement of what it launched;
	 * the pin the verifier compares comes from the bootloader's log on
	 * PCR 9, so a record elsewhere is not it. */
	add_event(&b, 4, 0x0000000D, 0x51, "(hd0,gpt2)/vmlinuz-6.19.4");

	CHECK(kernel_image_from_event_log(b.buf, b.len, &img) == -ENOENT,
	      "an EV_IPL kernel record on another PCR is not read as the pin");
}

static void test_sha1_only_kernel_is_its_own_answer(void)
{
	struct log_builder b;
	struct kernel_image img;

	begin_log(&b);
	add_sha1_event(&b, 9, 0x0000000D, "(hd0,gpt2)/vmlinuz-6.19.4");

	CHECK(kernel_image_from_event_log(b.buf, b.len, &img) == -ENOMSG,
	      "a kernel measured without SHA-256 is reported as that, not as absent");
}

static void test_a_good_record_beats_a_sha1_only_one(void)
{
	struct log_builder b;
	struct kernel_image img;

	begin_log(&b);
	add_sha1_event(&b, 9, 0x0000000D, "(hd0,gpt2)/vmlinuz-6.19.4");
	add_event(&b, 9, 0x0000000D, 0x51, "(hd0,gpt2)/vmlinuz-6.19.4");

	CHECK(kernel_image_from_event_log(b.buf, b.len, &img) == 0,
	      "a SHA-256 record answers even when a SHA-1-only one precedes it");
}

static void test_a_log_that_does_not_parse_is_not_an_absent_kernel(void)
{
	struct log_builder b;
	struct kernel_image img;
	uint8_t junk[8] = { 0 };

	CHECK(kernel_image_from_event_log(junk, sizeof(junk), &img) == -EINVAL,
	      "bytes that are not a log are refused rather than read as empty");

	grub_boot_log(&b, 0x01);
	CHECK(kernel_image_from_event_log(b.buf, b.len - 8, &img) == -EINVAL,
	      "a truncated log is refused rather than answered from its prefix");

	CHECK(kernel_image_from_event_log(NULL, 0, &img) == -EINVAL,
	      "no log is -EINVAL");
	CHECK(kernel_image_from_event_log(b.buf, b.len, NULL) == -EINVAL,
	      "nowhere to put the answer is -EINVAL");
}

static void test_an_unknown_digest_algorithm_stops_the_walk(void)
{
	struct log_builder b;
	struct kernel_image img;
	uint8_t digest[LOTA_HASH_SIZE];

	memset(digest, 0x51, sizeof(digest));
	begin_log(&b);
	put_u32(&b, 9);
	put_u32(&b, 0x0000000D);
	put_u32(&b, 1);
	put_u16(&b, 0x0099); /* no such algorithm, so no size to skip */
	put_bytes(&b, digest, sizeof(digest));
	put_u32(&b, 8);
	put_bytes(&b, "vmlinuz", 8);

	CHECK(kernel_image_from_event_log(b.buf, b.len, &img) == -EINVAL,
	      "a digest whose size is unknown stops the walk instead of sliding it");
}

static void test_which_paths_name_a_kernel(void)
{
	CHECK(kernel_image_path_names_kernel("(hd0,gpt2)/vmlinuz-6.19.4"),
	      "vmlinuz under a bootloader path");
	CHECK(kernel_image_path_names_kernel("/boot/kernel-6.19.4"),
	      "kernel under a unix path");
	CHECK(kernel_image_path_names_kernel("bzImage"), "a bare bzImage");
	CHECK(!kernel_image_path_names_kernel(
		      "(hd0,gpt2)/initramfs-6.19.4.img"),
	      "an initramfs does not name a kernel");
	CHECK(!kernel_image_path_names_kernel("(hd0,gpt2)/grub2/grubenv"),
	      "grubenv does not name a kernel");
	CHECK(!kernel_image_path_names_kernel(NULL), "no path names no kernel");
}

int main(void)
{
	printf("=== Kernel image (event log) tests ===\n\n");

	test_kernel_digest_survives_a_reboot();
	test_no_kernel_image_is_not_a_zero_digest();
	test_two_kernels_are_refused();
	test_one_kernel_measured_twice_is_one_answer();
	test_kernel_outside_pcr9_is_not_the_answer();
	test_sha1_only_kernel_is_its_own_answer();
	test_a_good_record_beats_a_sha1_only_one();
	test_a_log_that_does_not_parse_is_not_an_absent_kernel();
	test_an_unknown_digest_algorithm_stops_the_walk();
	test_which_paths_name_a_kernel();

	printf("\n%s\n", g_failures ? "FAILURES" : "All tests passed");
	return g_failures ? 1 : 0;
}
