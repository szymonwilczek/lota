/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * Cross-language attestation-report layout test, C half.
 *
 * Agent serializes attestation report by memcpy'ing the packed C struct onto
 * the wire (src/agent/report.c); verifier re-reads it in Go from hand-computed
 * offsets (src/verifier/types/report.go)
 *
 * Nothing links the two at build time, so field added, removed or reordered on
 * one side is only discovered when real host fails to attest -- with signature
 * or PCR-digest error that says nothing about the layout.
 *
 * This program writes report whose every field carries a position-derived pattern
 * to /tmp/lota_cross_report.bin
 * report_verify.go parses it with the production parser and checks each field
 * against the same patterns, so layout drift fails as layout error, in the build,
 * naming the field.
 *
 * Patterns are duplicated in report_verify.go on purpose:
 * two independent statements of the same contract is the point.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "../../include/attestation.h"
#include "lota.h"
#include "../test.h"

#define OUT_PATH "/tmp/lota_cross_report.bin"

/* event log the report carries;
 * contents are opaque to this test */
static const char event_log[] = "LOTA-CROSS-LANG-EVENT-LOG";
static const char mok_list[] = "LOTA-CROSS-LANG-MOK-LIST";

int main(void)
{
	struct lota_attestation_report report;
	struct lota_esrt esrt;
	uint8_t buf[16 * 1024];
	ssize_t wire_size;
	size_t expected;
	FILE *f;

	test_begin("cross lang report gen");

	memset(&report, 0, sizeof(report));
	memset(&esrt, 0, sizeof(esrt));

	report.header.magic = LOTA_MAGIC;
	report.header.version = LOTA_REPORT_VERSION;
	report.header.flags = 0xA5A5A5A5u;

	for (int i = 0; i < LOTA_PCR_COUNT; i++)
		for (int j = 0; j < LOTA_HASH_SIZE; j++)
			report.tpm.pcr_values[i][j] = (uint8_t)(i ^ j);
	report.tpm.pcr_mask = 0x00004083u;

	for (size_t i = 0; i < sizeof(report.tpm.quote_signature); i++)
		report.tpm.quote_signature[i] = (uint8_t)(0x11 ^ i);
	report.tpm.quote_sig_size = 256;

	for (size_t i = 0; i < sizeof(report.tpm.attest_data); i++)
		report.tpm.attest_data[i] = (uint8_t)(0x22 ^ i);
	report.tpm.attest_size = 145;

	for (size_t i = 0; i < sizeof(report.tpm.aik_public); i++)
		report.tpm.aik_public[i] = (uint8_t)(0x33 ^ i);
	report.tpm.aik_public_size = 294;

	for (size_t i = 0; i < sizeof(report.tpm.aik_certificate); i++)
		report.tpm.aik_certificate[i] = (uint8_t)(0x44 ^ i);
	report.tpm.aik_cert_size = 1000;

	for (size_t i = 0; i < sizeof(report.tpm.nonce); i++)
		report.tpm.nonce[i] = (uint8_t)(0x55 ^ i);
	report.tpm.quote_sig_alg = 0x0014; /* TPM2_ALG_RSASSA */
	report.tpm.quote_sig_hash_alg = 0x000B; /* TPM2_ALG_SHA256 */

	for (size_t i = 0; i < sizeof(report.system.kernel_hash); i++)
		report.system.kernel_hash[i] = (uint8_t)(0x88 ^ i);
	for (size_t i = 0; i < sizeof(report.system.agent_hash); i++)
		report.system.agent_hash[i] = (uint8_t)(0x99 ^ i);
	snprintf(report.system.kernel_path, sizeof(report.system.kernel_path),
		 "/boot/vmlinuz-cross-lang");
	report.system.iommu.vendor = 0x8086;
	report.system.iommu.flags = 0x07;
	report.system.iommu.unit_count = 2;
	snprintf((char *)report.system.iommu.cmdline_param,
		 sizeof(report.system.iommu.cmdline_param), "intel_iommu=on");

	esrt.present = 1;
	esrt.fw_version = 785;
	esrt.lowest_supported = 700;
	for (size_t i = 0; i < sizeof(esrt.fw_class); i++)
		esrt.fw_class[i] = (uint8_t)(0xC0 ^ i);

	/* event log length excludes the terminating NUL */
	expected = calculate_report_size((uint32_t)(sizeof(event_log) - 1),
					 (uint32_t)(sizeof(mok_list) - 1));
	TEST("calculate_report_size fits the buffer");
	if (expected == 0 || expected > sizeof(buf)) {
		FAIL("computed size %zu", expected);
		return test_end();
	}
	report.header.report_size = (uint32_t)expected;

	wire_size = serialize_report(&report, (const uint8_t *)event_log,
				     (uint32_t)(sizeof(event_log) - 1), &esrt,
				     (const uint8_t *)mok_list,
				     (uint32_t)(sizeof(mok_list) - 1), buf,
				     sizeof(buf));
	TEST("serialize_report writes the computed size");
	if (wire_size < 0) {
		FAIL("serialize_report failed: %zd", wire_size);
		return test_end();
	}
	if ((size_t)wire_size != expected) {
		FAIL("serialized %zd bytes, computed %zu", wire_size, expected);
		return test_end();
	}

	/* ESRT section is mandatory: NULL must be refused */
	TEST("serialize_report refuses a NULL ESRT");
	if (serialize_report(&report, (const uint8_t *)event_log,
			     (uint32_t)(sizeof(event_log) - 1), NULL,
			     (const uint8_t *)mok_list,
			     (uint32_t)(sizeof(mok_list) - 1), buf,
			     sizeof(buf)) != -EINVAL)
		FAIL("NULL ESRT accepted");

	TEST("report written to " OUT_PATH);
	int fd = open(OUT_PATH, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		FAIL("open: %s", strerror(errno));
		return test_end();
	}
	f = fdopen(fd, "wb");
	if (!f) {
		FAIL("fdopen: %s", strerror(errno));
		close(fd);
		return test_end();
	}
	if (fwrite(buf, 1, (size_t)wire_size, f) != (size_t)wire_size) {
		FAIL("fwrite: %s", strerror(errno));
		fclose(f);
		return test_end();
	}
	fclose(f);

	return test_end();
}
