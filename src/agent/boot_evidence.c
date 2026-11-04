/* SPDX-License-Identifier: MIT */
/*
 * LOTA - boot evidence for a token
 *
 * Copyright (C) 2026 Szymon Wilczek
 */
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "../../include/lota.h"
#include "../../include/lota_token.h"
#include "boot_evidence.h"
#include "tcg_log.h"
#include "tpm.h"

#define PCR_SECURE_BOOT 7u

/* EFI global variable namespace 8be4df61-93ca-11d2-aa0d-00e098032b8c */
static const uint8_t efi_global_guid[16] = {
	0x61, 0xdf, 0xe4, 0x8b, 0xca, 0x93, 0xd2, 0x11,
	0xaa, 0x0d, 0x00, 0xe0, 0x98, 0x03, 0x2b, 0x8c,
};

/* "SecureBoot" in UTF-16LE */
static const uint8_t secure_boot_name[20] = {
	'S', 0, 'e', 0, 'c', 0, 'u', 0, 'r', 0,
	'e', 0, 'B', 0, 'o', 0, 'o', 0, 't', 0,
};

static uint64_t get_le64(const uint8_t *p)
{
	uint64_t v = 0;

	for (int i = 7; i >= 0; i--)
		v = v << 8 | p[i];
	return v;
}

static void put_le16(uint8_t *p, uint16_t v)
{
	p[0] = (uint8_t)v;
	p[1] = (uint8_t)(v >> 8);
}

static void put_le32(uint8_t *p, uint32_t v)
{
	for (int i = 0; i < 4; i++)
		p[i] = (uint8_t)(v >> (8 * i));
}

/*
 * UEFI_VARIABLE_DATA: VariableName GUID, UnicodeNameLength and
 * VariableDataLength as 64-bit counts, the name, then the value.
 */
static bool names_secure_boot(const uint8_t *data, uint32_t size)
{
	const size_t hdr = 16 + 8 + 8;

	if (size < hdr + sizeof(secure_boot_name))
		return false;
	if (memcmp(data, efi_global_guid, sizeof(efi_global_guid)) != 0)
		return false;
	if (get_le64(data + 16) != sizeof(secure_boot_name) / 2)
		return false;
	return memcmp(data + hdr, secure_boot_name, sizeof(secure_boot_name)) ==
	       0;
}

int boot_evidence_encode(const uint8_t *log, size_t log_size, uint32_t pcr_mask,
			 const uint8_t pcrs[LOTA_PCR_COUNT][LOTA_HASH_SIZE],
			 uint8_t *out, size_t out_size, size_t *out_len)
{
	struct tcg_log c;
	struct tcg_event ev;
	size_t off = LOTA_BOOT_EVIDENCE_HEADER_SIZE;
	uint16_t count = 0;
	int ret;

	if (!log || !pcrs || !out || !out_len)
		return -EINVAL;
	if (!(pcr_mask & (1u << PCR_SECURE_BOOT)) || pcr_mask >> LOTA_PCR_COUNT)
		return -EINVAL;
	if (tcg_log_open(&c, log, log_size) < 0)
		return -EINVAL;
	if (out_size < off)
		return -ENOSPC;

	for (uint32_t i = 0; i < LOTA_PCR_COUNT; i++) {
		if (!(pcr_mask & (1u << i)))
			continue;
		if (out_size - off < LOTA_HASH_SIZE)
			return -ENOSPC;
		memcpy(out + off, pcrs[i], LOTA_HASH_SIZE);
		off += LOTA_HASH_SIZE;
	}

	while ((ret = tcg_log_next(&c, &ev)) > 0) {
		uint32_t data_size = 0;

		/* EV_NO_ACTION is never extended */
		if (ev.pcr != PCR_SECURE_BOOT || ev.type == TCG_EV_NO_ACTION)
			continue;
		if (!ev.sha256)
			return -ENOMSG;
		if (names_secure_boot(ev.data, ev.data_size))
			data_size = ev.data_size;
		if (count == UINT16_MAX || data_size > UINT16_MAX ||
		    out_size - off < LOTA_BOOT_EVIDENCE_EVENT_SIZE + data_size)
			return -ENOSPC;

		memcpy(out + off, ev.sha256, LOTA_HASH_SIZE);
		put_le16(out + off + LOTA_HASH_SIZE, (uint16_t)data_size);
		memcpy(out + off + LOTA_BOOT_EVIDENCE_EVENT_SIZE, ev.data,
		       data_size);
		off += LOTA_BOOT_EVIDENCE_EVENT_SIZE + data_size;
		count++;
	}
	if (ret < 0)
		return -EINVAL;

	put_le16(out, LOTA_BOOT_EVIDENCE_VERSION);
	put_le16(out + 2, count);
	put_le32(out + 4, pcr_mask);
	*out_len = off;
	return 0;
}

int boot_evidence_collect(struct tpm_context *tpm, uint32_t pcr_mask,
			  uint8_t *out, size_t out_size, size_t *out_len)
{
	uint8_t pcrs[LOTA_PCR_COUNT][LOTA_HASH_SIZE];
	uint8_t *log;
	size_t log_size = 0;
	int ret;

	ret = tpm_read_pcrs_batch(tpm, pcr_mask, pcrs);
	if (ret < 0)
		return ret;

	log = malloc(TPM_MAX_EVENT_LOG_SIZE);
	if (!log)
		return -ENOMEM;
	ret = tpm_read_event_log(log, TPM_MAX_EVENT_LOG_SIZE, &log_size);
	if (ret == 0)
		ret = boot_evidence_encode(log, log_size, pcr_mask, pcrs, out,
					   out_size, out_len);
	free(log);
	return ret;
}
