/* SPDX-License-Identifier: MIT */
/*
 * LOTA - Attestation report serialization.
 *
 * Wire format, sizes and ESRT fields little-endian:
 *   [lota_attestation_report]
 *   [event_log_size: uint32_t]
 *   [tpm_event_log: uint8_t * event_log_size]
 *   [lota_esrt]
 *   [mok_list_size: uint32_t]
 *   [mok_list: uint8_t * mok_list_size]
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#include <endian.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>

#include "../../include/attestation.h"

/*
 * The verifier walks this layout by the constants in
 * src/verifier/types/report.go; nothing else ties the two at build time.
 */
_Static_assert(sizeof(struct lota_tpm_evidence) == 4912,
	       "lota_tpm_evidence size changed; update types/report.go and its "
	       "layout test");
_Static_assert(sizeof(struct lota_system_measurement) == 396,
	       "lota_system_measurement size changed; update types/report.go");
_Static_assert(sizeof(struct lota_attestation_report) == 5324,
	       "fixed report size changed; update FixedReportSize in "
	       "types/report.go");
_Static_assert(sizeof(struct lota_esrt) == 28,
	       "lota_esrt size changed; update ESRTWireSize in types/report.go");
size_t calculate_report_size(uint32_t event_log_size, uint32_t mok_list_size)
{
	size_t size = sizeof(struct lota_attestation_report);

	if (size + sizeof(uint32_t) < size)
		return 0;
	size += sizeof(uint32_t);

	if (size + event_log_size < size)
		return 0;
	size += event_log_size;

	if (size + sizeof(struct lota_esrt) < size)
		return 0;
	size += sizeof(struct lota_esrt);

	if (size + sizeof(uint32_t) < size)
		return 0;
	size += sizeof(uint32_t);

	if (size + mok_list_size < size)
		return 0;
	size += mok_list_size;

	return size;
}

ssize_t serialize_report(const struct lota_attestation_report *report,
			 const uint8_t *event_log, uint32_t event_log_size,
			 const struct lota_esrt *esrt, const uint8_t *mok_list,
			 uint32_t mok_list_size, uint8_t *out_buf,
			 size_t out_buf_size)
{
	size_t total;
	size_t offset = 0;

	/* the verifier requires the ESRT section; present == 0 says none */
	if (!report || !out_buf || !esrt)
		return -EINVAL;

	if (!event_log)
		event_log_size = 0;

	if (!mok_list)
		mok_list_size = 0;

	total = calculate_report_size(event_log_size, mok_list_size);
	if (total == 0)
		return -EOVERFLOW;

	if (out_buf_size < total)
		return -ENOSPC;

	memcpy(out_buf + offset, report, sizeof(*report));
	offset += sizeof(*report);

	{
		uint32_t els_le = htole32(event_log_size);
		memcpy(out_buf + offset, &els_le, sizeof(els_le));
	}
	offset += sizeof(event_log_size);

	if (event_log_size > 0 && event_log) {
		memcpy(out_buf + offset, event_log, event_log_size);
		offset += event_log_size;
	}

	{
		uint32_t present_le = htole32(esrt->present);
		uint32_t ver_le = htole32(esrt->fw_version);
		uint32_t low_le = htole32(esrt->lowest_supported);

		memcpy(out_buf + offset, &present_le, sizeof(present_le));
		offset += sizeof(present_le);
		memcpy(out_buf + offset, &ver_le, sizeof(ver_le));
		offset += sizeof(ver_le);
		memcpy(out_buf + offset, &low_le, sizeof(low_le));
		offset += sizeof(low_le);
		memcpy(out_buf + offset, esrt->fw_class,
		       sizeof(esrt->fw_class));
		offset += sizeof(esrt->fw_class);
	}

	{
		uint32_t mls_le = htole32(mok_list_size);

		memcpy(out_buf + offset, &mls_le, sizeof(mls_le));
		offset += sizeof(mls_le);
	}

	if (mok_list_size > 0) {
		memcpy(out_buf + offset, mok_list, mok_list_size);
		offset += mok_list_size;
	}

	return (ssize_t)offset;
}
