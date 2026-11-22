/* SPDX-License-Identifier: MIT */
/*
 * LOTA - Attestation Report Serialization
 * Implements variable-length wire format for attestation reports.
 *
 * Wire format:
 *   [lota_attestation_report]    (fixed struct, see the static asserts below)
 *   [event_log_size: uint32_t]
 *   [tpm_event_log: uint8_t * event_log_size]
 *   [lota_esrt]                  (mandatory trailing section)
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
 * Go verifier parses this layout from hand-computed offsets
 * (src/verifier/types/report.go: FixedReportSize, MinReportSize
 * and the offset walk in ParseReport).
 * Nothing links the two languages at build time, so pin the sizes here:
 * field added, removed or reordered on either side breaks this build instead
 * of producing reports the verifier silently misreads.
 *
 * Keep these in step with the constants in report.go
 */
_Static_assert(sizeof(struct lota_tpm_evidence) == 5466,
	       "lota_tpm_evidence size changed; update types/report.go and its "
	       "layout test");
_Static_assert(sizeof(struct lota_system_measurement) == 396,
	       "lota_system_measurement size changed; update types/report.go");
_Static_assert(sizeof(struct lota_attestation_report) == 5878,
	       "fixed report size changed; update FixedReportSize in "
	       "types/report.go");
_Static_assert(sizeof(struct lota_esrt) == 28,
	       "lota_esrt size changed; update ESRTWireSize in types/report.go");
size_t calculate_report_size(uint32_t event_log_size)
{
	size_t size = sizeof(struct lota_attestation_report);

	/* TPM event log section: size + data */
	if (size + sizeof(uint32_t) < size)
		return 0;
	size += sizeof(uint32_t); /* event_log_size */

	if (size + event_log_size < size)
		return 0;
	size += event_log_size;

	/* Mandatory trailing ESRT section (fixed size) */
	if (size + sizeof(struct lota_esrt) < size)
		return 0;
	size += sizeof(struct lota_esrt);

	return size;
}

ssize_t serialize_report(const struct lota_attestation_report *report,
			 const uint8_t *event_log, uint32_t event_log_size,
			 const struct lota_esrt *esrt, uint8_t *out_buf,
			 size_t out_buf_size)
{
	size_t total;
	size_t offset = 0;

	/*
	 * esrt is mandatory:
	 * verifier requires the section and reads present == 0 as
	 * "this platform exposes no ESRT System Firmware entry",
	 * so there is no such thing as a report without it
	 */
	if (!report || !out_buf || !esrt)
		return -EINVAL;

	if (!event_log)
		event_log_size = 0;

	total = calculate_report_size(event_log_size);
	if (total == 0)
		return -EOVERFLOW;

	if (out_buf_size < total)
		return -ENOSPC;

	/* fixed report struct */
	memcpy(out_buf + offset, report, sizeof(*report));
	offset += sizeof(*report);

	/* TPM event log section */
	{
		uint32_t els_le = htole32(event_log_size);
		memcpy(out_buf + offset, &els_le, sizeof(els_le));
	}
	offset += sizeof(event_log_size);

	if (event_log_size > 0 && event_log) {
		memcpy(out_buf + offset, event_log, event_log_size);
		offset += event_log_size;
	}

	/* mandatory trailing ESRT section, little-endian fields */
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

	return (ssize_t)offset;
}
