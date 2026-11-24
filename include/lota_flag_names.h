/* SPDX-License-Identifier: MIT */
/*
 * Names of the status bits, shared by lota_flags_to_string() and
 * lota-agent --status so both print the same word for a bit.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */
#ifndef LOTA_FLAG_NAMES_H
#define LOTA_FLAG_NAMES_H

#include <stddef.h>
#include <stdint.h>

#include "lota_ipc.h"

struct lota_flag_name {
	uint32_t flag;
	const char *name;
};

/* The bits lota_flags_to_string() names, in the order it prints them */
static const struct lota_flag_name lota_flag_names[] = {
	{ LOTA_STATUS_ATTESTED, "ATTESTED" },
	{ LOTA_STATUS_TPM_OK, "TPM_OK" },
	{ LOTA_STATUS_IOMMU_OK, "IOMMU_OK" },
	{ LOTA_STATUS_BPF_LOADED, "BPF_LOADED" },
	{ LOTA_STATUS_SECURE_BOOT, "SECURE_BOOT" },
	{ LOTA_STATUS_UPDATE_PENDING, "UPDATE_PENDING" },
	/* No publisher reports here: no failure, unlike a bare NOT ATTESTED */
	{ LOTA_STATUS_TOKEN_ONLY, "TOKEN_ONLY" },
	{ LOTA_STATUS_IMAGE_FULLY_MEASURED, "IMAGE_FULLY_MEASURED" },
	{ LOTA_STATUS_IMAGE_CONTENT_HASHED, "IMAGE_CONTENT_HASHED" },
	{ LOTA_STATUS_PROTECTED_TERMINATED, "PROTECTED_TERMINATED" },
	{ LOTA_STATUS_KERNEL_APPRAISAL, "KERNEL_APPRAISAL" },
	{ LOTA_STATUS_BENCH, "BENCH" },
	{ LOTA_STATUS_ENFORCE, "ENFORCE" },
	{ LOTA_STATUS_STRICT_MMAP, "STRICT_MMAP" },
	{ LOTA_STATUS_STRICT_EXEC, "STRICT_EXEC" },
	{ LOTA_STATUS_STRICT_MODULES, "STRICT_MODULES" },
	{ LOTA_STATUS_BLOCK_ANON_EXEC, "BLOCK_ANON_EXEC" },
	{ LOTA_STATUS_BLOCK_PTRACE, "BLOCK_PTRACE" },
	{ LOTA_STATUS_AGENT_RESTARTED, "AGENT_RESTARTED" },
	{ LOTA_STATUS_EVENTS_LOST, "EVENTS_LOST" },
};

/* The bits lota-agent --status names and the SDK does not */
static const struct lota_flag_name lota_host_flag_names[] = {
	{ LOTA_STATUS_TPM_LOCKOUT, "TPM_LOCKOUT" },
};

#define LOTA_FLAG_NAME_COUNT \
	(sizeof(lota_flag_names) / sizeof(lota_flag_names[0]))
#define LOTA_HOST_FLAG_NAME_COUNT \
	(sizeof(lota_host_flag_names) / sizeof(lota_host_flag_names[0]))

#endif /* LOTA_FLAG_NAMES_H */
