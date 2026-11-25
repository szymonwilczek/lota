/* SPDX-License-Identifier: MIT */
/*
 * LOTA Agent - Policy Auto-Generation
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#ifndef LOTA_POLICY_H
#define LOTA_POLICY_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "../../include/lota.h"
#include "kernel_image.h"

#define POLICY_PCR_0 0
#define POLICY_PCR_1 1
#define POLICY_PCR_4 4
#define POLICY_PCR_7 7
#define POLICY_PCR_11 11
#define POLICY_PCR_14 14

#define POLICY_MAX_PCRS 24

struct policy_snapshot {
	char name[64];
	char description[256];
	char hostname[64];
	char timestamp[32]; /* ISO-8601 */

	struct {
		int index;
		uint8_t value[LOTA_HASH_SIZE];
		bool valid;
	} pcrs[POLICY_MAX_PCRS];
	int pcr_count;

	/* Kernel image the bootloader measured, from the event log */
	char kernel_release[65]; /* sizeof(struct utsname.release) */
	char kernel_image_path[KERNEL_IMAGE_PATH_MAX]; /* as logged */
	uint8_t kernel_hash[LOTA_HASH_SIZE];
	bool kernel_hash_valid;
	int kernel_hash_error; /* reader's -errno when there is no digest */

	char agent_path[LOTA_MAX_PATH_LEN];
	uint8_t agent_hash[LOTA_HASH_SIZE];
	bool agent_hash_valid;

	bool iommu_enabled;
	bool enforce_mode;
	bool module_sig;
	bool secureboot;
	bool lockdown;
	/*
	 * IMA appraisal blocks, and the agent reads a rule appraising exec from
	 * the IMA policy.
	 */
	bool ima_appraisal;
};

/**
 * policy_emit() - Write a snapshot as a lota-verifier --policy file.
 * @snap: The snapshot.
 * @out: Stream to write to.
 *
 * PCR 14 is left out even when @snap holds it.
 *
 * Return: 0, -EINVAL for a NULL argument, or -EIO when @out reports an error.
 */
int policy_emit(const struct policy_snapshot *snap, FILE *out);

/**
 * policy_kernel_hash_reason() - Why a policy carries no kernel digest.
 * @err: The reader's negative errno, as in kernel_hash_error.
 *
 * The policy file and the terminal print the same sentence.
 *
 * Return: a static string.
 */
const char *policy_kernel_hash_reason(int err);

/**
 * policy_export_pcrs() - The PCRs --export-policy reads from the TPM.
 * @count: Receives the number of entries, or NULL.
 *
 * Return: a static array.
 */
const int *policy_export_pcrs(size_t *count);

#endif /* LOTA_POLICY_H */
