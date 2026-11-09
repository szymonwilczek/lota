/* SPDX-License-Identifier: MIT */
/*
 * LOTA Agent - IOMMU state of the host.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#ifndef LOTA_IOMMU_H
#define LOTA_IOMMU_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#include "../../include/iommu_types.h"

/**
 * iommu_check_sysfs() - Count the IOMMU units in /sys/class/iommu.
 * @status: the state to fill.
 * @root: prefix of the path read, NULL for the live machine.
 *
 * Counts dmar* and ivhd* entries and sets the unit count, the vendor and,
 * for one or more, IOMMU_FLAG_SYSFS_PRESENT.
 *
 * Return: the count, 0 without the directory, or -1 for a bad argument.
 */
int iommu_check_sysfs(struct iommu_status *status, const char *root);

/**
 * iommu_check_cmdline() - Read the IOMMU parameters of /proc/cmdline.
 * @status: the state to fill.
 * @root: prefix of the path read, NULL for the live machine.
 *
 * Words after "--" are not read, and a dash in a parameter name reads as an
 * underscore. The last on or off in the intel_iommu= lists wins, amd_iommu=
 * needs force_enable and no off. The word that enabled it is recorded with
 * IOMMU_FLAG_CMDLINE_SET, Intel first. IOMMU_FLAG_STRICT is set when the last
 * valid iommu.strict= value asks for strict invalidation, or an intel_iommu=
 * list names strict or an amd_iommu= list names fullflush, which apply after
 * iommu.strict= wherever they stand.
 *
 * Return: 0 when the cmdline enables an IOMMU, -1 otherwise.
 */
int iommu_check_cmdline(struct iommu_status *status, const char *root);

/**
 * iommu_check_domains() - Count the IOMMU groups in a translating domain.
 * @status: the state to fill.
 * @root: prefix of the path read, NULL for the live machine.
 *
 * Counts groups whose domain type is DMA or DMA-FQ and sets
 * IOMMU_FLAG_DMA_REMAP for one or more.
 *
 * Return: the count, 0 without /sys/kernel/iommu_groups, or -1 for a bad
 * argument.
 */
int iommu_check_domains(struct iommu_status *status, const char *root);

/**
 * iommu_check_irq_remap() - Look for a remapped interrupt chip.
 * @status: the state to fill.
 * @root: prefix of the path read, NULL for the live machine.
 *
 * Sets IOMMU_FLAG_IRQ_REMAP when /proc/interrupts names an IR- chip.
 *
 * Return: 0, or -1 when the table is not read.
 */
int iommu_check_irq_remap(struct iommu_status *status, const char *root);

/**
 * iommu_verify_full() - Run every IOMMU check.
 * @status: the state, cleared first.
 *
 * Return: true when IOMMU_FLAG_SYSFS_PRESENT and IOMMU_FLAG_DMA_REMAP are set.
 */
bool iommu_verify_full(struct iommu_status *status);

/* iommu_verify_full() with every path read under @root, NULL for the host */
bool iommu_verify_full_at(struct iommu_status *status, const char *root);

/**
 * iommu_status_to_string() - Describe the IOMMU state.
 * @status: the state.
 * @buf: the text.
 * @buf_len: size of @buf.
 *
 * Return: the length snprintf() reports, or -1 for a bad argument.
 */
int iommu_status_to_string(const struct iommu_status *status, char *buf,
			   size_t buf_len);

#endif /* LOTA_IOMMU_H */
