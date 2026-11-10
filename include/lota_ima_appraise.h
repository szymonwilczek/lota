/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * IMA appraisal support of a kernel build.
 *
 * Without CONFIG_IMA_APPRAISE the kernel accepts appraise rules,
 * but its appraisal calls are stubs and ima_appraise starts at 0,
 * so no appraise rule refuses a file.
 */
#ifndef LOTA_IMA_APPRAISE_H
#define LOTA_IMA_APPRAISE_H

#include <errno.h>

#include <bpf/btf.h>
#include <linux/btf.h>

#define LOTA_VMLINUX_BTF_PATH "/sys/kernel/btf/vmlinux"

/**
 * lota_ima_appraise_built() - Test a kernel BTF for IMA appraisal.
 * @btf_path: kernel BTF, LOTA_VMLINUX_BTF_PATH for the booted kernel.
 *
 * Looks for the function ima_appraise_measurement(),
 * a static inline stub with no BTF entry without CONFIG_IMA_APPRAISE.
 *
 * Return: 1 when @btf_path has it, 0 when it does not,
 * -errno when @btf_path cannot be parsed.
 */
static inline int lota_ima_appraise_built(const char *btf_path)
{
	struct btf *btf = btf__parse(btf_path, NULL);
	int id;

	if (!btf)
		return errno ? -errno : -EIO;
	id = btf__find_by_name_kind(btf, "ima_appraise_measurement",
				    BTF_KIND_FUNC);
	btf__free(btf);
	return id > 0 ? 1 : 0;
}

#endif /* LOTA_IMA_APPRAISE_H */
