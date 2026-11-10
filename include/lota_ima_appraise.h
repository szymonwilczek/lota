/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * IMA appraisal support of a kernel build, and the mode its cmdline sets.
 *
 * Without CONFIG_IMA_APPRAISE the kernel accepts appraise rules,
 * but its appraisal calls are stubs and ima_appraise starts at 0,
 * so no appraise rule refuses a file.
 */
#ifndef LOTA_IMA_APPRAISE_H
#define LOTA_IMA_APPRAISE_H

#include <ctype.h>
#include <errno.h>
#include <string.h>

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

/**
 * lota_ima_cmdline_enforce() - Read the ima_appraise= mode of a cmdline.
 * @cmdline: kernel command line.
 *
 * Splits it as next_arg() does, quotes included, and stops at "--".
 * The last ima_appraise= (or ima-appraise=) decides. Its value is matched
 * as in ima_appraise_parse_cmdline(): "off", "log" and "fix" on 3 characters,
 * and any other value leaves the default, enforce. Secure Boot, which makes
 * the kernel keep enforce, is not read here.
 *
 * Return: 1 for enforce, 0 for off, log or fix.
 */
static inline int lota_ima_cmdline_enforce(const char *cmdline)
{
	static const char name[] = "ima_appraise";
	const char *val = NULL;
	const char *p = cmdline;

	while (*p) {
		const char *tok;
		const char *eq = NULL;
		size_t len;
		int lead;
		int quoted;

		while (isspace((unsigned char)*p))
			p++;
		if (!*p)
			break;
		lead = *p == '"';
		quoted = lead;
		tok = p + lead;
		for (p = tok; *p && (quoted || !isspace((unsigned char)*p));
		     p++) {
			if (*p == '=' && !eq)
				eq = p;
			if (*p == '"')
				quoted = !quoted;
		}
		len = (size_t)((eq ? eq : p) - tok);
		if (!eq && len == 2 + (size_t)(lead && p[-1] == '"') &&
		    tok[0] == '-' && tok[1] == '-')
			break;
		if (!eq || len != sizeof(name) - 1)
			continue;
		for (size_t i = 0; i < len; i++) {
			if ((tok[i] == '-' ? '_' : tok[i]) != name[i]) {
				eq = NULL;
				break;
			}
		}
		if (eq)
			val = eq[1] == '"' ? eq + 2 : eq + 1;
	}

	if (val && (strncmp(val, "off", 3) == 0 ||
		    strncmp(val, "log", 3) == 0 || strncmp(val, "fix", 3) == 0))
		return 0;
	return 1;
}

#endif /* LOTA_IMA_APPRAISE_H */
