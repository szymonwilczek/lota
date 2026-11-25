/* SPDX-License-Identifier: MIT */
/*
 * LOTA Agent - Policy Auto-Generation
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#include "policy.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "lota.h"

/*
 * PCR 8 and PCR 9 change across healthy reboots where GRUB measures grubenv,
 * so a pin on them refuses a good host. The verifier checks the command line
 * with its PCR 8 event-log denylist and the kernel image with kernel_hashes.
 * The verifier checks PCR 14 per client, against its baseline.
 */
static const int policy_export_pcr_list[] = {
	POLICY_PCR_0, POLICY_PCR_1, POLICY_PCR_4, POLICY_PCR_7, POLICY_PCR_11,
};

const int *policy_export_pcrs(size_t *count)
{
	if (count)
		*count = sizeof(policy_export_pcr_list) /
			 sizeof(policy_export_pcr_list[0]);
	return policy_export_pcr_list;
}

static void emit_hash_hex(FILE *out, const uint8_t hash[LOTA_HASH_SIZE])
{
	for (int i = 0; i < LOTA_HASH_SIZE; i++)
		fprintf(out, "%02x", hash[i]);
}

static void emit_yaml_string(FILE *out, const char *s)
{
	fputc('"', out);
	for (; *s; s++) {
		unsigned char c = (unsigned char)*s;
		switch (c) {
		case '"':
			fputs("\\\"", out);
			break;
		case '\\':
			fputs("\\\\", out);
			break;
		case '\0':
			fputs("\\0", out);
			break;
		case '\a':
			fputs("\\a", out);
			break;
		case '\b':
			fputs("\\b", out);
			break;
		case '\t':
			fputs("\\t", out);
			break;
		case '\n':
			fputs("\\n", out);
			break;
		case '\r':
			fputs("\\r", out);
			break;
		case '\x1b':
			fputs("\\e", out);
			break;
		default:
			if (c < 0x20 || c == 0x7f)
				fprintf(out, "\\x%02x", c);
			else
				fputc(c, out);
			break;
		}
	}
	fputc('"', out);
}

const char *policy_kernel_hash_reason(int err)
{
	switch (err) {
	case -ENOENT:
		return "this host's event log measures no kernel image, so the bootloader recorded nothing to pin";
	case -EEXIST:
		return "the event log measures two different kernel images and does not say which one booted";
	case -ENOMSG:
		return "the kernel image is measured without a SHA-256 digest, which is the only one the verifier compares";
	case -EINVAL:
		return "the event log could not be parsed";
	case -ENOMEM:
		return "the event log could not be held in memory";
	case 0:
		return "there is a kernel digest";
	default:
		return "the event log could not be read from securityfs";
	}
}

static void emit_yaml_comment(FILE *out, const char *prefix, const char *s)
{
	fprintf(out, "# %s: ", prefix);
	for (; *s; s++) {
		unsigned char c = (unsigned char)*s;
		if (c < 0x20 || c == 0x7f)
			fputc('?', out);
		else
			fputc(c, out);
	}
	fputc('\n', out);
}

int policy_emit(const struct policy_snapshot *snap, FILE *out)
{
	int i;

	if (!snap || !out)
		return -EINVAL;

	fprintf(out, "# SPDX-License-Identifier: MIT\n");
	fprintf(out, "# LOTA Policy - Auto-generated from live system\n");
	fprintf(out, "#\n");
	if (snap->hostname[0])
		emit_yaml_comment(out, "Host", snap->hostname);
	if (snap->timestamp[0])
		emit_yaml_comment(out, "Date", snap->timestamp);
	fprintf(out, "# Generator: lota-agent --export-policy\n");
	fprintf(out, "#\n");
	fprintf(out, "# Review all values before production use.\n");
	fprintf(out, "# Load with: lota-verifier --policy <this-file>\n");
	fprintf(out, "\n");

	fprintf(out, "name: ");
	emit_yaml_string(out, snap->name);
	fprintf(out, "\n");
	fprintf(out, "description: ");
	emit_yaml_string(out, snap->description);
	fprintf(out, "\n");
	fprintf(out, "\n");

	fprintf(out, "# PCR values (SHA-256, hex-encoded)\n");
	fprintf(out, "# Only listed PCRs are verified; others are ignored.\n");

	int valid_pcrs = 0;
	for (i = 0; i < snap->pcr_count; i++) {
		if (snap->pcrs[i].valid && snap->pcrs[i].index != POLICY_PCR_14)
			valid_pcrs++;
	}

	if (valid_pcrs == 0) {
		fprintf(out, "pcrs: {}\n");
	} else {
		fprintf(out, "pcrs:\n");
		for (i = 0; i < snap->pcr_count; i++) {
			if (!snap->pcrs[i].valid)
				continue;
			if (snap->pcrs[i].index == POLICY_PCR_14)
				continue;
			fprintf(out, "  %d: \"", snap->pcrs[i].index);
			emit_hash_hex(out, snap->pcrs[i].value);
			fprintf(out, "\"\n");
		}
	}
	fprintf(out,
		"# PCR14 (LOTA boot-commitment) is intentionally omitted: it is\n"
		"# validated by the verifier's boot-commitment derivation, not a\n"
		"# static pin, and changes on every boot.\n");
	fprintf(out, "\n");

	fprintf(out, "# Allowed kernel images (SHA-256)\n");
	if (snap->kernel_hash_valid) {
		emit_yaml_comment(
			out, "Source",
			"the bootloader's measurement of the kernel image (event log, PCR 9 EV_IPL)");
		emit_yaml_comment(out, "Image", snap->kernel_image_path);
		if (snap->kernel_release[0])
			emit_yaml_comment(out, "Booted kernel",
					  snap->kernel_release);
	} else {
		emit_yaml_comment(
			out, "Empty",
			policy_kernel_hash_reason(snap->kernel_hash_error));
		emit_yaml_comment(
			out, "Note",
			"a PCR value is not a substitute: it covers the whole boot and changes with it");
	}

	if (snap->kernel_hash_valid) {
		fprintf(out, "kernel_hashes:\n");
		fprintf(out, "  - \"");
		emit_hash_hex(out, snap->kernel_hash);
		fprintf(out, "\"\n");
	} else {
		fprintf(out, "kernel_hashes: []\n");
	}
	fprintf(out, "\n");

	fprintf(out, "# Allowed LOTA agent hashes (SHA-256)\n");
	if (snap->agent_path[0])
		emit_yaml_comment(out, "Source", snap->agent_path);

	if (snap->agent_hash_valid) {
		fprintf(out, "agent_hashes:\n");
		fprintf(out, "  - \"");
		emit_hash_hex(out, snap->agent_hash);
		fprintf(out, "\"\n");
	} else {
		fprintf(out, "agent_hashes: []\n");
	}
	fprintf(out, "\n");

	fprintf(out,
		"# Security requirements (auto-detected from live system)\n");
	fprintf(out, "require_iommu: %s\n",
		snap->iommu_enabled ? "true" : "false");
	fprintf(out, "require_enforce: %s\n",
		snap->enforce_mode ? "true" : "false");
	fprintf(out, "require_module_sig: %s\n",
		snap->module_sig ? "true" : "false");
	fprintf(out, "require_secureboot: %s\n",
		snap->secureboot ? "true" : "false");
	fprintf(out, "require_lockdown: %s\n",
		snap->lockdown ? "true" : "false");
	fprintf(out, "require_ima_appraisal: %s\n",
		snap->ima_appraisal ? "true" : "false");

	if (ferror(out))
		return -EIO;

	return 0;
}
