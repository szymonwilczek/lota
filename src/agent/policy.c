/* SPDX-License-Identifier: MIT */
/*
 * LOTA Agent - Policy Auto-Generation
 *
 * Generates a complete YAML policy file from the current system state.
 * The output is directly consumable by lota-verifier --policy.
 *
 * YAML structure matches PCRPolicy in src/verifier/verify/pcr.go:
 *
 *   name: <string>
 *   description: <string>
 *   pcrs:
 *     <index>: "<hex>"
 *   kernel_hashes:
 *     - "<hex>"
 *   agent_hashes:
 *     - "<hex>"
 *   require_iommu: <bool>
 *   require_enforce: <bool>
 *   require_module_sig: <bool>
 *   require_secureboot: <bool>
 *   require_lockdown: <bool>
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#include "policy.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

/*
 * Write a SHA-256 hash as a lowercase hex string.
 */
static void emit_hash_hex(FILE *out, const uint8_t hash[LOTA_HASH_SIZE]) {
  for (int i = 0; i < LOTA_HASH_SIZE; i++)
    fprintf(out, "%02x", hash[i]);
}

/*
 * Write a YAML double-quoted scalar with proper escaping.
 *
 * Escapes backslashes, double quotes and control characters so that
 * the output is a valid YAML double-quoted string regardless of
 * input content.
 */
static void emit_yaml_string(FILE *out, const char *s) {
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

/*
 * Write a sanitized YAML comment line.
 */
static void emit_yaml_comment(FILE *out, const char *prefix, const char *s) {
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

int policy_emit(const struct policy_snapshot *snap, FILE *out) {
  int i;

  if (!snap || !out)
    return -EINVAL;

  /*
   * YAML header comment block.
   * Includes provenance metadata so operators know when and where
   * this policy was generated.
   */
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

  /*
   * PCR values section.
   *
   * Only PCRs that were successfully read are emitted.
   * The verifier only checks PCRs present in this map; omitted
   * PCRs will be accepted unconditionally (by design).
   */
  fprintf(out, "# PCR values (SHA-256, hex-encoded)\n");
  fprintf(out, "# Only listed PCRs are verified; others are ignored.\n");

  int valid_pcrs = 0;
  for (i = 0; i < snap->pcr_count; i++) {
    if (snap->pcrs[i].valid)
      valid_pcrs++;
  }

  if (valid_pcrs == 0) {
    fprintf(out, "pcrs: {}\n");
  } else {
    fprintf(out, "pcrs:\n");
    for (i = 0; i < snap->pcr_count; i++) {
      if (!snap->pcrs[i].valid)
        continue;
      fprintf(out, "  %d: \"", snap->pcrs[i].index);
      emit_hash_hex(out, snap->pcrs[i].value);
      fprintf(out, "\"\n");
    }
  }
  fprintf(out, "\n");

  /*
   * Kernel image hash.
   */
  fprintf(out, "# Allowed kernel image hashes (SHA-256)\n");
  if (snap->kernel_path[0])
    emit_yaml_comment(out, "Source", snap->kernel_path);

  if (snap->kernel_hash_valid) {
    fprintf(out, "kernel_hashes:\n");
    fprintf(out, "  - \"");
    emit_hash_hex(out, snap->kernel_hash);
    fprintf(out, "\"\n");
  } else {
    fprintf(out, "kernel_hashes: []\n");
  }
  fprintf(out, "\n");

  /*
   * Agent binary hash.
   */
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

  /*
   * Security requirements.
   *
   * Each boolean reflects the current system state: if the feature
   * is detected as active, the requirement is set to true.
   */
  fprintf(out, "# Security requirements (auto-detected from live system)\n");
  fprintf(out, "require_iommu: %s\n", snap->iommu_enabled ? "true" : "false");
  fprintf(out, "require_enforce: %s\n", snap->enforce_mode ? "true" : "false");
  fprintf(out, "require_module_sig: %s\n", snap->module_sig ? "true" : "false");
  fprintf(out, "require_secureboot: %s\n", snap->secureboot ? "true" : "false");
  fprintf(out, "require_lockdown: %s\n", snap->lockdown ? "true" : "false");

  if (ferror(out))
    return -EIO;

  return 0;
}

int policy_emit_to_buf(const struct policy_snapshot *snap, char *buf,
                       size_t buf_size, size_t *written) {
  FILE *mem;
  int ret;
  long pos;

  if (!snap || !buf || buf_size == 0)
    return -EINVAL;

  /*
   * fmemopen opens a stream backed by the caller's buffer.
   * One byte is reserved for the NUL terminator that fclose writes.
   */
  mem = fmemopen(buf, buf_size, "w");
  if (!mem)
    return -errno;

  ret = policy_emit(snap, mem);

  /*
   * Detect silent truncation: fmemopen does not report an error when
   * writes exceed the buffer - it simply stops writing. Compare the
   * stream position to the usable capacity (buf_size - 1, reserving
   * one byte for the NUL terminator written by fclose).
   */
  if (ret == 0) {
    pos = ftell(mem);
    if (pos < 0) {
      ret = -EIO;
    } else if ((size_t)pos >= buf_size - 1) {
      ret = -ENOSPC;
    }
  }

  /*
   * fclose flushes and NUL-terminates the buffer.
   */
  if (fclose(mem) != 0 && ret == 0)
    ret = -EIO;

  if (ret == 0 && written)
    *written = strlen(buf);

  return ret;
}
