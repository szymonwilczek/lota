/* SPDX-License-Identifier: MIT */

#include "startup_policy.h"

#include <errno.h>
#include <string.h>

#include <stdlib.h>

#include <openssl/crypto.h>

static void hex_encode_upper(const uint8_t *in, size_t in_len, char *out,
                             size_t out_len) {
  static const char hex[] = "0123456789ABCDEF";

  if (!in || !out || out_len == 0)
    return;
  if (out_len < (in_len * 2 + 1)) {
    out[0] = '\0';
    return;
  }

  for (size_t i = 0; i < in_len; i++) {
    out[i * 2] = hex[(in[i] >> 4) & 0xF];
    out[i * 2 + 1] = hex[in[i] & 0xF];
  }
  out[in_len * 2] = '\0';
}

#include "../../include/lota.h"
#include "agent.h"
#include "bpf_loader.h"
#include "journal.h"
#include "main_utils.h"

int agent_apply_startup_policy(const struct agent_startup_policy *policy) {
  int ret;
  int mode;

  if (!policy)
    return -EINVAL;

  mode = policy->mode;

  if (policy->strict_mmap) {
    ret = bpf_loader_set_config(&g_agent.bpf_ctx, LOTA_CFG_STRICT_MMAP, 1);
    if (ret < 0)
      lota_warn("Failed to enable strict mmap: %s", strerror(-ret));
    else
      lota_info("Strict mmap enforcement: ON");
  }

  if (policy->allow_verity_count > 0) {
    int applied = 0;
    uint8_t *digests = NULL;

    digests = calloc((size_t)policy->allow_verity_count, 32);
    if (!digests)
      return -ENOMEM;

    for (int i = 0; i < policy->allow_verity_count; i++) {
      uint8_t *d = digests + (size_t)i * 32;

      ret = bpf_loader_measure_verity_digest(policy->allow_verity[i], d);
      if (ret < 0) {
        lota_err("Failed to measure fs-verity path %s: %s",
                 policy->allow_verity[i], strerror(-ret));
        goto rollback_allowlist;
      }

      ret = bpf_loader_allow_verity_digest(&g_agent.bpf_ctx, d);
      if (ret < 0) {
        lota_err("Failed to allow fs-verity digest for %s: %s",
                 policy->allow_verity[i], strerror(-ret));
        goto rollback_allowlist;
      }
      applied++;

      {
        char hex[65];
        hex_encode_upper(d, 32, hex, sizeof(hex));
        lota_dbg("Allowed fs-verity: %s digest=%s", policy->allow_verity[i],
                 hex);
      }
    }
    lota_info("fs-verity allowlist applied (%d entries)", applied);
    OPENSSL_cleanse(digests, (size_t)policy->allow_verity_count * 32);
    free(digests);
    digests = NULL;
    applied = applied;
    goto allowlist_done;

  rollback_allowlist:
    for (int k = 0; k < policy->allow_verity_count; k++) {
      uint8_t *d = digests + (size_t)k * 32;
      bool all_zero = true;
      for (int j = 0; j < 32; j++) {
        if (d[j] != 0) {
          all_zero = false;
          break;
        }
      }
      if (all_zero)
        continue;

      (void)bpf_loader_disallow_verity_digest(&g_agent.bpf_ctx, d);
    }

    OPENSSL_cleanse(digests, (size_t)policy->allow_verity_count * 32);
    free(digests);
    digests = NULL;
    return ret;
  } else if (policy->strict_exec || policy->strict_modules) {
    lota_err("Strict exec/modules requested but no allow_verity entries are "
             "configured");
    return -EINVAL;
  }

allowlist_done:

  if (policy->strict_exec) {
    ret = bpf_loader_set_config(&g_agent.bpf_ctx, LOTA_CFG_STRICT_EXEC, 1);
    if (ret < 0)
      lota_warn("Failed to enable strict exec: %s", strerror(-ret));
    else
      lota_info("Strict exec enforcement: ON");
  }

  if (policy->block_ptrace) {
    ret = bpf_loader_set_config(&g_agent.bpf_ctx, LOTA_CFG_BLOCK_PTRACE, 1);
    if (ret < 0)
      lota_warn("Failed to enable ptrace blocking: %s", strerror(-ret));
    else
      lota_info("Global ptrace blocking: ON");
  }

  if (policy->strict_modules) {
    ret = bpf_loader_set_config(&g_agent.bpf_ctx, LOTA_CFG_STRICT_MODULES, 1);
    if (ret < 0)
      lota_warn("Failed to enable strict modules: %s", strerror(-ret));
    else
      lota_info("Strict modules enforcement: ON");
  }

  if (policy->block_anon_exec) {
    ret = bpf_loader_set_config(&g_agent.bpf_ctx, LOTA_CFG_BLOCK_ANON_EXEC, 1);
    if (ret < 0)
      lota_warn("Failed to enable anonymous exec blocking: %s", strerror(-ret));
    else
      lota_info("Anonymous executable mappings: BLOCKED");
  }

  ret = bpf_loader_set_config(&g_agent.bpf_ctx, LOTA_CFG_LOCK_BPF, 1);
  if (ret < 0)
    lota_warn("Failed to enable bpf syscall lock: %s", strerror(-ret));
  else
    lota_info("BPF syscall lock: ON (non-agent bpf() denied in ENFORCE)");

  ret = bpf_loader_set_mode(&g_agent.bpf_ctx, mode);
  if (ret < 0) {
    lota_warn("Failed to set mode: %s", strerror(-ret));
  } else {
    lota_info("Mode: %s", mode_to_string(mode));
  }

  g_agent.mode = mode;
  if (mode == LOTA_MODE_ENFORCE)
    lota_notice("ENFORCE mode active");

  {
    int applied_pids = 0;
    for (int i = 0; i < policy->protect_pid_count; i++) {
      ret = bpf_loader_protect_pid(&g_agent.bpf_ctx, policy->protect_pids[i]);
      if (ret < 0) {
        lota_err("Failed to protect PID %u at startup: %s",
                 policy->protect_pids[i], strerror(-ret));
        for (int k = 0; k < applied_pids; k++) {
          int rollback_ret = bpf_loader_unprotect_pid(&g_agent.bpf_ctx,
                                                      policy->protect_pids[k]);
          if (rollback_ret < 0) {
            lota_warn("Failed to rollback protected PID %u: %s",
                      policy->protect_pids[k], strerror(-rollback_ret));
          }
        }
        return ret;
      }
      applied_pids++;
      lota_dbg("Protected PID: %u", policy->protect_pids[i]);
    }
    lota_info("Protected PIDs applied (%d entries)", applied_pids);
  }

  {
    int applied_libs = 0;
    for (int i = 0; i < policy->trust_lib_count; i++) {
      ret = bpf_loader_trust_lib(&g_agent.bpf_ctx, policy->trust_libs[i]);
      if (ret < 0) {
        lota_err("Failed to trust lib %s at startup: %s", policy->trust_libs[i],
                 strerror(-ret));
        for (int k = 0; k < applied_libs; k++) {
          int rollback_ret =
              bpf_loader_untrust_lib(&g_agent.bpf_ctx, policy->trust_libs[k]);
          if (rollback_ret < 0) {
            lota_warn("Failed to rollback trusted lib %s: %s",
                      policy->trust_libs[k], strerror(-rollback_ret));
          }
        }
        return ret;
      }
      applied_libs++;
      lota_dbg("Trusted lib: %s", policy->trust_libs[i]);
    }
    lota_info("Trusted libs applied (%d entries)", applied_libs);
  }

  return 0;
}
