/* SPDX-License-Identifier: MIT */

#include "startup_policy.h"

#include <errno.h>
#include <string.h>

#include <stdlib.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>

#include "../../include/lota_endian.h"

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

static int digest_cmp_32(const void *a, const void *b) {
  return memcmp(a, b, 32);
}

static int compute_policy_digest(const struct agent_startup_policy *policy,
                                 const uint8_t *digests, int digest_count,
                                 uint8_t out_digest[32]) {
  EVP_MD_CTX *mdctx = NULL;
  unsigned int out_len = 0;
  int ret = 0;
  uint8_t le[4];
  uint32_t flags = 0;

  if (!policy || !out_digest)
    return -EINVAL;
  if (digest_count < 0)
    return -EINVAL;
  if (digest_count > 0 && !digests)
    return -EINVAL;

  if (policy->strict_mmap)
    flags |= (1u << 0);
  if (policy->strict_exec)
    flags |= (1u << 1);
  if (policy->block_ptrace)
    flags |= (1u << 2);
  if (policy->strict_modules)
    flags |= (1u << 3);
  if (policy->block_anon_exec)
    flags |= (1u << 4);

  /* lock_bpf is always enabled by startup_policy */
  flags |= (1u << 5);

  mdctx = EVP_MD_CTX_new();
  if (!mdctx)
    return -ENOMEM;

  if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1) {
    ret = -EIO;
    goto out;
  }

  /* domain separator */
  {
    static const uint8_t prefix[] = "LOTA_POLICY_V1";
    if (EVP_DigestUpdate(mdctx, prefix, sizeof(prefix)) != 1) {
      ret = -EIO;
      goto out;
    }
  }

  lota__write_le32(le, (uint32_t)policy->mode);
  if (EVP_DigestUpdate(mdctx, le, sizeof(le)) != 1) {
    ret = -EIO;
    goto out;
  }

  lota__write_le32(le, flags);
  if (EVP_DigestUpdate(mdctx, le, sizeof(le)) != 1) {
    ret = -EIO;
    goto out;
  }

  lota__write_le32(le, (uint32_t)digest_count);
  if (EVP_DigestUpdate(mdctx, le, sizeof(le)) != 1) {
    ret = -EIO;
    goto out;
  }

  if (digest_count > 0) {
    size_t total = (size_t)digest_count * 32;
    if (EVP_DigestUpdate(mdctx, digests, total) != 1) {
      ret = -EIO;
      goto out;
    }
  }

  if (EVP_DigestFinal_ex(mdctx, out_digest, &out_len) != 1 || out_len != 32) {
    ret = -EIO;
    goto out;
  }

out:
  EVP_MD_CTX_free(mdctx);
  if (ret < 0)
    OPENSSL_cleanse(out_digest, 32);
  OPENSSL_cleanse(le, sizeof(le));
  return ret;
}

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

    /* compute and persist policy digest (order-independent allowlist) */
    qsort(digests, (size_t)policy->allow_verity_count, 32, digest_cmp_32);
    ret = compute_policy_digest(policy, digests, policy->allow_verity_count,
                                g_agent.policy_digest);
    if (ret < 0) {
      lota_err("Failed to compute policy digest: %s", strerror(-ret));
      goto rollback_allowlist;
    }
    g_agent.policy_digest_set = 1;

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

  /* no allowlist: still persist policy digest */
  ret = compute_policy_digest(policy, NULL, 0, g_agent.policy_digest);
  if (ret < 0) {
    lota_err("Failed to compute policy digest: %s", strerror(-ret));
    return ret;
  }
  g_agent.policy_digest_set = 1;

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
