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

static int u32_cmp(const void *a, const void *b);
static int cstr_ptr_cmp(const void *a, const void *b);
static int compute_policy_digest(const struct agent_startup_policy *policy,
                                 const uint8_t *digests, int digest_count,
                                 uint8_t out_digest[32]);

static void agent_policy_snapshot_clear(void) {
  if (g_agent.policy_verity_digests) {
    OPENSSL_cleanse(g_agent.policy_verity_digests,
                    (size_t)g_agent.policy_verity_digest_count * 32);
    free(g_agent.policy_verity_digests);
    g_agent.policy_verity_digests = NULL;
  }
  g_agent.policy_verity_digest_count = 0;

  if (g_agent.policy_protect_pids) {
    OPENSSL_cleanse(g_agent.policy_protect_pids,
                    (size_t)g_agent.policy_protect_pid_count *
                        sizeof(uint32_t));
    free(g_agent.policy_protect_pids);
    g_agent.policy_protect_pids = NULL;
  }
  g_agent.policy_protect_pid_count = 0;

  if (g_agent.policy_trust_libs) {
    OPENSSL_cleanse(g_agent.policy_trust_libs,
                    (size_t)g_agent.policy_trust_lib_count * PATH_MAX);
    free(g_agent.policy_trust_libs);
    g_agent.policy_trust_libs = NULL;
  }
  g_agent.policy_trust_lib_count = 0;

  g_agent.policy_snapshot_set = 0;
}

static int canonicalize_u32_set(const uint32_t *in, int in_count,
                                uint32_t **out, int *out_count) {
  uint32_t *tmp = NULL;
  int unique = 0;

  if (!out || !out_count)
    return -EINVAL;
  *out = NULL;
  *out_count = 0;

  if (in_count < 0)
    return -EINVAL;
  if (in_count == 0)
    return 0;
  if (!in)
    return -EINVAL;

  tmp = calloc((size_t)in_count, sizeof(uint32_t));
  if (!tmp)
    return -ENOMEM;
  for (int i = 0; i < in_count; i++)
    tmp[i] = in[i];

  qsort(tmp, (size_t)in_count, sizeof(uint32_t), u32_cmp);
  for (int i = 0; i < in_count; i++) {
    if (i == 0 || tmp[i] != tmp[i - 1])
      unique++;
  }

  uint32_t *canon = calloc((size_t)unique, sizeof(uint32_t));
  if (!canon) {
    OPENSSL_cleanse(tmp, (size_t)in_count * sizeof(uint32_t));
    free(tmp);
    return -ENOMEM;
  }

  int w = 0;
  for (int i = 0; i < in_count; i++) {
    if (i != 0 && tmp[i] == tmp[i - 1])
      continue;
    canon[w++] = tmp[i];
  }

  OPENSSL_cleanse(tmp, (size_t)in_count * sizeof(uint32_t));
  free(tmp);
  tmp = NULL;

  *out = canon;
  *out_count = unique;
  return 0;
}

static int canonicalize_trust_libs(char (*trust_libs)[PATH_MAX],
                                   int trust_lib_count,
                                   char (**out_libs)[PATH_MAX],
                                   int *out_count) {
  const char **sorted = NULL;
  int unique = 0;

  if (!out_libs || !out_count)
    return -EINVAL;
  *out_libs = NULL;
  *out_count = 0;

  if (trust_lib_count < 0)
    return -EINVAL;
  if (trust_lib_count == 0)
    return 0;
  if (!trust_libs)
    return -EINVAL;

  sorted = calloc((size_t)trust_lib_count, sizeof(char *));
  if (!sorted)
    return -ENOMEM;
  for (int i = 0; i < trust_lib_count; i++)
    sorted[i] = trust_libs[i];

  qsort(sorted, (size_t)trust_lib_count, sizeof(char *), cstr_ptr_cmp);
  for (int i = 0; i < trust_lib_count; i++) {
    if (i == 0 || strcmp(sorted[i], sorted[i - 1]) != 0)
      unique++;
  }

  char (*canon)[PATH_MAX] = calloc((size_t)unique, PATH_MAX);
  if (!canon) {
    OPENSSL_cleanse(sorted, (size_t)trust_lib_count * sizeof(char *));
    free(sorted);
    return -ENOMEM;
  }

  int w = 0;
  for (int i = 0; i < trust_lib_count; i++) {
    if (i != 0 && strcmp(sorted[i], sorted[i - 1]) == 0)
      continue;
    snprintf(canon[w], PATH_MAX, "%s", sorted[i]);
    w++;
  }

  OPENSSL_cleanse(sorted, (size_t)trust_lib_count * sizeof(char *));
  free(sorted);
  sorted = NULL;

  *out_libs = canon;
  *out_count = unique;
  return 0;
}

int agent_compute_policy_digest_for_protect_pids(const uint32_t *protect_pids,
                                                 int protect_pid_count,
                                                 uint8_t out_digest[32]) {
  struct agent_startup_policy pol;

  if (!out_digest)
    return -EINVAL;
  if (!g_agent.policy_snapshot_set)
    return -EINVAL;

  memset(&pol, 0, sizeof(pol));
  pol.mode = g_agent.policy_mode;
  pol.strict_mmap = g_agent.policy_strict_mmap;
  pol.strict_exec = g_agent.policy_strict_exec;
  pol.block_ptrace = g_agent.policy_block_ptrace;
  pol.strict_modules = g_agent.policy_strict_modules;
  pol.block_anon_exec = g_agent.policy_block_anon_exec;

  pol.protect_pids = (uint32_t *)protect_pids;
  pol.protect_pid_count = protect_pid_count;

  pol.trust_libs = g_agent.policy_trust_libs;
  pol.trust_lib_count = g_agent.policy_trust_lib_count;

  return compute_policy_digest(&pol, g_agent.policy_verity_digests,
                               g_agent.policy_verity_digest_count, out_digest);
}

static int digest_cmp_32(const void *a, const void *b) {
  return memcmp(a, b, 32);
}

static int u32_cmp(const void *a, const void *b) {
  uint32_t av = *(const uint32_t *)a;
  uint32_t bv = *(const uint32_t *)b;
  if (av < bv)
    return -1;
  if (av > bv)
    return 1;
  return 0;
}

static int cstr_ptr_cmp(const void *a, const void *b) {
  const char *const *ap = (const char *const *)a;
  const char *const *bp = (const char *const *)b;
  if (!*ap && !*bp)
    return 0;
  if (!*ap)
    return -1;
  if (!*bp)
    return 1;
  return strcmp(*ap, *bp);
}

static int compute_policy_digest(const struct agent_startup_policy *policy,
                                 const uint8_t *digests, int digest_count,
                                 uint8_t out_digest[32]) {
  EVP_MD_CTX *mdctx = NULL;
  unsigned int out_len = 0;
  int ret = 0;
  uint8_t le[4];
  uint32_t flags = 0;
  uint32_t *sorted_pids = NULL;
  const char **sorted_libs = NULL;

  if (!policy || !out_digest)
    return -EINVAL;
  if (digest_count < 0)
    return -EINVAL;
  if (digest_count > 0 && !digests)
    return -EINVAL;
  if (policy->protect_pid_count < 0 || policy->trust_lib_count < 0)
    return -EINVAL;
  if (policy->protect_pid_count > 0 && !policy->protect_pids)
    return -EINVAL;
  if (policy->trust_lib_count > 0 && !policy->trust_libs)
    return -EINVAL;

  /* hard caps: protect against unbounded memory/time via hostile inputs */
  if (policy->protect_pid_count > LOTA_MAX_PROTECTED_PIDS)
    return -ENOSPC;
  if (policy->trust_lib_count > LOTA_MAX_TRUSTED_LIBS)
    return -ENOSPC;

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
    if (EVP_DigestUpdate(mdctx, prefix, sizeof(prefix) - 1) != 1) {
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

  /* protect_pids: treat as a set (order-independent) */
  if (policy->protect_pid_count > 0) {
    sorted_pids = calloc((size_t)policy->protect_pid_count, sizeof(uint32_t));
    if (!sorted_pids) {
      ret = -ENOMEM;
      goto out;
    }
    for (int i = 0; i < policy->protect_pid_count; i++)
      sorted_pids[i] = policy->protect_pids[i];

    qsort(sorted_pids, (size_t)policy->protect_pid_count, sizeof(uint32_t),
          u32_cmp);

    /* hash unique count + values */
    int unique = 0;
    for (int i = 0; i < policy->protect_pid_count; i++) {
      if (i == 0 || sorted_pids[i] != sorted_pids[i - 1])
        unique++;
    }
    lota__write_le32(le, (uint32_t)unique);
    if (EVP_DigestUpdate(mdctx, le, sizeof(le)) != 1) {
      ret = -EIO;
      goto out;
    }
    for (int i = 0; i < policy->protect_pid_count; i++) {
      if (i != 0 && sorted_pids[i] == sorted_pids[i - 1])
        continue;
      lota__write_le32(le, sorted_pids[i]);
      if (EVP_DigestUpdate(mdctx, le, sizeof(le)) != 1) {
        ret = -EIO;
        goto out;
      }
    }
  } else {
    lota__write_le32(le, 0);
    if (EVP_DigestUpdate(mdctx, le, sizeof(le)) != 1) {
      ret = -EIO;
      goto out;
    }
  }

  /* trust_libs: treat as a set (order-independent) */
  if (policy->trust_lib_count > 0) {
    sorted_libs = calloc((size_t)policy->trust_lib_count, sizeof(char *));
    if (!sorted_libs) {
      ret = -ENOMEM;
      goto out;
    }
    for (int i = 0; i < policy->trust_lib_count; i++)
      sorted_libs[i] = policy->trust_libs[i];

    qsort(sorted_libs, (size_t)policy->trust_lib_count, sizeof(char *),
          cstr_ptr_cmp);

    int unique = 0;
    for (int i = 0; i < policy->trust_lib_count; i++) {
      if (i == 0 || strcmp(sorted_libs[i], sorted_libs[i - 1]) != 0)
        unique++;
    }
    lota__write_le32(le, (uint32_t)unique);
    if (EVP_DigestUpdate(mdctx, le, sizeof(le)) != 1) {
      ret = -EIO;
      goto out;
    }

    for (int i = 0; i < policy->trust_lib_count; i++) {
      if (i != 0 && strcmp(sorted_libs[i], sorted_libs[i - 1]) == 0)
        continue;
      uint32_t slen = (uint32_t)strlen(sorted_libs[i]);
      lota__write_le32(le, slen);
      if (EVP_DigestUpdate(mdctx, le, sizeof(le)) != 1 ||
          (slen > 0 &&
           EVP_DigestUpdate(mdctx, sorted_libs[i], (size_t)slen) != 1)) {
        ret = -EIO;
        goto out;
      }
    }
  } else {
    lota__write_le32(le, 0);
    if (EVP_DigestUpdate(mdctx, le, sizeof(le)) != 1) {
      ret = -EIO;
      goto out;
    }
  }

  if (EVP_DigestFinal_ex(mdctx, out_digest, &out_len) != 1 || out_len != 32) {
    ret = -EIO;
    goto out;
  }

out:
  if (sorted_pids) {
    OPENSSL_cleanse(sorted_pids,
                    (size_t)policy->protect_pid_count * sizeof(uint32_t));
    free(sorted_pids);
    sorted_pids = NULL;
  }
  if (sorted_libs) {
    OPENSSL_cleanse(sorted_libs,
                    (size_t)policy->trust_lib_count * sizeof(char *));
    free(sorted_libs);
    sorted_libs = NULL;
  }
  EVP_MD_CTX_free(mdctx);
  if (ret < 0)
    OPENSSL_cleanse(out_digest, 32);
  OPENSSL_cleanse(le, sizeof(le));
  return ret;
}

int agent_apply_startup_policy(const struct agent_startup_policy *policy) {
  int ret;
  int mode;
  uint8_t computed_policy_digest[32];
  int have_policy_digest = 0;
  uint8_t *digests = NULL;
  int digest_count = 0;
  int allowlist_applied = 0;

  if (!policy)
    return -EINVAL;

  mode = policy->mode;

  if (policy->strict_mmap) {
    ret = bpf_loader_set_config(&g_agent.bpf_ctx, LOTA_CFG_STRICT_MMAP, 1);
    if (ret < 0) {
      lota_err("Failed to enable strict mmap: %s", strerror(-ret));
      return ret;
    }
    lota_info("Strict mmap enforcement: ON");
  }

  if (policy->allow_verity_count > 0) {
    digests = calloc((size_t)policy->allow_verity_count, 32);
    if (!digests)
      return -ENOMEM;
    digest_count = policy->allow_verity_count;

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
      allowlist_applied++;

      {
        char hex[65];
        hex_encode_upper(d, 32, hex, sizeof(hex));
        lota_dbg("Allowed fs-verity: %s digest=%s", policy->allow_verity[i],
                 hex);
      }
    }

    /* canonicalize allowlist digest order */
    qsort(digests, (size_t)digest_count, 32, digest_cmp_32);
    ret = compute_policy_digest(policy, digests, digest_count,
                                computed_policy_digest);
    if (ret < 0) {
      lota_err("Failed to compute policy digest: %s", strerror(-ret));
      goto rollback_allowlist;
    }
    have_policy_digest = 1;

    lota_info("fs-verity allowlist applied (%d entries)", allowlist_applied);
    goto allowlist_done;

  rollback_allowlist:
    for (int k = 0; k < allowlist_applied; k++) {
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

    OPENSSL_cleanse(digests, (size_t)digest_count * 32);
    free(digests);
    digests = NULL;
    return ret;
  } else if (policy->strict_exec || policy->strict_modules) {
    lota_err("Strict exec/modules requested but no allow_verity entries are "
             "configured");
    return -EINVAL;
  }

  /* no allowlist: still compute policy digest */
  ret = compute_policy_digest(policy, NULL, 0, computed_policy_digest);
  if (ret < 0) {
    lota_err("Failed to compute policy digest: %s", strerror(-ret));
    return ret;
  }
  have_policy_digest = 1;

allowlist_done:

  if (!have_policy_digest) {
    lota_err("Internal error: policy digest is not computed");
    ret = -EIO;
    goto out_fail;
  }

  if (policy->strict_exec) {
    ret = bpf_loader_set_config(&g_agent.bpf_ctx, LOTA_CFG_STRICT_EXEC, 1);
    if (ret < 0) {
      lota_err("Failed to enable strict exec: %s", strerror(-ret));
      goto out_fail;
    }
    lota_info("Strict exec enforcement: ON");
  }

  if (policy->block_ptrace) {
    ret = bpf_loader_set_config(&g_agent.bpf_ctx, LOTA_CFG_BLOCK_PTRACE, 1);
    if (ret < 0) {
      lota_err("Failed to enable ptrace blocking: %s", strerror(-ret));
      goto out_fail;
    }
    lota_info("Global ptrace blocking: ON");
  }

  if (policy->strict_modules) {
    ret = bpf_loader_set_config(&g_agent.bpf_ctx, LOTA_CFG_STRICT_MODULES, 1);
    if (ret < 0) {
      lota_err("Failed to enable strict modules: %s", strerror(-ret));
      goto out_fail;
    }
    lota_info("Strict modules enforcement: ON");
  }

  if (policy->block_anon_exec) {
    ret = bpf_loader_set_config(&g_agent.bpf_ctx, LOTA_CFG_BLOCK_ANON_EXEC, 1);
    if (ret < 0) {
      lota_err("Failed to enable anonymous exec blocking: %s", strerror(-ret));
      goto out_fail;
    }
    lota_info("Anonymous executable mappings: BLOCKED");
  }

  ret = bpf_loader_set_config(&g_agent.bpf_ctx, LOTA_CFG_LOCK_BPF, 1);
  if (ret < 0) {
    lota_err("Failed to enable bpf syscall lock: %s", strerror(-ret));
    goto out_fail;
  }
  lota_info("BPF syscall lock: ON (non-agent bpf() denied in ENFORCE)");

  ret = bpf_loader_set_mode(&g_agent.bpf_ctx, mode);
  if (ret < 0) {
    lota_err("Failed to set mode: %s", strerror(-ret));
    goto out_fail;
  }
  lota_info("Mode: %s", mode_to_string(mode));

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
        goto out_fail;
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
        goto out_fail;
      }
      applied_libs++;
      lota_dbg("Trusted lib: %s", policy->trust_libs[i]);
    }
    lota_info("Trusted libs applied (%d entries)", applied_libs);
  }

  /* persist canonical policy snapshot for runtime recompute */
  {
    uint32_t *canon_pids = NULL;
    int canon_pid_count = 0;
    char (*canon_libs)[PATH_MAX] = NULL;
    int canon_lib_count = 0;
    uint8_t *canon_digests = NULL;

    if (digest_count > 0) {
      canon_digests = malloc((size_t)digest_count * 32);
      if (!canon_digests) {
        ret = -ENOMEM;
        goto out_fail;
      }
      memcpy(canon_digests, digests, (size_t)digest_count * 32);
    }

    ret = canonicalize_u32_set(policy->protect_pids, policy->protect_pid_count,
                               &canon_pids, &canon_pid_count);
    if (ret < 0) {
      if (canon_digests) {
        OPENSSL_cleanse(canon_digests, (size_t)digest_count * 32);
        free(canon_digests);
      }
      goto out_fail;
    }

    ret = canonicalize_trust_libs(policy->trust_libs, policy->trust_lib_count,
                                  &canon_libs, &canon_lib_count);
    if (ret < 0) {
      if (canon_digests) {
        OPENSSL_cleanse(canon_digests, (size_t)digest_count * 32);
        free(canon_digests);
      }
      if (canon_pids) {
        OPENSSL_cleanse(canon_pids, (size_t)canon_pid_count * sizeof(uint32_t));
        free(canon_pids);
      }
      goto out_fail;
    }

    agent_policy_snapshot_clear();
    g_agent.policy_mode = mode;
    g_agent.policy_strict_mmap = policy->strict_mmap;
    g_agent.policy_strict_exec = policy->strict_exec;
    g_agent.policy_block_ptrace = policy->block_ptrace;
    g_agent.policy_strict_modules = policy->strict_modules;
    g_agent.policy_block_anon_exec = policy->block_anon_exec;

    g_agent.policy_verity_digests = canon_digests;
    g_agent.policy_verity_digest_count = digest_count;
    g_agent.policy_protect_pids = canon_pids;
    g_agent.policy_protect_pid_count = canon_pid_count;
    g_agent.policy_trust_libs = canon_libs;
    g_agent.policy_trust_lib_count = canon_lib_count;
    g_agent.policy_snapshot_set = 1;
  }

  memcpy(g_agent.policy_digest, computed_policy_digest, 32);
  g_agent.policy_digest_set = 1;

  if (digests) {
    OPENSSL_cleanse(digests, (size_t)digest_count * 32);
    free(digests);
    digests = NULL;
  }
  OPENSSL_cleanse(computed_policy_digest, sizeof(computed_policy_digest));
  return 0;

out_fail:
  if (digests) {
    for (int k = 0; k < allowlist_applied; k++) {
      uint8_t *d = digests + (size_t)k * 32;
      (void)bpf_loader_disallow_verity_digest(&g_agent.bpf_ctx, d);
    }
    OPENSSL_cleanse(digests, (size_t)digest_count * 32);
    free(digests);
    digests = NULL;
  }
  OPENSSL_cleanse(computed_policy_digest, sizeof(computed_policy_digest));
  return ret;
}
