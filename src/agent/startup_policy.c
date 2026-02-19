/* SPDX-License-Identifier: MIT */

#include "startup_policy.h"

#include <errno.h>
#include <string.h>

#include "../../include/lota.h"
#include "bpf_loader.h"
#include "journal.h"
#include "main_utils.h"

extern struct bpf_loader_ctx g_bpf_ctx;
extern int g_mode;

int agent_apply_startup_policy(int mode, bool strict_mmap, bool block_ptrace,
                               bool strict_modules, bool block_anon_exec,
                               uint32_t *protect_pids, int protect_pid_count,
                               char trust_libs[][PATH_MAX],
                               int trust_lib_count) {
  int ret;

  ret = bpf_loader_set_mode(&g_bpf_ctx, mode);
  if (ret < 0) {
    lota_warn("Failed to set mode: %s", strerror(-ret));
  } else {
    lota_info("Mode: %s", mode_to_string(mode));
  }

  g_mode = mode;
  if (mode == LOTA_MODE_ENFORCE)
    lota_notice("ENFORCE mode active - module loading BLOCKED");

  if (strict_mmap) {
    ret = bpf_loader_set_config(&g_bpf_ctx, LOTA_CFG_STRICT_MMAP, 1);
    if (ret < 0)
      lota_warn("Failed to enable strict mmap: %s", strerror(-ret));
    else
      lota_info("Strict mmap enforcement: ON");
  }

  if (block_ptrace) {
    ret = bpf_loader_set_config(&g_bpf_ctx, LOTA_CFG_BLOCK_PTRACE, 1);
    if (ret < 0)
      lota_warn("Failed to enable ptrace blocking: %s", strerror(-ret));
    else
      lota_info("Global ptrace blocking: ON");
  }

  if (strict_modules) {
    ret = bpf_loader_set_config(&g_bpf_ctx, LOTA_CFG_STRICT_MODULES, 1);
    if (ret < 0)
      lota_warn("Failed to enable strict modules: %s", strerror(-ret));
    else
      lota_info("Strict modules enforcement: ON");
  }

  if (block_anon_exec) {
    ret = bpf_loader_set_config(&g_bpf_ctx, LOTA_CFG_BLOCK_ANON_EXEC, 1);
    if (ret < 0)
      lota_warn("Failed to enable anonymous exec blocking: %s", strerror(-ret));
    else
      lota_info("Anonymous executable mappings: BLOCKED");
  }

  {
    int applied_pids = 0;
    for (int i = 0; i < protect_pid_count; i++) {
      ret = bpf_loader_protect_pid(&g_bpf_ctx, protect_pids[i]);
      if (ret < 0) {
        lota_err("Failed to protect PID %u at startup: %s", protect_pids[i],
                 strerror(-ret));
        for (int k = 0; k < applied_pids; k++) {
          int rollback_ret =
              bpf_loader_unprotect_pid(&g_bpf_ctx, protect_pids[k]);
          if (rollback_ret < 0) {
            lota_warn("Failed to rollback protected PID %u: %s",
                      protect_pids[k], strerror(-rollback_ret));
          }
        }
        return ret;
      }
      applied_pids++;
      lota_dbg("Protected PID: %u", protect_pids[i]);
    }
    lota_info("Protected PIDs applied (%d entries)", applied_pids);
  }

  {
    int applied_libs = 0;
    for (int i = 0; i < trust_lib_count; i++) {
      ret = bpf_loader_trust_lib(&g_bpf_ctx, trust_libs[i]);
      if (ret < 0) {
        lota_err("Failed to trust lib %s at startup: %s", trust_libs[i],
                 strerror(-ret));
        for (int k = 0; k < applied_libs; k++) {
          int rollback_ret = bpf_loader_untrust_lib(&g_bpf_ctx, trust_libs[k]);
          if (rollback_ret < 0) {
            lota_warn("Failed to rollback trusted lib %s: %s", trust_libs[k],
                      strerror(-rollback_ret));
          }
        }
        return ret;
      }
      applied_libs++;
      lota_dbg("Trusted lib: %s", trust_libs[i]);
    }
    lota_info("Trusted libs applied (%d entries)", applied_libs);
  }

  return 0;
}
