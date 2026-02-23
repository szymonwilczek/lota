/* SPDX-License-Identifier: MIT */

#include "reload.h"

#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include "agent.h"
#include "bpf_loader.h"
#include "journal.h"
#include "main_utils.h"
#include "sdnotify.h"

static void copy_path(char dst[PATH_MAX], const char *src) {
  size_t len = strnlen(src, PATH_MAX - 1);
  memcpy(dst, src, len);
  dst[len] = '\0';
}

static void apply_runtime_flags_transactional(
    const struct lota_config *new_cfg, bool *strict_mmap, bool *strict_exec,
    bool *block_ptrace, bool *strict_modules, bool *block_anon_exec) {
  bool old_strict_mmap = *strict_mmap;
  bool old_strict_exec = *strict_exec;
  bool old_block_ptrace = *block_ptrace;
  bool old_strict_modules = *strict_modules;
  bool old_block_anon_exec = *block_anon_exec;
  bool runtime_flags_failed = false;

  if (new_cfg->strict_mmap != *strict_mmap) {
    if (bpf_loader_set_config(&g_agent.bpf_ctx, LOTA_CFG_STRICT_MMAP,
                              new_cfg->strict_mmap ? 1 : 0) == 0) {
      *strict_mmap = new_cfg->strict_mmap;
    } else {
      lota_warn("Failed to apply strict mmap on reload");
      runtime_flags_failed = true;
    }
  }

  if (!runtime_flags_failed && new_cfg->block_ptrace != *block_ptrace) {
    if (bpf_loader_set_config(&g_agent.bpf_ctx, LOTA_CFG_BLOCK_PTRACE,
                              new_cfg->block_ptrace ? 1 : 0) == 0) {
      *block_ptrace = new_cfg->block_ptrace;
    } else {
      lota_warn("Failed to apply block ptrace on reload");
      runtime_flags_failed = true;
    }
  }

  if (!runtime_flags_failed && new_cfg->strict_exec != *strict_exec) {
    if (bpf_loader_set_config(&g_agent.bpf_ctx, LOTA_CFG_STRICT_EXEC,
                              new_cfg->strict_exec ? 1 : 0) == 0) {
      *strict_exec = new_cfg->strict_exec;
    } else {
      lota_warn("Failed to apply strict exec on reload");
      runtime_flags_failed = true;
    }
  }

  if (!runtime_flags_failed && new_cfg->strict_modules != *strict_modules) {
    if (bpf_loader_set_config(&g_agent.bpf_ctx, LOTA_CFG_STRICT_MODULES,
                              new_cfg->strict_modules ? 1 : 0) == 0) {
      *strict_modules = new_cfg->strict_modules;
    } else {
      lota_warn("Failed to apply strict modules on reload");
      runtime_flags_failed = true;
    }
  }

  if (!runtime_flags_failed && new_cfg->block_anon_exec != *block_anon_exec) {
    if (bpf_loader_set_config(&g_agent.bpf_ctx, LOTA_CFG_BLOCK_ANON_EXEC,
                              new_cfg->block_anon_exec ? 1 : 0) == 0) {
      *block_anon_exec = new_cfg->block_anon_exec;
    } else {
      lota_warn("Failed to apply block anonymous exec on reload");
      runtime_flags_failed = true;
    }
  }

  if (runtime_flags_failed) {
    if (*strict_mmap != old_strict_mmap) {
      if (bpf_loader_set_config(&g_agent.bpf_ctx, LOTA_CFG_STRICT_MMAP,
                                old_strict_mmap ? 1 : 0) == 0) {
        *strict_mmap = old_strict_mmap;
      } else {
        lota_warn("Failed to rollback strict mmap after reload error");
      }
    }
    if (*block_ptrace != old_block_ptrace) {
      if (bpf_loader_set_config(&g_agent.bpf_ctx, LOTA_CFG_BLOCK_PTRACE,
                                old_block_ptrace ? 1 : 0) == 0) {
        *block_ptrace = old_block_ptrace;
      } else {
        lota_warn("Failed to rollback block ptrace after reload error");
      }
    }
    if (*strict_exec != old_strict_exec) {
      if (bpf_loader_set_config(&g_agent.bpf_ctx, LOTA_CFG_STRICT_EXEC,
                                old_strict_exec ? 1 : 0) == 0) {
        *strict_exec = old_strict_exec;
      } else {
        lota_warn("Failed to rollback strict exec after reload error");
      }
    }
    if (*strict_modules != old_strict_modules) {
      if (bpf_loader_set_config(&g_agent.bpf_ctx, LOTA_CFG_STRICT_MODULES,
                                old_strict_modules ? 1 : 0) == 0) {
        *strict_modules = old_strict_modules;
      } else {
        lota_warn("Failed to rollback strict modules after reload error");
      }
    }
    if (*block_anon_exec != old_block_anon_exec) {
      if (bpf_loader_set_config(&g_agent.bpf_ctx, LOTA_CFG_BLOCK_ANON_EXEC,
                                old_block_anon_exec ? 1 : 0) == 0) {
        *block_anon_exec = old_block_anon_exec;
      } else {
        lota_warn("Failed to rollback block anonymous exec after reload error");
      }
    }
    lota_warn("Keeping previous runtime enforcement flags after reload errors");
    return;
  }

  if (*strict_mmap != old_strict_mmap)
    lota_info("Strict mmap: %s", *strict_mmap ? "ON" : "OFF");
  if (*strict_exec != old_strict_exec)
    lota_info("Strict exec: %s", *strict_exec ? "ON" : "OFF");
  if (*block_ptrace != old_block_ptrace)
    lota_info("Block ptrace: %s", *block_ptrace ? "ON" : "OFF");
  if (*strict_modules != old_strict_modules)
    lota_info("Strict modules: %s", *strict_modules ? "ON" : "OFF");
  if (*block_anon_exec != old_block_anon_exec)
    lota_info("Block anonymous exec: %s", *block_anon_exec ? "ON" : "OFF");
}

static void reload_protected_pids(const struct lota_config *new_cfg,
                                  uint32_t **protect_pids,
                                  int *protect_pid_count) {
  int old_protect_pid_count = *protect_pid_count;
  uint32_t *old_protect_pids = *protect_pids;

  for (int k = 0; k < old_protect_pid_count; k++)
    bpf_loader_unprotect_pid(&g_agent.bpf_ctx, old_protect_pids[k]);

  if (new_cfg->protect_pid_count > 0) {
    uint32_t *new_pids =
        malloc((size_t)new_cfg->protect_pid_count * sizeof(uint32_t));
    if (!new_pids) {
      lota_err("Failed to allocate memory for protected PIDs on reload; "
               "restoring previous PID protection set");
      for (int k = 0; k < old_protect_pid_count; k++) {
        if (bpf_loader_protect_pid(&g_agent.bpf_ctx, old_protect_pids[k]) < 0) {
          lota_warn("Failed to restore protected PID %u after reload "
                    "allocation failure",
                    old_protect_pids[k]);
        }
      }
      return;
    }

    int applied_pids = 0;
    bool apply_failed = false;
    for (int k = 0; k < new_cfg->protect_pid_count; k++) {
      uint32_t pid = new_cfg->protect_pids[k];
      if (bpf_loader_protect_pid(&g_agent.bpf_ctx, pid) < 0) {
        lota_warn("Failed to protect PID %u on reload", pid);
        apply_failed = true;
        break;
      }
      new_pids[applied_pids++] = pid;
    }

    if (apply_failed) {
      for (int k = 0; k < applied_pids; k++)
        bpf_loader_unprotect_pid(&g_agent.bpf_ctx, new_pids[k]);
      for (int k = 0; k < old_protect_pid_count; k++) {
        if (bpf_loader_protect_pid(&g_agent.bpf_ctx, old_protect_pids[k]) < 0) {
          lota_warn("Failed to restore protected PID %u after reload apply "
                    "failure",
                    old_protect_pids[k]);
        }
      }
      free(new_pids);
      lota_warn("Keeping previous protected PID set after reload errors");
      return;
    }

    free(old_protect_pids);
    *protect_pids = new_pids;
    *protect_pid_count = applied_pids;
    return;
  }

  free(old_protect_pids);
  *protect_pids = NULL;
  *protect_pid_count = 0;
}

static void reload_trust_libs(const struct lota_config *new_cfg,
                              char trust_libs[LOTA_CONFIG_MAX_LIBS][PATH_MAX],
                              int *trust_lib_count) {
  int old_trust_lib_count = *trust_lib_count;
  char old_trust_libs[LOTA_CONFIG_MAX_LIBS][PATH_MAX];
  bool trust_reload_failed = false;
  int applied_libs = 0;

  for (int k = 0; k < old_trust_lib_count; k++) {
    copy_path(old_trust_libs[k], trust_libs[k]);
  }

  for (int k = 0; k < old_trust_lib_count; k++) {
    int untrust_ret =
        bpf_loader_untrust_lib(&g_agent.bpf_ctx, old_trust_libs[k]);
    if (untrust_ret < 0 && untrust_ret != -ENOENT) {
      lota_warn("Failed to remove trusted lib %s on reload: %s",
                old_trust_libs[k], strerror(-untrust_ret));
      trust_reload_failed = true;
      break;
    }
  }

  for (int k = 0; !trust_reload_failed && k < new_cfg->trust_lib_count; k++) {
    const char *lib = new_cfg->trust_libs[k];
    int trust_ret = bpf_loader_trust_lib(&g_agent.bpf_ctx, lib);
    if (trust_ret < 0) {
      lota_warn("Failed to trust lib %s on reload: %s", lib,
                strerror(-trust_ret));
      trust_reload_failed = true;
      break;
    }
    copy_path(trust_libs[applied_libs], lib);
    applied_libs++;
  }

  if (trust_reload_failed) {
    for (int k = 0; k < applied_libs; k++)
      bpf_loader_untrust_lib(&g_agent.bpf_ctx, trust_libs[k]);

    int restored_libs = 0;
    for (int k = 0; k < old_trust_lib_count; k++) {
      int restore_ret =
          bpf_loader_trust_lib(&g_agent.bpf_ctx, old_trust_libs[k]);
      if (restore_ret < 0) {
        lota_warn("Failed to restore trusted lib %s after reload error: %s",
                  old_trust_libs[k], strerror(-restore_ret));
        continue;
      }
      copy_path(trust_libs[restored_libs], old_trust_libs[k]);
      restored_libs++;
    }
    *trust_lib_count = restored_libs;
    lota_warn("Keeping previous trusted library set after reload errors");
    return;
  }

  *trust_lib_count = applied_libs;
}

static void sync_config_snapshot(
    struct lota_config *cfg, const struct lota_config *new_cfg, int mode,
    bool strict_mmap, bool strict_exec, bool block_ptrace, bool strict_modules,
    bool block_anon_exec, uint32_t *protect_pids, int protect_pid_count,
    char trust_libs[LOTA_CONFIG_MAX_LIBS][PATH_MAX], int trust_lib_count) {
  memcpy(cfg->server, new_cfg->server, sizeof(cfg->server));
  cfg->port = new_cfg->port;
  memcpy(cfg->ca_cert, new_cfg->ca_cert, sizeof(cfg->ca_cert));
  memcpy(cfg->pin_sha256, new_cfg->pin_sha256, sizeof(cfg->pin_sha256));
  memcpy(cfg->bpf_path, new_cfg->bpf_path, sizeof(cfg->bpf_path));
  if (mode == LOTA_MODE_ENFORCE)
    snprintf(cfg->mode, sizeof(cfg->mode), "enforce");
  else if (mode == LOTA_MODE_MAINTENANCE)
    snprintf(cfg->mode, sizeof(cfg->mode), "maintenance");
  else
    snprintf(cfg->mode, sizeof(cfg->mode), "monitor");

  cfg->strict_mmap = strict_mmap;
  cfg->strict_exec = strict_exec;
  cfg->block_ptrace = block_ptrace;
  cfg->strict_modules = strict_modules;
  cfg->block_anon_exec = block_anon_exec;
  cfg->attest_interval = new_cfg->attest_interval;
  cfg->aik_ttl = new_cfg->aik_ttl;
  cfg->aik_handle = new_cfg->aik_handle;
  cfg->daemon = new_cfg->daemon;
  memcpy(cfg->pid_file, new_cfg->pid_file, sizeof(cfg->pid_file));
  memcpy(cfg->signing_key, new_cfg->signing_key, sizeof(cfg->signing_key));
  memcpy(cfg->policy_pubkey, new_cfg->policy_pubkey,
         sizeof(cfg->policy_pubkey));
  cfg->trust_lib_count = trust_lib_count;
  for (int k = 0; k < trust_lib_count; k++) {
    copy_path(cfg->trust_libs[k], trust_libs[k]);
  }

  /* allow_verity is applied only at startup; keep existing snapshot */
  memcpy(cfg->log_level, new_cfg->log_level, sizeof(cfg->log_level));

  free(cfg->protect_pids);
  cfg->protect_pids = NULL;
  cfg->protect_pid_count = 0;
  if (protect_pid_count > 0) {
    cfg->protect_pids = malloc((size_t)protect_pid_count * sizeof(uint32_t));
    if (!cfg->protect_pids) {
      lota_warn("Failed to update config snapshot protected PIDs");
    } else {
      memcpy(cfg->protect_pids, protect_pids,
             (size_t)protect_pid_count * sizeof(uint32_t));
      cfg->protect_pid_count = protect_pid_count;
    }
  }
}

int agent_reload_config(const char *config_path, struct lota_config *cfg,
                        int *mode, bool *strict_mmap, bool *strict_exec,
                        bool *block_ptrace, bool *strict_modules,
                        bool *block_anon_exec, uint32_t **protect_pids,
                        int *protect_pid_count,
                        char trust_libs[LOTA_CONFIG_MAX_LIBS][PATH_MAX],
                        int *trust_lib_count) {
  struct lota_config new_cfg;

  config_init(&new_cfg);
  int reload_ret = config_load(&new_cfg, config_path);
  if (reload_ret == -ENOENT) {
    lota_warn("Config file not found on reload, keeping current state");
    free(new_cfg.protect_pids);
    sdnotify_ready();
    return 0;
  }

  if (reload_ret < 0) {
    lota_err("Failed to reload config: %s", strerror(-reload_ret));
    free(new_cfg.protect_pids);
    sdnotify_ready();
    return reload_ret;
  }

  int new_mode = parse_mode(new_cfg.mode);
  if (new_mode >= 0 && new_mode != *mode) {
    if (bpf_loader_set_mode(&g_agent.bpf_ctx, new_mode) == 0) {
      lota_info("Mode changed: %s -> %s", mode_to_string(*mode),
                mode_to_string(new_mode));
      *mode = new_mode;
    } else {
      lota_warn("Failed to apply new mode");
    }
  }

  apply_runtime_flags_transactional(&new_cfg, strict_mmap, strict_exec,
                                    block_ptrace, strict_modules,
                                    block_anon_exec);

  if (new_cfg.log_level[0] && strcmp(new_cfg.log_level, cfg->log_level) != 0) {
    int lvl = LOG_DEBUG;
    if (strcmp(new_cfg.log_level, "error") == 0)
      lvl = LOG_ERR;
    else if (strcmp(new_cfg.log_level, "warn") == 0)
      lvl = LOG_WARNING;
    else if (strcmp(new_cfg.log_level, "info") == 0)
      lvl = LOG_INFO;
    journal_set_level(lvl);
    lota_info("Log level changed to %s", new_cfg.log_level);
  }

  reload_protected_pids(&new_cfg, protect_pids, protect_pid_count);
  lota_info("Protected PIDs reloaded (%d entries)", *protect_pid_count);

  reload_trust_libs(&new_cfg, trust_libs, trust_lib_count);
  lota_info("Trusted libs reloaded (%d entries)", *trust_lib_count);

  if (new_cfg.allow_verity_count != cfg->allow_verity_count) {
    lota_warn(
        "allow_verity changes require restart; keeping previous allowlist");
  } else {
    for (int i = 0; i < new_cfg.allow_verity_count; i++) {
      if (strcmp(new_cfg.allow_verity[i], cfg->allow_verity[i]) != 0) {
        lota_warn(
            "allow_verity changes require restart; keeping previous allowlist");
        break;
      }
    }
  }

  sync_config_snapshot(cfg, &new_cfg, *mode, *strict_mmap, *strict_exec,
                       *block_ptrace, *strict_modules, *block_anon_exec,
                       *protect_pids, *protect_pid_count, trust_libs,
                       *trust_lib_count);

  free(new_cfg.protect_pids);

  sdnotify_ready();
  sdnotify_status("Monitoring, mode=%s", mode_to_string(*mode));
  lota_info("Configuration reloaded");

  return 0;
}
