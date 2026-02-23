/* SPDX-License-Identifier: MIT */
#ifndef LOTA_STARTUP_POLICY_H
#define LOTA_STARTUP_POLICY_H

#include <limits.h>
#include <stdbool.h>
#include <stdint.h>

struct agent_startup_policy {
  int mode;
  bool strict_mmap;
  bool strict_exec;
  bool block_ptrace;
  bool strict_modules;
  bool block_anon_exec;
  uint32_t *protect_pids;
  int protect_pid_count;
  char (*trust_libs)[PATH_MAX];
  int trust_lib_count;

  char (*allow_verity)[PATH_MAX];
  int allow_verity_count;
};

int agent_apply_startup_policy(const struct agent_startup_policy *policy);

int agent_compute_policy_digest_for_protect_pids(const uint32_t *protect_pids,
                                                 int protect_pid_count,
                                                 uint8_t out_digest[32]);

#endif /* LOTA_STARTUP_POLICY_H */
