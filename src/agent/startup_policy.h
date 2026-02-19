/* SPDX-License-Identifier: MIT */
#ifndef LOTA_STARTUP_POLICY_H
#define LOTA_STARTUP_POLICY_H

#include <limits.h>
#include <stdbool.h>
#include <stdint.h>

struct agent_startup_policy {
    int mode;
    bool strict_mmap;
    bool block_ptrace;
    bool strict_modules;
    bool block_anon_exec;
    uint32_t *protect_pids;
    int protect_pid_count;
    char (*trust_libs)[PATH_MAX];
    int trust_lib_count;
};

int agent_apply_startup_policy(const struct agent_startup_policy *policy);

#endif /* LOTA_STARTUP_POLICY_H */
