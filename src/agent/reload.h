/* SPDX-License-Identifier: MIT */
#ifndef LOTA_RELOAD_H
#define LOTA_RELOAD_H

#include <stdbool.h>
#include <stdint.h>

#include "config.h"

int agent_reload_config(const char *config_path, struct lota_config *cfg,
                        int *mode, bool *strict_mmap, bool *block_ptrace,
                        bool *strict_modules, bool *block_anon_exec,
                        uint32_t **protect_pids, int *protect_pid_count,
                        char trust_libs[LOTA_CONFIG_MAX_LIBS][PATH_MAX],
                        int *trust_lib_count);

#endif /* LOTA_RELOAD_H */
