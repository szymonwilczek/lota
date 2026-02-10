/* SPDX-License-Identifier: MIT */
/*
 * LOTA Agent - Structured Journal Logging
 *
 * Usage:
 *   journal_init("lota-agent");
 *   lota_err("TPM init failed: %s", strerror(-ret));
 *   lota_info("BPF program loaded from %s", path);
 *   lota_dbg("PCR %d value: %s", idx, hex);
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#ifndef LOTA_AGENT_JOURNAL_H
#define LOTA_AGENT_JOURNAL_H

#include <syslog.h>

/*
 * journal_init - Initialize logging subsystem.
 *
 * @ident: Program identifier (eg: "lota-agent").
 *         Used as prefix in stderr fallback mode.
 *
 * Automatically detects whether the process is running under systemd and
 * selects the backend.
 */
void journal_init(const char *ident);

/*
 * journal_print - Emit a log message at given priority.
 *
 * @file:     Source file name (__FILE__).
 * @line:     Source line number (__LINE__).
 * @func:     Function name (__func__).
 * @priority: Syslog priority (LOG_ERR, LOG_WARNING, LOG_INFO, LOG_DEBUG).
 * @fmt:      printf-style format string.
 *
 * Prefer the lota_err/lota_warn/lota_info/lota_dbg macros.
 */
__attribute__((format(printf, 5, 6))) void
journal_print(const char *file, int line, const char *func, int priority,
              const char *fmt, ...);

/*
 * journal_set_level - Set minimum priority for output.
 *
 * @priority: Minimum syslog priority to emit (LOG_ERR .. LOG_DEBUG).
 *            Messages below this level are silently dropped.
 *            Default: LOG_DEBUG (all messages).
 */
void journal_set_level(int priority);

/*
 * journal_get_level - Return current minimum priority.
 */
int journal_get_level(void);

/*
 * journal_use_journal - Check if journal backend is active.
 *
 * Returns: true if sd_journal_print is being used, false for stderr.
 */
_Bool journal_use_journal(void);

#define lota_err(fmt, ...)                                                     \
  journal_print(__FILE__, __LINE__, __func__, LOG_ERR, fmt, ##__VA_ARGS__)

#define lota_warn(fmt, ...)                                                    \
  journal_print(__FILE__, __LINE__, __func__, LOG_WARNING, fmt, ##__VA_ARGS__)

#define lota_info(fmt, ...)                                                    \
  journal_print(__FILE__, __LINE__, __func__, LOG_INFO, fmt, ##__VA_ARGS__)

#define lota_notice(fmt, ...)                                                  \
  journal_print(__FILE__, __LINE__, __func__, LOG_NOTICE, fmt, ##__VA_ARGS__)

#define lota_dbg(fmt, ...)                                                     \
  journal_print(__FILE__, __LINE__, __func__, LOG_DEBUG, fmt, ##__VA_ARGS__)

#endif /* LOTA_AGENT_JOURNAL_H */
