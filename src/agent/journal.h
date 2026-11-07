/* SPDX-License-Identifier: MIT */
/*
 * LOTA Agent - Structured Journal Logging
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#ifndef LOTA_AGENT_JOURNAL_H
#define LOTA_AGENT_JOURNAL_H

#include <syslog.h>

/**
 * journal_init() - Pick the backend and the identifier.
 * @ident: SYSLOG_IDENTIFIER and the stderr prefix; NULL keeps "lota".
 *
 * The journal when JOURNAL_STREAM or INVOCATION_ID is set, stderr otherwise.
 */
void journal_init(const char *ident);

/**
 * journal_print() - Log one message.
 * @file: CODE_FILE.
 * @line: CODE_LINE.
 * @func: CODE_FUNC.
 * @priority: Syslog priority.
 * @fmt: printf-style format; the message is cut at 1023 bytes.
 *
 * Called through the lota_* macros.
 */
__attribute__((format(printf, 5, 6))) void
journal_print(const char *file, int line, const char *func, int priority,
	      const char *fmt, ...);

/**
 * journal_set_level() - Drop messages less severe than @priority.
 * @priority: LOG_EMERG to LOG_DEBUG; any other value is ignored.
 *
 * LOG_DEBUG until called.
 */
void journal_set_level(int priority);

/**
 * journal_detached_from_terminal() - Log to the journal from here on.
 *
 * For a process that loses the stderr journal_init() chose, as daemonize()
 * points it at /dev/null.
 */
void journal_detached_from_terminal(void);

#define lota_err(fmt, ...) \
	journal_print(__FILE__, __LINE__, __func__, LOG_ERR, fmt, ##__VA_ARGS__)

#define lota_warn(fmt, ...)                                           \
	journal_print(__FILE__, __LINE__, __func__, LOG_WARNING, fmt, \
		      ##__VA_ARGS__)

#define lota_info(fmt, ...)                                        \
	journal_print(__FILE__, __LINE__, __func__, LOG_INFO, fmt, \
		      ##__VA_ARGS__)

#define lota_notice(fmt, ...)                                        \
	journal_print(__FILE__, __LINE__, __func__, LOG_NOTICE, fmt, \
		      ##__VA_ARGS__)

#define lota_dbg(fmt, ...)                                          \
	journal_print(__FILE__, __LINE__, __func__, LOG_DEBUG, fmt, \
		      ##__VA_ARGS__)

#endif /* LOTA_AGENT_JOURNAL_H */
