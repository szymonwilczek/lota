/* SPDX-License-Identifier: MIT */
/*
 * LOTA Agent - Structured Journal Logging
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#include "journal.h"

#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <systemd/sd-journal.h>

/* module state */
static bool g_use_journal;
static int g_min_priority = LOG_DEBUG; /* emit everything by default */
static const char *g_ident = "lota";

static const char *priority_prefix(int priority) {
  switch (priority) {
  case LOG_EMERG:
    return "EMG";
  case LOG_ALERT:
    return "ALR";
  case LOG_CRIT:
    return "CRT";
  case LOG_ERR:
    return "ERR";
  case LOG_WARNING:
    return "WRN";
  case LOG_NOTICE:
    return "NTC";
  case LOG_INFO:
    return "INF";
  case LOG_DEBUG:
    return "DBG";
  default:
    return "???";
  }
}

void journal_init(const char *ident) {
  if (ident)
    g_ident = ident;

  g_use_journal =
      (getenv("JOURNAL_STREAM") != NULL || getenv("INVOCATION_ID") != NULL);
}

void journal_set_level(int priority) {
  if (priority >= LOG_EMERG && priority <= LOG_DEBUG)
    g_min_priority = priority;
}

int journal_get_level(void) { return g_min_priority; }

_Bool journal_use_journal(void) { return g_use_journal; }

void journal_print(const char *file, int line, const char *func, int priority,
                   const char *fmt, ...) {
  va_list ap;
  char buf[1024];

  /* priority filter: lower number = higher severity */
  if (priority > g_min_priority)
    return;

  va_start(ap, fmt);
  vsnprintf(buf, sizeof(buf), fmt, ap);
  va_end(ap);

  if (g_use_journal) {
    sd_journal_send("MESSAGE=%s", buf, "PRIORITY=%d", priority,
                    "SYSLOG_IDENTIFIER=%s", g_ident, "CODE_FILE=%s", file,
                    "CODE_LINE=%d", line, "CODE_FUNC=%s", func, NULL);
  } else {
    /*
     * Fallback: human-readable format on stderr.
     *
     * Format: "lota-agent[PID] ERR: message\n"
     * Timestamps are omitted because the terminal or
     * syslog-ng/rsyslog will add them if needed.
     */
    fprintf(stderr, "%s: %s: %s\n", g_ident, priority_prefix(priority), buf);
  }
}
