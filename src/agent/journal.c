/* SPDX-License-Identifier: MIT */
/*
 * LOTA Agent - Structured Journal Logging
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#include "journal.h"

#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <systemd/sd-journal.h>

static bool g_use_journal;
static int g_min_priority = LOG_DEBUG;
static const char *g_ident = "lota";

static const char *priority_prefix(int priority)
{
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

void journal_init(const char *ident)
{
	if (ident)
		g_ident = ident;

	g_use_journal = (getenv("JOURNAL_STREAM") != NULL ||
			 getenv("INVOCATION_ID") != NULL);
}

void journal_set_level(int priority)
{
	if (priority >= LOG_EMERG && priority <= LOG_DEBUG)
		g_min_priority = priority;
}

void journal_detached_from_terminal(void)
{
	g_use_journal = true;
}

void journal_print(const char *file, int line, const char *func, int priority,
		   const char *fmt, ...)
{
	va_list ap;
	char buf[1024];

	if (priority > g_min_priority)
		return;

	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);

	if (g_use_journal) {
		sd_journal_send("MESSAGE=%s", buf, "PRIORITY=%d", priority,
				"SYSLOG_IDENTIFIER=%s", g_ident, "CODE_FILE=%s",
				file, "CODE_LINE=%d", line, "CODE_FUNC=%s",
				func, NULL);
	} else {
		fprintf(stderr, "%s: %s: %s\n", g_ident,
			priority_prefix(priority), buf);
	}
}
