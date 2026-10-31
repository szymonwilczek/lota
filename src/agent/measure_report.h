/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * Log line for measuring a protected process's live code, and whether it is
 * news. A digest does not change while mapped, so rounds on a timer repeat
 * the same answer; only a changed statement is written.
 * Pure, so tests can pin both.
 */

#ifndef LOTA_AGENT_MEASURE_REPORT_H
#define LOTA_AGENT_MEASURE_REPORT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <lota_ipc.h>

#include "standing_answer.h"

/* swept against the protected set, so never fuller than it */
#define MEASURE_REPORT_MAX_PIDS LOTA_IPC_TOKEN_MAX_PROTECT_PIDS

#define MEASURE_REPORT_STATEMENT_MAX STANDING_ANSWER_STATEMENT_MAX

/* A round's verdict on one protected process; sets the log level */
enum measure_answer {
	MEASURE_ANSWER_MEASURED = 0, /* every mapped object measured */
	MEASURE_ANSWER_PARTIAL, /* some mapped objects unmeasurable */
	MEASURE_ANSWER_ABSENT, /* unmeasurable, not the caller: left out */
	MEASURE_ANSWER_REFUSED, /* unmeasurable caller: round refused */
};

/* Standing answer for one protected PID */
struct measure_report_entry {
	bool used;
	uint32_t pid;
	struct standing_answer answer;
};

struct measure_report_table {
	struct measure_report_entry entries[MEASURE_REPORT_MAX_PIDS];
	uint64_t suppressed; /* repeated rounds not written */
	uint64_t unremembered; /* written, no room to remember */
};

/*
 * measure_report_note - Decide whether a round's answer is worth a line
 * @table: answers already in the log
 * @pid: measured process
 * @answer: enum measure_answer
 * @statement: rendered line; any change to it is news
 * @held: rounds the replaced answer had held
 *
 * Return: true to write @statement.
 */
static inline bool measure_report_note(struct measure_report_table *table,
				       uint32_t pid, int answer,
				       const char *statement, uint64_t *held)
{
	struct measure_report_entry *entry = NULL;
	struct measure_report_entry *free_slot = NULL;
	uint32_t i;
	bool stated_before;
	bool news;

	if (held)
		*held = 0;

	if (!table || !statement)
		return true;

	for (i = 0; i < MEASURE_REPORT_MAX_PIDS; i++) {
		if (!table->entries[i].used) {
			if (!free_slot)
				free_slot = &table->entries[i];
			continue;
		}
		if (table->entries[i].pid == pid) {
			entry = &table->entries[i];
			break;
		}
	}

	if (!entry)
		entry = free_slot;

	/* table full: an unremembered answer cannot be a known repeat */
	if (!entry) {
		table->unremembered++;
		return true;
	}

	entry->used = true;
	entry->pid = pid;

	stated_before = entry->answer.stated;
	news = standing_answer_note(&entry->answer, answer, statement, held);

	/* clean answers never written are not counted as withheld */
	if (!news && stated_before)
		table->suppressed++;

	return news;
}

/*
 * measure_report_retain - Forget PIDs no longer in the protected set
 * @table: answers already in the log
 * @pids: protected set
 * @count: entries in @pids
 *
 * A PID protected again later is news again.
 */
static inline void measure_report_retain(struct measure_report_table *table,
					 const uint32_t *pids, uint32_t count)
{
	uint32_t i, j;

	if (!table)
		return;

	for (i = 0; i < MEASURE_REPORT_MAX_PIDS; i++) {
		bool still_protected = false;

		if (!table->entries[i].used)
			continue;

		for (j = 0; pids && j < count; j++) {
			if (pids[j] == table->entries[i].pid) {
				still_protected = true;
				break;
			}
		}

		if (!still_protected) {
			table->entries[i].used = false;
			standing_answer_forget(&table->entries[i].answer);
		}
	}
}

/*
 * measure_report_line - Format the log line for one measured process
 * @out: caller's buffer
 * @cap: its size
 * @answer: enum measure_answer
 * @pid: measured process
 * @caller_pid: process that asked for the token
 * @measured: objects covered
 * @unmeasurable: objects not covered
 * @reason: why, as the measurement reported it
 *
 * Always NUL-terminated, no trailing newline.
 */
static inline void measure_report_line(char *out, size_t cap, int answer,
				       uint32_t pid, uint32_t caller_pid,
				       uint32_t measured, uint32_t unmeasurable,
				       const char *reason)
{
	if (!out || cap == 0)
		return;

	if (!reason)
		reason = "";

	switch (answer) {
	case MEASURE_ANSWER_REFUSED:
		snprintf(out, cap,
			 "runtime image measurement failed for the requesting "
			 "pid=%u: %s",
			 pid, reason);
		return;
	case MEASURE_ANSWER_ABSENT:
		snprintf(out, cap,
			 "runtime image measurement failed for pid=%u, which "
			 "is not the caller (pid=%u): the token reports "
			 "partial coverage rather than refusing every title "
			 "on this host: %s",
			 pid, caller_pid, reason);
		return;
	case MEASURE_ANSWER_PARTIAL:
		snprintf(out, cap,
			 "runtime image measurement for pid=%u covers %u "
			 "object%s and misses %u: %s",
			 pid, measured, measured == 1 ? "" : "s", unmeasurable,
			 reason);
		return;
	default:
		snprintf(out, cap,
			 "runtime image measurement for pid=%u covers every "
			 "object it has mapped",
			 pid);
		return;
	}
}

/*
 * measure_report_held_clause - Format how long the replaced answer held
 * @out: caller's buffer
 * @cap: its size
 * @held: rounds the replaced answer held
 *
 * Kept out of the compared statement, which would otherwise change every
 * round. Empty when @held is 0.
 */
static inline void measure_report_held_clause(char *out, size_t cap,
					      uint64_t held)
{
	standing_answer_held_clause(out, cap, held);
}

#endif /* LOTA_AGENT_MEASURE_REPORT_H */
