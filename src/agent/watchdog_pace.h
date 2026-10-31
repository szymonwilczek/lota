/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * When a loop owes systemd a watchdog ping: time since the last ping against
 * the deadline, asked wherever the loop is. A ping only where a sleep ends
 * misses every early wake, and a healthy loop is killed. No clock here.
 */

#ifndef LOTA_WATCHDOG_PACE_H
#define LOTA_WATCHDOG_PACE_H

#include <stdbool.h>
#include <stdint.h>

struct watchdog_pace {
	uint64_t deadline_ms; /* systemd kills past it; 0 when not watched */
	uint64_t last_ping_ms;
};

static inline void watchdog_pace_init(struct watchdog_pace *pace,
				      uint64_t deadline_ms, uint64_t now_ms)
{
	if (!pace)
		return;
	pace->deadline_ms = deadline_ms;
	pace->last_ping_ms = now_ms;
}

static inline bool watchdog_pace_armed(const struct watchdog_pace *pace)
{
	return pace && pace->deadline_ms > 0;
}

static inline void watchdog_pace_mark(struct watchdog_pace *pace,
				      uint64_t now_ms)
{
	if (!pace)
		return;
	pace->last_ping_ms = now_ms;
}

/* Owed at half the deadline, so one slow round still fits the rest */
static inline bool watchdog_pace_due(const struct watchdog_pace *pace,
				     uint64_t now_ms)
{
	if (!watchdog_pace_armed(pace))
		return false;

	/* clock went backwards: the deadline still runs, so ping */
	if (now_ms < pace->last_ping_ms)
		return true;

	return now_ms - pace->last_ping_ms >= pace->deadline_ms / 2;
}

/* wanted_ms, cut short to when the next ping is owed */
static inline uint64_t watchdog_pace_sleep_ms(const struct watchdog_pace *pace,
					      uint64_t now_ms,
					      uint64_t wanted_ms)
{
	uint64_t target;
	uint64_t left;

	if (!watchdog_pace_armed(pace))
		return wanted_ms;
	if (watchdog_pace_due(pace, now_ms))
		return 0;

	target = pace->last_ping_ms + pace->deadline_ms / 2;
	left = target - now_ms;

	return left < wanted_ms ? left : wanted_ms;
}

#endif /* LOTA_WATCHDOG_PACE_H */
