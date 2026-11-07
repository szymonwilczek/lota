/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * When a loop owes systemd a watchdog ping. The loop asks at each point it
 * passes, with its own clock.
 */

#ifndef LOTA_WATCHDOG_PACE_H
#define LOTA_WATCHDOG_PACE_H

#include <stdbool.h>
#include <stdint.h>

/**
 * struct watchdog_pace - ping schedule of one loop
 * @deadline_ms: WATCHDOG_USEC in ms; 0 when systemd does not watch.
 * @last_ping_ms: time of the last ping, or of watchdog_pace_init().
 */
struct watchdog_pace {
	uint64_t deadline_ms;
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

/**
 * watchdog_pace_due() - Whether a ping is owed.
 * @pace: the schedule.
 * @now_ms: the caller's clock, in ms.
 *
 * Owed at half the deadline, so one slow round still fits the rest.
 *
 * Return: false without a deadline; true from half the deadline since
 * the last ping, or when @now_ms is before it.
 */
static inline bool watchdog_pace_due(const struct watchdog_pace *pace,
				     uint64_t now_ms)
{
	if (!watchdog_pace_armed(pace))
		return false;

	if (now_ms < pace->last_ping_ms)
		return true;

	return now_ms - pace->last_ping_ms >= pace->deadline_ms / 2;
}

/**
 * watchdog_pace_sleep_ms() - Cut a sleep short to the next owed ping.
 * @pace: the schedule.
 * @now_ms: the caller's clock, in ms.
 * @wanted_ms: the sleep the loop asks for.
 *
 * Return: @wanted_ms without a deadline, 0 when a ping is owed,
 * else the shorter of @wanted_ms and the time until one is.
 */
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
