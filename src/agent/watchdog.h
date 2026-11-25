/* SPDX-License-Identifier: MIT */
/*
 * LOTA Agent - watchdog supervisor
 *
 * The task_kill hook refuses systemd's watchdog SIGABRT/SIGKILL but
 * delivers a signal to the agent's own thread group, so a supervisor
 * thread pings while the main loop advances and kills the process once
 * it has not.
 *
 *   watchdog_start()  -> spawn the supervisor
 *   watchdog_beat()   -> the main loop reports that it advanced
 *   watchdog_stop()   -> join the supervisor on shutdown
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#ifndef LOTA_AGENT_WATCHDOG_H
#define LOTA_AGENT_WATCHDOG_H

#include <stdint.h>

/**
 * enum watchdog_verdict - what the supervisor does on one wake-up
 * @WATCHDOG_PING: the loop beat within half the deadline; ping systemd.
 * @WATCHDOG_HOLD: it did not; withhold the ping.
 * @WATCHDOG_TERMINATE: no beat for the whole deadline; end the process.
 */
enum watchdog_verdict {
	WATCHDOG_PING,
	WATCHDOG_HOLD,
	WATCHDOG_TERMINATE,
};

/**
 * watchdog_verdict_for() - Verdict for one wake-up.
 * @now_ns: CLOCK_MONOTONIC now, in ns.
 * @last_beat_ns: CLOCK_MONOTONIC time of the last beat, in ns.
 * @deadline_ns: the watchdog interval, in ns; 0 means no watchdog.
 *
 * Return: WATCHDOG_HOLD from half @deadline_ns since the beat,
 * WATCHDOG_TERMINATE from all of it, else WATCHDOG_PING.
 * A beat at or after @now_ns and a zero @deadline_ns give WATCHDOG_PING.
 */
enum watchdog_verdict watchdog_verdict_for(uint64_t now_ns,
					   uint64_t last_beat_ns,
					   uint64_t deadline_ns);

/**
 * watchdog_start() - Spawn the supervisor thread.
 * @wd_usec: WATCHDOG_USEC from systemd; 0 does nothing.
 *
 * Beats once first, so the deadline counts from the start.
 *
 * Return: 0, -EALREADY when a supervisor runs, or a negative errno.
 */
int watchdog_start(uint64_t wd_usec);

/**
 * watchdog_beat() - Record that the main loop advanced.
 *
 * Safe without a supervisor.
 */
void watchdog_beat(void);

/**
 * watchdog_stop() - Stop and join the supervisor.
 *
 * Safe with none running.
 */
void watchdog_stop(void);

#endif /* LOTA_AGENT_WATCHDOG_H */
