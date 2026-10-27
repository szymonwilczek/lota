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

enum watchdog_verdict {
	/* the loop advanced inside its ping contract */
	WATCHDOG_PING,
	/* it did not: withhold the ping so systemd sees the same stall */
	WATCHDOG_HOLD,
	/* a whole interval with no progress: end the process */
	WATCHDOG_TERMINATE,
};

/*
 * watchdog_verdict_for - verdict for one wake-up (CLOCK_MONOTONIC, ns)
 *
 * HOLD past half @deadline_ns (the loop's epoll timeout), TERMINATE past
 * all of it. A beat after @now_ns (torn read) or a zero @deadline_ns (no
 * watchdog) is PING.
 */
enum watchdog_verdict watchdog_verdict_for(uint64_t now_ns,
					   uint64_t last_beat_ns,
					   uint64_t deadline_ns);

/*
 * watchdog_start - spawn the supervisor for WATCHDOG_USEC @wd_usec (0: no-op)
 *
 * Beats once first, so a slow startup is not a wedge. Returns 0 or -errno.
 */
int watchdog_start(uint64_t wd_usec);

/* record that the main loop advanced; safe with no supervisor */
void watchdog_beat(void);

/* stop and join the supervisor; safe with none running */
void watchdog_stop(void);

#endif /* LOTA_AGENT_WATCHDOG_H */
