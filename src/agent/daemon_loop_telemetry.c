/* SPDX-License-Identifier: MIT */
/*
 * LOTA agent - event-loop telemetry helpers
 *
 * Apart from daemon_loop.c, so a test links it without the agent's libraries.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#include <stdint.h>

#include "daemon_loop.h"

uint64_t agent_ringbuf_drop_delta(uint64_t current, uint64_t *last)
{
	if (!last)
		return 0;
	if (current <= *last) {
		*last = current;
		return 0;
	}
	uint64_t delta = current - *last;
	*last = current;
	return delta;
}
