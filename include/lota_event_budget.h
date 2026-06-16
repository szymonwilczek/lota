/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * Ring-buffer emission budget shared by the BPF LSM and its unit tests.
 *
 * In ENFORCE mode every event class is rate-limited per one-second window so an
 * attacker-driven flood cannot exhaust the ring buffer and starve the other
 * class.
 *
 * Allowed (benign) events get the tighter budget; blocked (security-relevant)
 * events get a larger one but are still bounded, so a flood of self-induced
 * denials cannot blind the agent to other events by filling the ring buffer
 * faster than user space drains it.
 *
 * Block counts themselves are never lost: they are tallied in the stats map
 * independently of ring-buffer emission, so suppressing a blocked event drops
 * only its per-event detail.
 *
 * Decision arithmetic lives here as pure helpers (no BPF maps, no atomics)
 * so it can be unit-tested in user space.
 * BPF program keeps the map lookup and the cross-CPU atomics around these
 * helpers.
 */

#ifndef LOTA_EVENT_BUDGET_H
#define LOTA_EVENT_BUDGET_H

#ifdef __BPF_PROGRAM__
#define LOTA_EB_INLINE static __always_inline
#else
#define LOTA_EB_INLINE static inline
#endif

#define LOTA_EVENT_BUDGET_WINDOW_NS 1000000000ULL
#define LOTA_ALLOW_EVENT_BUDGET_PER_SEC 256U
#define LOTA_BLOCKED_EVENT_BUDGET_PER_SEC 1024U

/*
 * Per-window emission cap for an event class, or 0 when the class is unbounded
 * (outside ENFORCE mode nothing is gated).
 * Blocked events earn the larger cap because they are security-relevant, but
 * the cap is finite so a flood cannot monopolise the ring buffer.
 */
LOTA_EB_INLINE unsigned int lota_event_budget_limit(unsigned int enforce,
						    int blocked)
{
	if (!enforce)
		return 0;
	return blocked ? LOTA_BLOCKED_EVENT_BUDGET_PER_SEC :
			 LOTA_ALLOW_EVENT_BUDGET_PER_SEC;
}

/*
 * Whether the one-second window that began at window_start_ns has elapsed, or
 * the clock moved backwards.
 * In either case the caller rotates the window and resets the counter.
 */
LOTA_EB_INLINE int
lota_event_budget_window_expired(unsigned long long now_ns,
				 unsigned long long window_start_ns)
{
	return now_ns < window_start_ns ||
	       now_ns - window_start_ns >= LOTA_EVENT_BUDGET_WINDOW_NS;
}

/*
 * Whether a slot claimed at count_before (the counter value before this
 * caller's increment) is over the per-window cap.
 */
LOTA_EB_INLINE int lota_event_budget_exhausted(unsigned int count_before,
					       unsigned int limit)
{
	return count_before >= limit;
}

#endif /* LOTA_EVENT_BUDGET_H */
