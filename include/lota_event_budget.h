/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * Ring-buffer emission budget: the arithmetic of should_emit_event(), free of
 * maps and atomics so it can be unit-tested in user space.
 *
 * In ENFORCE mode each event type has its own one-second window, so one
 * flooding type cannot spend another's budget. The refusals of a write to a
 * guarded cgroup file or a mapped executable and of an open of /dev/mem,
 * /dev/kmem, /dev/port or another process's memory take the ENFORCE window in
 * any mode; the other events budgeted here take it in ENFORCE only. Blocked
 * events get the larger cap, still finite so self-induced denials cannot fill
 * the ring faster than user space drains it; the stats map counts them
 * regardless, so only per-event detail is dropped.
 *
 * All types share one ring, so past the pressure watermark a type that spent
 * its share of the window yields to quieter ones.
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

/**
 * lota_event_budget_limit() - Emission cap of an event class per window.
 * @enforce: The event takes the ENFORCE window.
 * @blocked: The class is refused operations, else permitted ones.
 *
 * Return: the cap, or 0 (unbounded) when @enforce is zero.
 */
LOTA_EB_INLINE unsigned int lota_event_budget_limit(unsigned int enforce,
						    int blocked)
{
	if (!enforce)
		return 0;
	return blocked ? LOTA_BLOCKED_EVENT_BUDGET_PER_SEC :
			 LOTA_ALLOW_EVENT_BUDGET_PER_SEC;
}

/**
 * lota_event_budget_window_expired() - Test whether to rotate the window.
 * @now_ns:          monotonic time now.
 * @window_start_ns: monotonic time the window opened.
 *
 * Return: non-zero if the window has elapsed or the clock moved backwards.
 */
LOTA_EB_INLINE int
lota_event_budget_window_expired(unsigned long long now_ns,
				 unsigned long long window_start_ns)
{
	return now_ns < window_start_ns ||
	       now_ns - window_start_ns >= LOTA_EVENT_BUDGET_WINDOW_NS;
}

/**
 * lota_event_budget_exhausted() - Test a claimed slot against the cap.
 * @count_before: counter value before this caller's increment.
 * @limit: a non-zero cap from lota_event_budget_limit().
 *
 * Return: non-zero if the slot is over the cap.
 */
LOTA_EB_INLINE int lota_event_budget_exhausted(unsigned int count_before,
					       unsigned int limit)
{
	return count_before >= limit;
}

#define LOTA_EVENT_RING_PRESSURE_PCT 75U /* ring % full where yielding starts */
#define LOTA_EVENT_PRESSURE_SHARE 8U /* events per type per window under it */

/**
 * lota_event_ring_under_pressure() - Test the ring against the watermark.
 * @avail_bytes: bytes not yet consumed.
 * @ring_bytes: ring size, 0 if unknown.
 *
 * Return: non-zero if the ring is past the watermark.
 */
LOTA_EB_INLINE int
lota_event_ring_under_pressure(unsigned long long avail_bytes,
			       unsigned long long ring_bytes)
{
	if (ring_bytes == 0)
		return 0;
	return avail_bytes * 100ULL >=
	       ring_bytes * (unsigned long long)LOTA_EVENT_RING_PRESSURE_PCT;
}

/**
 * lota_event_type_yields() - Test whether a type yields to quieter ones.
 * @type_count_before: events of the type this window.
 * @avail_bytes: bytes not yet consumed.
 * @ring_bytes: ring size, 0 if unknown.
 *
 * Return: non-zero if the type must yield.
 */
LOTA_EB_INLINE int lota_event_type_yields(unsigned int type_count_before,
					  unsigned long long avail_bytes,
					  unsigned long long ring_bytes)
{
	if (!lota_event_ring_under_pressure(avail_bytes, ring_bytes))
		return 0;
	return type_count_before >= LOTA_EVENT_PRESSURE_SHARE;
}

#endif /* LOTA_EVENT_BUDGET_H */
