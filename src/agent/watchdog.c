/* SPDX-License-Identifier: MIT */
/*
 * LOTA Agent - watchdog supervisor
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#include "watchdog.h"

#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "journal.h"
#include "sdnotify.h"

#define NSEC_PER_USEC 1000ULL
#define NSEC_PER_SEC 1000000000ULL

/* relaxed: only its age is read, and a stale read costs one wake-up */
static atomic_uint_least64_t g_last_beat_ns;
static uint64_t g_deadline_ns;
static pthread_t g_thread;
static bool g_thread_running;
static pthread_mutex_t g_stop_lock;
static pthread_cond_t g_stop_cond;
static bool g_stop_requested;

static uint64_t monotonic_ns(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts) < 0)
		return 0;

	return (uint64_t)ts.tv_sec * NSEC_PER_SEC + (uint64_t)ts.tv_nsec;
}

enum watchdog_verdict watchdog_verdict_for(uint64_t now_ns,
					   uint64_t last_beat_ns,
					   uint64_t deadline_ns)
{
	uint64_t age;

	if (deadline_ns == 0)
		return WATCHDOG_PING;

	if (now_ns <= last_beat_ns)
		return WATCHDOG_PING;

	age = now_ns - last_beat_ns;

	if (age >= deadline_ns)
		return WATCHDOG_TERMINATE;

	if (age >= deadline_ns / 2)
		return WATCHDOG_HOLD;

	return WATCHDOG_PING;
}

void watchdog_beat(void)
{
	atomic_store_explicit(&g_last_beat_ns, monotonic_ns(),
			      memory_order_relaxed);
}

/*
 * SIGKILL to self: task_kill delivers it within one thread group, and unlike
 * the shutdown path it does not spend PCR 14, so the restart keeps the boot
 * commitment.
 */
static void end_wedged_process(uint64_t age_ns)
{
	lota_err("Watchdog: the main loop has not advanced in %llu ms, past "
		 "the %llu ms interval. Ending the process from inside: the "
		 "signal systemd sends is refused by this agent's own kill "
		 "guard.",
		 (unsigned long long)(age_ns / 1000000ULL),
		 (unsigned long long)(g_deadline_ns / 1000000ULL));

	kill(getpid(), SIGKILL);
}

static void *watchdog_thread(void *arg)
{
	uint64_t poll_ns = g_deadline_ns / 4;
	bool held = false;

	(void)arg;

	if (poll_ns == 0)
		poll_ns = 1;

	for (;;) {
		struct timespec deadline;
		uint64_t now;
		uint64_t beat;
		enum watchdog_verdict verdict;

		if (clock_gettime(CLOCK_MONOTONIC, &deadline) == 0) {
			deadline.tv_nsec += (long)(poll_ns % NSEC_PER_SEC);
			deadline.tv_sec += (time_t)(poll_ns / NSEC_PER_SEC);
			if (deadline.tv_nsec >= (long)NSEC_PER_SEC) {
				deadline.tv_nsec -= (long)NSEC_PER_SEC;
				deadline.tv_sec += 1;
			}
		}

		pthread_mutex_lock(&g_stop_lock);
		while (!g_stop_requested) {
			if (pthread_cond_timedwait(&g_stop_cond, &g_stop_lock,
						   &deadline) == ETIMEDOUT)
				break;
		}
		if (g_stop_requested) {
			pthread_mutex_unlock(&g_stop_lock);
			break;
		}
		pthread_mutex_unlock(&g_stop_lock);

		now = monotonic_ns();
		beat = atomic_load_explicit(&g_last_beat_ns,
					    memory_order_relaxed);
		verdict = watchdog_verdict_for(now, beat, g_deadline_ns);

		switch (verdict) {
		case WATCHDOG_PING:
			if (held) {
				lota_info("Watchdog: the main loop advanced "
					  "again, pings resumed");
				held = false;
			}
			sdnotify_watchdog_ping();
			break;
		case WATCHDOG_HOLD:
			if (!held) {
				lota_warn("Watchdog: the main loop has not "
					  "advanced in %llu ms, holding the "
					  "ping",
					  (unsigned long long)((now - beat) /
							       1000000ULL));
				held = true;
			}
			break;
		case WATCHDOG_TERMINATE:
			end_wedged_process(now - beat);
			break;
		}
	}

	return NULL;
}

int watchdog_start(uint64_t wd_usec)
{
	pthread_condattr_t attr;
	int ret;

	if (wd_usec == 0)
		return 0;

	if (g_thread_running)
		return -EALREADY;

	g_deadline_ns = wd_usec * NSEC_PER_USEC;
	g_stop_requested = false;
	watchdog_beat();

	/* CLOCK_MONOTONIC: a stepped wall clock must not move the deadline */
	ret = pthread_condattr_init(&attr);
	if (ret != 0)
		return -ret;
	ret = pthread_condattr_setclock(&attr, CLOCK_MONOTONIC);
	if (ret == 0)
		ret = pthread_cond_init(&g_stop_cond, &attr);
	pthread_condattr_destroy(&attr);
	if (ret != 0)
		return -ret;

	ret = pthread_mutex_init(&g_stop_lock, NULL);
	if (ret != 0) {
		pthread_cond_destroy(&g_stop_cond);
		return -ret;
	}

	ret = pthread_create(&g_thread, NULL, watchdog_thread, NULL);
	if (ret != 0) {
		pthread_mutex_destroy(&g_stop_lock);
		pthread_cond_destroy(&g_stop_cond);
		return -ret;
	}

	g_thread_running = true;
	return 0;
}

void watchdog_stop(void)
{
	if (!g_thread_running)
		return;

	pthread_mutex_lock(&g_stop_lock);
	g_stop_requested = true;
	pthread_cond_signal(&g_stop_cond);
	pthread_mutex_unlock(&g_stop_lock);

	pthread_join(g_thread, NULL);
	pthread_mutex_destroy(&g_stop_lock);
	pthread_cond_destroy(&g_stop_cond);
	g_thread_running = false;
}
