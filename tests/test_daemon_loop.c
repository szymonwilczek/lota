/* SPDX-License-Identifier: MIT */
/*
 * Unit tests for daemon event-loop helpers.
 *
 * Pins the contract of agent_ringbuf_drop_delta(): the function is
 * the source of truth for what counts as an alertable BPF ringbuf
 * drop. A daemon that does not call it from the loop, or that calls
 * it with a stale baseline, would either over-alert on every loop
 * iteration or miss the forensic gap entirely. The flood-style
 * scenario at the bottom of this file feeds a synthetic drop counter
 * across two windows and verifies the alerting delta matches the
 * number of newly dropped events exactly.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdint.h>

#include "../src/agent/attest_targets.h"
#include "../src/agent/bench_bpf.h"
#include "../src/agent/bench_protected.h"
#include "../src/agent/bench_snapshot.h"
#include "../src/agent/bpf_loader.h"
#include "../src/agent/container_watch.h"
#include "../src/agent/daemon_loop.h"
#include "../src/agent/dbus.h"
#include "../src/agent/ipc.h"
#include "../src/agent/journal.h"
#include "../src/agent/reload.h"
#include "../src/agent/sdnotify.h"
#include "../src/agent/watchdog.h"

/* What the loop calls besides epoll_wait(), none of it reached here */
int agent_reload_config(const char *config_path, struct lota_config *cfg,
			int *mode, bool *strict_mmap, bool *strict_exec,
			bool *block_ptrace, bool *strict_modules,
			bool *block_anon_exec, uint32_t **protect_pids,
			int *protect_pid_count,
			char trust_libs[LOTA_CONFIG_MAX_LIBS][PATH_MAX],
			int *trust_lib_count)
{
	(void)config_path;
	(void)cfg;
	(void)mode;
	(void)strict_mmap;
	(void)strict_exec;
	(void)block_ptrace;
	(void)strict_modules;
	(void)block_anon_exec;
	(void)protect_pids;
	(void)protect_pid_count;
	(void)trust_libs;
	(void)trust_lib_count;
	return 0;
}

int attest_targets_rebuild(const struct lota_config *cfg, const char *server,
			   int port, const char *ca_cert, int interval_sec,
			   struct attest_target *targets, size_t max,
			   size_t *count)
{
	(void)cfg;
	(void)server;
	(void)port;
	(void)ca_cert;
	(void)interval_sec;
	(void)targets;
	(void)max;
	(void)count;
	return 0;
}

int bench_bpf_protected(const struct bpf_loader_ctx *ctx, struct bench_pid *out,
			size_t max)
{
	(void)ctx;
	(void)out;
	(void)max;
	return 0;
}

bool bench_bpf_sample(const struct bpf_loader_ctx *ctx, bool run_stats,
		      struct bench_bpf *out)
{
	(void)ctx;
	(void)run_stats;
	(void)out;
	return false;
}

bool bench_due(struct bench_state *st, uint64_t now_ns)
{
	(void)st;
	(void)now_ns;
	return false;
}

void bench_protected_sample(struct bench_protected *bp,
			    const struct bench_pid *pids, size_t n, bool rollup,
			    struct bench_protected_sum *sum)
{
	(void)bp;
	(void)pids;
	(void)n;
	(void)rollup;
	(void)sum;
}

int bench_timeout_ms(const struct bench_state *st, uint64_t now_ns)
{
	(void)st;
	(void)now_ns;
	return -1;
}

int bench_write(struct bench_state *st, uint64_t now_ns,
		const struct bench_bpf *bpf,
		const struct bench_protected_sum *prot)
{
	(void)st;
	(void)now_ns;
	(void)bpf;
	(void)prot;
	return 0;
}

int bpf_loader_consume(struct bpf_loader_ctx *ctx)
{
	(void)ctx;
	return 0;
}

int bpf_loader_get_event_fd(struct bpf_loader_ctx *ctx)
{
	(void)ctx;
	return -1;
}

int bpf_loader_get_extended_stats(struct bpf_loader_ctx *ctx,
				  struct bpf_extended_stats *stats)
{
	(void)ctx;
	(void)stats;
	return -ENOENT;
}

int container_watch_fd(const struct container_watch *w)
{
	(void)w;
	return -1;
}

int container_watch_mount_fd(const struct container_watch *w)
{
	(void)w;
	return -1;
}

int container_watch_process(struct container_watch *w)
{
	(void)w;
	return 0;
}

int dbus_get_fd(struct dbus_context *ctx)
{
	(void)ctx;
	return -1;
}

int dbus_process(struct dbus_context *ctx, uint64_t timeout_us)
{
	(void)ctx;
	(void)timeout_us;
	return 0;
}

int ipc_get_fd(struct ipc_context *ctx)
{
	(void)ctx;
	return -1;
}

int ipc_process(struct ipc_context *ctx, int timeout_ms)
{
	(void)ctx;
	(void)timeout_ms;
	return 0;
}

int ipc_recheck_socket(struct ipc_context *ctx)
{
	(void)ctx;
	return 0;
}

void ipc_set_events_lost(struct ipc_context *ctx)
{
	(void)ctx;
}

void ipc_set_mode(struct ipc_context *ctx, uint8_t mode)
{
	(void)ctx;
	(void)mode;
}

void ipc_set_policy(struct ipc_context *ctx, uint32_t keys)
{
	(void)ctx;
	(void)keys;
}

void ipc_set_profiles(struct ipc_context *ctx, struct attest_target *profiles,
		      size_t count)
{
	(void)ctx;
	(void)profiles;
	(void)count;
}

int ipc_socket_watch_fd(const struct ipc_context *ctx)
{
	(void)ctx;
	return -1;
}

int sdnotify_reloading(void)
{
	return 0;
}

void watchdog_beat(void)
{
}

void journal_print(const char *file, int line, const char *func, int priority,
		   const char *fmt, ...)
{
	(void)file;
	(void)line;
	(void)func;
	(void)priority;
	(void)fmt;
}

static int tests_run;
static int tests_passed;

#define TEST(name)                                         \
	do {                                               \
		tests_run++;                               \
		printf("  [%2d] %-55s ", tests_run, name); \
	} while (0)

#define PASS()                    \
	do {                      \
		tests_passed++;   \
		printf("PASS\n"); \
	} while (0)

#define FAIL(fmt, ...)                                    \
	do {                                              \
		printf("FAIL: " fmt "\n", ##__VA_ARGS__); \
	} while (0)

static void test_drop_delta_first_observation_reports_total(void)
{
	TEST("drop_delta: first observation reports full counter");
	uint64_t last = 0;
	uint64_t delta = agent_ringbuf_drop_delta(7, &last);
	if (delta != 7) {
		FAIL("expected delta=7 on first non-zero current, got %lu",
		     (unsigned long)delta);
		return;
	}
	if (last != 7) {
		FAIL("baseline not updated, last=%lu", (unsigned long)last);
		return;
	}
	PASS();
}

static void test_drop_delta_quiet_when_unchanged(void)
{
	TEST("drop_delta: quiet when counter unchanged");
	uint64_t last = 42;
	uint64_t delta = agent_ringbuf_drop_delta(42, &last);
	if (delta != 0 || last != 42) {
		FAIL("expected delta=0 last=42, got delta=%lu last=%lu",
		     (unsigned long)delta, (unsigned long)last);
		return;
	}
	PASS();
}

static void test_drop_delta_reports_only_increment(void)
{
	TEST("drop_delta: reports only the increment");
	uint64_t last = 10;
	uint64_t delta = agent_ringbuf_drop_delta(13, &last);
	if (delta != 3 || last != 13) {
		FAIL("expected delta=3 last=13, got delta=%lu last=%lu",
		     (unsigned long)delta, (unsigned long)last);
		return;
	}
	PASS();
}

static void test_drop_delta_resets_on_counter_rollback(void)
{
	TEST("drop_delta: counter rollback rebases without alert");
	uint64_t last = 1000;
	uint64_t delta = agent_ringbuf_drop_delta(5, &last);
	if (delta != 0) {
		FAIL("expected delta=0 on rollback, got %lu",
		     (unsigned long)delta);
		return;
	}
	if (last != 5) {
		FAIL("baseline not rebased on rollback, last=%lu",
		     (unsigned long)last);
		return;
	}
	delta = agent_ringbuf_drop_delta(8, &last);
	if (delta != 3 || last != 8) {
		FAIL("post-rollback increment incorrect: delta=%lu last=%lu",
		     (unsigned long)delta, (unsigned long)last);
		return;
	}
	PASS();
}

static void test_drop_delta_null_last_returns_zero(void)
{
	TEST("drop_delta: NULL last pointer is rejected");
	if (agent_ringbuf_drop_delta(100, NULL) != 0) {
		FAIL("expected 0 on NULL last");
		return;
	}
	PASS();
}

/*
 * Synthesises a flood: 10 000 events queued, ring buffer absorbs the
 * first 8 192 and drops the rest. The helper must report 1 808 drops
 * on the first poll, then zero on a steady-state second poll where no
 * additional events were dropped. A regression that resets last_drops
 * incorrectly would re-fire 1 808 on every iteration; a regression
 * that fails to update last_drops would report 1 808 once and then
 * miss future drops.
 */
static void test_drop_delta_flood_scenario(void)
{
	TEST("drop_delta: 10k flood -> first poll 1808, steady second 0");
	uint64_t last = 0;
	uint64_t flood = 1808; /* 10000 emitted, 8192 absorbed */
	uint64_t delta = agent_ringbuf_drop_delta(flood, &last);
	if (delta != 1808) {
		FAIL("flood window 1: expected 1808, got %lu",
		     (unsigned long)delta);
		return;
	}
	delta = agent_ringbuf_drop_delta(flood, &last);
	if (delta != 0) {
		FAIL("flood window 2 (no new drops): expected 0, got %lu",
		     (unsigned long)delta);
		return;
	}
	delta = agent_ringbuf_drop_delta(flood + 250, &last);
	if (delta != 250) {
		FAIL("flood window 3 (250 new drops): expected 250, got %lu",
		     (unsigned long)delta);
		return;
	}
	PASS();
}

/* A daemon whose loop failed must not report a clean stop */
static void test_failed_epoll_wait_is_an_error(void)
{
	volatile sig_atomic_t running = 1;
	struct agent_loop_ctx ctx = {
		.epoll_fd = -1,
		.sfd = -1,
		.running = &running,
	};
	int ret;

	TEST("a failing epoll_wait ends the loop with its errno");
	ret = agent_run_event_loop(&ctx);
	if (ret != -EBADF)
		FAIL("returned %d", ret);
	else
		PASS();
}

int main(void)
{
	printf("=== LOTA daemon_loop unit tests ===\n\n");

	test_drop_delta_first_observation_reports_total();
	test_drop_delta_quiet_when_unchanged();
	test_drop_delta_reports_only_increment();
	test_drop_delta_resets_on_counter_rollback();
	test_drop_delta_null_last_returns_zero();
	test_drop_delta_flood_scenario();
	test_failed_epoll_wait_is_an_error();

	printf("\n=== Results: %d/%d passed ===\n", tests_passed, tests_run);
	return (tests_passed == tests_run) ? 0 : 1;
}
