/* SPDX-License-Identifier: MIT */
/*
 * SIGTERM-mid-attestation shutdown tests.
 *
 * The production signal handler can only clear the running flag while a
 * blocking TPM quote or verifier round is in flight. Cleanup happens after
 * that blocking operation returns, so this test pins the contract that a
 * graceful SIGTERM observed during such a round still reaches the runtime
 * PCR poison path before BPF unload.
 */

#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include "../src/agent/agent.h"
#include "../src/agent/daemon.h"
#include "../src/agent/journal.h"
#include "../src/agent/shutdown.h"

static int tests_run;
static int tests_passed;

#define TEST(name)                                                             \
	do {                                                                   \
		tests_run++;                                                   \
		printf("  [%2d] %-55s ", tests_run, name);                     \
	} while (0)

#define PASS()                                                                 \
	do {                                                                   \
		tests_passed++;                                                \
		printf("PASS\n");                                             \
	} while (0)

#define FAIL(fmt, ...)                                                         \
	do {                                                                   \
		printf("FAIL: " fmt "\n", ##__VA_ARGS__);                    \
	} while (0)

static volatile sig_atomic_t sig_running = 1;
static volatile sig_atomic_t sig_reload;
static volatile int extend_called;
static volatile int notice_seen;
static uint32_t extend_pcr;
static uint8_t extend_digest[LOTA_HASH_SIZE];

int tpm_pcr_extend(struct tpm_context *ctx, uint32_t pcr_index,
		   const uint8_t *digest)
{
	if (!ctx || !ctx->initialized || !digest)
		return -EINVAL;

	extend_called++;
	extend_pcr = pcr_index;
	memcpy(extend_digest, digest, sizeof(extend_digest));
	return 0;
}

void journal_print(const char *file, int line, const char *func, int priority,
		   const char *fmt, ...)
{
	char buf[256];
	va_list ap;

	(void)file;
	(void)line;
	(void)func;

	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);

	if (priority == LOG_NOTICE &&
	    strstr(buf, "Runtime PCR poisoned before BPF unload"))
		notice_seen = 1;
}

static int wait_for_running_clear(void)
{
	struct timespec ts = {
	    .tv_sec = 0,
	    .tv_nsec = 1000 * 1000,
	};

	for (int i = 0; i < 1000; i++) {
		if (!sig_running)
			return 0;
		nanosleep(&ts, NULL);
	}

	return -ETIMEDOUT;
}

struct blocked_round {
	int started[2];
	int release[2];
};

static void *blocked_attestation_round(void *arg)
{
	struct blocked_round *round = arg;
	char byte = 'x';
	ssize_t written;

	written = write(round->started[1], &byte, 1);
	(void)written;
	while (read(round->release[0], &byte, 1) < 0) {
		if (errno != EINTR)
			break;
	}

	return NULL;
}

static void release_blocked_round(struct blocked_round *round)
{
	char byte = 'x';
	ssize_t written;

	if (round->release[1] < 0)
		return;

	written = write(round->release[1], &byte, 1);
	(void)written;
}

static void reset_poison_observation(void)
{
	extend_called = 0;
	notice_seen = 0;
	extend_pcr = 0;
	memset(extend_digest, 0, sizeof(extend_digest));
}

static void test_sigterm_mid_round_reaches_poison_cleanup(void)
{
	struct blocked_round round;
	struct tpm_context tpm;
	struct bpf_loader_ctx bpf;
	pthread_t thread;
	char byte;
	int ret;

	TEST("SIGTERM during blocking attestation still poisons PCR");

	memset(&round, 0, sizeof(round));
	memset(&tpm, 0, sizeof(tpm));
	memset(&bpf, 0, sizeof(bpf));
	reset_poison_observation();
	round.started[0] = -1;
	round.started[1] = -1;
	round.release[0] = -1;
	round.release[1] = -1;

	sig_running = 1;
	sig_reload = 0;
	if (daemon_install_signals(&sig_running, &sig_reload) < 0) {
		FAIL("daemon_install_signals failed");
		return;
	}

	if (pipe(round.started) < 0 || pipe(round.release) < 0) {
		FAIL("pipe failed: %s", strerror(errno));
		goto cleanup_pipes;
	}

	if (pthread_create(&thread, NULL, blocked_attestation_round, &round) !=
	    0) {
		FAIL("pthread_create failed");
		goto cleanup_pipes;
	}

	if (read(round.started[0], &byte, 1) != 1) {
		FAIL("blocked round did not start");
		goto cleanup_thread;
	}

	if (kill(getpid(), SIGTERM) < 0) {
		FAIL("SIGTERM delivery failed: %s", strerror(errno));
		goto cleanup_thread;
	}

	ret = wait_for_running_clear();
	if (ret < 0) {
		FAIL("running flag was not cleared by SIGTERM");
		goto cleanup_thread;
	}

	release_blocked_round(&round);
	(void)pthread_join(thread, NULL);

	tpm.initialized = true;
	bpf.loaded = true;
	ret = agent_poison_runtime_pcr_before_bpf_unload(&tpm, &bpf, 0);
	if (ret != 0) {
		FAIL("poison cleanup returned %d", ret);
		goto cleanup_pipes;
	}
	if (extend_called != 1) {
		FAIL("expected one PCR extend, got %d", extend_called);
		goto cleanup_pipes;
	}
	if (extend_pcr != LOTA_PCR_SELF) {
		FAIL("expected PCR %d, got %u", LOTA_PCR_SELF, extend_pcr);
		goto cleanup_pipes;
	}
	if (!notice_seen) {
		FAIL("success journal notice was not emitted");
		goto cleanup_pipes;
	}

	PASS();
	goto cleanup_pipes;

cleanup_thread:
	release_blocked_round(&round);
	(void)pthread_join(thread, NULL);
cleanup_pipes:
	if (round.started[0] >= 0)
		close(round.started[0]);
	if (round.started[1] >= 0)
		close(round.started[1]);
	if (round.release[0] >= 0)
		close(round.release[0]);
	if (round.release[1] >= 0)
		close(round.release[1]);
}

static void test_poison_cleanup_is_gated_on_loaded_bpf(void)
{
	struct tpm_context tpm;
	struct bpf_loader_ctx bpf;
	int ret;

	TEST("poison cleanup is skipped before BPF load");

	memset(&tpm, 0, sizeof(tpm));
	memset(&bpf, 0, sizeof(bpf));
	reset_poison_observation();

	tpm.initialized = true;
	bpf.loaded = false;

	ret = agent_poison_runtime_pcr_before_bpf_unload(&tpm, &bpf, -EIO);
	if (ret != -EIO) {
		FAIL("existing error was changed to %d", ret);
		return;
	}
	if (extend_called != 0) {
		FAIL("PCR extend should not run before BPF load");
		return;
	}

	PASS();
}

int main(void)
{
	printf("=== LOTA signal shutdown tests ===\n\n");

	test_sigterm_mid_round_reaches_poison_cleanup();
	test_poison_cleanup_is_gated_on_loaded_bpf();

	printf("\n=== Results: %d/%d passed ===\n", tests_passed, tests_run);
	return (tests_passed == tests_run) ? 0 : 1;
}
