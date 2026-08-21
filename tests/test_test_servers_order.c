/* SPDX-License-Identifier: MIT */
/*
 * What the diagnostic servers touch before they know they can run.
 *
 * --test-signed needs a signing key and a socket. Only one of the two can refuse:
 * the socket is already held on any host where the daemon is running, which is
 * every host an operator would debug on.
 * Provisioning first means a run that cannot start still spends one of the TPM's
 * persistent objects -- the ceiling on how many publishers the host can answer to
 * -- and rewrites the AIK metadata on its way out.
 *
 * These tests drive the real server functions with the layers below them stubbed,
 * so the order they touch things in is the whole of what is asserted.
 * The stubs record it; nothing here needs a TPM or a socket.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "../src/agent/agent.h"
#include "../src/agent/dbus.h"
#include "../src/agent/ipc.h"
#include "../src/agent/sdnotify.h"
#include "../src/agent/test_servers.h"
#include "../src/agent/tpm.h"

struct agent_globals g_agent;

/* What the server did, in the order it did it */
#define TRACE_MAX 32
static const char *trace[TRACE_MAX];
static int trace_len;

static void note(const char *what)
{
	if (trace_len < TRACE_MAX)
		trace[trace_len++] = what;
}

static int step_index(const char *what)
{
	for (int i = 0; i < trace_len; i++)
		if (strcmp(trace[i], what) == 0)
			return i;
	return -1;
}

/* Whether the socket can be claimed on this run */
static int ipc_init_result;

int ipc_init_or_activate(struct ipc_context *ctx)
{
	(void)ctx;
	note("ipc_init");
	return ipc_init_result;
}

void ipc_cleanup(struct ipc_context *ctx)
{
	(void)ctx;
	note("ipc_cleanup");
}

int tpm_init(struct tpm_context *ctx)
{
	(void)ctx;
	note("tpm_init");
	return 0;
}

int tpm_provision_aik(struct tpm_context *ctx)
{
	(void)ctx;
	note("tpm_provision_aik");
	return 0;
}

void tpm_cleanup(struct tpm_context *ctx)
{
	(void)ctx;
	note("tpm_cleanup");
}

int tpm_handle_holds_object(struct tpm_context *ctx, uint32_t handle)
{
	(void)ctx;
	(void)handle;
	return 1; /* a key is already there: the ordinary case */
}

const char *tpm_strerror(int err)
{
	(void)err;
	return "test";
}

void setup_container_listener(struct ipc_context *ctx,
			      const struct lota_config *cfg)
{
	(void)ctx;
	(void)cfg;
	note("container_listener");
}

void setup_dbus(struct ipc_context *ctx)
{
	(void)ctx;
	note("dbus");
}

void ipc_set_tpm(struct ipc_context *ctx, struct tpm_context *tpm,
		 uint32_t pcr_mask)
{
	(void)ctx;
	(void)tpm;
	(void)pcr_mask;
	note("ipc_set_tpm");
}

void ipc_update_status(struct ipc_context *ctx, uint32_t flags,
		       uint64_t valid_until)
{
	(void)ctx;
	(void)flags;
	(void)valid_until;
}

void ipc_set_mode(struct ipc_context *ctx, uint8_t mode)
{
	(void)ctx;
	(void)mode;
}

void ipc_record_attestation(struct ipc_context *ctx, bool success)
{
	(void)ctx;
	(void)success;
}

int ipc_process(struct ipc_context *ctx, int timeout_ms)
{
	(void)ctx;
	(void)timeout_ms;
	return 0;
}

bool ipc_can_issue_tokens(const struct ipc_context *ctx)
{
	(void)ctx;
	return true;
}

const char *ipc_token_capability_str(const struct ipc_context *ctx)
{
	(void)ctx;
	return "test";
}

int dbus_process(struct dbus_context *ctx, uint64_t timeout_us)
{
	(void)ctx;
	(void)timeout_us;
	return 0;
}

void dbus_cleanup(struct dbus_context *ctx)
{
	(void)ctx;
}

int sdnotify_ready(void)
{
	return 0;
}

int sdnotify_stopping(void)
{
	return 0;
}

static int tests_run;
static int tests_passed;

#define TEST(name)                                         \
	do {                                               \
		tests_run++;                               \
		printf("  [%2d] %-58s ", tests_run, name); \
	} while (0)

#define PASS()                    \
	do {                      \
		tests_passed++;   \
		printf("PASS\n"); \
	} while (0)

#define FAIL(msg)                          \
	do {                               \
		printf("FAIL: %s\n", msg); \
	} while (0)

/*
 * The server narrates itself on both streams. Only the order matters here,
 * so the narration is put aside for the duration and the test output stays
 * readable.
 */
static void run_signed(int ipc_result)
{
	int saved_out, saved_err, devnull;

	memset(trace, 0, sizeof(trace));
	trace_len = 0;
	ipc_init_result = ipc_result;
	g_agent.running = 0; /* the serving loop exits at once */

	fflush(stdout);
	fflush(stderr);
	saved_out = dup(STDOUT_FILENO);
	saved_err = dup(STDERR_FILENO);
	devnull = open("/dev/null", O_WRONLY);
	if (devnull >= 0) {
		dup2(devnull, STDOUT_FILENO);
		dup2(devnull, STDERR_FILENO);
		close(devnull);
	}

	run_signed_ipc_test_server(NULL);

	fflush(stdout);
	fflush(stderr);
	if (saved_out >= 0) {
		dup2(saved_out, STDOUT_FILENO);
		close(saved_out);
	}
	if (saved_err >= 0) {
		dup2(saved_err, STDERR_FILENO);
		close(saved_err);
	}
}

/*
 * The socket is the one thing that can refuse, so it is asked first.
 *
 * Everything after it is a side effect on the machine -- a persistent TPM
 * object, the AIK metadata, D-Bus, the container listener -- and a command
 * that is about to exit has no business leaving any of it behind.
 */
static void test_socket_is_claimed_before_the_tpm(void)
{
	TEST("--test-signed claims the socket before it touches the TPM");

	run_signed(0);

	if (step_index("ipc_init") < 0) {
		FAIL("the socket was never claimed");
		return;
	}
	if (step_index("tpm_init") < 0) {
		FAIL("the TPM was never initialised");
		return;
	}
	if (step_index("ipc_init") > step_index("tpm_init")) {
		FAIL("the TPM is initialised before the socket is claimed");
		return;
	}
	if (step_index("ipc_init") > step_index("tpm_provision_aik")) {
		FAIL("a key is provisioned before the socket is claimed");
		return;
	}

	PASS();
}

/* A socket that is already held costs the machine nothing at all */
static void test_refused_socket_provisions_nothing(void)
{
	TEST("a refused socket leaves the TPM untouched");

	run_signed(-EADDRINUSE);

	if (step_index("tpm_provision_aik") >= 0) {
		FAIL("a persistent key was created for a run that cannot start");
		return;
	}
	if (step_index("tpm_init") >= 0) {
		FAIL("the TPM was opened for a run that cannot start");
		return;
	}
	if (step_index("container_listener") >= 0 || step_index("dbus") >= 0) {
		FAIL("the session layers were set up for a run that cannot start");
		return;
	}

	PASS();
}

int main(void)
{
	printf("=== diagnostic server startup order ===\n\n");

	test_socket_is_claimed_before_the_tpm();
	test_refused_socket_provisions_nothing();

	printf("\n=== %d/%d passed ===\n", tests_passed, tests_run);
	return tests_passed == tests_run ? 0 : 1;
}
