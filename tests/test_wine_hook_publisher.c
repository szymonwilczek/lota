/* SPDX-License-Identifier: MIT */
/*
 * Which publisher the Wine/Proton hook attests for
 *
 * A multi-publisher host refuses a token to a connection that names no
 * publisher. The real library is dlopen()ed (the connection and its
 * environment are in the load-time half) against a mock agent that records
 * the selected identity and refuses a token when there is none.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "lota_gaming.h"
#include "lota_ipc.h"
#include "lota_wine_hook.h"

#ifndef LOTA_HOOK_LIB_PATH
#define LOTA_HOOK_LIB_PATH "build/liblota_wine_hook.so"
#endif

/* Spelled out, not from the header: launch scripts depend on the name */
#define HOOK_ENV_PUBLISHER "LOTA_HOOK_PUBLISHER"

/* Hex SHA-256 of the publisher's CA anchor, as lota_connect_opts() takes */
#define TITLE_PUBLISHER \
	"5f2d18c4a90b7e63d4118fa27c05be9138a6470de2fc81b5a33c96e07d4b2a18"

#define AGENT_ATTEST_COUNT 11u

#define MOCK_ATTEST_SIZE 64
#define MOCK_SIG_SIZE 64

static int tests_run;
static int tests_passed;

#define TEST(name)                                        \
	do {                                              \
		tests_run++;                              \
		printf("  [%d] %-58s ", tests_run, name); \
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

static char tmpdir[64]; /* short: paths built from it must fit */
static char sock_path[104];
static char named_dir[96]; /* <tmpdir>/<name> */
static char unnamed_dir[96];
static char token_path[PATH_MAX];
static char profile_path[PATH_MAX];
static char log_path[PATH_MAX];

/* Mock agent */

static int mock_send(int fd, uint32_t result, const void *payload,
		     uint32_t payload_len)
{
	struct lota_ipc_response resp;

	resp.magic = LOTA_IPC_MAGIC;
	resp.version = LOTA_IPC_VERSION;
	resp.result = result;
	resp.payload_len = payload_len;

	if (send(fd, &resp, sizeof(resp), MSG_NOSIGNAL) != sizeof(resp))
		return -1;

	if (payload_len > 0 && payload) {
		if (send(fd, payload, payload_len, MSG_NOSIGNAL) !=
		    (ssize_t)payload_len)
			return -1;
	}

	return 0;
}

static int mock_recv(int fd, struct lota_ipc_request *req, void *payload,
		     size_t max_payload)
{
	ssize_t n;

	n = recv(fd, req, sizeof(*req), MSG_WAITALL);
	if (n != sizeof(*req))
		return -1;

	if (req->payload_len > 0) {
		size_t want = req->payload_len;

		if (want > max_payload)
			want = max_payload;
		n = recv(fd, payload, want, MSG_WAITALL);
		if (n != (ssize_t)want)
			return -1;
	}

	return 0;
}

static void record_profile(const uint8_t *id, size_t len)
{
	int fd = open(profile_path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC,
		      0600);
	FILE *f = fd < 0 ? NULL : fdopen(fd, "w");

	if (!f)
		_exit(91);
	for (size_t i = 0; i < len; i++)
		fprintf(f, "%02x", id[i]);
	fprintf(f, "\n");
	fclose(f);
}

/* Shape only: the SDK parses it, nothing verifies it */
static int mock_send_token(int fd)
{
	uint8_t payload[sizeof(struct lota_ipc_token) + MOCK_ATTEST_SIZE +
			MOCK_SIG_SIZE];
	struct lota_ipc_token hdr;

	memset(payload, 0xa5, sizeof(payload));
	memset(&hdr, 0, sizeof(hdr));

	hdr.valid_until = (uint64_t)time(NULL) + 600;
	hdr.flags = LOTA_FLAG_ATTESTED;
	hdr.attest_size = MOCK_ATTEST_SIZE;
	hdr.sig_size = MOCK_SIG_SIZE;
	hdr.sig_alg = 0x0014; /* TPM2_ALG_RSASSA */
	hdr.hash_alg = 0x000b; /* TPM2_ALG_SHA256 */
	hdr.pcr_mask = 1u << 14;
	hdr.protect_pid_count = 0;
	hdr.pid_list_size = 0;
	hdr.runtime_protect_version = LOTA_IPC_RUNTIME_PROTECT_V1;

	memcpy(payload, &hdr, sizeof(hdr));

	return mock_send(fd, LOTA_IPC_OK, payload, (uint32_t)sizeof(payload));
}

/* Status is per host; a token needs a publisher, so none means refusal */
static void mock_serve(int client_fd)
{
	struct lota_ipc_request req;
	uint8_t payload[256];
	int have_profile = 0;

	while (mock_recv(client_fd, &req, payload, sizeof(payload)) == 0) {
		if (req.cmd == LOTA_IPC_CMD_SET_PROFILE) {
			struct lota_ipc_set_profile sel;

			memset(&sel, 0, sizeof(sel));
			if (req.payload_len >= sizeof(sel))
				memcpy(&sel, payload, sizeof(sel));

			record_profile(sel.profile_id, sizeof(sel.profile_id));
			have_profile = 1;

			if (mock_send(client_fd, LOTA_IPC_OK, NULL, 0) < 0)
				return;
			continue;
		}

		if (req.cmd == LOTA_IPC_CMD_GET_STATUS) {
			struct lota_ipc_status status;

			memset(&status, 0, sizeof(status));
			status.flags = LOTA_FLAG_ATTESTED;
			status.attest_count = AGENT_ATTEST_COUNT;
			status.last_attest_time = (uint64_t)time(NULL);
			status.valid_until = (uint64_t)time(NULL) + 600;
			if (mock_send(client_fd, LOTA_IPC_OK, &status,
				      sizeof(status)) < 0)
				return;
			continue;
		}

		if (req.cmd == LOTA_IPC_CMD_GET_TOKEN) {
			int ret;

			if (!have_profile)
				ret = mock_send(client_fd,
						LOTA_IPC_ERR_UNKNOWN_PROFILE,
						NULL, 0);
			else
				ret = mock_send_token(client_fd);

			if (ret < 0)
				return;
			continue;
		}

		if (mock_send(client_fd, LOTA_IPC_OK, NULL, 0) < 0)
			return;
	}
}

static pid_t start_mock_agent(void)
{
	struct sockaddr_un addr;
	int listen_fd;
	pid_t pid;

	listen_fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (listen_fd < 0)
		return -1;

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, sock_path, sizeof(addr.sun_path) - 1);

	if (bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		close(listen_fd);
		return -1;
	}

	if (listen(listen_fd, 4) < 0) {
		close(listen_fd);
		unlink(sock_path);
		return -1;
	}

	pid = fork();
	if (pid < 0) {
		close(listen_fd);
		unlink(sock_path);
		return -1;
	}

	if (pid == 0) {
		for (;;) {
			int client_fd = accept(listen_fd, NULL, NULL);

			if (client_fd < 0)
				_exit(99);
			mock_serve(client_fd);
			close(client_fd);
		}
	}

	close(listen_fd);
	usleep(30000); /* let the child reach accept() */
	return pid;
}

/* Hook loading */

static void *hook_lib;

/*
 * Activation matches the executable path, so the test binary names itself
 * rather than depend on where the build tree sits.
 */
static int load_hook(const char *token_dir, const char *publisher,
		     const char *log_level)
{
	char exe[PATH_MAX];
	ssize_t n;

	n = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
	if (n < 0)
		return -1;
	exe[n] = '\0';

	setenv("LOTA_HOOK_ACTIVATE_PATH", exe, 1);
	setenv(LOTA_HOOK_ENV_SOCKET, sock_path, 1);
	setenv(LOTA_HOOK_ENV_TOKEN_DIR, token_dir, 1);
	setenv(LOTA_HOOK_ENV_LOG_LEVEL, log_level, 1);
	setenv(LOTA_HOOK_ENV_REFRESH_SEC, "1", 1);
	setenv(LOTA_HOOK_ENV_PROTECT_DELAY, "0", 1);

	if (publisher)
		setenv(HOOK_ENV_PUBLISHER, publisher, 1);
	else
		unsetenv(HOOK_ENV_PUBLISHER);

	hook_lib = dlopen(LOTA_HOOK_LIB_PATH, RTLD_NOW);
	if (!hook_lib) {
		printf("  dlopen(%s): %s\n", LOTA_HOOK_LIB_PATH, dlerror());
		return -1;
	}

	return 0;
}

/* The hook starts once per process, so this run is a child; log to a file */
static int run_unnamed_publisher(void)
{
	pid_t pid;
	int status;

	/* nothing of this process's own output belongs in the child's copy */
	fflush(NULL);

	pid = fork();
	if (pid < 0)
		return -1;

	if (pid == 0) {
		int fd = open(log_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);

		if (fd < 0)
			_exit(92);
		dup2(fd, STDERR_FILENO);
		close(fd);

		if (load_hook(unnamed_dir, NULL, "info") != 0)
			_exit(93);

		/* long enough for the status answer and the refusal */
		sleep(3);
		fflush(NULL);
		_exit(0);
	}

	if (waitpid(pid, &status, 0) < 0)
		return -1;

	return 0;
}

/* Hook output */

static int wait_for_file(const char *path, int timeout_sec)
{
	for (int i = 0; i < timeout_sec * 10; i++) {
		struct stat st;

		if (stat(path, &st) == 0)
			return 0;
		usleep(100000);
	}

	return -1;
}

/* Recorded identity as lowercase hex, or "" */
static void read_profile(char *out, size_t out_sz)
{
	FILE *f;

	out[0] = '\0';

	f = fopen(profile_path, "r");
	if (!f)
		return;

	if (fgets(out, (int)out_sz, f))
		out[strcspn(out, "\n")] = '\0';

	fclose(f);
}

static int log_mentions(const char *needle)
{
	char line[512];
	int found = 0;
	FILE *f;

	f = fopen(log_path, "r");
	if (!f)
		return 0;

	while (fgets(line, sizeof(line), f)) {
		if (strstr(line, needle)) {
			found = 1;
			break;
		}
	}

	fclose(f);
	return found;
}

/* Tests */

/* The hook is a Wine title's only path to name its publisher */
static void test_the_hook_names_the_title_s_publisher(void)
{
	char selected[128];

	TEST("the hook names the publisher its title was launched for");

	read_profile(selected, sizeof(selected));
	if (!selected[0]) {
		FAIL("the connection selected no publisher");
		return;
	}

	if (strcmp(selected, TITLE_PUBLISHER) != 0) {
		printf("FAIL: connection selected %s\n", selected);
		return;
	}

	PASS();
}

static void test_a_named_publisher_gets_a_token(void)
{
	struct stat st;

	TEST("a named publisher gets this title a token");

	if (stat(token_path, &st) != 0) {
		FAIL("no token file was written");
		return;
	}

	if (st.st_size <= 0) {
		FAIL("the token file is empty");
		return;
	}

	PASS();
}

/* An unnamed launch runs and publishes status; only the token is missing */
static void test_the_refusal_reaches_the_player_s_log(void)
{
	TEST("the token refusal is in the log a player is sent to");

	if (!log_mentions("no token")) {
		FAIL("the refusal is not in the log");
		return;
	}

	PASS();
}

int main(void)
{
	char template[] = "/tmp/lota-hook-pub-XXXXXX";
	pid_t agent;
	int failures;

	printf("\n=== Wine hook publisher identity ===\n\n");

	if (!mkdtemp(template)) {
		perror("mkdtemp");
		return 1;
	}
	snprintf(tmpdir, sizeof(tmpdir), "%s", template);
	snprintf(sock_path, sizeof(sock_path), "%s/agent.sock", tmpdir);
	snprintf(named_dir, sizeof(named_dir), "%s/named", tmpdir);
	snprintf(unnamed_dir, sizeof(unnamed_dir), "%s/unnamed", tmpdir);
	snprintf(profile_path, sizeof(profile_path), "%s/selected.profile",
		 tmpdir);
	snprintf(log_path, sizeof(log_path), "%s/unnamed.log", tmpdir);
	snprintf(token_path, sizeof(token_path), "%s/%s", named_dir,
		 LOTA_HOOK_TOKEN_FILE);

	if (mkdir(named_dir, 0700) != 0 || mkdir(unnamed_dir, 0700) != 0) {
		perror("mkdir");
		return 1;
	}

	agent = start_mock_agent();
	if (agent < 0) {
		printf("  cannot start the mock agent: %s\n", strerror(errno));
		return 2;
	}

	if (run_unnamed_publisher() != 0) {
		printf("  cannot drive the unnamed-publisher launch: %s\n",
		       strerror(errno));
		kill(agent, SIGKILL);
		waitpid(agent, NULL, 0);
		return 2;
	}

	if (load_hook(named_dir, TITLE_PUBLISHER, "silent") != 0) {
		kill(agent, SIGKILL);
		waitpid(agent, NULL, 0);
		return 2;
	}

	if (wait_for_file(token_path, 10) < 0)
		printf("  the hook wrote no token\n");

	test_the_hook_names_the_title_s_publisher();
	test_a_named_publisher_gets_a_token();
	test_the_refusal_reaches_the_player_s_log();

	kill(agent, SIGKILL);
	waitpid(agent, NULL, 0);
	unlink(sock_path);

	printf("\n%d/%d passed\n\n", tests_passed, tests_run);
	failures = tests_run - tests_passed;

	/* the hook's destructor would join its thread on a dead agent */
	fflush(stdout);
	_exit(failures ? 1 : 0);
}
