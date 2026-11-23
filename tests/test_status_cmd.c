/* SPDX-License-Identifier: MIT */
/*
 * Unit tests for lota-agent --status.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../include/lota.h"
#include "../include/lota_ipc.h"
#include "../src/agent/status_cmd.h"

static int g_failures;

#define CHECK(cond, msg)                                    \
	do {                                                \
		if (!(cond)) {                              \
			fprintf(stderr, "FAIL: %s\n", msg); \
			g_failures++;                       \
		} else {                                    \
			printf("PASS: %s\n", msg);          \
		}                                           \
	} while (0)

static void test_flags(void)
{
	char buf[256];

	status_flags_string(LOTA_STATUS_TPM_OK | LOTA_STATUS_BPF_LOADED |
				    LOTA_STATUS_BENCH,
			    buf, sizeof(buf));
	CHECK(strcmp(buf, "TPM_OK,BPF_LOADED,BENCH") == 0,
	      "flags print by the names a title sees");

	status_flags_string(LOTA_STATUS_ATTESTED | LOTA_STATUS_TPM_LOCKOUT |
				    LOTA_STATUS_RINGBUF_DROPS,
			    buf, sizeof(buf));
	CHECK(strcmp(buf, "ATTESTED,TPM_LOCKOUT,RINGBUF_DROPS") == 0,
	      "host-only bits are named too");

	status_flags_string(LOTA_STATUS_TPM_OK | (1U << 30), buf, sizeof(buf));
	CHECK(strcmp(buf, "TPM_OK,0x40000000") == 0,
	      "a bit without a name is not dropped");

	status_flags_string(0, buf, sizeof(buf));
	CHECK(strcmp(buf, "none") == 0, "no bits reads as none");

	status_flags_string(LOTA_STATUS_TPM_OK | LOTA_STATUS_BENCH, buf, 8);
	CHECK(strlen(buf) == 7, "a short buffer is cut, not overrun");
}

static void test_format(void)
{
	struct lota_ipc_status s;
	char buf[1024];

	memset(&s, 0, sizeof(s));
	s.flags = LOTA_STATUS_TPM_OK | LOTA_STATUS_BENCH;
	s.mode = LOTA_MODE_ENFORCE;
	s.last_attest_time = 1700000000;
	s.attest_count = 5;
	s.fail_count = 1;
	status_format(&s, buf, sizeof(buf));
	CHECK(strcmp(buf, "Mode:         enforce\n"
			  "Flags:        TPM_OK,BENCH\n"
			  "Attested:     2023-11-14 22:13:20 UTC\n"
			  "Token until:  none\n"
			  "Attestations: 5 succeeded, 1 failed\n") == 0,
	      "the report has one line per field");

	s.mode = 9;
	status_format(&s, buf, sizeof(buf));
	CHECK(strstr(buf, "Mode:         unknown (9)\n") != NULL,
	      "a mode this build does not know is shown as a number");

	s.last_attest_time = 0;
	status_format(&s, buf, sizeof(buf));
	CHECK(strstr(buf, "Attested:     never\n") != NULL,
	      "a host never attested says so");
}

/* One connection answered with @resp and @body, then the child exits */
static pid_t serve_once(const char *path, const struct lota_ipc_response *resp,
			const void *body, size_t body_len)
{
	struct sockaddr_un addr;
	int lfd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	pid_t pid;

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", path);
	if (lfd < 0 || bind(lfd, (struct sockaddr *)&addr, sizeof(addr)) < 0 ||
	    listen(lfd, 1) < 0)
		return -1;

	pid = fork();
	if (pid == 0) {
		struct lota_ipc_request req;
		int cfd = accept(lfd, NULL, NULL);
		int ok;

		ok = cfd >= 0 &&
		     read(cfd, &req, sizeof(req)) == (ssize_t)sizeof(req) &&
		     req.cmd == LOTA_IPC_CMD_GET_STATUS;
		if (ok)
			ok = write(cfd, resp, sizeof(*resp)) ==
				     (ssize_t)sizeof(*resp) &&
			     write(cfd, body, body_len) == (ssize_t)body_len;
		_exit(ok ? 0 : 1);
	}
	close(lfd);
	return pid;
}

static int reap(pid_t pid)
{
	int st;

	return waitpid(pid, &st, 0) == pid && WIFEXITED(st) ? WEXITSTATUS(st) :
							      -1;
}

static void test_request(void)
{
	char dir[] = "/tmp/lota-status-XXXXXX";
	char path[64];
	struct lota_ipc_response resp = {
		.magic = LOTA_IPC_MAGIC,
		.version = LOTA_IPC_VERSION,
		.result = LOTA_IPC_OK,
		.payload_len = sizeof(struct lota_ipc_status),
	};
	struct lota_ipc_status sent, got;
	pid_t pid;

	if (!mkdtemp(dir)) {
		CHECK(0, "mkdtemp");
		return;
	}
	snprintf(path, sizeof(path), "%s/sock", dir);

	CHECK(status_request(path, &got) == -ENOENT,
	      "no agent on the socket is an error");

	memset(&sent, 0, sizeof(sent));
	sent.flags = LOTA_STATUS_BENCH;
	sent.mode = LOTA_MODE_MONITOR;
	sent.attest_count = 3;
	pid = serve_once(path, &resp, &sent, sizeof(sent));
	CHECK(pid > 0, "fake agent listening");
	memset(&got, 0xff, sizeof(got));
	CHECK(status_request(path, &got) == 0 && got.flags == sent.flags &&
		      got.mode == sent.mode && got.attest_count == 3,
	      "the daemon's answer is read whole");
	CHECK(reap(pid) == 0, "GET_STATUS was the request");
	unlink(path);

	resp.payload_len = 4;
	pid = serve_once(path, &resp, &sent, 4);
	CHECK(status_request(path, &got) == -EPROTO,
	      "a status of the wrong size is refused");
	reap(pid);
	unlink(path);

	resp.payload_len = sizeof(sent);
	resp.magic = 0;
	pid = serve_once(path, &resp, &sent, sizeof(sent));
	CHECK(status_request(path, &got) == -EPROTO,
	      "an answer without the magic is refused");
	reap(pid);
	unlink(path);

	resp.magic = LOTA_IPC_MAGIC;
	resp.result = LOTA_IPC_ERR_ACCESS_DENIED;
	pid = serve_once(path, &resp, &sent, sizeof(sent));
	CHECK(status_request(path, &got) == -EACCES,
	      "a refusal is not read as a status");
	reap(pid);
	unlink(path);

	rmdir(dir);
}

int main(void)
{
	printf("=== agent --status tests ===\n\n");

	test_flags();
	test_format();
	test_request();

	printf("\n%s: %d failure(s)\n", g_failures ? "FAILED" : "OK",
	       g_failures);
	return g_failures ? 1 : 0;
}
