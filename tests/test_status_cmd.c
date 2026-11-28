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

#include "test.h"

static void test_flags(void)
{
	char buf[256];

	status_flags_string(LOTA_STATUS_TPM_OK | LOTA_STATUS_BPF_LOADED |
				    LOTA_STATUS_BENCH,
			    buf, sizeof(buf));
	TEST("flags print by the names a title sees");
	if (strcmp(buf, "TPM_OK,BPF_LOADED,BENCH") != 0)
		FAIL("expected: strcmp(buf, \"TPM_OK,BPF_LOADED,BENCH\") == 0");

	status_flags_string(LOTA_STATUS_ATTESTED | LOTA_STATUS_TPM_LOCKOUT |
				    LOTA_STATUS_EVENTS_LOST,
			    buf, sizeof(buf));
	TEST("host-only bits are named too");
	if (strcmp(buf, "ATTESTED,EVENTS_LOST,TPM_LOCKOUT") != 0)
		FAIL("expected: strcmp(buf, "
		     "\"ATTESTED,EVENTS_LOST,TPM_LOCKOUT\") == 0");

	status_flags_string(LOTA_STATUS_TPM_OK | (1U << 30), buf, sizeof(buf));
	TEST("a bit without a name is not dropped");
	if (strcmp(buf, "TPM_OK,0x40000000") != 0)
		FAIL("expected: strcmp(buf, \"TPM_OK,0x40000000\") == 0");

	status_flags_string(0, buf, sizeof(buf));
	TEST("no bits reads as none");
	if (strcmp(buf, "none") != 0)
		FAIL("expected: strcmp(buf, \"none\") == 0");

	status_flags_string(LOTA_STATUS_TPM_OK | LOTA_STATUS_BENCH, buf, 8);
	TEST("a short buffer is cut, not overrun");
	if (strlen(buf) != 7)
		FAIL("expected: strlen(buf) == 7");
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
	TEST("the report has one line per field");
	if (strcmp(buf, "Mode:         enforce\n"
			"Flags:        TPM_OK,BENCH\n"
			"Policy:       none (LSM not loaded)\n"
			"Attested:     2023-11-14 22:13:20 UTC\n"
			"Token until:  none\n"
			"Attestations: 5 succeeded, 1 failed\n") != 0)
		FAIL("expected: strcmp(buf, \"Mode:         enforce\\n\" "
		     "\"Flags:        TPM_OK,BENCH\\n\" \"Policy:       none "
		     "(LSM not loaded)\\n\" \"Attested:     2023-11-14 "
		     "22:13:20 UTC\\n\" \"Token until:  none\\n\" "
		     "\"Attestations: 5 succeeded, 1 failed\\n\") == 0");

	s.mode = 9;
	status_format(&s, buf, sizeof(buf));
	TEST("a mode this build does not know is shown as a number");
	if (strstr(buf, "Mode:         unknown (9)\n") == NULL)
		FAIL("expected: strstr(buf, \"Mode:         unknown (9)\\n\") "
		     "!= NULL");

	s.last_attest_time = 0;
	status_format(&s, buf, sizeof(buf));
	TEST("a host never attested says so");
	if (strstr(buf, "Attested:     never\n") == NULL)
		FAIL("expected: strstr(buf, \"Attested:     never\\n\") != "
		     "NULL");
}

static void test_policy(void)
{
	struct lota_ipc_status s;
	char buf[256];

	memset(&s, 0, sizeof(s));
	s.mode = LOTA_MODE_ENFORCE;
	s.flags = LOTA_STATUS_BPF_LOADED | LOTA_STATUS_ENFORCE |
		  LOTA_STATUS_STRICT_MMAP | LOTA_STATUS_BLOCK_PTRACE;
	status_policy_string(&s, buf, sizeof(buf));
	TEST("the keys print as lota.conf names them, with where refusals go");
	if (strcmp(buf, "strict_mmap,block_ptrace; each refusal is logged "
			"as *_BLOCKED with its file") != 0)
		FAIL("expected: strcmp(buf, \"strict_mmap,block_ptrace; each "
		     "refusal is logged \" \"as *_BLOCKED with its file\") == "
		     "0");

	s.flags = LOTA_STATUS_BPF_LOADED | LOTA_STATUS_ENFORCE;
	status_policy_string(&s, buf, sizeof(buf));
	TEST("enforce with no key reads as none");
	if (strcmp(buf, "none") != 0)
		FAIL("expected: strcmp(buf, \"none\") == 0");

	s.mode = LOTA_MODE_MONITOR;
	s.flags = LOTA_STATUS_BPF_LOADED;
	status_policy_string(&s, buf, sizeof(buf));
	TEST("monitor says why no key applies");
	if (strcmp(buf, "none (monitor mode)") != 0)
		FAIL("expected: strcmp(buf, \"none (monitor mode)\") == 0");

	s.mode = LOTA_MODE_ENFORCE;
	s.flags = 0;
	status_policy_string(&s, buf, sizeof(buf));
	TEST("enforce without the LSM says so, not none");
	if (strcmp(buf, "none (LSM not loaded)") != 0)
		FAIL("expected: strcmp(buf, \"none (LSM not loaded)\") == 0");
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
		TEST("mkdtemp");
		if (!0)
			FAIL("expected: 0");
		return;
	}
	snprintf(path, sizeof(path), "%s/sock", dir);

	TEST("no agent on the socket is an error");
	if (status_request(path, &got) != -ENOENT)
		FAIL("expected: status_request(path, &got) == -ENOENT");

	memset(&sent, 0, sizeof(sent));
	sent.flags = LOTA_STATUS_BENCH;
	sent.mode = LOTA_MODE_MONITOR;
	sent.attest_count = 3;
	pid = serve_once(path, &resp, &sent, sizeof(sent));
	TEST("fake agent listening");
	if (pid <= 0)
		FAIL("expected: pid > 0");
	memset(&got, 0xff, sizeof(got));
	TEST("the daemon's answer is read whole");
	if (!(status_request(path, &got) == 0 && got.flags == sent.flags &&
	      got.mode == sent.mode && got.attest_count == 3))
		FAIL("expected: status_request(path, &got) == 0 && got.flags "
		     "== sent.flags && got.mode == sent.mode && "
		     "got.attest_count == 3");
	TEST("GET_STATUS was the request");
	if (reap(pid) != 0)
		FAIL("expected: reap(pid) == 0");
	unlink(path);

	resp.payload_len = 4;
	pid = serve_once(path, &resp, &sent, 4);
	TEST("a status of the wrong size is refused");
	if (status_request(path, &got) != -EPROTO)
		FAIL("expected: status_request(path, &got) == -EPROTO");
	reap(pid);
	unlink(path);

	resp.payload_len = sizeof(sent);
	resp.magic = 0;
	pid = serve_once(path, &resp, &sent, sizeof(sent));
	TEST("an answer without the magic is refused");
	if (status_request(path, &got) != -EPROTO)
		FAIL("expected: status_request(path, &got) == -EPROTO");
	reap(pid);
	unlink(path);

	resp.magic = LOTA_IPC_MAGIC;
	resp.result = LOTA_IPC_ERR_ACCESS_DENIED;
	pid = serve_once(path, &resp, &sent, sizeof(sent));
	TEST("a refusal is not read as a status");
	if (status_request(path, &got) != -EACCES)
		FAIL("expected: status_request(path, &got) == -EACCES");
	reap(pid);
	unlink(path);

	rmdir(dir);
}

int main(void)
{
	test_begin("status cmd");

	test_flags();
	test_format();
	test_policy();
	test_request();

	return test_end();
}
