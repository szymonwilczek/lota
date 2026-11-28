/* SPDX-License-Identifier: MIT */
/*
 * What a caller learns from starting the agent with --daemon.
 *
 * Daemonising forks, and everything that decides whether the agent may run
 * happens in the child: the PID file lock, the key the enforcement object is
 * verified against, and the startup policy. A launcher that exits at the fork
 * reports success for every one of those refusals, with no process running
 * and the reason written to a stderr nobody holds -- an init script, a container
 * entrypoint or an operator following a runbook cannot tell a refused start
 * from a good one.
 *
 * The refusal driven here is the PID file already being held, because it needs
 * no privilege and no TPM: the test takes the lock itself and asks the agent to
 * start against the same file.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/file.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "test.h"

#ifndef AGENT_BIN_PATH
#define AGENT_BIN_PATH "build/lota-agent"
#endif

/*
 * Run the agent with the given arguments, with its output discarded,
 * and return its wait status.
 * -1 when it could not be run at all.
 */
static int run_agent(char *const argv[])
{
	pid_t pid;
	int status;

	pid = fork();
	if (pid < 0)
		return -1;

	if (pid == 0) {
		int devnull = open("/dev/null", O_RDWR);

		if (devnull >= 0) {
			dup2(devnull, STDOUT_FILENO);
			dup2(devnull, STDERR_FILENO);
			if (devnull > STDERR_FILENO)
				close(devnull);
		}
		execv(AGENT_BIN_PATH, argv);
		_exit(127);
	}

	if (waitpid(pid, &status, 0) < 0)
		return -1;

	return status;
}

int main(void)
{
	char pid_path[128];
	char *argv[6];
	int held_fd;
	int status;

	test_begin("daemon start status");

	snprintf(pid_path, sizeof(pid_path), "/tmp/lota_dss_%d.pid",
		 (int)getpid());

	/*
	 * Hold the PID file the way a running agent holds it,
	 * so the start below meets the same refusal a second instance would.
	 */
	held_fd = open(pid_path, O_RDWR | O_CREAT, 0644);
	if (held_fd < 0 || flock(held_fd, LOCK_EX | LOCK_NB) < 0) {
		FAIL("could not hold %s", pid_path);
		return 1;
	}

	argv[0] = (char *)"lota-agent";
	argv[1] = (char *)"--daemon";
	argv[2] = (char *)"--pid-file";
	argv[3] = pid_path;
	argv[4] = NULL;

	status = run_agent(argv);

	TEST("a daemonised start that is refused terminates normally");
	if (!(status >= 0 && WIFEXITED(status)))
		FAIL("expected: status >= 0 && WIFEXITED(status)");
	TEST("a daemonised start that is refused exits non-zero");
	if (!(status >= 0 && WIFEXITED(status) && WEXITSTATUS(status) != 0))
		FAIL("expected: status >= 0 && WIFEXITED(status) && "
		     "WEXITSTATUS(status) != 0");
	TEST("the agent binary under test was found and run");
	if (!(status >= 0 && WIFEXITED(status) && WEXITSTATUS(status) != 127))
		FAIL("expected: status >= 0 && WIFEXITED(status) && "
		     "WEXITSTATUS(status) != 127");

	flock(held_fd, LOCK_UN);
	close(held_fd);
	unlink(pid_path);

	return test_end();
}
