/* SPDX-License-Identifier: MIT
 *
 * lota-install - Child Process Runner
 */

#include "run.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

/* Spinner cadence while a child is running */
#define RUN_TICK_MS 90

/* Forks argv with stdout+stderr merged into a pipe.
 * On success stores the read end and the pid.
 * 0 or -errno. */
static int spawn_child(const char *const argv[], int *fd_out, pid_t *pid_out)
{
	int pfd[2];
	pid_t pid;

	if (pipe2(pfd, O_CLOEXEC) != 0)
		return -errno;

	pid = fork();
	if (pid < 0) {
		int err = errno;

		close(pfd[0]);
		close(pfd[1]);
		return -err;
	}

	if (pid == 0) {
		/* child: merge stdout+stderr into the pipe, detach stdin */
		int devnull = open("/dev/null", O_RDONLY);

		if (devnull >= 0)
			dup2(devnull, STDIN_FILENO);
		dup2(pfd[1], STDOUT_FILENO);
		dup2(pfd[1], STDERR_FILENO);
		execvp(argv[0], (char *const *)argv);
		fprintf(stderr, "exec %s: %s\n", argv[0], strerror(errno));
		_exit(127);
	}

	close(pfd[1]);
	*fd_out = pfd[0];
	*pid_out = pid;
	return 0;
}

static int wait_exit_code(pid_t pid)
{
	int status;

	while (waitpid(pid, &status, 0) < 0) {
		if (errno != EINTR)
			return -errno;
	}
	if (WIFEXITED(status))
		return WEXITSTATUS(status);
	if (WIFSIGNALED(status))
		return 128 + WTERMSIG(status);
	return -EIO;
}

int run_cmd(struct ui *ui, const char *label, const char *const argv[])
{
	char buf[1024];
	struct pollfd pfd;
	pid_t pid;
	int fd;
	int ret;
	int code;

	ret = spawn_child(argv, &fd, &pid);
	if (ret < 0)
		return ret;

	ui_live_begin(ui, label);

	pfd.fd = fd;
	pfd.events = POLLIN;
	while (1) {
		int ready;

		/* user abort from the full-screen frontend:
		 * terminate the child and keep draining the pipe until EOF
		 * so the exit status below reflects the signal */
		if (ui->sink && ui->sink->abort &&
		    ui->sink->abort(ui->sink->ud))
			kill(pid, SIGTERM);

		ready = poll(&pfd, 1, RUN_TICK_MS);
		if (ready < 0) {
			if (errno == EINTR)
				continue;
			break;
		}
		if (ready == 0) {
			ui_live_tick(ui);
			continue;
		}

		ssize_t got = read(fd, buf, sizeof(buf));

		if (got < 0) {
			if (errno == EINTR)
				continue;
			break;
		}
		if (got == 0)
			break;
		ui_live_feed(ui, buf, (size_t)got);
	}
	close(fd);

	code = wait_exit_code(pid);
	ui_live_end(ui, code == 0 ? UI_OK : UI_FAIL);
	return code;
}

int run_capture(const char *const argv[], char *out, size_t cap)
{
	size_t used = 0;
	pid_t pid;
	int fd;
	int ret;

	if (!out || cap < 1)
		return -EINVAL;
	out[0] = '\0';

	ret = spawn_child(argv, &fd, &pid);
	if (ret < 0)
		return ret;

	while (1) {
		char buf[1024];
		ssize_t got = read(fd, buf, sizeof(buf));

		if (got < 0) {
			if (errno == EINTR)
				continue;
			break;
		}
		if (got == 0)
			break;
		if (used < cap - 1) {
			size_t take = (size_t)got;

			if (take > cap - 1 - used)
				take = cap - 1 - used;
			memcpy(out + used, buf, take);
			used += take;
		}
	}
	out[used] = '\0';
	close(fd);

	return wait_exit_code(pid);
}
