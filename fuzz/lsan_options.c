/* SPDX-License-Identifier: MIT */
/*
 * LeakSanitizer options for the C fuzz targets.
 *
 * LSan ptrace-attaches to every thread before it scans. Where the attach is
 * refused (LOTA block_ptrace, seccomp, Yama scope 3) the scan aborts, and
 * libFuzzer saves the abort as a crash reproducer that reproduces nothing.
 * Probe the attach on a child and set detect_leaks=0 when it fails.
 */

#include <signal.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

/*
 * Called while the sanitizer runtime parses its options, before it is
 * initialised: uninstrumented, raw system calls only.
 * The hook's prototype lives in clang's <sanitizer/lsan_interface.h>.
 */
static int ptrace_attach_works(void)
	__attribute__((no_sanitize("address", "coverage")));
const char *__lsan_default_options(void)
	__attribute__((no_sanitize("address", "coverage")));

static const char lsan_off_msg[] =
	"fuzz: ptrace attach is refused on this host, so LeakSanitizer cannot "
	"run; leak detection is off for this process\n";

static int ptrace_attach_works(void)
{
	long pid;
	long ret;
	int status;

	pid = syscall(SYS_clone, (long)SIGCHLD, 0L, 0L, 0L, 0L);
	if (pid < 0)
		return 1; /* cannot tell; leave the default alone */
	if (pid == 0) {
		for (;;)
			syscall(SYS_ppoll, 0L, 0L, 0L, 0L, 0L);
	}

	ret = syscall(SYS_ptrace, (long)PTRACE_ATTACH, pid, 0L, 0L);
	syscall(SYS_kill, pid, (long)SIGKILL);
	for (;;) {
		if (syscall(SYS_wait4, pid, &status, (long)__WALL, 0L) < 0)
			break;
		if (WIFEXITED(status) || WIFSIGNALED(status))
			break;
	}
	return ret == 0;
}

const char *__lsan_default_options(void)
{
	if (ptrace_attach_works())
		return "";
	syscall(SYS_write, 2L, lsan_off_msg, (long)(sizeof(lsan_off_msg) - 1));
	return "detect_leaks=0";
}
