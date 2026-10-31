/* SPDX-License-Identifier: MIT */
/*
 * LOTA Wine/Proton Hook - LD_PRELOAD Integration
 *
 * Shared library loaded via LD_PRELOAD into Wine/Proton processes
 * to transparently bridge LOTA attestation into Windows games.
 *
 * Lifecycle:
 *   1. Constructor: connect to agent, write initial status/token,
 *      start background refresh thread.
 *   2. Background thread: periodically re-query agent, atomically
 *      update the status and token files.
 *   3. Destructor: stop thread, disconnect, remove files.
 *
 * The hook is self-contained -- the Gaming SDK is linked statically
 * into the .so!
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <ctype.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <stdint.h>

#include "../../include/lota_endian.h"
#include "../../include/lota_gaming.h"
#include "../../include/lota_ipc.h"
#include "../../include/lota_snapshot.h"
#include "../../include/lota_wine_hook.h"
#include "hook_container.h"

/* log levels */
enum hook_log_level {
	HOOK_LOG_DEBUG = 0,
	HOOK_LOG_INFO = 1,
	HOOK_LOG_WARN = 2,
	HOOK_LOG_ERROR = 3,
	HOOK_LOG_SILENT = 4,
};

/* global state */
static struct {
	struct lota_client *client;
	pthread_t thread;
	atomic_int running;
	atomic_int thread_started;
	int log_level;
	int refresh_sec;
	char token_dir[PATH_MAX - 64]; /* leave room for filename suffix */
	char socket_path[PATH_MAX]; /* empty -> default */
	/* hex; empty -> unnamed */
	char publisher[LOTA_PUBLISHER_PROFILE_LEN + 1];
	char status_path[PATH_MAX];
	char token_path[PATH_MAX];
	char snapshot_path[PATH_MAX]; /* atomic snapshot file (flags + token) */
	pid_t init_pid;
	time_t init_time; /* when the loader started bringing us up */
	int protect_delay_sec; /* wait before joining protected_pids */
	char refused_object[256]; /* last object that would not load */
	time_t refused_at;
	struct lota_status last_status; /* the last one the agent gave */
	atomic_int have_status;
	atomic_int offline_errno; /* the refusal already reported, negated */
	atomic_int publisher_errno; /* the publisher refusal already reported */
	atomic_int token_errno; /* the token refusal already reported */
	atomic_int self_protected;
	atomic_int offline_published;
} g_hook;

/* Guards last_status against the loader thread reading it. */
static pthread_mutex_t g_status_lock;
static pthread_once_t g_status_lock_once = PTHREAD_ONCE_INIT;

static void status_lock_init(void)
{
	pthread_mutex_init(&g_status_lock, NULL);
}

#define HOOK_PREFIX "lota-hook"

#define HOOK_LOG(level, fmt, ...)                                  \
	do {                                                       \
		if ((level) >= g_hook.log_level)                   \
			fprintf(stderr, HOOK_PREFIX ": " fmt "\n", \
				##__VA_ARGS__);                    \
	} while (0)

#define LOG_DBG(fmt, ...) HOOK_LOG(HOOK_LOG_DEBUG, fmt, ##__VA_ARGS__)
#define LOG_INF(fmt, ...) HOOK_LOG(HOOK_LOG_INFO, fmt, ##__VA_ARGS__)
#define LOG_WRN(fmt, ...) HOOK_LOG(HOOK_LOG_WARN, fmt, ##__VA_ARGS__)
#define LOG_ERR(fmt, ...) HOOK_LOG(HOOK_LOG_ERROR, fmt, ##__VA_ARGS__)

#ifndef LOTA_HOOK_TESTING
/*
 * Resolve /proc/self/exe into a caller-owned buffer. Returns 0 on
 * success, -errno on failure. The buffer is left empty on failure so
 * callers can treat an empty path as "unknown" and fall back to the
 * permissive default. Gated on !LOTA_HOOK_TESTING because the
 * /proc-free unit tests drive the policy decision directly through
 * policy_should_activate() with synthetic paths.
 */
static int read_self_exe(char *out, size_t out_sz)
{
	ssize_t n;

	if (!out || out_sz < 2)
		return -EINVAL;
	out[0] = '\0';
	n = readlink("/proc/self/exe", out, out_sz - 1);
	if (n < 0)
		return -errno;
	out[n] = '\0';
	return 0;
}

/*
 * Copy argv[1] from /proc/self/cmdline. Under Wine's loader it is the hosted
 * Windows program: the preloader has dropped its own name, and the loader
 * rewrites the line only after every preloaded constructor.
 * 0 or -errno; @out is empty when argv[1] is absent or does not fit.
 */
static int read_self_program(char *out, size_t out_sz)
{
	char buf[PATH_MAX * 2];
	size_t first, len;
	ssize_t n;
	int fd;

	if (!out || out_sz < 2)
		return -EINVAL;
	out[0] = '\0';
	fd = open("/proc/self/cmdline", O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -errno;
	n = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (n < 0)
		return -errno;
	buf[n] = '\0';

	first = strnlen(buf, (size_t)n);
	if (first + 1 >= (size_t)n)
		return 0;
	len = strnlen(buf + first + 1, (size_t)n - first - 1);
	if (len >= out_sz)
		return 0;
	memcpy(out, buf + first + 1, len);
	out[len] = '\0';
	return 0;
}
#endif

/*
 * Check whether path begins with any comma-separated prefix in list.
 * Empty list or empty path returns false. Each prefix is matched
 * against path verbatim; leading and trailing whitespace inside the
 * list entry is ignored.
 */
static bool path_has_prefix_in(const char *path, const char *list)
{
	const char *p;
	size_t path_len;

	if (!path || !*path || !list || !*list)
		return false;
	path_len = strlen(path);
	for (p = list; *p;) {
		const char *end = strchr(p, ',');
		size_t span = end ? (size_t)(end - p) : strlen(p);
		while (span > 0 && (p[0] == ' ' || p[0] == '\t')) {
			p++;
			span--;
		}
		while (span > 0 && (p[span - 1] == ' ' || p[span - 1] == '\t'))
			span--;
		if (span > 0 && path_len >= span && strncmp(path, p, span) == 0)
			return true;
		if (!end)
			break;
		p = end + 1;
	}
	return false;
}

/*
 * FHS-mandated system-binary path prefixes.
 *
 * The Filesystem Hierarchy Standard fixes system binaries under
 * /usr/, /bin, /sbin, /lib, /lib64. On usrmerge distros (Fedora)
 * /bin, /sbin, /lib, /lib64 are symlinks back into /usr,
 * so /proc/self/exe always resolves to the /usr form after
 * readlink; the extra entries cover non-usrmerge layouts where the
 * legacy paths survive verbatim. The /run/host/ entries cover the
 * Steam pressure-vessel case where the container exposes the host
 * /usr tree as /run/host/usr/ so a process exec'd through that path
 * still resolves to a system binary.
 *
 * Kept as a compile-time string so the constants live next to the
 * policy that consumes them; distro-specific paths that fall
 * outside FHS are an operator concern and reach the policy through
 * LOTA_HOOK_SKIP_PATH.
 */
#define LOTA_HOOK_FHS_SYSTEM_PREFIXES                    \
	"/usr/,/bin/,/sbin/,/lib/,/lib64/,"              \
	"/run/host/usr/,/run/host/bin/,/run/host/sbin/," \
	"/run/host/lib/,/run/host/lib64/"

/*
 * Pure policy decision: should the hook activate for the process
 * whose /proc/self/exe resolves to @exe, with @allow as the
 * positive-pin prefix list and @skip as the additional skip prefix
 * list (both comma-separated, both nullable / may be empty)?
 *
 * Decision order matches should_activate():
 *
 *   1. Empty @exe (read_self_exe failed): default to activate.
 *      This preserves the original constructor contract on systems
 *      where /proc is not mounted (build-time test, chroot smoke).
 *   2. Non-empty @allow: positive pin. Activate iff @exe starts
 *      with one of the comma-separated prefixes; otherwise skip.
 *      The default FHS list is ignored when @allow is set so a
 *      pin to /opt/games/ does not get widened by accident.
 *   3. Non-empty @skip and @exe matches: skip. Used by
 *      operators on non-FHS distros to extend the built-in list
 *      without rebuilding the hook.
 *   4. Default: skip iff @exe starts with one of
 *      LOTA_HOOK_FHS_SYSTEM_PREFIXES; otherwise activate.
 */
static bool policy_should_activate(const char *exe, const char *allow,
				   const char *skip)
{
	if (!exe || !exe[0])
		return true;

	if (allow && *allow)
		return path_has_prefix_in(exe, allow);

	if (skip && path_has_prefix_in(exe, skip))
		return false;

	return !path_has_prefix_in(exe, LOTA_HOOK_FHS_SYSTEM_PREFIXES);
}

/* Wine's loader, with or without a preloader: every Wine process's exe */
static bool exe_is_wine_loader(const char *exe)
{
	static const char *const names[] = { "wine", "wine64", "wine-preloader",
					     "wine64-preloader" };
	static const char deleted[] = " (deleted)";
	const char *base;
	size_t len, i;

	if (!exe)
		return false;
	base = strrchr(exe, '/');
	base = base ? base + 1 : exe;
	len = strlen(base);
	if (len > sizeof(deleted) - 1 &&
	    strcmp(base + len - (sizeof(deleted) - 1), deleted) == 0)
		len -= sizeof(deleted) - 1;

	for (i = 0; i < sizeof(names) / sizeof(names[0]); i++)
		if (strlen(names[i]) == len &&
		    strncmp(base, names[i], len) == 0)
			return true;
	return false;
}

static bool win_path_sep(char c)
{
	return c == '/' || c == '\\';
}

/*
 * Whether Windows path @program lies inside @dir ("steamapps/common/Title/")
 * on any drive. @dir matches whole components only; either separator
 * matches either and ASCII case is ignored, as on Windows.
 */
static bool program_in_dir(const char *program, const char *dir)
{
	size_t dlen, plen, i, j;

	if (!program || !dir)
		return false;
	while (win_path_sep(*dir))
		dir++;
	dlen = strlen(dir);
	while (dlen > 0 && win_path_sep(dir[dlen - 1]))
		dlen--;
	if (dlen == 0)
		return false;

	plen = strlen(program);
	for (i = 0; i + dlen < plen; i++) {
		if (i > 0 && !win_path_sep(program[i - 1]) &&
		    program[i - 1] != ':')
			continue;
		for (j = 0; j < dlen; j++) {
			char p = program[i + j], d = dir[j];

			if (win_path_sep(p) && win_path_sep(d))
				continue;
			if (tolower((unsigned char)p) !=
			    tolower((unsigned char)d))
				break;
		}
		if (j == dlen && win_path_sep(program[i + dlen]))
			return true;
	}
	return false;
}

/*
 * @exe as above, @program its argv[1], @title_dir the title's directory
 * as Wine sees it (nullable / may be empty), @allow and @skip as for
 * policy_should_activate().
 *
 * With a title dir, Wine's loader activates only for a program inside it:
 * the title and the prefix's services are one pinned loader binary.
 * Anything else is decided by its path.
 */
static bool policy_should_activate_process(const char *exe, const char *program,
					   const char *title_dir,
					   const char *allow, const char *skip)
{
	if (title_dir && *title_dir && exe_is_wine_loader(exe))
		return program_in_dir(program, title_dir);

	return policy_should_activate(exe, allow, skip);
}

#ifndef LOTA_HOOK_TESTING
/*
 * Decide whether the hook should activate in the current process.
 *
 * LD_PRELOAD is inherited by every fork+exec inside the launcher
 * shell. Running the hook's agent-connect + background-thread
 * machinery in throwaway shells and POSIX utilities (basename,
 * dirname, ldconfig, sudo, ...) stalls the launcher script and
 * thrashes the per-process token sink for no value.
 *
 * The hook treats /proc/self/exe as the source of truth and
 * delegates the policy decision to policy_should_activate_process(). Three
 * operator-visible overrides apply on top of the FHS default:
 *
 *   LOTA_HOOK_ACTIVATE_PATH=~/.local/share/Steam,/opt/games
 *     If set and non-empty, the hook activates ONLY when
 *     /proc/self/exe begins with one of the comma-separated
 *     prefixes. Use this to pin attestation to a specific install
 *     tree rather than the FHS default. lota-proton-hook sets it
 *     to the directories Steam names for the launch, which hold
 *     the title, not the client helpers.
 *
 *   LOTA_HOOK_ACTIVATE_PROGRAM=steamapps/common/Title/
 *     Wine's loader activates ONLY when its Windows program
 *     (argv[1]) lies in this directory, whatever the pin says.
 *     lota-proton-hook sets it from the title's install directory.
 *
 *   LOTA_HOOK_SKIP_PATH=/extra/skip/prefix
 *     Extends the built-in system-path skip list. Useful when a
 *     distro keeps utilities outside FHS (e.g. /nix/store) without
 *     recompiling the hook.
 *
 * Returns true when the hook should run its constructor body,
 * false when the constructor should early-return cleanly. Gated on
 * !LOTA_HOOK_TESTING because the unit tests drive
 * policy_should_activate() directly with synthetic paths and would
 * trip -Werror=unused-function otherwise.
 */
static bool should_activate(void)
{
	char exe[PATH_MAX];
	char program[PATH_MAX];

	if (read_self_exe(exe, sizeof(exe)) != 0 || !exe[0])
		return true;
	if (read_self_program(program, sizeof(program)) != 0)
		program[0] = '\0';

	return policy_should_activate_process(
		exe, program, getenv(LOTA_HOOK_ENV_ACTIVATE_PROGRAM),
		getenv(LOTA_HOOK_ENV_ACTIVATE_PATH),
		getenv(LOTA_HOOK_ENV_SKIP_PATH));
}
#endif

/*
 * Parse log level string. Returns HOOK_LOG_WARN for NULL or
 * unrecognised values (safe default for LD_PRELOAD context).
 */
static int parse_log_level(const char *s)
{
	if (!s)
		return HOOK_LOG_WARN;
	if (strcmp(s, "debug") == 0)
		return HOOK_LOG_DEBUG;
	if (strcmp(s, "info") == 0)
		return HOOK_LOG_INFO;
	if (strcmp(s, "warn") == 0)
		return HOOK_LOG_WARN;
	if (strcmp(s, "error") == 0)
		return HOOK_LOG_ERROR;
	if (strcmp(s, "silent") == 0)
		return HOOK_LOG_SILENT;
	return HOOK_LOG_WARN;
}

/*
 * Write the @n'th token-directory candidate into g_hook.token_dir.
 *
 * Candidates, in order:
 *   0. LOTA_HOOK_TOKEN_DIR        (explicit override, absent -> skipped)
 *   1. $XDG_RUNTIME_DIR/lota-hook (the player's own runtime directory)
 *   2. /tmp/lota-<uid>            (no runtime directory at all)
 *
 * $XDG_RUNTIME_DIR/lota is deliberately not among them: the agent creates
 * that one root:lota 0750 for the container socket
 * (src/agent/steam_runtime.c::steam_runtime_ensure_socket_dir),
 * and this directory holds files the player must own and nobody else may read.
 *
 * Returns 0 when a candidate was written, -ENOENT when @n names none.
 */
static int token_dir_candidate(int n)
{
	const char *env;

	switch (n) {
	case 0:
		env = getenv(LOTA_HOOK_ENV_TOKEN_DIR);
		if (!env || !env[0])
			return -ENOENT;
		snprintf(g_hook.token_dir, sizeof(g_hook.token_dir), "%s", env);
		return 0;
	case 1:
		env = getenv("XDG_RUNTIME_DIR");
		if (!env || !env[0])
			return -ENOENT;
		snprintf(g_hook.token_dir, sizeof(g_hook.token_dir),
			 "%s/" LOTA_HOOK_TOKEN_DIR_NAME, env);
		return 0;
	case 2:
		snprintf(g_hook.token_dir, sizeof(g_hook.token_dir),
			 "/tmp/lota-%u", (unsigned)getuid());
		return 0;
	default:
		return -ENOENT;
	}
}

/*
 * Create and validate the token directory.
 *
 * Security requirements:
 *  - path must resolve to a real directory (no symlink traversal)
 *  - owned by current uid
 *  - mode forced to 0700 (private attestation artifacts)
 *
 * @repaired_from: receives the mode a tightened directory had, else 0.
 *
 * Returns 0 on success, negative errno on failure.
 */
static int ensure_token_dir(mode_t *repaired_from)
{
	struct stat st;
	int dirfd;

	/* try to create; EEXIST is fine */
	if (mkdir(g_hook.token_dir, 0700) < 0 && errno != EEXIST) {
		LOG_ERR("mkdir %s: %s", g_hook.token_dir, strerror(errno));
		return -errno;
	}

	dirfd = open(g_hook.token_dir,
		     O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
	if (dirfd < 0) {
		LOG_ERR("open token dir %s: %s", g_hook.token_dir,
			strerror(errno));
		return -errno;
	}

	if (fstat(dirfd, &st) != 0) {
		int err = errno;
		close(dirfd);
		LOG_ERR("fstat %s: %s", g_hook.token_dir, strerror(err));
		return -err;
	}

	if (!S_ISDIR(st.st_mode)) {
		close(dirfd);
		LOG_ERR("token dir exists but is not a directory: %s",
			g_hook.token_dir);
		return -ENOTDIR;
	}

	if (st.st_uid != getuid()) {
		close(dirfd);
		LOG_ERR("token dir owned by uid %u, expected %u: %s",
			(unsigned)st.st_uid, (unsigned)getuid(),
			g_hook.token_dir);
		return -EACCES;
	}

	if (repaired_from)
		*repaired_from = 0;

	if ((st.st_mode & 0777) != 0700) {
		if (fchmod(dirfd, 0700) < 0) {
			int err = errno;
			close(dirfd);
			LOG_ERR("fchmod 0700 %s: %s", g_hook.token_dir,
				strerror(err));
			return -err;
		}
		if (repaired_from)
			*repaired_from = st.st_mode & 0777;
	}

	close(dirfd);

	return 0;
}

/*
 * Settle on a token directory: the first candidate that can be made
 * a private directory of the player's own.
 *
 * A candidate that cannot be used is not the end of the hook -- a player
 * whose runtime directory is unusable still gets attestation out of /tmp
 * -- so each refusal is reported and the next candidate is tried.
 * The directory that was settled on is named by the caller's own log line,
 * because a hook writing somewhere other than the documented default is
 * the first thing an integrator needs to know.
 *
 * Returns 0 with g_hook.token_dir set, or the last error when every
 * candidate was refused.
 */
static int setup_token_dir(void)
{
	int last = -ENOENT;

	for (int n = 0; n < 3; n++) {
		mode_t repaired = 0;
		int ret;

		if (token_dir_candidate(n) != 0)
			continue;

		ret = ensure_token_dir(&repaired);
		if (ret == 0) {
			if (repaired)
				LOG_WRN("token dir %s was mode %04o, tightened to 0700",
					g_hook.token_dir, (unsigned)repaired);
			return 0;
		}

		last = ret;
		LOG_WRN("token dir unusable (%s); trying the next one",
			strerror(-ret));
	}

	g_hook.token_dir[0] = '\0';
	return last;
}

#ifndef LOTA_HOOK_TESTING
/*
 * Warn on stderr when the token directory is private to the container.
 * Only inside a container: on the host a non-mount directory is normal.
 */
static void report_unshared_token_dir(void)
{
	char msg[PATH_MAX + 256];
	bool mounted = false;
	char line[PATH_MAX * 2];
	bool skipping = false;
	FILE *f;

	if (!hook_in_container(getenv("container")))
		return;

	/*
	 * Unreadable mountinfo: say nothing rather than guess. Read line by
	 * line (it has no size and runs to tens of KB); an overlong line is
	 * skipped whole, since a fragment could fake the fields.
	 */
	f = fopen("/proc/self/mountinfo", "re");
	if (!f)
		return;

	while (fgets(line, sizeof(line), f)) {
		bool complete = strchr(line, '\n') != NULL;

		if (skipping) {
			skipping = !complete;
			continue;
		}

		if (!complete) {
			skipping = true;
			continue;
		}

		if (hook_dir_is_mount(line, g_hook.token_dir)) {
			mounted = true;
			break;
		}
	}

	fclose(f);

	if (mounted)
		return;

	hook_container_private_message(g_hook.token_dir, msg, sizeof(msg));
	LOG_WRN("%s", msg);
}
#endif

/*
 * Write data to a file atomically.
 *
 * Writes to a PID-tagged temporary file, fsyncs, then renames
 * over the target path. This guarantees readers never see a
 * partially written file.
 */
static int atomic_write(const char *path, const void *data, size_t len)
{
	char tmp[PATH_MAX];
	int fd, err;
	ssize_t n;

	snprintf(tmp, sizeof(tmp), "%s.tmp.XXXXXX", path);

	fd = mkostemp(tmp, O_CLOEXEC);
	if (fd < 0)
		return -errno;

	n = write(fd, data, len);
	if (n != (ssize_t)len) {
		err = (n < 0) ? errno : EIO;
		close(fd);
		unlink(tmp);
		return -err;
	}

	if (fsync(fd) < 0) {
		err = errno;
		close(fd);
		unlink(tmp);
		return -err;
	}

	close(fd);

	if (rename(tmp, path) < 0) {
		err = errno;
		unlink(tmp);
		return -err;
	}

	return 0;
}

/*
 * Write the text status file.
 *
 * Render the agent's last reported status into the key=value text file
 * the operator-facing consumers (verify-attested.sh, server-side
 * bridges) poll. @offline non-zero means the hook lost the agent
 * channel entirely: the LOTA_OFFLINE=1 marker lets consumers
 * distinguish "agent reachable, says not attested" (UNTRUSTED) from
 * "agent unreachable" (OFFLINE).
 *
 * Format: key=value, one per line, no quoting.
 * Parseable from C, Python, shell, and Wine-side code.
 */
static int write_status_payload(const struct lota_status *status, int offline)
{
	char buf[1024];
	int len;

	len = snprintf(buf, sizeof(buf),
		       "LOTA_ATTESTED=%d\n"
		       "LOTA_OFFLINE=%d\n"
		       "LOTA_FLAGS=0x%08x\n"
		       "LOTA_VALID_UNTIL=%lu\n"
		       "LOTA_ATTEST_COUNT=%u\n"
		       "LOTA_FAIL_COUNT=%u\n"
		       "LOTA_UPDATED=%lu\n"
		       "LOTA_PID=%d\n"
		       "LOTA_PROTECTED=%d\n",
		       (status->flags & LOTA_FLAG_ATTESTED) ? 1 : 0, offline,
		       status->flags, (unsigned long)status->valid_until,
		       status->attest_count, status->fail_count,
		       (unsigned long)time(NULL), (int)getpid(),
		       atomic_load(&g_hook.self_protected) ? 1 : 0);

	if (len < 0 || (size_t)len >= sizeof(buf))
		return -ENOMEM;

	if (g_hook.refused_object[0]) {
		int add = snprintf(buf + len, sizeof(buf) - (size_t)len,
				   "LOTA_REFUSED_OBJECT=%s\n"
				   "LOTA_REFUSED_AT=%lu\n",
				   g_hook.refused_object,
				   (unsigned long)g_hook.refused_at);

		if (add < 0 || (size_t)(len + add) >= sizeof(buf))
			return -ENOMEM;
		len += add;
	}

	return atomic_write(g_hook.status_path, buf, (size_t)len);
}

static int write_status(const struct lota_status *status)
{
	return write_status_payload(status, 0);
}

/* lets the hook republish its own state without asking the agent */
static void hook_cache_status(const struct lota_status *status)
{
	pthread_once(&g_status_lock_once, status_lock_init);
	pthread_mutex_lock(&g_status_lock);
	g_hook.last_status = *status;
	pthread_mutex_unlock(&g_status_lock);
	atomic_store(&g_hook.have_status, 1);
}

/* rewrite the status file from the cache; no-op before the first status */
static void hook_publish_state(void)
{
	struct lota_status status;
	int ret;

	if (!atomic_load(&g_hook.have_status))
		return;

	pthread_once(&g_status_lock_once, status_lock_init);
	pthread_mutex_lock(&g_status_lock);
	status = g_hook.last_status;
	pthread_mutex_unlock(&g_status_lock);

	ret = write_status(&status);
	if (ret < 0)
		LOG_DBG("write_status: %s", strerror(-ret));
}

/*
 * Publish an explicit "offline" status so consumers of lota-status
 * (verify-attested.sh, server-side bridges) observe the transition to OFFLINE.
 * The token / snapshot files are also unlinked because they cannot be trusted
 * past the disconnect.
 */
static void publish_offline_status(void)
{
	struct lota_status offline = { 0 };
	int ret;

	ret = write_status_payload(&offline, 1);
	if (ret < 0)
		LOG_WRN("write_status (offline): %s", strerror(-ret));
	unlink(g_hook.token_path);
	unlink(g_hook.snapshot_path);
}

/*
 * One OFFLINE per disconnect. Every road that loses the agent ends here
 * -- the polling refresh, a failed status query, and the reconnect the
 * event-driven thread retries every refresh_sec -- so the sink states
 * the transition once and is not rewritten while the agent stays away.
 * hook_offline_clear() re-arms it on the next connect.
 */
static void hook_offline_publish(void)
{
	if (atomic_exchange(&g_hook.offline_published, 1))
		return;
	publish_offline_status();
}

static void hook_offline_clear(void)
{
	atomic_store(&g_hook.offline_published, 0);
	atomic_store(&g_hook.offline_errno, 0);
	atomic_store(&g_hook.publisher_errno, 0);
}

#ifdef LOTA_HOOK_TESTING
#define LOTA_UNUSED __attribute__((unused))
#else
#define LOTA_UNUSED
#endif

static int LOTA_UNUSED write_snapshot(uint32_t flags, const uint8_t *token_wire,
				      size_t token_size)
{
	uint8_t buf[sizeof(struct lota_snapshot_wire_hdr) + 2048];
	if (!token_wire || token_size == 0 || token_size > 2048)
		return -EINVAL;

	uint8_t *p = buf;
	lota__write_le32(p + 0, LOTA_SNAPSHOT_MAGIC);
	lota__write_le16(p + 4, (uint16_t)LOTA_SNAPSHOT_VERSION);
	lota__write_le16(p + 6, 0);
	lota__write_le32(p + 8, flags);
	lota__write_le32(p + 12, (uint32_t)token_size);
	memcpy(p + sizeof(struct lota_snapshot_wire_hdr), token_wire,
	       token_size);

	return atomic_write(g_hook.snapshot_path, buf,
			    sizeof(struct lota_snapshot_wire_hdr) + token_size);
}

/* hint for a lasting token refusal @err, or NULL */
static const char *LOTA_UNUSED hook_token_reason(int err)
{
	switch (err) {
	case LOTA_ERR_UNKNOWN_PROFILE:
		return LOTA_HOOK_ENV_PUBLISHER
			" names the publisher this title belongs to";
	case LOTA_ERR_CONSENT_REQUIRED:
		return "nobody at this machine has agreed to attest for this publisher yet";
	case LOTA_ERR_NO_TPM:
		return "this machine has no TPM to sign one with";
	case LOTA_ERR_TPM_LOCKED:
		return "the TPM is in lockout and signs nothing until it recovers";
	case LOTA_ERR_RATE_LIMITED:
		return "the agent is issuing tokens faster than it allows";
	default:
		return NULL;
	}
}

/* warn once per reason why no token was issued; repeats stay at debug */
static void LOTA_UNUSED hook_report_no_token(int err)
{
	const char *why = hook_token_reason(err);

	if (atomic_exchange(&g_hook.token_errno, err) == err) {
		LOG_DBG("the agent still issued no token: %s",
			lota_strerror(err));
		return;
	}

	if (why)
		LOG_WRN("the agent issued no token: %s -- %s",
			lota_strerror(err), why);
	else
		LOG_WRN("the agent issued no token: %s", lota_strerror(err));
}

static int LOTA_UNUSED fetch_token_wire(struct lota_client *client,
					uint8_t *wire, size_t wire_sz,
					size_t *written)
{
	struct lota_token token;
	int ret;

	if (!client || !wire || !written)
		return LOTA_ERR_INVALID_ARG;

	ret = lota_get_token(client, NULL, &token);
	if (ret != LOTA_OK) {
		/* transient: no verdict until the next round */
		if (ret == LOTA_ERR_NOT_ATTESTED)
			LOG_DBG("get_token: %s", lota_strerror(ret));
		else
			hook_report_no_token(ret);
		return ret;
	}

	atomic_store(&g_hook.token_errno, 0);

	ret = lota_token_serialize(&token, wire, wire_sz, written);
	lota_token_free(&token);
	if (ret != LOTA_OK) {
		LOG_WRN("token_serialize: %s", lota_strerror(ret));
		return ret;
	}

	return LOTA_OK;
}

/*
 * Fetch and write the binary token file.
 *
 * Requests a token without a client nonce (nonce = NULL).
 * The resulting token is still TPM-signed and proves attestation
 * at a point in time; it is just not bound to a specific server
 * challenge. Games requiring challenge-response freshness should
 * use the SDK directly.
 */
static int write_token(struct lota_client *client, uint32_t flags)
{
	uint8_t wire[2048];
	size_t written = 0;
	int ret;

	ret = fetch_token_wire(client, wire, sizeof(wire), &written);
	if (ret != LOTA_OK) {
		unlink(g_hook.token_path);
		unlink(g_hook.snapshot_path);
		return ret;
	}

	int wr = atomic_write(g_hook.token_path, wire, written);
	if (wr < 0)
		return wr;

	(void)write_snapshot(flags, wire, written);
	return 0;
}

/*
 * Probe the sockets lota_connect() would try, in its order, since it reports
 * every failure as LOTA_ERR_CONNECTION_FAILED. Names the judged path in @path;
 * returns 0 or the negative errno it refused with.
 */
static int hook_probe_socket(char *path, size_t len)
{
	const char *candidates[2];
	const char *runtime;
	char session[PATH_MAX];
	int count = 0;

	if (g_hook.socket_path[0]) {
		candidates[count++] = g_hook.socket_path;
	} else {
		candidates[count++] = LOTA_IPC_SOCKET_PATH;
		runtime = getenv("XDG_RUNTIME_DIR");
		if (runtime && runtime[0]) {
			snprintf(session, sizeof(session), "%s/lota/lota.sock",
				 runtime);
			candidates[count++] = session;
		}
	}

	snprintf(path, len, "%s", candidates[0]);

	for (int i = 0; i < count; i++) {
		struct stat st;

		if (stat(candidates[i], &st) != 0)
			continue;

		/* the first candidate that exists is the one to explain */
		snprintf(path, len, "%s", candidates[i]);
		if (access(candidates[i], R_OK | W_OK) != 0)
			return -errno;

		return -ECONNREFUSED;
	}

	return -ENOENT;
}

/* hint for @err, or NULL when the errno says enough */
static const char *hook_connect_reason(int err)
{
	switch (err) {
	case -EACCES:
	case -EPERM:
		return "the session is usually missing the lota group";
	case -ENOENT:
		return "the agent is not running, or its per-session listener is not configured for this session";
	case -ECONNREFUSED:
		return "the agent is stopped or restarting";
	case -ETIMEDOUT:
		return "the agent did not answer before the connect timeout";
	default:
		return NULL;
	}
}

/* hint for a publisher refusal @err, or NULL */
static const char *hook_publisher_reason(int err)
{
	switch (err) {
	case LOTA_ERR_UNKNOWN_PROFILE:
		return "this machine holds no enrollment for that publisher";
	case LOTA_ERR_CONSENT_REQUIRED:
		return "nobody at this machine has agreed to attest for that publisher yet";
	case LOTA_ERR_NO_KEY_SLOT:
		return "the agent has no room left for another publisher's key";
	case LOTA_ERR_INVALID_ARG:
		return "the agent would not take that identity";
	default:
		return NULL;
	}
}

/* Warn once per reason; the socket answered, so no probe */
static void hook_report_publisher(int err)
{
	const char *why = hook_publisher_reason(err);

	if (atomic_exchange(&g_hook.publisher_errno, err) == err) {
		LOG_DBG("the agent still refuses publisher %s: %s",
			g_hook.publisher, lota_strerror(err));
		return;
	}

	if (why)
		LOG_WRN("the agent will not attest for publisher %s: %s -- %s",
			g_hook.publisher, lota_strerror(err), why);
	else
		LOG_WRN("the agent will not attest for publisher %s: %s",
			g_hook.publisher, lota_strerror(err));
}

/* warn on the first refusal and each new reason; repeats stay at debug */
static void hook_report_unreachable(void)
{
	char path[PATH_MAX];
	const char *why;
	int err;

	/* the agent may have answered and refused the publisher */
	err = lota_connect_last_error();
	if (err != LOTA_OK && err != LOTA_ERR_CONNECTION_FAILED) {
		hook_report_publisher(err);
		return;
	}

	err = hook_probe_socket(path, sizeof(path));
	why = hook_connect_reason(err);

	if (atomic_exchange(&g_hook.offline_errno, err) == err) {
		LOG_DBG("agent still unreachable at %s: %s", path,
			strerror(-err));
		return;
	}

	if (why)
		LOG_WRN("cannot reach the agent at %s: %s -- %s", path,
			strerror(-err), why);
	else
		LOG_WRN("cannot reach the agent at %s: %s", path,
			strerror(-err));
}

/* Not 64 hex chars: reported and dropped, the launch goes on unnamed */
static void LOTA_UNUSED hook_publisher(const char *env)
{
	size_t len;
	size_t i;

	if (!env || !*env)
		return;

	len = strlen(env);
	if (len != LOTA_PUBLISHER_PROFILE_LEN) {
		LOG_WRN("%s is %zu characters, expected %d: ignoring it",
			LOTA_HOOK_ENV_PUBLISHER, len,
			LOTA_PUBLISHER_PROFILE_LEN);
		return;
	}

	for (i = 0; i < len; i++) {
		if (!isxdigit((unsigned char)env[i])) {
			LOG_WRN("%s is not hex at character %zu: ignoring it",
				LOTA_HOOK_ENV_PUBLISHER, i + 1);
			return;
		}
	}

	memcpy(g_hook.publisher, env, LOTA_PUBLISHER_PROFILE_LEN);
}

#undef LOTA_UNUSED

static struct lota_client *hook_connect(void)
{
	struct lota_connect_opts opts;
	struct lota_client *client;

	memset(&opts, 0, sizeof(opts));
	opts.struct_size = sizeof(opts);

	if (g_hook.socket_path[0])
		opts.socket_path = g_hook.socket_path;
	/* unnamed: no token on a multi-enrollment host */
	if (g_hook.publisher[0])
		opts.publisher_profile = g_hook.publisher;
	opts.timeout_ms = LOTA_HOOK_CONNECT_TIMEOUT_MS;

	client = lota_connect_opts(&opts);
	if (!client)
		return NULL;

	lota_set_request_timeout(client, LOTA_HOOK_REQUEST_TIMEOUT_MS);

	return client;
}

/*
 * Seconds to wait before joining the protected set. Unset or invalid is the
 * default; 0 registers on the first connect (objects carry fs-verity).
 */
static int hook_protect_delay(const char *env)
{
	char *end;
	long val;

	if (!env || !*env)
		return LOTA_HOOK_DEFAULT_PROTECT_DELAY_SEC;

	errno = 0;
	val = strtol(env, &end, 10);
	if (errno || end == env || *end || val < 0 || val > INT_MAX)
		return LOTA_HOOK_DEFAULT_PROTECT_DELAY_SEC;

	return (int)val;
}

/* Has the loader been given its @delay_sec seconds yet? */
static bool hook_protect_due(time_t init_time, int delay_sec, time_t now)
{
	if (delay_sec <= 0)
		return true;

	return now >= init_time + delay_sec;
}

/*
 * Add this process to protected_pids, which scopes every runtime gate.
 * Called after each connect, since the launch path connects before
 * refresh_once(). Once per process; the fork handler clears the latch.
 */
static void hook_register_self(void)
{
	int ret;

	if (!g_hook.client || atomic_load(&g_hook.self_protected))
		return;

	/* let the loader map its libraries first */
	if (!hook_protect_due(g_hook.init_time, g_hook.protect_delay_sec,
			      time(NULL)))
		return;

	ret = lota_protect_self(g_hook.client);
	if (ret != LOTA_OK) {
		LOG_WRN("lota_protect_self: %s", lota_strerror(ret));
		return;
	}

	atomic_store(&g_hook.self_protected, 1);
	LOG_INF("registered pid=%d for runtime enforcement", (int)getpid());
	hook_publish_state();
}

/*
 * Was a failed load the gate's refusal? Reading dlerror() would consume
 * the title's message, so judge the object: an existing readable path
 * was refused, a bare name never found is just missing.
 */
static bool hook_refusal_is_gate(const char *path)
{
	if (!path || !strchr(path, '/'))
		return false;

	return access(path, R_OK) == 0;
}

/* Keep the refusal where the player's launcher already reads. */
static void hook_record_refusal(const char *path)
{
	snprintf(g_hook.refused_object, sizeof(g_hook.refused_object), "%s",
		 path);
	g_hook.refused_at = time(NULL);
}

/*
 * Report a gate refusal on stderr and in the status file;
 * the handle and the pending dlerror() are the real dlopen()'s, untouched.
 */
LOTA_HOOK_EXPORT void *dlopen(const char *file, int mode)
{
	static void *(*real_dlopen)(const char *, int);
	void *handle;

	if (!real_dlopen) {
		real_dlopen = dlsym(RTLD_NEXT, "dlopen");
		if (!real_dlopen) {
			LOG_ERR("no dlopen underneath the hook");
			return NULL;
		}
	}

	handle = real_dlopen(file, mode);
	if (handle || !atomic_load(&g_hook.self_protected))
		return handle;

	if (hook_refusal_is_gate(file)) {
		hook_record_refusal(file);
		hook_publish_state();
		LOG_ERR("%s did not load while this process is in LOTA's protected set -- a protected process may map only objects the agent allows, so cover this one (fs-verity digest or trusted_libs) or start the title with %s longer than it takes to reach this load",
			file, LOTA_HOOK_ENV_PROTECT_DELAY);
	}

	return handle;
}

/*
 * Perform one refresh cycle.
 *
 * Reconnects to the agent if needed, queries status, writes files.
 * All failures are handled gracefully -- the hook never aborts
 * the host process.
 */
static void refresh_once(void)
{
	struct lota_status status;
	int ret;

	if (!g_hook.client) {
		g_hook.client = hook_connect();
		if (!g_hook.client) {
			hook_report_unreachable();
			hook_offline_publish();
			return;
		}
		hook_offline_clear();
		LOG_DBG("connected to agent");
	}

	hook_register_self();

	ret = lota_get_status(g_hook.client, &status);

	/* busy, not gone: keep the connection and status, ask again */
	if (ret == LOTA_ERR_TIMEOUT) {
		LOG_DBG("get_status: %s -> asking again in %ds",
			lota_strerror(ret), g_hook.refresh_sec);
		return;
	}

	if (ret != LOTA_OK) {
		LOG_DBG("get_status: %s -> reconnecting", lota_strerror(ret));
		lota_disconnect(g_hook.client);
		g_hook.client = NULL;
		hook_offline_publish();
		return;
	}

	hook_cache_status(&status);

	ret = write_status(&status);
	if (ret < 0)
		LOG_WRN("write_status: %s", strerror(-ret));

	if (status.flags & LOTA_FLAG_ATTESTED) {
		ret = write_token(g_hook.client, status.flags);
		if (ret < 0 && ret != LOTA_ERR_NOT_ATTESTED)
			LOG_DBG("write_token: %s", lota_strerror(ret));
	} else {
		unlink(g_hook.token_path);
		unlink(g_hook.snapshot_path);
	}
}

/* lota_poll_events() returns a count of events, or a negative refusal */
static bool hook_poll_failed(int ret)
{
	return ret < 0;
}

/* load-time only; the tests drive the connect and refresh path above */
#ifndef LOTA_HOOK_TESTING

/* flags change rarely; every attestation round moves counts and validity */
#define HOOK_EVENT_MASK (LOTA_EVENT_STATUS | LOTA_EVENT_ATTEST)

static void hook_status_cb(const struct lota_status *status, uint32_t events,
			   void *user_data)
{
	int ret;

	(void)events;
	(void)user_data;

	hook_cache_status(status);

	ret = write_status(status);
	if (ret < 0)
		LOG_WRN("write_status: %s", strerror(-ret));

	if (status->flags & LOTA_FLAG_ATTESTED) {
		ret = write_token(g_hook.client, status->flags);
		if (ret < 0 && ret != LOTA_ERR_NOT_ATTESTED)
			LOG_DBG("write_token: %s", lota_strerror(ret));
	} else {
		unlink(g_hook.token_path);
		unlink(g_hook.snapshot_path);
	}
}

/*
 * Refresh thread.
 * Waits for STATUS events (lota_subscribe + lota_poll_events).
 * If the agent refuses the subscription, which it should not, logs it once
 * and polls with refresh_once() every refresh_sec so the hook keeps working.
 */
static void *refresh_thread_fn(void *arg)
{
	sigset_t all;
	int ret;
	bool subscribed;

	(void)arg;

	sigfillset(&all);
	pthread_sigmask(SIG_BLOCK, &all, NULL);

	subscribed = false;

	while (g_hook.running) {
		if (!g_hook.client) {
			g_hook.client = hook_connect();
			if (!g_hook.client) {
				hook_report_unreachable();
				LOG_DBG("retrying in %ds", g_hook.refresh_sec);
				hook_offline_publish();
				sleep(g_hook.refresh_sec);
				continue;
			}
			hook_offline_clear();
			LOG_INF("connected to agent");
			refresh_once();

			ret = lota_subscribe(g_hook.client, HOOK_EVENT_MASK,
					     hook_status_cb, NULL);
			subscribed = (ret == LOTA_OK);
			if (!subscribed)
				LOG_WRN("subscribe failed: %s, falling back "
					"to polling every %ds",
					lota_strerror(ret), g_hook.refresh_sec);
		}

		/* usually too early on the first cycle; no-op once latched */
		hook_register_self();

		if (subscribed) {
			ret = lota_poll_events(g_hook.client, 5000);
		} else {
			sleep(g_hook.refresh_sec);
			refresh_once();
			ret = g_hook.client ? LOTA_OK : LOTA_ERR_NOT_CONNECTED;
		}

		if (ret == LOTA_ERR_PROTOCOL || ret == LOTA_ERR_NOT_CONNECTED ||
		    ret == -EPIPE || ret == -ECONNRESET) {
			LOG_WRN("connection lost (%s), reconnecting...",
				lota_strerror(ret));
			if (g_hook.client) {
				lota_disconnect(g_hook.client);
				g_hook.client = NULL;
			}
			subscribed = false;
			/* avoid tight loop on persistent failure */
			sleep(1);
		} else if (hook_poll_failed(ret)) {
			LOG_DBG("poll error: %s", lota_strerror(ret));
		}
	}

	return NULL;
}

static void hook_child_after_fork(void)
{
	g_hook.thread_started = 0;
	g_hook.running = 0;
	g_hook.client = NULL;
	g_hook.init_pid = 0;
	/*
	 * Forked child has a new PID, so the parent's protected_pids
	 * registration does not cover it. Clear the latch so the next
	 * refresh_once() in the child reconnects and re-issues
	 * lota_protect_self() against the child PID.
	 */
	atomic_store(&g_hook.self_protected, 0);

	/* the child is bringing up its own image: give it the same wait */
	g_hook.init_time = time(NULL);
	hook_offline_clear();
}

__attribute__((constructor)) static void lota_wine_hook_init(void)
{
	const char *env;

	/* check disable flag */
	env = getenv(LOTA_HOOK_ENV_DISABLE);
	if (env && (strcmp(env, "1") == 0 || strcmp(env, "true") == 0))
		return;

	/*
	 * LD_PRELOAD reaches every utility the launcher shell runs;
	 * skip them so none blocks on agent I/O. See should_activate().
	 */
	if (!should_activate())
		return;

	/* parse configuration from environment */
	g_hook.log_level = parse_log_level(getenv(LOTA_HOOK_ENV_LOG_LEVEL));

	env = getenv(LOTA_HOOK_ENV_SOCKET);
	if (env && env[0])
		snprintf(g_hook.socket_path, sizeof(g_hook.socket_path), "%s",
			 env);

	hook_publisher(getenv(LOTA_HOOK_ENV_PUBLISHER));

	env = getenv(LOTA_HOOK_ENV_REFRESH_SEC);
	g_hook.refresh_sec = (env && atoi(env) > 0) ?
				     atoi(env) :
				     LOTA_HOOK_DEFAULT_REFRESH_SEC;

	/* the registration delay counts from here */
	g_hook.init_time = time(NULL);
	g_hook.protect_delay_sec =
		hook_protect_delay(getenv(LOTA_HOOK_ENV_PROTECT_DELAY));

	/* settle on a token directory the player owns */
	if (setup_token_dir() < 0)
		return;

	report_unshared_token_dir();

	snprintf(g_hook.status_path, sizeof(g_hook.status_path), "%s/%s",
		 g_hook.token_dir, LOTA_HOOK_STATUS_FILE);
	snprintf(g_hook.token_path, sizeof(g_hook.token_path), "%s/%s",
		 g_hook.token_dir, LOTA_HOOK_TOKEN_FILE);
	snprintf(g_hook.snapshot_path, sizeof(g_hook.snapshot_path), "%s/%s",
		 g_hook.token_dir, LOTA_HOOK_SNAPSHOT_FILE);

	/* export token directory for wine-side discovery */
	setenv(LOTA_HOOK_ENV_TOKEN_DIR, g_hook.token_dir, 0);

	LOG_INF("initializing (token_dir=%s, refresh=%ds, protect_delay=%ds)",
		g_hook.token_dir, g_hook.refresh_sec, g_hook.protect_delay_sec);

	g_hook.init_pid = getpid();
	pthread_atfork(NULL, NULL, hook_child_after_fork);

	/*
	 * Connect + first refresh are deferred to the background thread.
	 * The constructor must return immediately so the host process
	 * (game binary or its launcher shell) does not block on agent
	 * I/O. The thread's first loop iteration drives hook_connect()
	 * and refresh_once() and retries every refresh_sec seconds while
	 * the agent is unreachable.
	 */
	g_hook.running = 1;
	if (pthread_create(&g_hook.thread, NULL, refresh_thread_fn, NULL) !=
	    0) {
		LOG_ERR("pthread_create: %s", strerror(errno));
		g_hook.running = 0;
		return;
	}
	g_hook.thread_started = 1;

	LOG_INF("hook active (pid=%d)", (int)getpid());
}

__attribute__((destructor)) static void lota_wine_hook_fini(void)
{
	if (g_hook.init_pid != getpid())
		return;

	if (!g_hook.thread_started && !g_hook.client)
		return;

	LOG_DBG("shutting down");

	g_hook.running = 0;

	if (g_hook.thread_started) {
		pthread_join(g_hook.thread, NULL);
		g_hook.thread_started = 0;
	}

	if (g_hook.client) {
		lota_disconnect(g_hook.client);
		g_hook.client = NULL;
	}

	/*
	 * Do NOT unlink the status / token / snapshot files here. The
	 * Steam launch chain inherits LD_PRELOAD into every fork+exec;
	 * each one runs its own constructor and destructor, all sharing
	 * the same $XDG_RUNTIME_DIR/lota-hook/ token sink. A helper that
	 * exits before the game binary would otherwise unlink the
	 * artefacts the still-running cs2 hook just wrote, leaving the
	 * consumer (verify-attested.sh, server-side bridge) with a
	 * vanished token while the game is still attested.
	 *
	 * The OFFLINE contract is owned by publish_offline_status() in
	 * refresh_once(): when the agent becomes unreachable the hook
	 * actively rewrites lota-status with LOTA_ATTESTED=0 and
	 * unlinks the token / snapshot files. Stale artefacts from a
	 * prior session are overwritten by the next refresh_once() on
	 * the next launch.
	 */

	LOG_INF("hook detached");
}

#endif /* !LOTA_HOOK_TESTING */

/* exported query functions */

LOTA_HOOK_EXPORT int lota_hook_active(void)
{
	return g_hook.thread_started && g_hook.running;
}

LOTA_HOOK_EXPORT const char *lota_hook_status_path(void)
{
	if (!g_hook.status_path[0])
		return NULL;
	return g_hook.status_path;
}

LOTA_HOOK_EXPORT const char *lota_hook_token_path(void)
{
	if (!g_hook.token_path[0])
		return NULL;
	return g_hook.token_path;
}
