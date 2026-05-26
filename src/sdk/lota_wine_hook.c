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

#include "../../include/lota_endian.h"
#include "../../include/lota_gaming.h"
#include "../../include/lota_snapshot.h"
#include "../../include/lota_wine_hook.h"

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
	char socket_path[PATH_MAX];    /* empty -> default */
	char status_path[PATH_MAX];
	char token_path[PATH_MAX];
	char snapshot_path[PATH_MAX]; /* atomic snapshot file (flags + token) */
	pid_t init_pid;
} g_hook;

#define HOOK_PREFIX "lota-hook"

#define HOOK_LOG(level, fmt, ...)                                              \
	do {                                                                   \
		if ((level) >= g_hook.log_level)                               \
			fprintf(stderr, HOOK_PREFIX ": " fmt "\n",             \
				##__VA_ARGS__);                                \
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
#define LOTA_HOOK_FHS_SYSTEM_PREFIXES                                          \
	"/usr/,/bin/,/sbin/,/lib/,/lib64/,"                                    \
	"/run/host/usr/,/run/host/bin/,/run/host/sbin/,"                       \
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
 * delegates the policy decision to policy_should_activate(). Two
 * operator-visible overrides apply on top of the FHS default:
 *
 *   LOTA_HOOK_ACTIVATE_PATH=~/.local/share/Steam,/opt/games
 *     If set and non-empty, the hook activates ONLY when
 *     /proc/self/exe begins with one of the comma-separated
 *     prefixes. Use this to pin attestation to a specific install
 *     tree rather than the FHS default.
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

	if (read_self_exe(exe, sizeof(exe)) != 0 || !exe[0])
		return true;

	return policy_should_activate(exe, getenv("LOTA_HOOK_ACTIVATE_PATH"),
				      getenv("LOTA_HOOK_SKIP_PATH"));
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
 * Determine the token output directory.
 *
 * Priority:
 *   1. LOTA_HOOK_TOKEN_DIR   (explicit override)
 *   2. $XDG_RUNTIME_DIR/lota (standard runtime directory)
 *   3. /tmp/lota-<uid>       (fallback)
 *
 * Writes result into g_hook.token_dir
 */
static void resolve_token_dir(void)
{
	const char *env;

	env = getenv(LOTA_HOOK_ENV_TOKEN_DIR);
	if (env && env[0]) {
		snprintf(g_hook.token_dir, sizeof(g_hook.token_dir), "%s", env);
		return;
	}

	env = getenv("XDG_RUNTIME_DIR");
	if (env && env[0]) {
		snprintf(g_hook.token_dir, sizeof(g_hook.token_dir), "%s/lota",
			 env);
		return;
	}

	snprintf(g_hook.token_dir, sizeof(g_hook.token_dir), "/tmp/lota-%u",
		 (unsigned)getuid());
}

/*
 * Create and validate the token directory.
 *
 * Security requirements:
 *  - path must resolve to a real directory (no symlink traversal)
 *  - owned by current uid
 *  - mode forced to 0700 (private attestation artifacts)
 *
 * Returns 0 on success, negative errno on failure.
 */
static int ensure_token_dir(void)
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

	if ((st.st_mode & 0777) != 0700) {
		if (fchmod(dirfd, 0700) < 0) {
			int err = errno;
			close(dirfd);
			LOG_ERR("fchmod 0700 %s: %s", g_hook.token_dir,
				strerror(err));
			return -err;
		}
	}

	close(dirfd);

	return 0;
}

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
 * Format: key=value, one per line, no quoting.
 * Parseable from C, Python, shell, and Wine-side code.
 */
static int write_status(const struct lota_status *status)
{
	char buf[512];
	int len;

	len = snprintf(buf, sizeof(buf),
		       "LOTA_ATTESTED=%d\n"
		       "LOTA_FLAGS=0x%08x\n"
		       "LOTA_VALID_UNTIL=%lu\n"
		       "LOTA_ATTEST_COUNT=%u\n"
		       "LOTA_FAIL_COUNT=%u\n"
		       "LOTA_UPDATED=%lu\n"
		       "LOTA_PID=%d\n",
		       (status->flags & LOTA_FLAG_ATTESTED) ? 1 : 0,
		       status->flags, (unsigned long)status->valid_until,
		       status->attest_count, status->fail_count,
		       (unsigned long)time(NULL), (int)getpid());

	if (len < 0 || (size_t)len >= sizeof(buf))
		return -ENOMEM;

	return atomic_write(g_hook.status_path, buf, (size_t)len);
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
		LOG_DBG("get_token: %s", lota_strerror(ret));
		return ret;
	}

	ret = lota_token_serialize(&token, wire, wire_sz, written);
	lota_token_free(&token);
	if (ret != LOTA_OK) {
		LOG_WRN("token_serialize: %s", lota_strerror(ret));
		return ret;
	}

	return LOTA_OK;
}

#undef LOTA_UNUSED

/* Runtime-only: refresh, thread, fork safety, constructor/destructor */
#ifndef LOTA_HOOK_TESTING

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

static struct lota_client *hook_connect(void)
{
	struct lota_connect_opts opts;

	memset(&opts, 0, sizeof(opts));

	if (g_hook.socket_path[0])
		opts.socket_path = g_hook.socket_path;
	opts.timeout_ms = LOTA_HOOK_CONNECT_TIMEOUT_MS;

	return lota_connect_opts(&opts);
}

/*
 * Perform one refresh cycle.
 *
 * Reconnects to the agent if needed, queries status, writes files.
 * All failures are handled gracefully -- the hook never aborts
 * the host process.
 */
/*
 * Publish an explicit "offline" status so consumers of lota-status
 * (verify-attested.sh, server-side bridges) observe the transition
 * to OFFLINE. The token / snapshot files are also unlinked because
 * they cannot be trusted past the disconnect.
 */
static void publish_offline_status(void)
{
	struct lota_status offline = {0};
	int ret;

	offline.valid_until = (uint64_t)time(NULL);
	ret = write_status(&offline);
	if (ret < 0)
		LOG_WRN("write_status (offline): %s", strerror(-ret));
	unlink(g_hook.token_path);
	unlink(g_hook.snapshot_path);
}

static void refresh_once(void)
{
	struct lota_status status;
	int ret;

	if (!g_hook.client) {
		g_hook.client = hook_connect();
		if (!g_hook.client) {
			LOG_DBG("agent not available");
			publish_offline_status();
			return;
		}
		LOG_DBG("connected to agent");
	}

	ret = lota_get_status(g_hook.client, &status);
	if (ret != LOTA_OK) {
		LOG_DBG("get_status: %s -> reconnecting", lota_strerror(ret));
		lota_disconnect(g_hook.client);
		g_hook.client = NULL;
		publish_offline_status();
		return;
	}

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

static void hook_status_cb(const struct lota_status *status, uint32_t events,
			   void *user_data)
{
	int ret;

	(void)events;
	(void)user_data;

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
 * Refresh thread. Prefers the event-driven path (lota_subscribe +
 * lota_poll_events) and falls back to a fixed-cadence
 * refresh_once() poll when SUBSCRIBE is denied. The agent restricts
 * SUBSCRIBE to its own PID by design (see ipc.c:ipc_client_is_agent_self),
 * so EACCES is the steady-state outcome for any external client and
 * must not produce a warning per process.
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
				LOG_DBG("agent not available, retrying in %ds",
					g_hook.refresh_sec);
				sleep(g_hook.refresh_sec);
				continue;
			}
			LOG_INF("connected to agent");
			refresh_once();

			ret = lota_subscribe(g_hook.client, LOTA_EVENT_STATUS,
					     hook_status_cb, NULL);
			subscribed = (ret == LOTA_OK);
			if (!subscribed) {
				if (ret == LOTA_ERR_ACCESS_DENIED)
					LOG_DBG("subscribe denied (agent-only "
						"by design), polling every %ds",
						g_hook.refresh_sec);
				else
					LOG_WRN("subscribe failed: %s, "
						"falling back to polling",
						lota_strerror(ret));
			}
		}

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
		} else if (ret != LOTA_OK && ret != LOTA_ERR_TIMEOUT) {
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
}

__attribute__((constructor)) static void lota_wine_hook_init(void)
{
	const char *env;

	/* check disable flag */
	env = getenv(LOTA_HOOK_ENV_DISABLE);
	if (env && (strcmp(env, "1") == 0 || strcmp(env, "true") == 0))
		return;

	/*
	 * LD_PRELOAD is inherited by every fork+exec inside the launcher
	 * shell, including throwaway POSIX utilities. Skip those so the
	 * hook never blocks `basename cs2.sh` or its peers on agent I/O.
	 * Operators can override with LOTA_HOOK_ACTIVATE_COMM (positive
	 * allowlist) or LOTA_HOOK_SKIP_COMM (extend the built-in skip
	 * list); see should_activate() for the policy.
	 */
	if (!should_activate())
		return;

	/* parse configuration from environment */
	g_hook.log_level = parse_log_level(getenv(LOTA_HOOK_ENV_LOG_LEVEL));

	env = getenv(LOTA_HOOK_ENV_SOCKET);
	if (env && env[0])
		snprintf(g_hook.socket_path, sizeof(g_hook.socket_path), "%s",
			 env);

	env = getenv(LOTA_HOOK_ENV_REFRESH_SEC);
	g_hook.refresh_sec =
	    (env && atoi(env) > 0) ? atoi(env) : LOTA_HOOK_DEFAULT_REFRESH_SEC;

	/* resolve and create token directory */
	resolve_token_dir();

	if (ensure_token_dir() < 0)
		return;

	snprintf(g_hook.status_path, sizeof(g_hook.status_path), "%s/%s",
		 g_hook.token_dir, LOTA_HOOK_STATUS_FILE);
	snprintf(g_hook.token_path, sizeof(g_hook.token_path), "%s/%s",
		 g_hook.token_dir, LOTA_HOOK_TOKEN_FILE);
	snprintf(g_hook.snapshot_path, sizeof(g_hook.snapshot_path), "%s/%s",
		 g_hook.token_dir, LOTA_HOOK_SNAPSHOT_FILE);

	/* export token directory for wine-side discovery */
	setenv(LOTA_HOOK_ENV_TOKEN_DIR, g_hook.token_dir, 0);

	LOG_INF("initializing (token_dir=%s, refresh=%ds)", g_hook.token_dir,
		g_hook.refresh_sec);

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

/*
 * Safely unlink a path after verifying it is a regular file
 * owned by the current user (not a symlink).
 */
static void safe_unlink(const char *path)
{
	struct stat st;

	if (lstat(path, &st) < 0)
		return;
	if (S_ISLNK(st.st_mode) || st.st_uid != getuid())
		return;
	unlink(path);
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

	if (g_hook.status_path[0])
		safe_unlink(g_hook.status_path);
	if (g_hook.token_path[0])
		safe_unlink(g_hook.token_path);
	if (g_hook.snapshot_path[0])
		safe_unlink(g_hook.snapshot_path);

	LOG_INF("hook detached");
}

#endif /* !LOTA_HOOK_TESTING */

/* exported query functions */

int lota_hook_active(void)
{
	return g_hook.thread_started && g_hook.running;
}

const char *lota_hook_status_path(void)
{
	if (!g_hook.status_path[0])
		return NULL;
	return g_hook.status_path;
}

const char *lota_hook_token_path(void)
{
	if (!g_hook.token_path[0])
		return NULL;
	return g_hook.token_path;
}
