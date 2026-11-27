/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * LOTA Agent - IPC Server Implementation
 * Unix socket server for local attestation queries.
 */

#include "attest_aggregate.h"
#include "boot_evidence.h"
#include "enroll.h"
#include "hardening.h"
#include "ipc.h"
#include "ipc_privilege.h"
#include "ipc_payload.h"
#include "measure_report.h"
#include "standing_answer.h"
#include "protect_pids.h"
#include "registry.h"
#include "status_flags.h"
#include "terminate_policy.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <poll.h>
#include <sys/syscall.h>
#include <openssl/crypto.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/inotify.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>
#include <sys/types.h>

#include "../../include/lota.h"
#include "../../include/lota_ipc.h"
#include "dbus.h"
#include "journal.h"
#include "quote.h"
#include "attest.h"
#include "token_gate.h"
#include "tpm.h"
#include "agent.h"
#include "runtime_image_measure.h"
#include "../../include/lota_runtime_protect_digest.h"
#include "../../include/lota_token_quote_nonce.h"
#include "bpf_loader.h"
#include "lota_endian.h"
#include "socket_watch.h"

_Static_assert(MEASURE_REPORT_STATEMENT_MAX >=
		       MEASURE_REPORT_PREFIX_MAX + LOTA_RT_REASON_MAX,
	       "a measurement line cuts its reason");

#define MAX_EVENTS 64
#define MAX_CONNECTED_CLIENTS 2048

#define IPC_CLIENT_FD_EMPTY (-1)
#define IPC_CLIENT_FD_TOMB (-2)
#define SOCKET_DIR "/run/lota"
#define LOTA_GROUP_NAME "lota"

#ifndef SO_PEERPIDFD
#define SO_PEERPIDFD 77
#endif

/*
 * Events any connected client may subscribe to. PROFILE is reserved
 * to the attestation loop, which SYNC_ATTEST subscribes.
 */
#define IPC_EVENT_PUBLIC \
	(LOTA_IPC_EVENT_STATUS | LOTA_IPC_EVENT_ATTEST | LOTA_IPC_EVENT_MODE)

#define PROTECT_PID_RATE_LIMIT 60 /* requests */
#define PROTECT_PID_RATE_WINDOW_SEC 60 /* per minute */

struct uid_rate {
	uid_t uid;
	int count;
	uint64_t window_start_sec;
};

#define MAX_RATE_ENTRIES 256

/* how often the status word is refolded while it may move unannounced */
#define IPC_STATUS_TICK_NS (1000ULL * 1000 * 1000)
static struct uid_rate token_rate_table[MAX_RATE_ENTRIES];
static int token_rate_count = 0;
static uint64_t token_last_table_full_warn_sec = 0;

static struct uid_rate protect_pid_rate_table[MAX_RATE_ENTRIES];
static int protect_pid_rate_count = 0;
static uint64_t protect_pid_last_table_full_warn_sec = 0;

static int u32_cmp(const void *a, const void *b);
static void client_attestation_view(const struct ipc_context *ctx,
				    const struct ipc_client *client,
				    uint32_t *flags, uint64_t *valid_until);
static uint32_t runtime_coverage_fold(uint32_t flags);
static void runtime_protect_catch_up(void);
static int build_canonical_runtime_pid_list(uint32_t **out_pids,
					    uint32_t *out_count);

static void ipc_secure_bzero(void *ptr, size_t len)
{
	if (ptr && len)
		OPENSSL_cleanse(ptr, len);
}

static uint64_t monotonic_now_sec(void)
{
	struct timespec ts;
	if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0)
		return (uint64_t)ts.tv_sec;

	return (uint64_t)time(NULL);
}

/*
 * Check and update a per-UID fixed-window rate limiter.
 * Returns 0 if allowed, -1 if rate limited.
 */
static int check_rate_limit(struct uid_rate *table, int *entry_count,
			    int request_limit, int window_sec,
			    uint64_t *last_table_full_warn_sec, uid_t uid,
			    const char *name)
{
	uint64_t now = monotonic_now_sec();

	if (!table || !entry_count || request_limit <= 0 || window_sec <= 0 ||
	    !last_table_full_warn_sec || !name)
		return -1;

	for (int i = 0; i < *entry_count; i++) {
		if (table[i].uid == uid) {
			if (now < table[i].window_start_sec ||
			    now - table[i].window_start_sec >=
				    (uint64_t)window_sec) {
				table[i].count = 1;
				table[i].window_start_sec = now;
				return 0;
			}
			if (table[i].count >= request_limit)
				return -1;
			table[i].count++;
			return 0;
		}
	}

	if (*entry_count < MAX_RATE_ENTRIES) {
		table[*entry_count].uid = uid;
		table[*entry_count].count = 1;
		table[*entry_count].window_start_sec = now;
		(*entry_count)++;
		return 0;
	}

	/*
	 * Table full: reuse only an entry whose window has expired.
	 * Evicting a live one would let a caller fill the table to
	 * reset a uid's count.
	 */
	for (int i = 0; i < *entry_count; i++) {
		if (now < table[i].window_start_sec ||
		    now - table[i].window_start_sec >= (uint64_t)window_sec) {
			table[i].uid = uid;
			table[i].count = 1;
			table[i].window_start_sec = now;
			return 0;
		}
	}

	if (now >= *last_table_full_warn_sec + 60) {
		*last_table_full_warn_sec = now;
		lota_warn("%s rate limiter table exhausted (%d entries); "
			  "refusing new UID %u",
			  name, *entry_count, (unsigned)uid);
	}

	return -1;
}

static int check_get_token_rate_limit(uid_t uid)
{
	return check_rate_limit(token_rate_table, &token_rate_count,
				TOKEN_RATE_LIMIT, TOKEN_RATE_WINDOW_SEC,
				&token_last_table_full_warn_sec, uid,
				"IPC GET_TOKEN");
}

static int check_protect_pid_rate_limit(uid_t uid)
{
	return check_rate_limit(protect_pid_rate_table, &protect_pid_rate_count,
				PROTECT_PID_RATE_LIMIT,
				PROTECT_PID_RATE_WINDOW_SEC,
				&protect_pid_last_table_full_warn_sec, uid,
				"IPC PROTECT_PID");
}

/* recv_buf and send_buf each hold one maximum-size IPC message */
struct ipc_client {
	int fd;
	uid_t peer_uid; /* authenticated peer UID via SO_PEERCRED */
	pid_t peer_pid; /* authenticated peer PID */
	uint64_t peer_start_time_ticks; /* /proc/<pid>/stat field 22 */
	uint8_t recv_buf[LOTA_IPC_REQUEST_SIZE + LOTA_IPC_MAX_PAYLOAD];
	size_t recv_len;
	uint8_t send_buf[LOTA_IPC_RESPONSE_SIZE + LOTA_IPC_MAX_PAYLOAD];
	size_t send_len;
	size_t send_offset;
	bool subscribed; /* client subscribed to notifications */
	uint32_t event_mask; /* LOTA_IPC_EVENT_* subscription mask */
	bool notify_pending; /* notification queued behind current send */
	uint32_t pending_events; /* accumulated LOTA_IPC_EVENT_* while busy */
	uint32_t told_flags; /* status word of the last answer it was pushed */
	bool shutdown_on_flush; /* trigger graceful daemon stop after reply */

	/* per-connection GET_TOKEN budget, a fixed window like the uid table */
	int token_count;
	uint64_t token_window_start_sec;

	/*
	 * The publisher set by SET_PROFILE, borrowed from ctx->profiles, which
	 * a reload replaces. Not const: unbinding maintains its session count.
	 */
	struct attest_target *profile;

	/*
	 * Its id, from which ipc_set_profiles() binds again when the list is
	 * replaced. Empty when this connection named no publisher.
	 */
	char profile_id[LOTA_PROFILE_ID_LEN];

	/* an accepted SYNC_ATTEST: this is the agent's attestation loop */
	bool attest_peer;

	/*
	 * Last token answer journalled; an unchanged one is not written again.
	 * Per connection, so a reconnect's refusal is news.
	 */
	struct standing_answer token_answer;

	struct ipc_client *next;
};

/*
 * Per-session fixed-window budget for GET_TOKEN.
 * Returns 0 if allowed, -1 if rate limited.
 *
 * The state lives on the connection, so there is no table to exhaust.
 * The per-UID ceiling bounds a caller that opens more connections.
 */
static int check_session_token_rate_limit(struct ipc_client *client)
{
	uint64_t now = monotonic_now_sec();

	if (!client)
		return -1;

	/* CLOCK_MONOTONIC does not go back: covers the fallback clock */
	if (now < client->token_window_start_sec ||
	    now - client->token_window_start_sec >=
		    (uint64_t)TOKEN_RATE_WINDOW_SEC) {
		client->token_count = 1;
		client->token_window_start_sec = now;
		return 0;
	}

	if (client->token_count >= TOKEN_RATE_LIMIT_PER_SESSION)
		return -1;

	client->token_count++;
	return 0;
}

static int read_pid_start_time_ticks(pid_t pid, uint64_t *start_time_ticks)
{
	char path[64];
	FILE *fp;
	char line[4096];
	char *rparen;
	char *field;
	char *saveptr = NULL;
	int field_index = 3;

	if (!start_time_ticks || pid <= 0)
		return -EINVAL;

	snprintf(path, sizeof(path), "/proc/%d/stat", (int)pid);
	fp = fopen(path, "r");
	if (!fp)
		return -errno;

	if (!fgets(line, sizeof(line), fp)) {
		int err = ferror(fp) ? -errno : -EIO;
		fclose(fp);
		return err;
	}
	fclose(fp);

	rparen = strrchr(line, ')');
	if (!rparen)
		return -EINVAL;

	field = rparen + 2;
	if (*field == '\0')
		return -EINVAL;

	for (char *tok = strtok_r(field, " ", &saveptr); tok;
	     tok = strtok_r(NULL, " ", &saveptr), field_index++) {
		if (field_index == 22) {
			char *end = NULL;
			unsigned long long val;

			errno = 0;
			val = strtoull(tok, &end, 10);
			if (errno != 0 || end == tok || (end && *end != '\0'))
				return -EINVAL;

			*start_time_ticks = (uint64_t)val;
			return 0;
		}
	}

	return -EINVAL;
}

static int read_pid_exe_path(pid_t pid, char *out, size_t out_len)
{
	char proc_path[64];
	ssize_t n;

	if (!out || out_len < 2 || pid <= 0)
		return -EINVAL;

	snprintf(proc_path, sizeof(proc_path), "/proc/%d/exe", (int)pid);
	n = readlink(proc_path, out, out_len - 1);
	if (n < 0)
		return -errno;
	if (n == 0)
		return -EINVAL;

	out[n] = '\0';

	if (strstr(out, " (deleted)") != NULL)
		return -ENOENT;

	if (out[0] != '/')
		return -EINVAL;

	return 0;
}

static int is_allowed_verity_digest(const struct lota_verity_digest_key *key)
{
	if (!key || !LOTA_VERITY_DIGEST_LEN_SUPPORTED(key->len))
		return 0;

	if (!g_agent.policy_verity_digests ||
	    g_agent.policy_verity_digest_count <= 0)
		return 0;

	for (int i = 0; i < g_agent.policy_verity_digest_count; i++) {
		const struct lota_verity_digest_key *allowed =
			&g_agent.policy_verity_digests[i];
		if (!allowed || allowed->len != key->len)
			continue;
		if (CRYPTO_memcmp(allowed->digest, key->digest, key->len) == 0)
			return 1;
	}

	return 0;
}

static int ipc_client_has_trusted_executable(const struct ipc_client *client)
{
	char exe_path[PATH_MAX];
	struct lota_verity_digest_key digest = { 0 };
	int ret;

	if (!client)
		return 0;

	ret = read_pid_exe_path(client->peer_pid, exe_path, sizeof(exe_path));
	if (ret < 0)
		return 0;

	ret = bpf_loader_measure_verity_digest(exe_path, &digest);
	if (ret < 0)
		return 0;

	return is_allowed_verity_digest(&digest);
}

static uint32_t client_map_hash_fd(int fd)
{
	return (uint32_t)fd * 2654435761u;
}

static void client_map_init(struct ipc_context *ctx)
{
	for (size_t i = 0; i < IPC_CLIENT_MAP_SIZE; i++) {
		ctx->client_map[i].fd = IPC_CLIENT_FD_EMPTY;
		ctx->client_map[i].client = NULL;
	}
}

static int client_map_insert(struct ipc_context *ctx, int fd,
			     struct ipc_client *client)
{
	uint32_t mask = (uint32_t)IPC_CLIENT_MAP_SIZE - 1;
	uint32_t idx = client_map_hash_fd(fd) & mask;
	int tomb = -1;

	for (uint32_t probe = 0; probe < IPC_CLIENT_MAP_SIZE; probe++) {
		struct ipc_client_map_entry *e = &ctx->client_map[idx];

		if (e->fd == fd) {
			e->client = client;
			return 0;
		}

		if (e->fd == IPC_CLIENT_FD_EMPTY) {
			if (tomb >= 0)
				e = &ctx->client_map[tomb];
			e->fd = fd;
			e->client = client;
			return 0;
		}

		if (e->fd == IPC_CLIENT_FD_TOMB && tomb < 0)
			tomb = (int)idx;

		idx = (idx + 1) & mask;
	}

	if (tomb >= 0) {
		struct ipc_client_map_entry *e = &ctx->client_map[tomb];
		e->fd = fd;
		e->client = client;
		return 0;
	}

	return -1;
}

static struct ipc_client *client_map_find(struct ipc_context *ctx, int fd)
{
	uint32_t mask = (uint32_t)IPC_CLIENT_MAP_SIZE - 1;
	uint32_t idx = client_map_hash_fd(fd) & mask;

	for (uint32_t probe = 0; probe < IPC_CLIENT_MAP_SIZE; probe++) {
		struct ipc_client_map_entry *e = &ctx->client_map[idx];
		if (e->fd == fd)
			return e->client;
		if (e->fd == IPC_CLIENT_FD_EMPTY)
			return NULL;
		idx = (idx + 1) & mask;
	}

	return NULL;
}

static void client_map_remove(struct ipc_context *ctx, int fd)
{
	uint32_t mask = (uint32_t)IPC_CLIENT_MAP_SIZE - 1;
	uint32_t idx = client_map_hash_fd(fd) & mask;

	for (uint32_t probe = 0; probe < IPC_CLIENT_MAP_SIZE; probe++) {
		struct ipc_client_map_entry *e = &ctx->client_map[idx];
		if (e->fd == fd) {
			e->fd = IPC_CLIENT_FD_TOMB;
			e->client = NULL;
			return;
		}
		if (e->fd == IPC_CLIENT_FD_EMPTY)
			return;
		idx = (idx + 1) & mask;
	}
}

_Static_assert(LOTA_IPC_MAX_PAYLOAD == 8192,
	       "IPC payload cap is the fixed 8 KiB practical socket limit");
_Static_assert(LOTA_IPC_MAX_PAYLOAD <= UINT16_MAX,
	       "IPC payload cap must fit the wire's 16-bit size fields");
_Static_assert(LOTA_IPC_TOKEN_MAX_SIZE <= LOTA_IPC_MAX_PAYLOAD,
	       "maximum GET_TOKEN payload must fit the IPC parser buffer");

/*
 * LOTA_IPC_MAX_PROFILES sizes the SYNC_ATTEST frame in the public IPC header,
 * which does not see the configuration parser.
 */
_Static_assert(LOTA_IPC_MAX_PROFILES == LOTA_CONFIG_MAX_PROFILES,
	       "the IPC profile cap must match the configurable profile count");
_Static_assert(LOTA_IPC_ATTEST_SYNC_MAX_SIZE <= LOTA_IPC_MAX_PAYLOAD,
	       "maximum SYNC_ATTEST payload must fit the IPC parser buffer");
_Static_assert(LOTA_IPC_ATTEST_SYNC_RESPONSE_MAX_SIZE <= LOTA_IPC_MAX_PAYLOAD,
	       "maximum SYNC_ATTEST response must fit the IPC parser buffer");

/*
 * Whether a process still answers on @path. A socket file survives an unclean
 * stop, so only connect() can tell.
 *
 * Returns 1 when something answers, 0 for a leftover (ECONNREFUSED) or a clean
 * slate (ENOENT), and -errno when socket() or connect() fails otherwise.
 */
static int socket_has_live_listener(const char *path)
{
	struct sockaddr_un addr;
	int fd, ret;

	fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -errno;

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);

	ret = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
	if (ret == 0) {
		close(fd);
		return 1;
	}

	ret = errno;
	close(fd);

	if (ret == ECONNREFUSED || ret == ENOENT)
		return 0;
	return -ret;
}

/*
 * 0 when @path may be taken; otherwise the reason it is refused.
 */
static int socket_path_free(const char *path)
{
	int ret = socket_has_live_listener(path);

	if (ret > 0) {
		lota_err("%s already has a listener; refusing to take it over",
			 path);
		return -EADDRINUSE;
	}
	if (ret < 0)
		lota_err("cannot probe %s (%s); refusing to take it over", path,
			 strerror(-ret));
	return ret;
}

static int set_nonblocking(int fd)
{
	int flags = fcntl(fd, F_GETFL, 0);
	if (flags < 0)
		return -errno;
	if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0)
		return -errno;
	return 0;
}

/*
 * Bind a listener at the primary path, replacing the file there.
 * The caller decides whether taking the path over is legitimate.
 */
static int open_primary_listener(int *out_fd)
{
	struct sockaddr_un addr;
	struct group *grp;
	int fd, ret;

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0)
		return -errno;

	ret = set_nonblocking(fd);
	if (ret < 0)
		goto err_close;

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, LOTA_IPC_SOCKET_PATH, sizeof(addr.sun_path) - 1);

	unlink(LOTA_IPC_SOCKET_PATH);

	/* restrict socket access to owner (root) and the 'lota' group */
	{
		mode_t old_umask = umask(0117);
		ret = bind(fd, (struct sockaddr *)&addr, sizeof(addr));
		umask(old_umask);
	}
	if (ret < 0) {
		ret = -errno;
		lota_err("bind(%s) failed: %s", LOTA_IPC_SOCKET_PATH,
			 strerror(-ret));
		goto err_close;
	}

	grp = getgrnam(LOTA_GROUP_NAME);
	if (grp) {
		if (chown(LOTA_IPC_SOCKET_PATH, 0, grp->gr_gid) < 0)
			lota_warn("chown(%s, 0, %d) failed: %s",
				  LOTA_IPC_SOCKET_PATH, grp->gr_gid,
				  strerror(errno));
	} else {
		lota_warn("group '%s' not found, socket accessible to "
			  "current group only",
			  LOTA_GROUP_NAME);
	}

	if (listen(fd, 16) < 0) {
		ret = -errno;
		lota_err("listen() failed: %s", strerror(-ret));
		unlink(LOTA_IPC_SOCKET_PATH);
		goto err_close;
	}

	*out_fd = fd;
	return 0;

err_close:
	close(fd);
	return ret;
}

/*
 * Record the (device, inode) at the socket path. The fd outlives an unlink,
 * so a changed pair shows that clients connect somewhere else.
 */
static void record_listen_identity(struct ipc_context *ctx)
{
	struct stat st;

	if (stat(LOTA_IPC_SOCKET_PATH, &st) < 0) {
		ctx->listen_dev = 0;
		ctx->listen_ino = 0;
		return;
	}

	ctx->listen_dev = st.st_dev;
	ctx->listen_ino = st.st_ino;
}

static int ensure_socket_dir(void)
{
	int dirfd;
	struct stat st;
	struct group *grp;
	gid_t lota_gid = (gid_t)-1;
	int err;

	grp = getgrnam(LOTA_GROUP_NAME);
	if (grp)
		lota_gid = grp->gr_gid;

	if (mkdir(SOCKET_DIR, 0750) < 0 && errno != EEXIST)
		return -errno;

	dirfd = open(SOCKET_DIR,
		     O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
	if (dirfd < 0)
		return -errno;

	if (fstat(dirfd, &st) < 0) {
		err = errno;
		close(dirfd);
		return -err;
	}

	if (!S_ISDIR(st.st_mode)) {
		close(dirfd);
		return -ENOTDIR;
	}

	if (st.st_uid != 0) {
		close(dirfd);
		return -EACCES;
	}

	if ((st.st_mode & 0777) != 0750) {
		if (fchmod(dirfd, 0750) < 0) {
			err = errno;
			close(dirfd);
			return -err;
		}
	}

	if (lota_gid != (gid_t)-1 && st.st_gid != lota_gid) {
		if (fchown(dirfd, (uid_t)-1, lota_gid) < 0) {
			err = errno;
			close(dirfd);
			lota_warn("fchown(%s, -1, %u) failed: %s", SOCKET_DIR,
				  (unsigned)lota_gid, strerror(err));
			return -err;
		}
	}

	close(dirfd);

	return 0;
}

static struct ipc_client *client_create(struct ipc_context *ctx, int fd,
					uid_t uid, pid_t pid)
{
	struct ipc_client *client;

	if (ctx->client_count >= MAX_CONNECTED_CLIENTS) {
		lota_warn("Max clients (%d) reached, rejecting connection",
			  MAX_CONNECTED_CLIENTS);
		return NULL;
	}

	client = calloc(1, sizeof(*client));
	if (!client)
		return NULL;

	client->fd = fd;
	client->peer_uid = uid;
	client->peer_pid = pid;

	if (client_map_insert(ctx, fd, client) < 0) {
		free(client);
		return NULL;
	}

	client->next = ctx->client_list;
	ctx->client_list = client;
	ctx->client_count++;

	return client;
}

static struct ipc_client *client_find(struct ipc_context *ctx, int fd)
{
	return client_map_find(ctx, fd);
}

static void client_destroy(struct ipc_context *ctx, struct ipc_client *client)
{
	struct ipc_client **pp = &ctx->client_list;

	client_map_remove(ctx, client->fd);

	/* a session lasts as long as its connection */
	if (client->profile) {
		if (client->profile->sessions > 0)
			client->profile->sessions--;
		client->profile->session_changed = true;
		client->profile = NULL;
		ctx->profiles_changed = true;
	}
	client->profile_id[0] = '\0';

	while (*pp) {
		if (*pp == client) {
			*pp = client->next;
			ctx->client_count--;
			if (client->shutdown_on_flush) {
				agent_globals_lock(&g_agent);
				g_agent.running = 0;
				agent_globals_unlock(&g_agent);
			}
			ipc_secure_bzero(client->recv_buf,
					 sizeof(client->recv_buf));
			ipc_secure_bzero(client->send_buf,
					 sizeof(client->send_buf));
			close(client->fd);
			free(client);
			return;
		}
		pp = &(*pp)->next;
	}
}

static void build_error_response(struct ipc_client *client, uint32_t result)
{
	struct lota_ipc_response *resp = (void *)client->send_buf;

	ipc_secure_bzero(client->send_buf, sizeof(client->send_buf));

	resp->magic = LOTA_IPC_MAGIC;
	resp->version = LOTA_IPC_VERSION;
	resp->result = result;
	resp->payload_len = 0;

	client->send_len = LOTA_IPC_RESPONSE_SIZE;
	client->send_offset = 0;
}

/*
 * Gather the inputs the privileged-IPC rule decides on;
 * the rule itself is ipc_privilege_granted() in ipc_privilege.h
 */
static int ipc_client_is_privileged(struct ipc_context *ctx,
				    const struct ipc_client *client)
{
	uint64_t current_ticks = 0;
	bool pid_identity_ok;

	if (!ctx || !client)
		return 0;

	pid_identity_ok = client->peer_start_time_ticks != 0 &&
			  read_pid_start_time_ticks(client->peer_pid,
						    &current_ticks) >= 0 &&
			  current_ticks == client->peer_start_time_ticks;

	/* cheap checks first: a refused caller must not cost a file hash */
	if (!ipc_privilege_granted(client->peer_uid == geteuid(),
				   pid_identity_ok, 0, true))
		return 0;

	return ipc_privilege_granted(
		       true, true, g_agent.policy_verity_digest_count,
		       ipc_client_has_trusted_executable(client) != 0) ?
		       1 :
		       0;
}

/*
 * SYNC_ATTEST writes the verdicts titles read, and group lota reaches this
 * socket. The peer needs the agent's uid, from SO_PEERCRED, and the start time
 * it connected with.
 *
 * Under the unit that uid is 0, so any root process passes.
 */
static int ipc_client_is_agent_peer(const struct ipc_client *client)
{
	uint64_t current_ticks = 0;

	if (!client)
		return 0;

	if (client->peer_uid != geteuid())
		return 0;

	if (client->peer_start_time_ticks == 0)
		return 0;

	if (read_pid_start_time_ticks(client->peer_pid, &current_ticks) < 0)
		return 0;

	return current_ticks == client->peer_start_time_ticks;
}

/*
 * Ask the event loop to write what this client has queued. Between frames a
 * client's interest is EPOLLIN alone, and a notification can be built while
 * another connection is being served.
 */
static void client_arm_send(struct ipc_context *ctx, struct ipc_client *client)
{
	struct epoll_event ev;

	if (!ctx || !client || ctx->epoll_fd < 0 || client->send_len == 0)
		return;

	ev.events = EPOLLIN | EPOLLOUT;
	ev.data.fd = client->fd;
	epoll_ctl(ctx->epoll_fd, EPOLL_CTL_MOD, client->fd, &ev);
}

static void build_notification(struct ipc_context *ctx,
			       struct ipc_client *client, uint32_t events)
{
	struct lota_ipc_response *resp = (void *)client->send_buf;
	struct lota_ipc_notify *notify;
	uint64_t valid_until;
	uint32_t flags;

	client_attestation_view(ctx, client, &flags, &valid_until);
	flags = runtime_coverage_fold(flags);
	client->told_flags = flags;

	resp->magic = LOTA_IPC_MAGIC;
	resp->version = LOTA_IPC_VERSION;
	resp->result = LOTA_IPC_NOTIFY;
	resp->payload_len = sizeof(*notify);

	notify = (void *)(client->send_buf + LOTA_IPC_RESPONSE_SIZE);
	notify->events = events;
	notify->flags = flags;
	notify->last_attest_time = ctx->last_attest_time;
	notify->valid_until = valid_until;
	notify->attest_count = ctx->attest_count;
	notify->fail_count = ctx->fail_count;
	notify->mode = ctx->mode;
	memset(notify->reserved, 0, sizeof(notify->reserved));

	client->send_len = LOTA_IPC_RESPONSE_SIZE + sizeof(*notify);
	client->send_offset = 0;

	client_arm_send(ctx, client);
}

static void push_notify(struct ipc_context *ctx, struct ipc_client *client,
			uint32_t events)
{
	uint32_t relevant = events & client->event_mask;

	if (!relevant)
		return;

	if (client->send_len > client->send_offset) {
		/* send in progress -> accumulate */
		client->notify_pending = true;
		client->pending_events |= relevant;
		return;
	}

	build_notification(ctx, client, relevant);
}

static void notify_subscribers(struct ipc_context *ctx, uint32_t events)
{
	struct ipc_client *c = ctx->client_list;
	while (c) {
		if (c->subscribed)
			push_notify(ctx, c, events);
		c = c->next;
	}
}

static void handle_ping(struct ipc_context *ctx, struct ipc_client *client)
{
	struct lota_ipc_response *resp = (void *)client->send_buf;
	struct lota_ipc_ping_response *ping;

	resp->magic = LOTA_IPC_MAGIC;
	resp->version = LOTA_IPC_VERSION;
	resp->result = LOTA_IPC_OK;
	resp->payload_len = sizeof(*ping);

	ping = (void *)(client->send_buf + LOTA_IPC_RESPONSE_SIZE);
	{
		uint64_t now = monotonic_now_sec();
		ping->uptime_sec = (now >= ctx->start_time_sec) ?
					   (now - ctx->start_time_sec) :
					   0;
	}
	ping->pid = (uint32_t)getpid();

	client->send_len = LOTA_IPC_RESPONSE_SIZE + sizeof(*ping);
	client->send_offset = 0;
}

/*
 * The attestation answer this connection gets: the host's, unless it named a
 * publisher. Then that publisher decides ATTESTED, REENROLLING,
 * PROTECTED_TERMINATED and valid_until, and one without a verifier also
 * sets TOKEN_ONLY. The other bits stay the host's.
 */
static void client_attestation_view(const struct ipc_context *ctx,
				    const struct ipc_client *client,
				    uint32_t *flags, uint64_t *valid_until)
{
	*flags = ctx->status_flags;
	*valid_until = ctx->valid_until;

	if (!client->profile)
		return;

	if (client->profile->reenrolling)
		*flags |= LOTA_STATUS_REENROLLING;
	else
		*flags &= ~(uint32_t)LOTA_STATUS_REENROLLING;

	if (client->profile->protected_terminated)
		*flags |= LOTA_STATUS_PROTECTED_TERMINATED;
	else
		*flags &= ~(uint32_t)LOTA_STATUS_PROTECTED_TERMINATED;

	/* never reported to, so this host holds no verdict of theirs */
	if (client->profile->token_only) {
		*flags |= LOTA_STATUS_TOKEN_ONLY;
		*flags &= ~(uint32_t)LOTA_STATUS_ATTESTED;
		*valid_until = 0;
		return;
	}

	if (client->profile->attested) {
		*flags |= LOTA_STATUS_ATTESTED;
		*valid_until = client->profile->valid_until;
	} else {
		*flags &= ~(uint32_t)LOTA_STATUS_ATTESTED;
		*valid_until = 0;
	}
}

/* Cached coverage verdict, dropped on an epoch change or on forget */
static struct {
	uint64_t epoch; /* protected-set mutation id it was taken under */
	uint64_t forgets; /* ipc_runtime_coverage_forget() calls */
	bool full;
	bool content_hashed; /* a content hash answered for one of them */
	bool valid;
} g_coverage;

void ipc_runtime_coverage_forget(void)
{
	g_coverage.valid = false;
	g_coverage.forgets++;
}

/* Last answer reported per protected PID; an unchanged round stays quiet */
static struct measure_report_table g_measure_reports;

/* what the last token round found mapped; IPC thread only */
static struct registry g_registry;

/*
 * Who each process of the set is protected for; IPC thread only. An entry
 * outlives a catch-up only in the set or as the root of one in it, and each
 * PROTECT_PID catches up before it adds one.
 */
static struct protect_owner g_protect_owner_v[2 * LOTA_MAX_PROTECTED_PIDS + 1];
static struct protect_owners g_protect_owners = {
	.v = g_protect_owner_v,
	.cap = sizeof(g_protect_owner_v) / sizeof(g_protect_owner_v[0]),
};

#define REGISTRY_OBJECTS_MAX LOTA_IPC_REGISTRY_MAX_OBJECTS
_Static_assert(REGISTRY_OBJECTS_MAX >= LOTA_RUNTIME_IMAGE_MAX_MODULES,
	       "the registry must hold every object a process is measured with");

static int exec_history_alive(uint32_t tgid, uint64_t start_ticks)
{
	uint64_t ticks = 0;

	return read_pid_start_time_ticks((pid_t)tgid, &ticks) == 0 &&
	       ticks == start_ticks;
}

/*
 * The exec history of every live process.
 * False when it is missing or a kernel record was lost: every list of the
 * round may then lack an object.
 */
static bool exec_history_read(struct lota_exec_history_key **keys,
			      struct lota_exec_history_val **vals, size_t *n)
{
	struct bpf_extended_stats stats;
	int ret;

	ret = bpf_loader_exec_history(&g_agent.bpf_ctx, exec_history_alive,
				      keys, vals, n);
	if (ret < 0) {
		lota_warn("exec history unavailable: %s", strerror(-ret));
		return false;
	}
	if (bpf_loader_get_extended_stats(&g_agent.bpf_ctx, &stats) < 0)
		return false;
	return stats.exec_history_lost == 0;
}

/*
 * Every process outside an instance that reached one of its unix sockets.
 * False when the record is missing or one was lost.
 */
static bool instance_actors_read(struct lota_instance_actor_key **keys,
				 struct lota_instance_actor_val **vals,
				 size_t *n)
{
	struct bpf_extended_stats stats;
	int ret;

	ret = bpf_loader_instance_actors(&g_agent.bpf_ctx, exec_history_alive,
					 keys, vals, n);
	if (ret < 0) {
		lota_warn("instance actors unavailable: %s", strerror(-ret));
		return false;
	}
	if (bpf_loader_get_extended_stats(&g_agent.bpf_ctx, &stats) < 0)
		return false;
	return stats.instance_actors_lost == 0;
}

static int read_pid_real_uid(pid_t pid, uint32_t *out_uid);

/* Token rounds that repeated a journalled answer; reported at shutdown */
static uint64_t g_token_answer_repeats;

void ipc_runtime_measure_stats(uint64_t *repeated, uint64_t *unremembered)
{
	if (repeated)
		*repeated = g_measure_reports.suppressed;
	if (unremembered)
		*unremembered = g_measure_reports.unremembered;
}

void ipc_token_answer_stats(uint64_t *repeated)
{
	if (repeated)
		*repeated = g_token_answer_repeats;
}

/*
 * Coverage and content-hash use in one walk, so both describe one host state:
 * the token nonce binds the status flags.
 */
static void runtime_coverage_take(bool *full_out, bool *content_hashed_out)
{
	uint64_t epoch;
	bool content_hashed = false;
	bool full;
	int count;

	/*
	 * An exited PID is unmeasurable, so a stale entry would report partial
	 * coverage. Before the cache check: a dropped PID bumps the epoch.
	 */
	runtime_protect_catch_up();

	agent_globals_lock(&g_agent);
	count = g_agent.policy_protect_pid_count;
	epoch = g_agent.policy_protect_epoch;
	agent_globals_unlock(&g_agent);

	if (g_coverage.valid && g_coverage.epoch == epoch) {
		*full_out = g_coverage.full;
		*content_hashed_out = g_coverage.content_hashed;
		return;
	}

	full = true;
	if (count <= 0 || !g_agent.policy_protect_pids) {
		count = 0;
	} else {
		for (int i = 0; i < count; i++) {
			struct lota_runtime_measure_coverage cov;

			if (lota_runtime_coverage_pid(
				    (pid_t)g_agent.policy_protect_pids[i],
				    &cov) != 0) {
				full = false;
				break;
			}
			if (cov.content_hashed > 0)
				content_hashed = true;
			if (cov.unmeasurable > 0) {
				full = false;
				break;
			}
		}
	}

	full = lota_coverage_is_full((size_t)count, full);

	g_coverage.epoch = epoch;
	g_coverage.full = full;
	g_coverage.content_hashed = content_hashed;
	g_coverage.valid = true;

	*full_out = full;
	*content_hashed_out = content_hashed;
}

/* Coverage and content-hash bits, folded alike for status and token */
static uint32_t runtime_coverage_fold(uint32_t flags)
{
	bool content_hashed = false;
	bool full = false;

	runtime_coverage_take(&full, &content_hashed);

	return lota_status_fold_content_hash(
		lota_status_fold_coverage(flags, full), content_hashed);
}

uint32_t ipc_host_status_flags(const struct ipc_context *ctx)
{
	if (!ctx)
		return 0;

	return runtime_coverage_fold(ctx->status_flags);
}

/* The word @client reads now, as GET_STATUS answers it */
static uint32_t client_status_word(const struct ipc_context *ctx,
				   const struct ipc_client *client)
{
	uint64_t valid_until;
	uint32_t flags;

	client_attestation_view(ctx, client, &flags, &valid_until);
	return runtime_coverage_fold(flags);
}

/*
 * Push STATUS to each subscriber whose word moved since its last push,
 * and announce the host word on the bus when it moved.
 */
static void publish_status(struct ipc_context *ctx)
{
	uint32_t flags = ipc_host_status_flags(ctx);

	agent_globals_lock(&g_agent);
	ctx->published_epoch = g_agent.policy_protect_epoch;
	agent_globals_unlock(&g_agent);
	ctx->published_forgets = g_coverage.forgets;

	for (struct ipc_client *c = ctx->client_list; c; c = c->next) {
		if (c->subscribed &&
		    client_status_word(ctx, c) != c->told_flags)
			push_notify(ctx, c, LOTA_IPC_EVENT_STATUS);
	}

	if (flags == ctx->published_flags)
		return;

	ctx->published_flags = flags;
	dbus_emit_status_changed(ctx->dbus);
}

/*
 * The coverage bits may have moved since the last announcement,
 * or a protected PID may exit, which only a fold notices.
 */
static bool status_needs_tick(const struct ipc_context *ctx)
{
	uint64_t epoch;
	int count;

	agent_globals_lock(&g_agent);
	epoch = g_agent.policy_protect_epoch;
	count = g_agent.policy_protect_pid_count;
	agent_globals_unlock(&g_agent);

	return count > 0 || epoch != ctx->published_epoch ||
	       g_coverage.forgets != ctx->published_forgets;
}

int ipc_status_timeout_ms(const struct ipc_context *ctx, uint64_t now_ns)
{
	if (!ctx->running || !status_needs_tick(ctx))
		return -1;
	if (now_ns >= ctx->status_due_ns)
		return 0;

	return (int)((ctx->status_due_ns - now_ns + 999999) / 1000000);
}

void ipc_status_tick(struct ipc_context *ctx, uint64_t now_ns)
{
	if (!ctx->running || now_ns < ctx->status_due_ns ||
	    !status_needs_tick(ctx))
		return;

	ctx->status_due_ns = now_ns + IPC_STATUS_TICK_NS;
	publish_status(ctx);
}

static void handle_get_status(struct ipc_context *ctx,
			      struct ipc_client *client)
{
	struct lota_ipc_response *resp = (void *)client->send_buf;
	struct lota_ipc_status *status;
	uint64_t valid_until;
	uint32_t flags;

	resp->magic = LOTA_IPC_MAGIC;
	resp->version = LOTA_IPC_VERSION;
	resp->result = LOTA_IPC_OK;
	resp->payload_len = sizeof(*status);

	client_attestation_view(ctx, client, &flags, &valid_until);
	flags = runtime_coverage_fold(flags);

	status = (void *)(client->send_buf + LOTA_IPC_RESPONSE_SIZE);
	status->flags = flags;
	status->last_attest_time = ctx->last_attest_time;
	status->valid_until = valid_until;
	status->attest_count = ctx->attest_count;
	status->fail_count = ctx->fail_count;
	status->mode = ctx->mode;
	status->_reserved1 = 0;
	memset(status->reserved, 0, sizeof(status->reserved));

	client->send_len = LOTA_IPC_RESPONSE_SIZE + sizeof(*status);
	client->send_offset = 0;
}

/*
 * The PCR values a token quotes and the PCR 7 events behind them.
 * Charged to the GET_TOKEN uid ceiling: each answer reads the TPM and the log.
 */
static void handle_get_boot_evidence(struct ipc_context *ctx,
				     struct ipc_client *client)
{
	struct lota_ipc_response *resp = (void *)client->send_buf;
	size_t len = 0;
	int ret;

	if (check_get_token_rate_limit(client->peer_uid) < 0) {
		build_error_response(client, LOTA_IPC_ERR_RATE_LIMITED);
		return;
	}
	if (!ipc_can_issue_tokens(ctx)) {
		build_error_response(client, LOTA_IPC_ERR_NO_TPM);
		return;
	}

	ret = boot_evidence_collect(ctx->tpm, ctx->quote_pcr_mask,
				    client->send_buf + LOTA_IPC_RESPONSE_SIZE,
				    LOTA_IPC_MAX_PAYLOAD, &len);
	if (ret < 0) {
		lota_err("cannot build boot evidence: %s", strerror(-ret));
		build_error_response(client, LOTA_IPC_ERR_INTERNAL);
		return;
	}

	resp->magic = LOTA_IPC_MAGIC;
	resp->version = LOTA_IPC_VERSION;
	resp->result = LOTA_IPC_OK;
	resp->payload_len = (uint32_t)len;
	client->send_len = LOTA_IPC_RESPONSE_SIZE + len;
	client->send_offset = 0;
}

#ifndef SYS_pidfd_open
#define SYS_pidfd_open 434
#endif

static bool pidfd_exited(int pidfd)
{
	struct pollfd pfd = { .fd = pidfd, .events = POLLIN };

	return poll(&pfd, 1, 0) > 0;
}

/*
 * The PID of the process @pidfd names, in the agent's PID namespace, from the
 * "Pid:" line of its fdinfo. The kernel prints -1 there once that process is
 * reaped and 0 when it runs in a PID namespace outside the agent's.
 * @nested, when set, says whether "NSpid:" lists more than that PID,
 * i.e. the process runs in a PID namespace below the agent's.
 */
static int pidfd_own_pid(int pidfd, uint32_t *out, bool *nested)
{
	char path[64];
	char line[128];
	FILE *fp;
	long v = 0;
	bool found = false;

	if (nested)
		*nested = false;

	snprintf(path, sizeof(path), "/proc/self/fdinfo/%d", pidfd);
	fp = fopen(path, "r");
	if (!fp)
		return -errno;
	while (fgets(line, sizeof(line), fp)) {
		char *end = NULL;

		if (nested && strncmp(line, "NSpid:\t", 7) == 0) {
			*nested = strchr(line + 7, '\t') != NULL;
			continue;
		}
		if (strncmp(line, "Pid:\t", 5) != 0)
			continue;
		errno = 0;
		v = strtol(line + 5, &end, 10);
		found = errno == 0 && end != line + 5;
	}
	fclose(fp);

	if (!found)
		return -EINVAL;
	if (v <= 0 || v > INT_MAX)
		return -ESRCH;
	*out = (uint32_t)v;
	return 0;
}

/* The instance a process belongs to, by the root the LSM keys it on */
struct proc_instance {
	uint32_t root_tgid;
	uint64_t root_start_ticks;
};

static bool pidfd_instance(int pidfd, uint32_t pid, struct proc_instance *out)
{
	return bpf_loader_task_instance(&g_agent.bpf_ctx, pidfd, pid,
					&out->root_tgid,
					&out->root_start_ticks) == 1;
}

/* The instance of the process that connected; false when it has none */
static bool peer_instance(const struct ipc_client *client,
			  struct proc_instance *out)
{
	socklen_t len = sizeof(int);
	uint32_t pid = 0;
	int pidfd = -1;
	bool ok;

	if (getsockopt(client->fd, SOL_SOCKET, SO_PEERPIDFD, &pidfd, &len) < 0)
		return false;
	ok = pidfd_own_pid(pidfd, &pid, NULL) == 0 &&
	     pidfd_instance(pidfd, pid, out);
	close(pidfd);
	return ok;
}

/* @pid runs in the instance @caller names */
static bool pid_in_instance(const struct proc_instance *caller, uint32_t pid)
{
	struct proc_instance id;
	bool ok;
	int pidfd;

	pidfd = (int)syscall(SYS_pidfd_open, (pid_t)pid, 0);
	if (pidfd < 0)
		return false;
	ok = pidfd_instance(pidfd, pid, &id) &&
	     id.root_tgid == caller->root_tgid &&
	     id.root_start_ticks == caller->root_start_ticks;
	close(pidfd);
	return ok;
}

static void handle_get_token(struct ipc_context *ctx, struct ipc_client *client,
			     const uint8_t *payload, uint32_t payload_len)
{
	struct lota_ipc_response *resp = (void *)client->send_buf;
	struct lota_ipc_token *token;
	struct lota_ipc_token_request req_local;
	bool has_req = false;
	uint8_t binding_nonce[LOTA_NONCE_SIZE] = { 0 };
	uint8_t runtime_protect_digest[32] = { 0 };
	struct tpm_quote_response quote;
	uint8_t *data_ptr;
	uint32_t *runtime_pids = NULL;
	uint32_t runtime_pid_count = 0;
	uint8_t *in_token = NULL;
	uint32_t token_pid_count = 0;
	uint64_t stopped_ms = 0;
	uint16_t pid_list_size = 0;
	uint8_t (*registry_digests)[32] = NULL;
	size_t registry_list_size = 0;
	struct lota_rt_object_record *objs = NULL;
	struct registry next_registry = { 0 };
	struct lota_exec_history_key *hist_keys = NULL;
	struct lota_exec_history_val *hist_vals = NULL;
	size_t n_hist = 0;
	bool hist_lost = false;
	struct lota_instance_actor_key *actor_keys = NULL;
	struct lota_instance_actor_val *actor_vals = NULL;
	struct lota_ipc_registry_actor *actors = NULL;
	size_t n_actor_hist = 0;
	bool actors_lost = false;
	size_t total_size;
	uint64_t view_valid_until;
	uint32_t view_flags;
	struct proc_instance instance;
	bool has_instance;
	int ret;
	bool fail = false;
	bool rebound = false;
	bool image_fully_measured = true;
	bool image_content_hashed = false;
	uint32_t fail_code = LOTA_IPC_ERR_INTERNAL;
	/* compared as text: one code with two reasons is two answers */
	char refusal[STANDING_ANSWER_STATEMENT_MAX] = "";
	int refusal_level = -1;

	memset(&quote, 0, sizeof(quote));

	client_attestation_view(ctx, client, &view_flags, &view_valid_until);

	/*
	 * Before the verdict: a lockout is why the verdict lapsed,
	 * and NOT_ATTESTED would invite a retry.
	 */
	if ((ctx->tpm && tpm_is_locked_out(ctx->tpm)) ||
	    (ctx->status_flags & LOTA_STATUS_TPM_LOCKOUT)) {
		fail = true;
		fail_code = LOTA_IPC_ERR_TPM_LOCKOUT;
		goto out;
	}

	if (token_gate_needs_attested(view_flags) &&
	    !(view_flags & LOTA_STATUS_ATTESTED)) {
		fail = true;
		fail_code = LOTA_IPC_ERR_NOT_ATTESTED;
		goto out;
	}

	/* session budget first: its refusal does not charge the uid ceiling */
	if (check_session_token_rate_limit(client) < 0) {
		refusal_level = LOG_WARNING;
		snprintf(refusal, sizeof(refusal),
			 "rate limited GET_TOKEN for session pid=%d uid=%d",
			 client->peer_pid, client->peer_uid);
		fail = true;
		fail_code = LOTA_IPC_ERR_RATE_LIMITED;
		goto out;
	}

	if (check_get_token_rate_limit(client->peer_uid) < 0) {
		refusal_level = LOG_WARNING;
		snprintf(refusal, sizeof(refusal),
			 "rate limited GET_TOKEN for uid=%d pid=%d",
			 client->peer_uid, client->peer_pid);
		fail = true;
		fail_code = LOTA_IPC_ERR_RATE_LIMITED;
		goto out;
	}

	/*
	 * The quote would be signed by whichever AIK the TPM is bound to.
	 * With one publisher that is no guess, and a title there names nobody.
	 */
	if (!client->profile && ctx->profile_count > 1) {
		refusal_level = LOG_ERR;
		snprintf(
			refusal, sizeof(refusal),
			"Refusing GET_TOKEN for pid=%d: this agent answers for %zu publishers and the connection named none. Send SET_PROFILE first",
			client->peer_pid, ctx->profile_count);
		fail = true;
		fail_code = LOTA_IPC_ERR_UNKNOWN_PROFILE;
		goto out;
	}

	/*
	 * After the rate limiters, and before the protected set is reaped and
	 * measured, which cannot change this answer.
	 */
	if (!ipc_can_issue_tokens(ctx)) {
		refusal_level = LOG_ERR;
		snprintf(
			refusal, sizeof(refusal),
			"Refusing GET_TOKEN for pid=%d: no TPM on this agent, and an unsigned token is not evidence",
			client->peer_pid);
		fail = true;
		fail_code = LOTA_IPC_ERR_NO_TPM;
		goto out;
	}

	if (payload_len >= sizeof(req_local)) {
		memcpy(&req_local, payload, sizeof(req_local));
		has_req = true;
	}

	token = (void *)(client->send_buf + LOTA_IPC_RESPONSE_SIZE);

	/* this publisher's window, not the host's aggregate */
	token->valid_until = view_valid_until;

	/*
	 * No verifier, so no round to take a window from: the agent bounds the
	 * token itself. The status keeps a zero valid_until: there is no verdict.
	 */
	if (view_flags & LOTA_STATUS_TOKEN_ONLY)
		token->valid_until =
			(uint64_t)time(NULL) + TOKEN_ONLY_VALIDITY_SEC;
	token->flags = view_flags;
	token->pcr_mask = ctx->quote_pcr_mask;

	/*
	 * Quote with this publisher's own AIK. The first profile's binding is
	 * restored at out.
	 */
	if (client->profile && ctx->tpm) {
		ret = tpm_bind_profile(ctx->tpm, &client->profile->paths);
		if (ret == -ENOSPC) {
			/* a full handle range, not a full disk */
			lota_err("no attestation-key slot left for publisher "
				 "%s: every handle this build reserves is "
				 "taken. lota-agent --list-publishers says "
				 "which, and --forget-publisher frees one",
				 client->profile->paths.id);
			fail = true;
			fail_code = LOTA_IPC_ERR_NO_KEY_SLOT;
			goto out;
		}
		if (ret < 0) {
			lota_err(
				"cannot bind publisher profile for GET_TOKEN: %s",
				tpm_strerror(ret));
			fail = true;
			fail_code = LOTA_IPC_ERR_INTERNAL;
			goto out;
		}
		rebound = ctx->profiles && ctx->profile_count > 0 &&
			  client->profile != &ctx->profiles[0];
	}

	if (!g_agent.policy_digest_set) {
		lota_err("Refusing GET_TOKEN: policy_digest is not set");
		fail = true;
		fail_code = LOTA_IPC_ERR_INTERNAL;
		goto out;
	}
	memcpy(token->policy_digest, g_agent.policy_digest,
	       sizeof(token->policy_digest));

	/* an exited PID left in the set would report partial coverage */
	runtime_protect_catch_up();

	ret = build_canonical_runtime_pid_list(&runtime_pids,
					       &runtime_pid_count);
	if (ret < 0) {
		lota_err("failed to canonicalize protected PID set: %s",
			 strerror(-ret));
		fail = true;
		fail_code = LOTA_IPC_ERR_INTERNAL;
		goto out;
	}

	/* forget unprotected PIDs before a reuse can match them */
	measure_report_retain(&g_measure_reports, runtime_pids,
			      runtime_pid_count);

	in_token = calloc(runtime_pid_count ? runtime_pid_count : 1,
			  sizeof(*in_token));
	if (!in_token) {
		fail = true;
		fail_code = LOTA_IPC_ERR_INTERNAL;
		goto out;
	}
	/* a token carries the processes of the caller's own instance */
	has_instance = peer_instance(client, &instance);
	for (uint32_t i = 0; has_instance && i < runtime_pid_count; i++) {
		in_token[i] = pid_in_instance(&instance, runtime_pids[i]);
		if (in_token[i])
			token_pid_count++;
	}

	if (token_pid_count > LOTA_IPC_TOKEN_MAX_PROTECT_PIDS) {
		lota_err("runtime protected PID count %u exceeds the per-token "
			 "limit of %u",
			 token_pid_count,
			 (unsigned)LOTA_IPC_TOKEN_MAX_PROTECT_PIDS);
		fail = true;
		fail_code = LOTA_IPC_ERR_TOO_MANY_PROTECTED_PIDS;
		goto out;
	}

	{
		size_t pid_bytes = (size_t)token_pid_count * sizeof(uint32_t);
		if (pid_bytes > UINT16_MAX) {
			fail = true;
			fail_code = LOTA_IPC_ERR_INTERNAL;
			goto out;
		}
		pid_list_size = (uint16_t)pid_bytes;
	}

	/* opened even when empty, so the last exit unpins everything */
	lota_rt_measure_round_begin();

	/*
	 * Each process of the token joins the protect digest with its registry
	 * digest. One that cannot be measured stays a zero digest and clears
	 * LOTA_STATUS_IMAGE_FULLY_MEASURED; only the caller's own refuses.
	 */
	if (runtime_pid_count > 0) {
		registry_list_size = (size_t)runtime_pid_count *
				     LOTA_IPC_TOKEN_REGISTRY_DIGEST_SIZE;
		registry_digests =
			calloc(runtime_pid_count, sizeof(*registry_digests));
		objs = calloc(REGISTRY_OBJECTS_MAX, sizeof(*objs));
		actors = calloc(LOTA_IPC_REGISTRY_MAX_ACTORS, sizeof(*actors));
		if (!registry_digests || !objs || !actors) {
			fail = true;
			fail_code = LOTA_IPC_ERR_INTERNAL;
			goto out;
		}
		hist_lost = !exec_history_read(&hist_keys, &hist_vals, &n_hist);
		actors_lost = !instance_actors_read(&actor_keys, &actor_vals,
						    &n_actor_hist);
		for (uint32_t i = 0; i < runtime_pid_count; i++) {
			struct lota_runtime_measure_failure mfail;
			struct lota_runtime_measure_coverage cov = { 0 };
			uint8_t image_digest[LOTA_RUNTIME_IMAGE_DIGEST_SIZE];
			char statement[MEASURE_REPORT_STATEMENT_MAX];
			char held_clause[80];
			uint64_t held = 0;
			char reason[LOTA_RT_REASON_MAX];
			uint32_t owner = UINT32_MAX;
			uint64_t start_ticks = 0;
			uint16_t rflags = 0;
			int lost = 0;
			int actor_overflow = 0;
			size_t n_objs = 0;
			size_t n_actors;
			int rec;

			/* unreadable owner: only root reads the entry */
			(void)read_pid_real_uid((pid_t)runtime_pids[i], &owner);
			ret = lota_runtime_measure_pid_objects(
				(pid_t)runtime_pids[i], image_digest, &cov,
				&mfail, objs, &n_objs);

			/* what the maps no longer show, from the history */
			if (read_pid_start_time_ticks((pid_t)runtime_pids[i],
						      &start_ticks) < 0)
				lost = 1;
			n_objs = registry_merge_history(objs, n_objs,
							REGISTRY_OBJECTS_MAX,
							hist_keys, hist_vals,
							n_hist, runtime_pids[i],
							start_ticks, &lost);
			if (hist_lost || lost)
				rflags |= LOTA_IPC_REGISTRY_HISTORY_LOST;
			if (cov.past_limit > 0)
				rflags |= LOTA_IPC_REGISTRY_TRUNCATED;

			n_actors = registry_collect_actors(
				actors, LOTA_IPC_REGISTRY_MAX_ACTORS,
				actor_keys, actor_vals, n_actor_hist,
				runtime_pids[i], start_ticks, &actor_overflow);
			if (actors_lost || lost || actor_overflow)
				rflags |= LOTA_IPC_REGISTRY_ACTORS_LOST;
			if (bpf_loader_born_protected(&g_agent.bpf_ctx,
						      runtime_pids[i],
						      start_ticks) > 0)
				rflags |= LOTA_IPC_REGISTRY_FROM_EXEC;

			/* the token's entry binds the whole list */
			if (ret >= 0) {
				rec = registry_digest(
					rflags | LOTA_IPC_REGISTRY_MEASURED,
					objs, n_objs, actors, n_actors,
					registry_digests[i]);
				if (rec == 0)
					rec = registry_add(
						&next_registry, runtime_pids[i],
						start_ticks, owner, rflags,
						registry_digests[i], objs,
						n_objs, actors, n_actors);
			} else {
				rec = registry_add(&next_registry,
						   runtime_pids[i], start_ticks,
						   owner, rflags, NULL, objs,
						   n_objs, actors, n_actors);
			}

			/* a digest the registry cannot back is not sent */
			if (rec < 0) {
				lota_err("registry of pid=%u not kept: %s",
					 runtime_pids[i], strerror(-rec));
				fail = true;
				fail_code = LOTA_IPC_ERR_INTERNAL;
				goto out;
			}
			if (ret < 0) {
				lota_rt_failure_reason(&mfail, ret, reason,
						       sizeof(reason));

				if (token_gate_failure_is_fatal(
					    (pid_t)runtime_pids[i],
					    client->peer_pid)) {
					measure_report_line(
						statement, sizeof(statement),
						MEASURE_ANSWER_REFUSED,
						runtime_pids[i],
						(uint32_t)client->peer_pid, 0,
						0, reason);
					if (measure_report_note(
						    &g_measure_reports,
						    runtime_pids[i],
						    MEASURE_ANSWER_REFUSED,
						    statement, &held)) {
						measure_report_held_clause(
							held_clause,
							sizeof(held_clause),
							held);
						lota_err("%s%s", statement,
							 held_clause);
					}
					fail = true;
					fail_code =
						lota_rt_err_is_agent_failure(
							ret) ?
							LOTA_IPC_ERR_INTERNAL :
							LOTA_IPC_ERR_UNMEASURABLE_SELF;
					goto out;
				}

				measure_report_line(statement,
						    sizeof(statement),
						    MEASURE_ANSWER_ABSENT,
						    runtime_pids[i],
						    (uint32_t)client->peer_pid,
						    0, 0, reason);
				if (measure_report_note(&g_measure_reports,
							runtime_pids[i],
							MEASURE_ANSWER_ABSENT,
							statement, &held)) {
					measure_report_held_clause(
						held_clause,
						sizeof(held_clause), held);
					lota_warn("%s%s", statement,
						  held_clause);
				}
				if (in_token[i])
					image_fully_measured = false;
				continue;
			}
			if (cov.content_hashed > 0 && in_token[i])
				image_content_hashed = true;

			if (cov.unmeasurable > 0) {
				lota_rt_failure_reason(&mfail, mfail.err,
						       reason, sizeof(reason));
				measure_report_line(
					statement, sizeof(statement),
					MEASURE_ANSWER_PARTIAL, runtime_pids[i],
					(uint32_t)client->peer_pid,
					cov.measured, cov.unmeasurable, reason);
				if (measure_report_note(&g_measure_reports,
							runtime_pids[i],
							MEASURE_ANSWER_PARTIAL,
							statement, &held)) {
					measure_report_held_clause(
						held_clause,
						sizeof(held_clause), held);
					lota_warn("%s%s", statement,
						  held_clause);
				}
				if (in_token[i])
					image_fully_measured = false;
				continue;
			}

			/* stated only when coverage recovers */
			measure_report_line(statement, sizeof(statement),
					    MEASURE_ANSWER_MEASURED,
					    runtime_pids[i],
					    (uint32_t)client->peer_pid,
					    cov.measured, 0, NULL);
			if (measure_report_note(&g_measure_reports,
						runtime_pids[i],
						MEASURE_ANSWER_MEASURED,
						statement, &held)) {
				measure_report_held_clause(
					held_clause, sizeof(held_clause), held);
				lota_info("%s%s", statement, held_clause);
			}
		}
	}

	/* unpin what this round did not reach */
	{
		size_t released = 0;
		int sweep = lota_rt_measure_round_end(&released);

		if (sweep < 0)
			lota_warn("failed to release write guards of objects "
				  "no longer measured: %s",
				  strerror(-sweep));
		else if (released > 0)
			lota_dbg("released %zu write guard%s", released,
				 released == 1 ? "" : "s");
	}

	registry_replace(&g_registry, &next_registry);

	/* the round measured the whole set; the token keeps its own part */
	for (uint32_t i = 0, n = 0; i < runtime_pid_count; i++) {
		if (!in_token[i])
			continue;
		runtime_pids[n] = runtime_pids[i];
		memmove(registry_digests[n], registry_digests[i],
			sizeof(registry_digests[n]));
		n++;
	}

	ret = lota_compute_runtime_protect_digest(runtime_pids,
						  registry_digests,
						  token_pid_count,
						  runtime_protect_digest);
	if (ret < 0) {
		lota_err("runtime protected PID digest computation failed: %s",
			 strerror(-ret));
		fail = true;
		fail_code = LOTA_IPC_ERR_INTERNAL;
		goto out;
	}

	token->flags = lota_status_fold_content_hash(
		lota_status_fold_coverage(
			token->flags,
			lota_coverage_is_full(token_pid_count,
					      image_fully_measured)),
		image_content_hashed);

	memcpy(token->runtime_protect_digest, runtime_protect_digest,
	       sizeof(token->runtime_protect_digest));
	token->protect_pid_count = token_pid_count;
	token->pid_list_size = pid_list_size;
	token->runtime_protect_version = LOTA_IPC_RUNTIME_PROTECT_V1;

	if (has_req)
		memcpy(token->client_nonce, req_local.nonce, 32);
	else
		memset(token->client_nonce, 0, 32);

	ret = bpf_loader_instance_stopped_ms(
		&g_agent.bpf_ctx, (uint32_t)client->peer_pid, &stopped_ms);
	if (ret < 0) {
		lota_err("stopped time of PID %d unreadable: %s",
			 client->peer_pid, strerror(-ret));
		fail = true;
		fail_code = LOTA_IPC_ERR_INTERNAL;
		goto out;
	}
	token->stopped_ms = stopped_ms;

	ret = lota_compute_token_quote_nonce(token->valid_until, token->flags,
					     token->pcr_mask,
					     token->client_nonce,
					     token->policy_digest,
					     token->runtime_protect_digest,
					     token->stopped_ms, binding_nonce);
	if (ret < 0) {
		lota_err("token quote nonce computation failed: %s",
			 strerror(-ret));
		fail = true;
		fail_code = LOTA_IPC_ERR_INTERNAL;
		goto out;
	}

	ret = tpm_quote(ctx->tpm, binding_nonce, ctx->quote_pcr_mask, &quote);
	if (ret < 0) {
		lota_err("tpm_quote failed: %s", tpm_strerror(ret));
		fail = true;
		/*
		 * GET_TOKEN may see the lockout first: seed the status so the
		 * next request stops at the early refusal.
		 */
		if (tpm_is_locked_out(ctx->tpm)) {
			fail_code = LOTA_IPC_ERR_TPM_LOCKOUT;
			ipc_update_status(ctx,
					  ctx->status_flags |
						  LOTA_STATUS_TPM_LOCKOUT,
					  ctx->valid_until);
		} else {
			fail_code = LOTA_IPC_ERR_TPM_FAILURE;
		}
		goto out;
	}

	total_size =
		LOTA_IPC_TOKEN_HEADER_SIZE + pid_list_size +
		(size_t)token_pid_count * LOTA_IPC_TOKEN_REGISTRY_DIGEST_SIZE +
		quote.attest_size + quote.signature_size;
	if (total_size > LOTA_IPC_MAX_PAYLOAD) {
		lota_err("token too large (%zu bytes): too many protected PIDs",
			 total_size);
		fail = true;
		fail_code = LOTA_IPC_ERR_TOO_MANY_PROTECTED_PIDS;
		goto out;
	}

	token->attest_size = quote.attest_size;
	token->sig_size = quote.signature_size;
	token->sig_alg = quote.sig_alg;
	token->hash_alg = quote.hash_alg;
	if (quote.pcr_mask != token->pcr_mask) {
		lota_err("tpm_quote returned unexpected pcr_mask=0x%X "
			 "(expected 0x%X)",
			 quote.pcr_mask, token->pcr_mask);
		fail = true;
		fail_code = LOTA_IPC_ERR_TPM_FAILURE;
		goto out;
	}

	data_ptr = client->send_buf + LOTA_IPC_RESPONSE_SIZE +
		   LOTA_IPC_TOKEN_HEADER_SIZE;
	for (uint32_t i = 0; i < token_pid_count; i++) {
		uint8_t pid_le[4];
		lota__write_le32(pid_le, runtime_pids[i]);
		memcpy(data_ptr, pid_le, sizeof(pid_le));
		data_ptr += sizeof(pid_le);
	}
	if (token_pid_count > 0) {
		size_t len = (size_t)token_pid_count *
			     LOTA_IPC_TOKEN_REGISTRY_DIGEST_SIZE;

		memcpy(data_ptr, registry_digests, len);
		data_ptr += len;
	}
	memcpy(data_ptr, quote.attest_data, quote.attest_size);
	data_ptr += quote.attest_size;
	memcpy(data_ptr, quote.signature, quote.signature_size);

	resp->magic = LOTA_IPC_MAGIC;
	resp->version = LOTA_IPC_VERSION;
	resp->result = LOTA_IPC_OK;
	resp->payload_len = (uint32_t)total_size;

	client->send_len = LOTA_IPC_RESPONSE_SIZE + total_size;
	client->send_offset = 0;

out:
	/* back to the first profile */
	if (rebound) {
		int rb = tpm_bind_profile(ctx->tpm, &ctx->profiles[0].paths);

		if (rb < 0)
			lota_warn("cannot restore the default publisher "
				  "binding: %s",
				  tpm_strerror(rb));
	}
	ipc_secure_bzero(binding_nonce, sizeof(binding_nonce));
	ipc_secure_bzero(runtime_protect_digest,
			 sizeof(runtime_protect_digest));
	if (runtime_pids) {
		OPENSSL_cleanse(runtime_pids,
				(size_t)runtime_pid_count * sizeof(uint32_t));
		free(runtime_pids);
	}
	if (registry_digests) {
		OPENSSL_cleanse(registry_digests, registry_list_size);
		free(registry_digests);
	}
	free(in_token);
	free(objs);
	free(hist_keys);
	free(hist_vals);
	free(actor_keys);
	free(actor_vals);
	free(actors);
	registry_clear(&next_registry);
	ipc_secure_bzero(&quote, sizeof(quote));

	/* journal only news; the client is answered every round */
	{
		int answer = fail ? (int)fail_code :
				    STANDING_ANSWER_NOTHING_WRONG;
		uint64_t held = 0;
		char held_clause[80];

		if (standing_answer_note(&client->token_answer, answer, refusal,
					 &held)) {
			standing_answer_held_clause(held_clause,
						    sizeof(held_clause), held);

			if (refusal_level == LOG_ERR)
				lota_err("%s%s", refusal, held_clause);
			else if (refusal_level == LOG_WARNING)
				lota_warn("%s%s", refusal, held_clause);
			else if (!fail && held > 0)
				lota_info(
					"GET_TOKEN for pid=%d is answered again%s",
					client->peer_pid, held_clause);

			/* silent refusal: nothing withheld, nothing counted */
			if (refusal_level < 0 && fail)
				client->token_answer.stated = false;
		} else if (client->token_answer.stated) {
			g_token_answer_repeats++;
		}
	}

	if (fail)
		build_error_response(client, fail_code);
}

/*
 * Bind this connection to one publisher, named by the SHA-256 of its CA trust
 * anchor SubjectPublicKeyInfo.
 *
 * An id without a profile is refused: a title that asked for one publisher must
 * not read another's answers.
 */
static void handle_set_profile(struct ipc_context *ctx,
			       struct ipc_client *client,
			       const uint8_t *payload, uint32_t payload_len)
{
	struct lota_ipc_response *resp = (void *)client->send_buf;
	struct lota_ipc_set_profile req;
	char want[LOTA_PROFILE_ID_LEN];

	if (payload_len < sizeof(req)) {
		build_error_response(client, LOTA_IPC_ERR_BAD_REQUEST);
		return;
	}
	memcpy(&req, payload, sizeof(req));

	if (!ctx->profiles || ctx->profile_count == 0) {
		build_error_response(client, LOTA_IPC_ERR_UNKNOWN_PROFILE);
		return;
	}

	for (size_t i = 0; i < sizeof(req.profile_id); i++)
		snprintf(want + i * 2, 3, "%02x", req.profile_id[i]);

	for (size_t i = 0; i < ctx->profile_count; i++) {
		uint32_t recorded_handle = 0;
		time_t agreed = 0;

		if (!ctx->profiles[i].has_profile)
			continue;
		if (strcmp(ctx->profiles[i].paths.id, want) != 0)
			continue;

		/*
		 * Answering to a publisher hands them a stable handle on this
		 * machine, so somebody here has to have agreed. The own code
		 * lets the title show a screen.
		 */
		if (profile_consent_time(&ctx->profiles[i].paths, &agreed) ==
		    -ENOENT) {
			lota_warn("connection pid=%d asked for publisher %s, "
				  "which nobody on this machine has agreed to",
				  client->peer_pid, want);
			build_error_response(client,
					     LOTA_IPC_ERR_CONSENT_REQUIRED);
			return;
		}

		/*
		 * A publisher with no key yet needs a free handle: refused here
		 * so the session does not fail at its first GET_TOKEN.
		 */
		if (ctx->tpm &&
		    profile_aik_handle_load(&ctx->profiles[i].paths,
					    &recorded_handle) == -ENOENT) {
			struct profile_aik_slots slots;

			if (tpm_aik_slot_census(ctx->tpm, NULL, &slots) == 0 &&
			    slots.free_slots == 0) {
				lota_warn("connection pid=%d asked for "
					  "publisher %s, which holds no "
					  "attestation key yet and this host "
					  "has no slot left for one: "
					  "--list-publishers says what holds "
					  "the range, --forget-publisher frees "
					  "a slot",
					  client->peer_pid, want);
				build_error_response(client,
						     LOTA_IPC_ERR_NO_KEY_SLOT);
				return;
			}
		}

		client->profile = &ctx->profiles[i];
		snprintf(client->profile_id, sizeof(client->profile_id), "%s",
			 ctx->profiles[i].paths.id);
		ctx->profiles[i].sessions++;
		ctx->profiles[i].session_changed = true;
		ctx->profiles_changed = true;
		lota_dbg(
			"connection pid=%d bound to publisher %s (%d session%s)",
			client->peer_pid, want, ctx->profiles[i].sessions,
			ctx->profiles[i].sessions == 1 ? "" : "s");

		/*
		 * Never enrolled with this publisher: the attestation loop runs
		 * the enrollment, a TLS round trip and TPM credential
		 * activation. The connection reads not attested until it
		 * completes.
		 */
		{
			struct enroll_state st;

			if (enroll_state_load_path(
				    ctx->profiles[i].paths.enroll_state, &st) ==
			    -ENOENT) {
				ctx->profiles[i].enroll_pending = true;
				ctx->profiles_changed = true;
			} else
				ipc_secure_bzero(&st, sizeof(st));
		}

		resp->magic = LOTA_IPC_MAGIC;
		resp->version = LOTA_IPC_VERSION;
		resp->result = LOTA_IPC_OK;
		resp->payload_len = 0;
		client->send_len = LOTA_IPC_RESPONSE_SIZE;
		client->send_offset = 0;
		return;
	}

	/*
	 * A publisher with an unreadable anchor has no identity to match,
	 * so it may be the one asked for.
	 */
	{
		const struct attest_target *first = NULL;
		size_t unreadable = 0;

		for (size_t i = 0; i < ctx->profile_count; i++) {
			if (!ctx->profiles[i].profile_error)
				continue;
			if (!first)
				first = &ctx->profiles[i];
			unreadable++;
		}

		if (first)
			lota_warn("connection pid=%d asked for publisher %s, "
				  "which this host has no profile bound to. "
				  "%zu configured publisher%s cannot be "
				  "identified here because the trust anchor "
				  "could not be read (%s: %s); one of them may "
				  "be the publisher asked for",
				  client->peer_pid, want, unreadable,
				  unreadable == 1 ? "" : "s", first->ca_cert,
				  strerror(-first->profile_error));
		else
			lota_warn("connection pid=%d asked for publisher %s, "
				  "which this host has no profile for",
				  client->peer_pid, want);
	}
	build_error_response(client, LOTA_IPC_ERR_UNKNOWN_PROFILE);
}

static void profile_id_to_hex(const uint8_t id[32], char *out, size_t out_len)
{
	for (size_t i = 0; i < 32 && (i * 2 + 3) <= out_len; i++)
		snprintf(out + i * 2, 3, "%02x", id[i]);
}

/* Reverse of the above; a malformed stored id yields zeros */
static void profile_id_from_hex(const char *hex, uint8_t out[32])
{
	memset(out, 0, 32);

	if (!hex || strlen(hex) < 64)
		return;

	for (size_t i = 0; i < 32; i++) {
		unsigned int byte;

		if (sscanf(hex + i * 2, "%2x", &byte) != 1) {
			memset(out, 0, 32);
			return;
		}
		out[i] = (uint8_t)byte;
	}
}

/*
 * True when /proc/self/exe ends in " (deleted)": the file of the running binary
 * was replaced or removed. PCR 14 commits to the running build and resets on
 * every boot, so an update takes effect after a reboot.
 */
static bool agent_binary_replaced_on_disk(void)
{
	char exe_path[LOTA_MAX_PATH_LEN];
	static const char deleted_suffix[] = " (deleted)";
	ssize_t len;
	size_t suffix_len = sizeof(deleted_suffix) - 1;

	len = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
	if (len < 0 || (size_t)len < suffix_len)
		return false;
	exe_path[len] = '\0';

	return memcmp(exe_path + (size_t)len - suffix_len, deleted_suffix,
		      suffix_len) == 0;
}

/* Fold every publisher's verdict into the answer of a title naming nobody */
static void recompute_host_attestation(struct ipc_context *ctx)
{
	struct attest_aggregate agg;
	uint32_t flags = ctx->status_flags;

	attest_aggregate_compute(ctx->profiles, ctx->profile_count, &agg);

	if (agg.attested)
		flags |= LOTA_STATUS_ATTESTED;
	else
		flags &= ~(uint32_t)LOTA_STATUS_ATTESTED;

	/*
	 * Nothing reports: TOKEN_ONLY tells a title naming nobody why it is not
	 * attested.
	 */
	if (ctx->profile_count > 0 && agg.reporting == 0)
		flags |= LOTA_STATUS_TOKEN_ONLY;
	else
		flags &= ~(uint32_t)LOTA_STATUS_TOKEN_ONLY;

	if (agg.reenrolling)
		flags |= LOTA_STATUS_REENROLLING;
	else
		flags &= ~(uint32_t)LOTA_STATUS_REENROLLING;

	/* the update lands while this process runs */
	if (agent_binary_replaced_on_disk())
		flags |= LOTA_STATUS_UPDATE_PENDING;
	else
		flags &= ~(uint32_t)LOTA_STATUS_UPDATE_PENDING;

	ipc_update_status(ctx, flags, agg.valid_until);
}

/*
 * Set LOTA_STATUS_TPM_LOCKOUT while the loop or this process sees a lockout,
 * clear it when neither does, so clearing the chip needs no restart.
 */
static void adopt_loop_observations(struct ipc_context *ctx,
				    const struct lota_ipc_attest_sync *hdr)
{
	bool reported = (hdr->host_flags & LOTA_STATUS_TPM_LOCKOUT) != 0;
	bool was = (ctx->status_flags & LOTA_STATUS_TPM_LOCKOUT) != 0;
	bool mine = ctx->tpm && tpm_is_locked_out(ctx->tpm);
	bool locked;

	/*
	 * The early refusal makes no TPM call that could clear our latch;
	 * a round the loop completed shows the chip works.
	 */
	if (mine && !reported && hdr->attest_count > ctx->attest_count) {
		tpm_reset_lockout_state(ctx->tpm);
		mine = false;
	}

	locked = reported || mine;

	if (locked && !was)
		lota_err("TPM DA lockout: the attestation loop cannot use the "
			 "chip, so tokens are refused with "
			 "LOTA_IPC_ERR_TPM_LOCKOUT until it is cleared");
	else if (!locked && was)
		lota_notice("TPM DA lockout cleared: token issuance resumes");

	if (locked)
		ctx->status_flags |= LOTA_STATUS_TPM_LOCKOUT;
	else
		ctx->status_flags &= ~(uint32_t)LOTA_STATUS_TPM_LOCKOUT;
}

/*
 * Adopt the attestation loop's counters and announce any round they show.
 *
 * The loop sends running totals, so a round shows as a counter going up.
 * Both can rise in one sync when it reports several publishers, so pass and fail
 * are signalled separately. A counter that drops, as after a loop restart,
 * is adopted silently.
 */
static void adopt_attest_counters(struct ipc_context *ctx,
				  const struct lota_ipc_attest_sync *hdr)
{
	bool passed = hdr->attest_count > ctx->attest_count;
	bool failed = hdr->fail_count > ctx->fail_count;

	ctx->attest_count = hdr->attest_count;
	ctx->fail_count = hdr->fail_count;
	if (hdr->last_attest_time)
		ctx->last_attest_time = hdr->last_attest_time;

	if (!passed && !failed)
		return;

	notify_subscribers(ctx, LOTA_IPC_EVENT_ATTEST);

	if (passed)
		dbus_emit_attestation_result(ctx->dbus, true);
	if (failed)
		dbus_emit_attestation_result(ctx->dbus, false);
}

/*
 * The state exchange with the attestation loop: it hands over the verdict it
 * holds for each publisher and reads back the sessions and enrollment requests.
 *
 * enroll_pending is cleared as it is handed over: the loop keeps its own
 * backoff for an enrollment that fails, and a later SET_PROFILE raises it
 * again.
 */
static void handle_sync_attest(struct ipc_context *ctx,
			       struct ipc_client *client,
			       const uint8_t *payload, uint32_t payload_len)
{
	struct lota_ipc_response *resp = (void *)client->send_buf;
	struct lota_ipc_attest_sync_response *out;
	struct lota_ipc_profile_demand *demand;
	struct lota_ipc_attest_sync hdr;
	uint32_t verdicts;
	uint32_t emitted = 0;

	if (!ipc_client_is_agent_peer(client)) {
		lota_warn("SYNC_ATTEST denied for uid=%d pid=%d: other uid or "
			  "stale pid",
			  client->peer_uid, client->peer_pid);
		build_error_response(client, LOTA_IPC_ERR_ACCESS_DENIED);
		return;
	}

	if (payload_len < sizeof(hdr)) {
		build_error_response(client, LOTA_IPC_ERR_BAD_REQUEST);
		return;
	}
	memcpy(&hdr, payload, sizeof(hdr));

	verdicts = (uint32_t)((payload_len - sizeof(hdr)) /
			      sizeof(struct lota_ipc_attest_verdict));
	if (hdr.count != verdicts) {
		build_error_response(client, LOTA_IPC_ERR_BAD_REQUEST);
		return;
	}

	for (uint32_t i = 0; i < verdicts; i++) {
		struct lota_ipc_attest_verdict v;
		char id[LOTA_PROFILE_ID_LEN];

		memcpy(&v, payload + sizeof(hdr) + i * sizeof(v), sizeof(v));
		profile_id_to_hex(v.profile_id, id, sizeof(id));

		for (size_t j = 0; j < ctx->profile_count; j++) {
			if (!ctx->profiles[j].has_profile)
				continue;
			if (strcmp(ctx->profiles[j].paths.id, id) != 0)
				continue;

			ctx->profiles[j].attested = v.attested != 0;
			ctx->profiles[j].reenrolling = v.reenrolling != 0;
			ctx->profiles[j].valid_until = v.valid_until;
			break;
		}
	}

	resp->magic = LOTA_IPC_MAGIC;
	resp->version = LOTA_IPC_VERSION;
	resp->result = LOTA_IPC_OK;

	out = (void *)(client->send_buf + LOTA_IPC_RESPONSE_SIZE);
	demand = (void *)(client->send_buf + LOTA_IPC_RESPONSE_SIZE +
			  sizeof(*out));

	for (size_t j = 0; j < ctx->profile_count; j++) {
		if (!ctx->profiles[j].has_profile)
			continue;

		profile_id_from_hex(ctx->profiles[j].paths.id,
				    demand[emitted].profile_id);
		demand[emitted].sessions = (uint32_t)ctx->profiles[j].sessions;
		demand[emitted].enroll_pending =
			ctx->profiles[j].enroll_pending ? 1 : 0;
		memset(demand[emitted].reserved, 0,
		       sizeof(demand[emitted].reserved));
		ctx->profiles[j].enroll_pending = false;
		emitted++;
	}

	out->count = emitted;
	out->_reserved1 = 0;

	resp->payload_len =
		(uint32_t)(sizeof(*out) + (size_t)emitted * sizeof(*demand));
	client->send_len = LOTA_IPC_RESPONSE_SIZE + resp->payload_len;
	client->send_offset = 0;

	/* publisher events only: a session opening must wake the loop */
	client->attest_peer = true;
	client->subscribed = true;
	client->event_mask = LOTA_IPC_EVENT_PROFILE;

	adopt_loop_observations(ctx, &hdr);
	recompute_host_attestation(ctx);
	adopt_attest_counters(ctx, &hdr);
}

/*
 * event_mask = 0 cancels the subscription. Bits the caller may not have are
 * dropped; the request fails only if nothing is left.
 */
static void handle_subscribe(struct ipc_context *ctx, struct ipc_client *client,
			     const uint8_t *payload, uint32_t payload_len)
{
	struct lota_ipc_response *resp = (void *)client->send_buf;
	struct lota_ipc_subscribe_request sub;

	if (payload_len < sizeof(sub)) {
		build_error_response(client, LOTA_IPC_ERR_BAD_REQUEST);
		return;
	}

	memcpy(&sub, payload, sizeof(sub));

	if (sub.event_mask == 0) {
		client->subscribed = false;
		client->event_mask = 0;
		client->notify_pending = false;
		client->pending_events = 0;
	} else {
		uint32_t mask = sub.event_mask;

		if (!client->attest_peer)
			mask &= IPC_EVENT_PUBLIC;

		if (mask == 0) {
			build_error_response(client, LOTA_IPC_ERR_BAD_REQUEST);
			return;
		}

		client->subscribed = true;
		client->event_mask = mask;
		client->told_flags = client_status_word(ctx, client);
	}

	resp->magic = LOTA_IPC_MAGIC;
	resp->version = LOTA_IPC_VERSION;
	resp->result = LOTA_IPC_OK;
	resp->payload_len = 0;

	client->send_len = LOTA_IPC_RESPONSE_SIZE;
	client->send_offset = 0;
}

static int pid_set_contains(const uint32_t *pids, int count, uint32_t pid)
{
	if (!pids || count <= 0)
		return 0;
	for (int i = 0; i < count; i++) {
		if (pids[i] == pid)
			return 1;
	}
	return 0;
}

static int u32_cmp(const void *a, const void *b)
{
	uint32_t av = *(const uint32_t *)a;
	uint32_t bv = *(const uint32_t *)b;
	if (av < bv)
		return -1;
	if (av > bv)
		return 1;
	return 0;
}

/*
 * A pid whose /proc/<pid>/stat cannot be read counts as gone. That file is
 * world-readable, so this works on a process with dumpable cleared.
 */
static bool protect_pid_is_alive(uint32_t pid, void *ctx)
{
	uint64_t ticks = 0;

	(void)ctx;
	return read_pid_start_time_ticks((pid_t)pid, &ticks) == 0;
}

/*
 * Drop every protected PID whose process has exited; lota_task_free drops it
 * from the kernel's map. A changed set moves the epoch.
 */
static void runtime_protect_reap_exited(void)
{
	uint32_t *kept = NULL;
	int kept_count = 0;
	int count;
	int ret;

	count = g_agent.policy_protect_pid_count;
	if (count <= 0 || !g_agent.policy_protect_pids)
		return;

	kept = calloc((size_t)count, sizeof(uint32_t));
	if (!kept)
		return;

	ret = protect_pids_reap(g_agent.policy_protect_pids, count,
				protect_pid_is_alive, NULL, kept, &kept_count);
	if (ret <= 0) {
		OPENSSL_cleanse(kept, (size_t)count * sizeof(uint32_t));
		free(kept);
		return;
	}

	if (g_agent.policy_protect_epoch == UINT64_MAX) {
		lota_err("Refusing to reap exited protected PIDs: epoch "
			 "exhausted");
		OPENSSL_cleanse(kept, (size_t)count * sizeof(uint32_t));
		free(kept);
		return;
	}

	/* lota_task_free drops the map entry: best effort */
	for (int i = 0; i < count; i++) {
		uint32_t pid = g_agent.policy_protect_pids[i];
		bool still_kept = false;

		for (int j = 0; j < kept_count; j++) {
			if (kept[j] == pid) {
				still_kept = true;
				break;
			}
		}
		if (still_kept)
			continue;

		lota_info("Protected PID %u has exited; dropping it from the "
			  "runtime set",
			  pid);
		(void)bpf_loader_unprotect_pid(&g_agent.bpf_ctx, pid);
	}

	agent_globals_lock(&g_agent);
	OPENSSL_cleanse(g_agent.policy_protect_pids,
			(size_t)count * sizeof(uint32_t));
	free(g_agent.policy_protect_pids);
	g_agent.policy_protect_pids = kept;
	g_agent.policy_protect_pid_count = kept_count;
	g_agent.policy_protect_epoch += 1;
	agent_globals_unlock(&g_agent);
}

static int protect_pid_adopt(uint32_t pid, void *ctx)
{
	struct bpf_instance_member m;
	int ret;

	(void)ctx;
	ret = bpf_loader_adopt_instance_member(&g_agent.bpf_ctx, pid, &m);
	if (ret > 0 &&
	    protect_owner_note(&g_protect_owners, pid, m.start_ticks,
			       m.root_tgid, m.root_start_ticks, NULL) < 0)
		lota_warn("PID %u joins the runtime set for no publisher: "
			  "owner table full",
			  pid);
	return ret;
}

/* Every running process but the agent, from /proc */
static int list_running_pids(uint32_t **out, int *out_count)
{
	uint32_t self = (uint32_t)getpid();
	uint32_t *pids = NULL;
	struct dirent *de;
	int count = 0;
	int cap = 0;
	DIR *dir;

	*out = NULL;
	*out_count = 0;

	dir = opendir("/proc");
	if (!dir)
		return -errno;

	while ((de = readdir(dir)) != NULL) {
		unsigned long val;
		char *end;

		if (de->d_name[0] < '1' || de->d_name[0] > '9')
			continue;
		errno = 0;
		val = strtoul(de->d_name, &end, 10);
		if (errno || *end || val > UINT32_MAX || val == self)
			continue;

		if (count == cap) {
			int next_cap = cap ? cap * 2 : 256;
			uint32_t *next;

			next = realloc(pids, (size_t)next_cap * sizeof(*pids));
			if (!next) {
				free(pids);
				closedir(dir);
				return -ENOMEM;
			}
			pids = next;
			cap = next_cap;
		}
		pids[count++] = (uint32_t)val;
	}
	closedir(dir);

	*out = pids;
	*out_count = count;
	return 0;
}

/*
 * Add the processes a protected one created: the kernel protects them from
 * their first instruction, and only the root of the tree was named here.
 */
static void runtime_protect_adopt_members(void)
{
	uint32_t *cands = NULL;
	uint32_t *next = NULL;
	int cand_count = 0;
	int next_count = 0;
	int count;
	int ret;

	if (g_agent.bpf_ctx.instance_fd < 0)
		return;

	count = g_agent.policy_protect_pid_count;
	if (count < 0 || (count > 0 && !g_agent.policy_protect_pids))
		return;

	if (g_agent.policy_protect_epoch == UINT64_MAX)
		return;

	if (list_running_pids(&cands, &cand_count) < 0)
		return;

	next = calloc(LOTA_MAX_PROTECTED_PIDS, sizeof(*next));
	if (!next)
		goto out;

	ret = protect_pids_adopt(g_agent.policy_protect_pids, count, cands,
				 cand_count, protect_pid_adopt, NULL,
				 LOTA_MAX_PROTECTED_PIDS, next, &next_count);
	if (ret <= 0)
		goto out;

	for (int i = count; i < next_count; i++)
		lota_info("PID %u runs in a protected instance; adding it to "
			  "the runtime set",
			  next[i]);

	agent_globals_lock(&g_agent);
	if (g_agent.policy_protect_pids) {
		OPENSSL_cleanse(g_agent.policy_protect_pids,
				(size_t)count * sizeof(uint32_t));
		free(g_agent.policy_protect_pids);
	}
	g_agent.policy_protect_pids = next;
	g_agent.policy_protect_pid_count = next_count;
	g_agent.policy_protect_epoch += 1;
	agent_globals_unlock(&g_agent);
	next = NULL;

out:
	free(next);
	free(cands);
}

/* Bring the set in step with the kernel: exited processes out, members in */
static void runtime_protect_catch_up(void)
{
	runtime_protect_reap_exited();
	runtime_protect_adopt_members();
	protect_owners_retain(&g_protect_owners, g_agent.policy_protect_pids,
			      g_agent.policy_protect_pid_count);
}

static int build_canonical_runtime_pid_list(uint32_t **out_pids,
					    uint32_t *out_count)
{
	uint32_t *canon = NULL;
	uint32_t count = 0;

	if (!out_pids || !out_count)
		return -EINVAL;
	*out_pids = NULL;
	*out_count = 0;

	if (g_agent.policy_protect_pid_count < 0)
		return -EINVAL;

	count = (uint32_t)g_agent.policy_protect_pid_count;
	if (count == 0)
		return 0;
	if (!g_agent.policy_protect_pids)
		return -EINVAL;

	canon = calloc(count, sizeof(uint32_t));
	if (!canon)
		return -ENOMEM;

	memcpy(canon, g_agent.policy_protect_pids, count * sizeof(uint32_t));
	qsort(canon, count, sizeof(uint32_t), u32_cmp);

	for (uint32_t i = 1; i < count; i++) {
		if (canon[i - 1] == canon[i]) {
			OPENSSL_cleanse(canon, count * sizeof(uint32_t));
			free(canon);
			return -EINVAL;
		}
	}

	*out_pids = canon;
	*out_count = count;
	return 0;
}

static int pid_set_add(const uint32_t *pids, int count, uint32_t pid,
		       uint32_t **out, int *out_count)
{
	if (!out || !out_count)
		return -EINVAL;
	*out = NULL;
	*out_count = 0;
	if (count < 0)
		return -EINVAL;
	if (pid == 0)
		return -EINVAL;

	if (pid_set_contains(pids, count, pid)) {
		uint32_t *copy = NULL;
		if (count > 0) {
			copy = calloc((size_t)count, sizeof(uint32_t));
			if (!copy)
				return -ENOMEM;
			memcpy(copy, pids, (size_t)count * sizeof(uint32_t));
		}
		*out = copy;
		*out_count = count;
		return 0;
	}

	uint32_t *new_pids = calloc((size_t)count + 1, sizeof(uint32_t));
	if (!new_pids)
		return -ENOMEM;
	if (count > 0)
		memcpy(new_pids, pids, (size_t)count * sizeof(uint32_t));
	new_pids[count] = pid;

	*out = new_pids;
	*out_count = count + 1;
	return 0;
}

/*
 * 0 when @pid has no tracer. A process under one is refused protection:
 * the LSM stops new attaches, not the one already there.
 */
static int protect_target_untraced(uint32_t pid)
{
	long tracer = 0;
	int ret;

	ret = hardening_read_tracer_pid((pid_t)pid, &tracer);
	if (ret == -EPERM)
		lota_warn("Refusing PROTECT_PID %u: traced by pid %ld, "
			  "which protection does not detach",
			  pid, tracer);
	else if (ret < 0)
		lota_warn("Refusing PROTECT_PID %u: cannot read its tracer: %s",
			  pid, strerror(-ret));
	return ret;
}

/* @pid is protected for the publisher @client named */
static void protect_owner_note_add(const struct ipc_client *client,
				   uint32_t pid, uint64_t ticks)
{
	const char *publisher = client->profile ? client->profile->paths.id :
						  NULL;

	if (protect_owner_note(&g_protect_owners, pid, ticks, pid, ticks,
			       publisher) < 0)
		lota_warn("PID %u is protected for no publisher: owner table "
			  "full",
			  pid);
}

static void protect_pid_reply(struct ipc_client *client)
{
	struct lota_ipc_response *resp = (void *)client->send_buf;
	struct lota_ipc_policy_update *out;

	resp->magic = LOTA_IPC_MAGIC;
	resp->version = LOTA_IPC_VERSION;
	resp->result = LOTA_IPC_OK;
	resp->payload_len = sizeof(*out);
	out = (void *)(client->send_buf + LOTA_IPC_RESPONSE_SIZE);
	memcpy(out->policy_digest, g_agent.policy_digest,
	       sizeof(out->policy_digest));
	out->_reserved1 = 0;
	client->send_len = LOTA_IPC_RESPONSE_SIZE + sizeof(*out);
	client->send_offset = 0;
}

/*
 * 0 when @pid still names the process @pidfd holds, with @ticks its start
 * time. Asked after the map holds @pid: a process alive then keeps its PID.
 */
static int protect_target_live(int pidfd, uint32_t pid, uint64_t *ticks)
{
	if (read_pid_start_time_ticks((pid_t)pid, ticks) < 0 ||
	    pidfd_exited(pidfd)) {
		lota_warn("Refusing PROTECT_PID %u: the process exited", pid);
		return -ESRCH;
	}
	return 0;
}

static void protect_peer(struct ipc_client *client, int pidfd, uint32_t pid)
{
	uint32_t *new_pids = NULL;
	int new_count = 0;
	uint64_t ticks = 0;
	int ret;

	if (check_protect_pid_rate_limit(client->peer_uid) < 0) {
		lota_warn("rate limited PROTECT_PID for uid=%d pid=%u",
			  client->peer_uid, pid);
		build_error_response(client, LOTA_IPC_ERR_RATE_LIMITED);
		return;
	}

	/*
	 * Runtime PID policy changes what the startup policy left behind.
	 * An agent that applied none has nothing to change.
	 */
	if (!g_agent.policy_snapshot_set) {
		lota_warn("Refusing PROTECT_PID for uid=%d pid=%u: this agent "
			  "applied no startup policy, so it enforces nothing "
			  "and has no runtime PID policy to change",
			  client->peer_uid, pid);
		build_error_response(client, LOTA_IPC_ERR_NO_ENFORCEMENT);
		return;
	}

	if (!g_agent.policy_digest_set) {
		lota_err("Refusing PROTECT_PID for uid=%d pid=%u: the startup "
			 "policy is applied but its digest is unset, which "
			 "nothing should be able to produce",
			 client->peer_uid, pid);
		build_error_response(client, LOTA_IPC_ERR_INTERNAL);
		return;
	}

	/* judge the no-op against the running processes */
	runtime_protect_catch_up();

	/* idempotent no-op: return current digest */
	if (pid_set_contains(g_agent.policy_protect_pids,
			     g_agent.policy_protect_pid_count, pid)) {
		if (protect_target_live(pidfd, pid, &ticks) < 0) {
			build_error_response(client,
					     LOTA_IPC_ERR_ACCESS_DENIED);
			return;
		}
		protect_owner_note_add(client, pid, ticks);
		protect_pid_reply(client);
		return;
	}

	if (g_agent.policy_protect_epoch == UINT64_MAX) {
		lota_err("Refusing runtime PID policy mutation: protect epoch "
			 "exhausted");
		build_error_response(client, LOTA_IPC_ERR_INTERNAL);
		return;
	}

	if ((uint32_t)g_agent.policy_protect_pid_count + 1u >
	    LOTA_MAX_PROTECTED_PIDS) {
		lota_warn("Refusing PROTECT_PID %u: protected PID map "
			  "capacity reached "
			  "(%d)",
			  pid, LOTA_MAX_PROTECTED_PIDS);
		build_error_response(client, LOTA_IPC_ERR_BAD_REQUEST);
		return;
	}

	ret = bpf_loader_protect_pid(&g_agent.bpf_ctx, pid);
	if (ret < 0) {
		lota_err("Failed to protect PID %u (IPC): %s", pid,
			 strerror(-ret));
		build_error_response(client, LOTA_IPC_ERR_INTERNAL);
		return;
	}

	/*
	 * Read after the map holds the process, so no attach lands
	 * between the check and the protection: a tracer seen now
	 * was attached before it, and stays.
	 */
	if (protect_target_untraced(pid) < 0 ||
	    protect_target_live(pidfd, pid, &ticks) < 0) {
		if (bpf_loader_unprotect_pid(&g_agent.bpf_ctx, pid) < 0)
			lota_err("Failed to withdraw protection from "
				 "PID %u",
				 pid);
		build_error_response(client, LOTA_IPC_ERR_ACCESS_DENIED);
		return;
	}

	ret = pid_set_add(g_agent.policy_protect_pids,
			  g_agent.policy_protect_pid_count, pid, &new_pids,
			  &new_count);
	if (ret < 0) {
		lota_err("PID set update failed: %s", strerror(-ret));
		(void)bpf_loader_unprotect_pid(&g_agent.bpf_ctx, pid);
		build_error_response(client, LOTA_IPC_ERR_INTERNAL);
		return;
	}

	agent_globals_lock(&g_agent);
	if (g_agent.policy_protect_pids) {
		OPENSSL_cleanse(g_agent.policy_protect_pids,
				(size_t)g_agent.policy_protect_pid_count *
					sizeof(uint32_t));
		free(g_agent.policy_protect_pids);
	}
	g_agent.policy_protect_pids = new_pids;
	g_agent.policy_protect_pid_count = new_count;
	g_agent.policy_protect_epoch += 1;
	agent_globals_unlock(&g_agent);

	protect_owner_note_add(client, pid, ticks);
	protect_pid_reply(client);
}

/*
 * The process that connected protects itself. Its PID comes from the socket,
 * in the agent's namespace; a PID in the request is refused.
 */
static void handle_protect_pid(struct ipc_client *client,
			       const uint8_t *payload, uint32_t payload_len)
{
	struct lota_ipc_pid_request req;
	socklen_t len = sizeof(int);
	uint32_t pid = 0;
	int pidfd = -1;

	if (payload_len < sizeof(req)) {
		build_error_response(client, LOTA_IPC_ERR_BAD_REQUEST);
		return;
	}
	memcpy(&req, payload, sizeof(req));
	if (req.pid != 0) {
		build_error_response(client, LOTA_IPC_ERR_BAD_REQUEST);
		return;
	}

	if (getsockopt(client->fd, SOL_SOCKET, SO_PEERPIDFD, &pidfd, &len) <
		    0 ||
	    pidfd_own_pid(pidfd, &pid, NULL) < 0) {
		lota_warn("PROTECT_PID denied for uid=%d pid=%d: the process "
			  "is gone or runs in a PID namespace outside the "
			  "agent's",
			  client->peer_uid, client->peer_pid);
		if (pidfd >= 0)
			close(pidfd);
		build_error_response(client, LOTA_IPC_ERR_ACCESS_DENIED);
		return;
	}

	protect_peer(client, pidfd, pid);
	close(pidfd);
}

/* The real uid of @pid, from /proc/<pid>/status */
static int read_pid_real_uid(pid_t pid, uint32_t *out_uid)
{
	char path[64];
	FILE *fp;
	char line[512];
	int ret = -ESRCH;

	if (!out_uid || pid <= 0)
		return -EINVAL;

	snprintf(path, sizeof(path), "/proc/%d/status", (int)pid);
	fp = fopen(path, "r");
	if (!fp)
		return -errno;

	while (fgets(line, sizeof(line), fp)) {
		unsigned int real_uid;

		if (strncmp(line, "Uid:", 4) != 0)
			continue;
		if (sscanf(line + 4, "%u", &real_uid) != 1)
			break;
		*out_uid = (uint32_t)real_uid;
		ret = 0;
		break;
	}

	fclose(fp);
	return ret;
}

/*
 * One page of the objects the last token round found mapped in a process,
 * for its owner calling from the same instance. A PID absent from that
 * round, or now naming another process, is answered NOT_PROTECTED.
 */
static void handle_get_registry(struct ipc_client *client,
				const uint8_t *payload, uint32_t payload_len)
{
	struct lota_ipc_response *resp = (void *)client->send_buf;
	struct lota_ipc_registry_request req;
	const struct registry_process *p = NULL;
	struct proc_instance instance;
	uint64_t ticks = 0;
	size_t len = 0;
	int ret;

	if (payload_len < sizeof(req)) {
		build_error_response(client, LOTA_IPC_ERR_BAD_REQUEST);
		return;
	}
	memcpy(&req, payload, sizeof(req));

	if (read_pid_start_time_ticks((pid_t)req.pid, &ticks) == 0)
		p = registry_find(&g_registry, req.pid, ticks);
	if (!p) {
		build_error_response(client, LOTA_IPC_ERR_NOT_PROTECTED);
		return;
	}
	if ((uint32_t)client->peer_uid != p->uid ||
	    !peer_instance(client, &instance) ||
	    !pid_in_instance(&instance, req.pid)) {
		build_error_response(client, LOTA_IPC_ERR_ACCESS_DENIED);
		return;
	}

	ret = registry_encode_page(p, g_registry.round, req.start,
				   client->send_buf + LOTA_IPC_RESPONSE_SIZE,
				   LOTA_IPC_MAX_PAYLOAD, &len);
	if (ret < 0) {
		build_error_response(client, ret == -ERANGE ?
						     LOTA_IPC_ERR_BAD_REQUEST :
						     LOTA_IPC_ERR_INTERNAL);
		return;
	}

	resp->magic = LOTA_IPC_MAGIC;
	resp->version = LOTA_IPC_VERSION;
	resp->result = LOTA_IPC_OK;
	resp->payload_len = (uint32_t)len;
	client->send_len = LOTA_IPC_RESPONSE_SIZE + len;
	client->send_offset = 0;
}

/*
 * The caller's own last refused file, all zero when none is kept.
 * The pidfd names the process that connected, not one that took its PID later.
 */
static void handle_get_refusal(struct ipc_client *client)
{
	struct lota_ipc_response *resp = (void *)client->send_buf;
	struct lota_ipc_refusal out = { 0 };
	socklen_t len = sizeof(int);
	uint64_t at_ns = 0;
	int pidfd = -1;

	if (getsockopt(client->fd, SOL_SOCKET, SO_PEERPIDFD, &pidfd, &len) ==
	    0) {
		if (bpf_loader_get_refusal(&g_agent.bpf_ctx, pidfd, &at_ns,
					   out.object, sizeof(out.object)) == 0)
			out.at_ns = at_ns;
		close(pidfd);
	}

	memcpy(client->send_buf + LOTA_IPC_RESPONSE_SIZE, &out, sizeof(out));
	resp->magic = LOTA_IPC_MAGIC;
	resp->version = LOTA_IPC_VERSION;
	resp->result = LOTA_IPC_OK;
	resp->payload_len = sizeof(out);
	client->send_len = LOTA_IPC_RESPONSE_SIZE + sizeof(out);
	client->send_offset = 0;
}

/* The protected processes of @inst other than @target */
static uint32_t instance_others_protected(const struct proc_instance *inst,
					  uint32_t target)
{
	uint32_t *pids = NULL;
	uint32_t others = 0;
	int count;

	agent_globals_lock(&g_agent);
	count = g_agent.policy_protect_pid_count;
	if (count > 0)
		pids = calloc((size_t)count, sizeof(*pids));
	if (pids)
		memcpy(pids, g_agent.policy_protect_pids,
		       (size_t)count * sizeof(*pids));
	agent_globals_unlock(&g_agent);

	for (int i = 0; pids && i < count; i++) {
		if (pids[i] != target && pid_in_instance(inst, pids[i]))
			others++;
	}
	free(pids);
	return others;
}

/*
 * End a protected process for its owner or root; terminate_policy_decide()
 * holds the rule.
 *
 * No privilege gate: the LSM lets the caller send these signals itself.
 * This adds the journal line and the status bit.
 */
static void handle_terminate_protected(struct ipc_context *ctx,
				       struct ipc_client *client,
				       const uint8_t *payload,
				       uint32_t payload_len)
{
	struct lota_ipc_response *resp = (void *)client->send_buf;
	struct lota_ipc_terminate_request req;
	struct lota_ipc_terminate_response *out;
	struct terminate_request decision_input = { 0 };
	enum terminate_decision decision;
	char owner[LOTA_PROFILE_ID_LEN];
	struct proc_instance instance;
	bool has_instance;
	socklen_t len = sizeof(int);
	uint32_t target_uid = 0;
	uint64_t ticks = 0;
	uint32_t caller = 0;
	bool nested = true;
	int caller_fd = -1;
	int pidfd;
	int uid_ret;

	if (payload_len < sizeof(req)) {
		build_error_response(client, LOTA_IPC_ERR_BAD_REQUEST);
		return;
	}
	memcpy(&req, payload, sizeof(req));

	if (req.pid == 0 || req.pid > INT_MAX) {
		build_error_response(client, LOTA_IPC_ERR_BAD_REQUEST);
		return;
	}

	/* @req.pid is read in the agent's PID namespace */
	if (getsockopt(client->fd, SOL_SOCKET, SO_PEERPIDFD, &caller_fd, &len) <
		    0 ||
	    pidfd_own_pid(caller_fd, &caller, &nested) < 0 || nested) {
		if (caller_fd >= 0)
			close(caller_fd);
		lota_warn("TERMINATE_PROTECTED denied for uid=%d pid=%d: send "
			  "it from the host's PID namespace",
			  client->peer_uid, client->peer_pid);
		build_error_response(client, LOTA_IPC_ERR_ACCESS_DENIED);
		return;
	}
	close(caller_fd);

	pidfd = (int)syscall(SYS_pidfd_open, (pid_t)req.pid, 0);
	if (pidfd < 0) {
		lota_warn("TERMINATE_PROTECTED for pid=%u from uid=%d: %s",
			  req.pid, client->peer_uid, strerror(errno));
		build_error_response(client, LOTA_IPC_ERR_BAD_REQUEST);
		return;
	}

	uid_ret = read_pid_real_uid((pid_t)req.pid, &target_uid);
	if (uid_ret == 0)
		uid_ret = read_pid_start_time_ticks((pid_t)req.pid, &ticks);
	if (uid_ret == 0 && pidfd_exited(pidfd))
		uid_ret = -ESRCH;
	if (uid_ret < 0) {
		close(pidfd);
		lota_warn("TERMINATE_PROTECTED for pid=%u from uid=%d: cannot "
			  "read the owner of that process (%s)",
			  req.pid, client->peer_uid, strerror(-uid_ret));
		build_error_response(client, LOTA_IPC_ERR_BAD_REQUEST);
		return;
	}

	runtime_protect_catch_up();

	agent_globals_lock(&g_agent);
	decision_input.target_is_protected =
		pid_set_contains(g_agent.policy_protect_pids,
				 g_agent.policy_protect_pid_count,
				 req.pid) != 0;
	agent_globals_unlock(&g_agent);

	decision_input.target_pid = req.pid;
	decision_input.target_uid = target_uid;
	decision_input.caller_uid = (uint32_t)client->peer_uid;
	decision_input.agent_pid = (uint32_t)getpid();
	decision_input.signal = (int)req.signal;

	decision = terminate_policy_decide(&decision_input);
	if (decision != TERMINATE_ALLOW) {
		close(pidfd);
		lota_warn("TERMINATE_PROTECTED denied for uid=%d pid=%d "
			  "target=%u sig=%u: %s",
			  client->peer_uid, client->peer_pid, req.pid,
			  req.signal, terminate_decision_reason(decision));
		build_error_response(client,
				     terminate_decision_result(decision));
		return;
	}

	snprintf(owner, sizeof(owner), "%s",
		 protect_owner_publisher(&g_protect_owners, req.pid, ticks));
	has_instance = pidfd_instance(pidfd, req.pid, &instance);

	if (syscall(SYS_pidfd_send_signal, pidfd, (int)req.signal, NULL, 0) <
	    0) {
		int err = errno;

		close(pidfd);
		lota_err("TERMINATE_PROTECTED failed for pid=%u sig=%u: %s",
			 req.pid, req.signal, strerror(err));
		build_error_response(client, err == ESRCH ?
						     LOTA_IPC_ERR_BAD_REQUEST :
						     LOTA_IPC_ERR_INTERNAL);
		return;
	}
	close(pidfd);

	lota_notice("Protected pid=%u (uid=%u) terminated with signal %u at "
		    "the request of uid=%d pid=%d",
		    req.pid, target_uid, req.signal, client->peer_uid,
		    client->peer_pid);

	/*
	 * The status word says until the agent ends that a protected process
	 * was ended here: a session closed locally differs from one that
	 * vanished. A publisher's titles see it for that publisher's processes.
	 */
	ctx->protected_terminated = true;
	ctx->status_flags |= LOTA_STATUS_PROTECTED_TERMINATED;
	for (size_t i = 0; owner[0] && i < ctx->profile_count; i++) {
		if (ctx->profiles[i].has_profile &&
		    strcmp(ctx->profiles[i].paths.id, owner) == 0)
			ctx->profiles[i].protected_terminated = true;
	}
	publish_status(ctx);

	resp->magic = LOTA_IPC_MAGIC;
	resp->version = LOTA_IPC_VERSION;
	resp->result = LOTA_IPC_OK;
	resp->payload_len = sizeof(*out);
	out = (void *)(client->send_buf + LOTA_IPC_RESPONSE_SIZE);
	out->pid = req.pid;
	out->signal = req.signal;
	out->other_protect_pid_count =
		has_instance ? instance_others_protected(&instance, req.pid) :
			       0;
	out->_reserved1 = 0;
	client->send_len = LOTA_IPC_RESPONSE_SIZE + sizeof(*out);
	client->send_offset = 0;
}

static void handle_shutdown(struct ipc_context *ctx, struct ipc_client *client,
			    const uint8_t *payload, uint32_t payload_len)
{
	struct lota_ipc_response *resp = (void *)client->send_buf;
	(void)payload;

	if (payload_len != 0) {
		build_error_response(client, LOTA_IPC_ERR_BAD_REQUEST);
		return;
	}

	if (!ipc_client_is_privileged(ctx, client)) {
		lota_warn("SHUTDOWN denied for uid=%d pid=%d", client->peer_uid,
			  client->peer_pid);
		build_error_response(client, LOTA_IPC_ERR_ACCESS_DENIED);
		return;
	}

	resp->magic = LOTA_IPC_MAGIC;
	resp->version = LOTA_IPC_VERSION;
	resp->result = LOTA_IPC_OK;
	resp->payload_len = 0;
	client->send_len = LOTA_IPC_RESPONSE_SIZE;
	client->send_offset = 0;
	client->shutdown_on_flush = true;

	lota_notice("Privileged shutdown requested via IPC by uid=%d pid=%d",
		    client->peer_uid, client->peer_pid);
}

static void process_request(struct ipc_context *ctx, struct ipc_client *client)
{
	struct lota_ipc_request req;
	uint8_t *payload = client->recv_buf + LOTA_IPC_REQUEST_SIZE;
	uint32_t payload_len;

	memcpy(&req, client->recv_buf, sizeof(req));
	payload_len = req.payload_len;

	if (req.magic != LOTA_IPC_MAGIC) {
		build_error_response(client, LOTA_IPC_ERR_BAD_REQUEST);
		return;
	}

	if (req.version != LOTA_IPC_VERSION) {
		build_error_response(client, LOTA_IPC_ERR_BAD_VERSION);
		return;
	}

	if (!ipc_payload_len_valid(req.cmd, payload_len)) {
		lota_warn("invalid payload length for cmd=0x%X from pid=%d "
			  "uid=%d (len=%u)",
			  req.cmd, client->peer_pid, client->peer_uid,
			  payload_len);
		build_error_response(client, LOTA_IPC_ERR_BAD_REQUEST);
		return;
	}

	switch (req.cmd) {
	case LOTA_IPC_CMD_PING:
		handle_ping(ctx, client);
		break;

	case LOTA_IPC_CMD_GET_STATUS:
		handle_get_status(ctx, client);
		break;

	case LOTA_IPC_CMD_GET_TOKEN:
		handle_get_token(ctx, client, payload, payload_len);
		break;

	case LOTA_IPC_CMD_GET_BOOT_EVIDENCE:
		handle_get_boot_evidence(ctx, client);
		break;

	case LOTA_IPC_CMD_SET_PROFILE:
		handle_set_profile(ctx, client, payload, payload_len);
		break;

	case LOTA_IPC_CMD_SUBSCRIBE:
		handle_subscribe(ctx, client, payload, payload_len);
		break;

	case LOTA_IPC_CMD_PROTECT_PID:
		handle_protect_pid(client, payload, payload_len);
		break;

	case LOTA_IPC_CMD_SYNC_ATTEST:
		handle_sync_attest(ctx, client, payload, payload_len);
		break;

	case LOTA_IPC_CMD_TERMINATE_PROTECTED:
		handle_terminate_protected(ctx, client, payload, payload_len);
		break;

	case LOTA_IPC_CMD_GET_REGISTRY:
		handle_get_registry(client, payload, payload_len);
		break;

	case LOTA_IPC_CMD_GET_REFUSAL:
		handle_get_refusal(client);
		break;

	case LOTA_IPC_CMD_SHUTDOWN:
		handle_shutdown(ctx, client, payload, payload_len);
		break;

	default:
		build_error_response(client, LOTA_IPC_ERR_UNKNOWN_CMD);
		break;
	}
}

static int handle_client_read(struct ipc_context *ctx,
			      struct ipc_client *client)
{
	ssize_t n;
	size_t need;
	struct lota_ipc_request req;

	/* the buffer may already hold a complete pipelined request */
	if (client->recv_len < LOTA_IPC_REQUEST_SIZE)
		goto do_recv;

	memcpy(&req, client->recv_buf, sizeof(req));

	if (req.payload_len > LOTA_IPC_MAX_PAYLOAD) {
		lota_warn("oversized payload from pid=%d uid=%d (len=%u)",
			  client->peer_pid, client->peer_uid, req.payload_len);
		return -1; /* close: cannot recover from protocol desync */
	}

	need = LOTA_IPC_REQUEST_SIZE + req.payload_len;
	if (client->recv_len >= need)
		goto have_request;

do_recv:
	need = sizeof(client->recv_buf) - client->recv_len;
	n = recv(client->fd, client->recv_buf + client->recv_len, need, 0);

	if (n < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK)
			return 0;
		return -errno;
	}

	if (n == 0)
		return -ECONNRESET; /* client disconnected */

	client->recv_len += n;

	if (client->recv_len < LOTA_IPC_REQUEST_SIZE)
		return 0;

	memcpy(&req, client->recv_buf, sizeof(req));

	if (req.payload_len > LOTA_IPC_MAX_PAYLOAD) {
		lota_warn("oversized payload from pid=%d uid=%d (len=%u)",
			  client->peer_pid, client->peer_uid, req.payload_len);
		return -1; /* close: cannot recover from protocol desync */
	}

	need = LOTA_IPC_REQUEST_SIZE + req.payload_len;
	if (client->recv_len < need)
		return 0;

have_request:
	/* defer if a previous response is still pending */
	if (client->send_len > 0)
		return 0;
	process_request(ctx, client);

	client_arm_send(ctx, client);

	{
		size_t consumed = LOTA_IPC_REQUEST_SIZE + req.payload_len;
		if (client->recv_len > consumed) {
			ipc_secure_bzero(client->recv_buf, consumed);
			memmove(client->recv_buf, client->recv_buf + consumed,
				client->recv_len - consumed);
			client->recv_len -= consumed;
		} else {
			ipc_secure_bzero(client->recv_buf, client->recv_len);
			client->recv_len = 0;
		}
	}

	return 1; /* response ready */
}

static int handle_client_write(struct ipc_context *ctx,
			       struct ipc_client *client)
{
	ssize_t n;
	size_t remaining;

	if (client->send_len == 0)
		return 0;

	while (client->send_offset < client->send_len) {
		remaining = client->send_len - client->send_offset;
		n = send(client->fd, client->send_buf + client->send_offset,
			 remaining, MSG_NOSIGNAL);

		if (n < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				return 0; /* yield to event loop, EPOLLOUT will
					     re-fire */
			return -errno;
		}

		client->send_offset += n;
	}

	if (client->send_offset >= client->send_len) {
		ipc_secure_bzero(client->send_buf, client->send_len);
		client->send_len = 0;
		client->send_offset = 0;

		if (client->subscribed && client->notify_pending) {
			uint32_t pending = client->pending_events;
			client->notify_pending = false;
			client->pending_events = 0;
			build_notification(ctx, client, pending);
		}

		/*
		 * A request deferred by handle_client_read(): its bytes are
		 * already in recv_buf, so no EPOLLIN announces them.
		 */
		if (client->send_len == 0 &&
		    client->recv_len >= LOTA_IPC_REQUEST_SIZE &&
		    handle_client_read(ctx, client) < 0)
			return -1;

		if (client->send_len == 0) {
			struct epoll_event ev;
			ev.events = EPOLLIN;
			ev.data.fd = client->fd;
			epoll_ctl(ctx->epoll_fd, EPOLL_CTL_MOD, client->fd,
				  &ev);
		}

		if (client->shutdown_on_flush) {
			client->shutdown_on_flush = false;
			agent_globals_lock(&g_agent);
			g_agent.running = 0;
			agent_globals_unlock(&g_agent);
			lota_info(
				"Graceful shutdown initiated via IPC command");
		}
	}

	return 0;
}

static int accept_client(struct ipc_context *ctx, int listen_fd)
{
	struct sockaddr_un addr;
	socklen_t len = sizeof(addr);
	struct ipc_client *client;
	struct epoll_event ev;
	struct ucred cred;
	socklen_t cred_len = sizeof(cred);
	int fd;
	int ret;

	fd = accept(listen_fd, (struct sockaddr *)&addr, &len);
	if (fd < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK)
			return 0;
		return -errno;
	}

	if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &cred_len) < 0) {
		lota_err("SO_PEERCRED failed: %s", strerror(errno));
		close(fd);
		return -errno;
	}

	lota_dbg("client connected pid=%d uid=%d gid=%d", cred.pid, cred.uid,
		 cred.gid);

	ret = set_nonblocking(fd);
	if (ret < 0) {
		close(fd);
		return ret;
	}

	client = client_create(ctx, fd, cred.uid, cred.pid);
	if (!client) {
		close(fd);
		return -ENOMEM;
	}

	ret = read_pid_start_time_ticks(cred.pid,
					&client->peer_start_time_ticks);
	if (ret < 0) {
		lota_warn("failed to read peer start_time_ticks for pid=%d: %s",
			  cred.pid, strerror(-ret));
		client->peer_start_time_ticks = 0;
	}

	ev.events = EPOLLIN;
	ev.data.fd = fd;
	if (epoll_ctl(ctx->epoll_fd, EPOLL_CTL_ADD, fd, &ev) < 0) {
		client_destroy(ctx, client);
		return -errno;
	}

	return 0;
}

int ipc_init(struct ipc_context *ctx)
{
	struct epoll_event ev;
	int ret;

	memset(ctx, 0, sizeof(*ctx));
	ctx->listen_fd = -1;
	ctx->epoll_fd = -1;
	ctx->sock_watch_fd = -1;
	ctx->start_time_sec = monotonic_now_sec();

	client_map_init(ctx);

	for (int i = 0; i < IPC_MAX_EXTRA_LISTENERS; i++)
		ctx->extra[i].fd = -1;
	ctx->extra_count = 0;

	ret = ensure_socket_dir();
	if (ret < 0) {
		lota_err("failed to create %s: %s", SOCKET_DIR, strerror(-ret));
		return ret;
	}

	/*
	 * A socket somebody still answers on is not ours to take. One that
	 * refuses the connection is a leftover of an unclean stop.
	 */
	ret = socket_path_free(LOTA_IPC_SOCKET_PATH);
	if (ret < 0)
		return ret;

	ret = open_primary_listener(&ctx->listen_fd);
	if (ret < 0)
		return ret;

	ctx->epoll_fd = epoll_create1(EPOLL_CLOEXEC);
	if (ctx->epoll_fd < 0) {
		ret = -errno;
		lota_err("epoll_create1() failed: %s", strerror(-ret));
		goto err_listener;
	}

	ev.events = EPOLLIN;
	ev.data.fd = ctx->listen_fd;
	if (epoll_ctl(ctx->epoll_fd, EPOLL_CTL_ADD, ctx->listen_fd, &ev) < 0) {
		ret = -errno;
		lota_err("epoll_ctl() failed: %s", strerror(-ret));
		close(ctx->epoll_fd);
		ctx->epoll_fd = -1;
		goto err_listener;
	}

	ctx->running = true;
	ctx->status_flags = 0;
	ctx->dbus_fd = -1;
	record_listen_identity(ctx);

	lota_info("IPC listening on %s", LOTA_IPC_SOCKET_PATH);
	return 0;

err_listener:
	unlink(LOTA_IPC_SOCKET_PATH);
	close(ctx->listen_fd);
	ctx->listen_fd = -1;
	return ret;
}

int ipc_watch_socket_path(struct ipc_context *ctx)
{
	int fd, ret;

	if (!ctx)
		return -EINVAL;
	if (ctx->sock_watch_fd >= 0)
		return ctx->sock_watch_fd;

	fd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
	if (fd < 0)
		return -errno;

	if (inotify_add_watch(fd, SOCKET_DIR,
			      IN_CREATE | IN_DELETE | IN_MOVED_FROM |
				      IN_MOVED_TO | IN_ATTRIB) < 0) {
		ret = -errno;
		close(fd);
		return ret;
	}

	ctx->sock_watch_fd = fd;
	return fd;
}

int ipc_socket_watch_fd(const struct ipc_context *ctx)
{
	return ctx ? ctx->sock_watch_fd : -1;
}

/*
 * Take the socket path back after something replaced the file,
 * whatever answers on it: the name belongs to this running daemon.
 */
static int ipc_rebind_primary(struct ipc_context *ctx)
{
	struct epoll_event ev;
	int fd = -1, ret;

	ret = ensure_socket_dir();
	if (ret < 0) {
		lota_err("cannot recreate %s: %s", SOCKET_DIR, strerror(-ret));
		return ret;
	}

	ret = open_primary_listener(&fd);
	if (ret < 0)
		return ret;

	ev.events = EPOLLIN;
	ev.data.fd = fd;
	if (epoll_ctl(ctx->epoll_fd, EPOLL_CTL_ADD, fd, &ev) < 0) {
		ret = -errno;
		lota_err("epoll_ctl(new listener) failed: %s", strerror(-ret));
		close(fd);
		return ret;
	}

	if (ctx->listen_fd >= 0) {
		epoll_ctl(ctx->epoll_fd, EPOLL_CTL_DEL, ctx->listen_fd, NULL);
		close(ctx->listen_fd);
	}

	ctx->listen_fd = fd;
	/* ipc_cleanup() unlinks it from here on */
	ctx->activated = false;
	record_listen_identity(ctx);

	lota_warn("IPC socket %s was replaced; rebound, titles can reach the "
		  "agent again",
		  LOTA_IPC_SOCKET_PATH);
	return 1;
}

int ipc_socket_was_replaced(const char *path, dev_t dev, ino_t ino)
{
	struct stat st;

	if (!path)
		return 0;

	if (ino == 0)
		return 0;

	if (stat(path, &st) < 0)
		return 1;

	return (st.st_dev != dev || st.st_ino != ino) ? 1 : 0;
}

int ipc_recheck_socket(struct ipc_context *ctx)
{
	char buf[4096]
		__attribute__((aligned(__alignof__(struct inotify_event))));
	ssize_t len;

	if (!ctx || ctx->listen_fd < 0)
		return -EINVAL;

	if (ctx->sock_watch_fd >= 0) {
		bool named = false;

		while ((len = read(ctx->sock_watch_fd, buf, sizeof(buf))) > 0)
			named |= socket_events_name(buf, (size_t)len,
						    LOTA_IPC_SOCKET_NAME);
		if (len < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
			lota_warn("socket watch read failed: %s",
				  strerror(errno));
			named = true;
		}
		/* the directory holds other files, such as --bench's */
		if (!named)
			return 0;
	}

	if (!ipc_socket_was_replaced(LOTA_IPC_SOCKET_PATH, ctx->listen_dev,
				     ctx->listen_ino))
		return 0;

	return ipc_rebind_primary(ctx);
}

static bool fd_bound_to_primary(int fd)
{
	struct sockaddr_un addr = { 0 };
	socklen_t len = sizeof(addr);

	if (getsockname(fd, (struct sockaddr *)&addr, &len) < 0 ||
	    addr.sun_family != AF_UNIX ||
	    len <= offsetof(struct sockaddr_un, sun_path))
		return false;

	return strncmp(addr.sun_path, LOTA_IPC_SOCKET_PATH,
		       sizeof(addr.sun_path)) == 0;
}

int ipc_init_activated(struct ipc_context *ctx, int fd)
{
	struct epoll_event ev;
	int ret;

	if (!ctx || fd < 0)
		return -EINVAL;

	memset(ctx, 0, sizeof(*ctx));
	ctx->listen_fd = -1;
	ctx->epoll_fd = -1;
	ctx->sock_watch_fd = -1;
	ctx->start_time_sec = monotonic_now_sec();

	client_map_init(ctx);

	for (int i = 0; i < IPC_MAX_EXTRA_LISTENERS; i++)
		ctx->extra[i].fd = -1;
	ctx->extra_count = 0;

	ret = set_nonblocking(fd);
	if (ret < 0) {
		lota_err("set_nonblocking(activated fd) failed: %s",
			 strerror(-ret));
		return ret;
	}

	/* the initramfs lock may have created the directory first */
	if (fd_bound_to_primary(fd)) {
		ret = ensure_socket_dir();
		if (ret < 0) {
			lota_err("cannot secure %s: %s", SOCKET_DIR,
				 strerror(-ret));
			return ret;
		}
	}

	ctx->listen_fd = fd;
	ctx->activated = true;

	ctx->epoll_fd = epoll_create1(EPOLL_CLOEXEC);
	if (ctx->epoll_fd < 0) {
		ret = -errno;
		lota_err("epoll_create1() failed: %s", strerror(-ret));
		ctx->listen_fd = -1;
		return ret;
	}

	ev.events = EPOLLIN;
	ev.data.fd = ctx->listen_fd;
	if (epoll_ctl(ctx->epoll_fd, EPOLL_CTL_ADD, ctx->listen_fd, &ev) < 0) {
		ret = -errno;
		lota_err("epoll_ctl() failed: %s", strerror(-ret));
		close(ctx->epoll_fd);
		ctx->epoll_fd = -1;
		ctx->listen_fd = -1;
		return ret;
	}

	ctx->running = true;
	ctx->status_flags = 0;
	ctx->dbus_fd = -1;
	record_listen_identity(ctx);

	lota_info("IPC using socket-activated fd %d", fd);
	return 0;
}

void ipc_cleanup(struct ipc_context *ctx)
{
	ctx->running = false;

	while (ctx->client_list) {
		client_destroy(ctx, ctx->client_list);
	}
	ctx->client_list = NULL;
	ctx->client_count = 0;

	client_map_init(ctx);

	if (ctx->epoll_fd >= 0) {
		close(ctx->epoll_fd);
		ctx->epoll_fd = -1;
	}

	if (ctx->listen_fd >= 0) {
		close(ctx->listen_fd);
		ctx->listen_fd = -1;
	}

	if (ctx->sock_watch_fd >= 0) {
		close(ctx->sock_watch_fd);
		ctx->sock_watch_fd = -1;
	}

	if (!ctx->activated)
		unlink(LOTA_IPC_SOCKET_PATH);

	for (int i = 0; i < IPC_MAX_EXTRA_LISTENERS; i++) {
		if (ctx->extra[i].fd >= 0) {
			close(ctx->extra[i].fd);
			ctx->extra[i].fd = -1;
			if (ctx->extra[i].path[0]) {
				unlink(ctx->extra[i].path);
				ctx->extra[i].path[0] = '\0';
			}
		}
	}
	ctx->extra_count = 0;

	lota_dbg("IPC cleaned up");
}

int ipc_process(struct ipc_context *ctx, int timeout_ms)
{
	struct epoll_event events[MAX_EVENTS];
	int nfds;
	int processed = 0;

	if (!ctx->running || ctx->epoll_fd < 0)
		return -EINVAL;

	nfds = epoll_wait(ctx->epoll_fd, events, MAX_EVENTS, timeout_ms);
	if (nfds < 0) {
		if (errno == EINTR)
			return 0;
		return -errno;
	}

	for (int i = 0; i < nfds; i++) {
		int fd = events[i].data.fd;

		if (ctx->dbus && ctx->dbus_fd >= 0 && fd == ctx->dbus_fd) {
			dbus_process(ctx->dbus, 0);
			processed++;
			continue;
		}

		if (fd == ctx->listen_fd || ipc_is_listener(ctx, fd)) {
			accept_client(ctx, fd);
			processed++;
		} else {
			struct ipc_client *client = client_find(ctx, fd);
			if (!client)
				continue;

			int ret = 0;

			if (events[i].events & EPOLLIN) {
				ret = handle_client_read(ctx, client);
			}

			if (events[i].events & EPOLLOUT) {
				if (handle_client_write(ctx, client) < 0)
					ret = -1;
			}

			if ((events[i].events & (EPOLLERR | EPOLLHUP)) ||
			    ret < 0) {
				epoll_ctl(ctx->epoll_fd, EPOLL_CTL_DEL, fd,
					  NULL);
				client_destroy(ctx, client);
			}

			processed++;
		}
	}

	/*
	 * A session opening wakes the attestation loop: a title that has just
	 * launched wants its first report.
	 */
	if (ctx->profiles_changed) {
		ctx->profiles_changed = false;
		recompute_host_attestation(ctx);
		notify_subscribers(ctx, LOTA_IPC_EVENT_PROFILE);
	}

	return processed;
}

int ipc_get_fd(struct ipc_context *ctx)
{
	return ctx->epoll_fd;
}

void ipc_update_status(struct ipc_context *ctx, uint32_t flags,
		       uint64_t valid_until)
{
	if (!ctx->running)
		return;

	/* a round publishes this word from scratch */
	if (ctx->protected_terminated)
		flags |= LOTA_STATUS_PROTECTED_TERMINATED;
	if (ctx->agent_restarted)
		flags |= LOTA_STATUS_AGENT_RESTARTED;
	if (ctx->events_lost)
		flags |= LOTA_STATUS_EVENTS_LOST;

	/* a round knows nothing of the policy, the daemon does */
	flags = lota_status_fold_policy(flags, ctx->mode, ctx->policy_keys);

	ctx->status_flags = flags;
	ctx->valid_until = valid_until;
	publish_status(ctx);
}

/* Refold the policy bits after the mode or a key changed */
static void refold_policy(struct ipc_context *ctx)
{
	if (!ctx->running)
		return;

	ctx->status_flags = lota_status_fold_policy(
		ctx->status_flags, ctx->mode, ctx->policy_keys);
	publish_status(ctx);
}

void ipc_set_policy(struct ipc_context *ctx, uint32_t keys)
{
	ctx->policy_keys = keys & LOTA_STATUS_POLICY_KEYS;
	refold_policy(ctx);
}

void ipc_record_attestation(struct ipc_context *ctx, bool success)
{
	if (success) {
		ctx->attest_count++;
		ctx->last_attest_time = (uint64_t)time(NULL);
	} else {
		ctx->fail_count++;
	}

	notify_subscribers(ctx, LOTA_IPC_EVENT_ATTEST);
	dbus_emit_attestation_result(ctx->dbus, success);
}

void ipc_set_agent_restarted(struct ipc_context *ctx)
{
	ctx->agent_restarted = true;
	ctx->status_flags |= LOTA_STATUS_AGENT_RESTARTED;
	publish_status(ctx);
}

void ipc_set_events_lost(struct ipc_context *ctx)
{
	ctx->events_lost = true;
	ctx->status_flags |= LOTA_STATUS_EVENTS_LOST;
	publish_status(ctx);
}

void ipc_set_mode(struct ipc_context *ctx, uint8_t mode)
{
	uint8_t old_mode = ctx->mode;

	ctx->mode = mode;

	if (old_mode != mode) {
		notify_subscribers(ctx, LOTA_IPC_EVENT_MODE);
		dbus_emit_mode_changed(ctx->dbus, mode);
	}
	refold_policy(ctx);
}

void ipc_set_tpm(struct ipc_context *ctx, struct tpm_context *tpm,
		 uint32_t pcr_mask)
{
	ctx->tpm = tpm;
	ctx->quote_pcr_mask = pcr_mask;
}

bool ipc_can_issue_tokens(const struct ipc_context *ctx)
{
	return ctx && ctx->tpm;
}

const char *ipc_token_capability_str(const struct ipc_context *ctx)
{
	if (ipc_can_issue_tokens(ctx))
		return "Tokens are signed by the TPM AIK.";

	return "GET_TOKEN is refused: signing needs a TPM, and an unsigned token is never issued. Use --test-signed for tokens.";
}

void ipc_set_profiles(struct ipc_context *ctx, struct attest_target *profiles,
		      size_t count)
{
	if (!ctx)
		return;

	ctx->profiles = count ? profiles : NULL;
	ctx->profile_count = profiles ? count : 0;

	/*
	 * Every binding points into the list being replaced. Session counts are
	 * rebuilt below from the connections that survive.
	 */
	for (struct ipc_client *c = ctx->client_list; c; c = c->next)
		c->profile = NULL;
	for (size_t i = 0; i < ctx->profile_count; i++)
		ctx->profiles[i].sessions = 0;

	/*
	 * A title sends SET_PROFILE once: bind it again by the publisher it
	 * named, or leave it unbound when that publisher is gone.
	 */
	for (struct ipc_client *c = ctx->client_list; c; c = c->next) {
		if (!c->profile_id[0])
			continue;

		for (size_t i = 0; i < ctx->profile_count; i++) {
			if (!ctx->profiles[i].has_profile)
				continue;
			if (strcmp(ctx->profiles[i].paths.id, c->profile_id) !=
			    0)
				continue;

			c->profile = &ctx->profiles[i];
			ctx->profiles[i].sessions++;
			break;
		}

		if (!c->profile) {
			lota_info(
				"connection pid=%d named publisher %s, which the "
				"reloaded configuration no longer holds; it is "
				"unbound and nothing is reported for them",
				c->peer_pid, c->profile_id);
			c->profile_id[0] = '\0';
		}
	}

	/* the loop learns the rebuilt counts on its next sync */
	for (size_t i = 0; i < ctx->profile_count; i++)
		ctx->profiles[i].session_changed = true;
	ctx->profiles_changed = true;
}

int ipc_add_listener(struct ipc_context *ctx, const char *socket_path)
{
	struct sockaddr_un addr;
	struct epoll_event ev;
	int fd, ret, slot;

	if (!ctx || !socket_path || !socket_path[0])
		return -EINVAL;

	if (ctx->epoll_fd < 0)
		return -EINVAL;

	if (ctx->extra_count >= IPC_MAX_EXTRA_LISTENERS)
		return -ENOSPC;

	slot = -1;
	for (int i = 0; i < IPC_MAX_EXTRA_LISTENERS; i++) {
		if (ctx->extra[i].fd < 0) {
			slot = i;
			break;
		}
	}
	if (slot < 0)
		return -ENOSPC;

	/*
	 * As for the primary socket: a path somebody still answers on is
	 * refused, and a leftover of an unclean stop is unlinked.
	 */
	ret = socket_path_free(socket_path);
	if (ret < 0)
		return ret;

	unlink(socket_path);

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0) {
		ret = -errno;
		lota_err("extra socket() failed: %s", strerror(-ret));
		return ret;
	}

	ret = set_nonblocking(fd);
	if (ret < 0) {
		close(fd);
		return ret;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);

	{
		mode_t old_umask = umask(0117);
		ret = bind(fd, (struct sockaddr *)&addr, sizeof(addr));
		umask(old_umask);
	}

	/*
	 * logind's tmpfs can replace a login's runtime directory under the bind
	 * or the chown; the caller retries or reports.
	 */
	if (ret < 0) {
		ret = -errno;
		close(fd);
		return ret;
	}

	/* bound 0660: only the group lets a title connect, failure refuses */
	{
		struct group *grp = getgrnam(LOTA_GROUP_NAME);

		if (!grp) {
			lota_err(
				"no '%s' group: %s would be reachable by root alone",
				LOTA_GROUP_NAME, socket_path);
			close(fd);
			unlink(socket_path);
			return -ENOENT;
		}

		if (chown(socket_path, 0, grp->gr_gid) < 0) {
			ret = -errno;
			close(fd);
			unlink(socket_path);
			return ret;
		}
	}

	if (listen(fd, 16) < 0) {
		ret = -errno;
		close(fd);
		unlink(socket_path);
		return ret;
	}

	ev.events = EPOLLIN;
	ev.data.fd = fd;
	if (epoll_ctl(ctx->epoll_fd, EPOLL_CTL_ADD, fd, &ev) < 0) {
		ret = -errno;
		close(fd);
		unlink(socket_path);
		return ret;
	}

	ctx->extra[slot].fd = fd;
	snprintf(ctx->extra[slot].path, sizeof(ctx->extra[slot].path), "%s",
		 socket_path);
	ctx->extra_count++;

	lota_info("IPC extra listener on %s", socket_path);
	return 0;
}

int ipc_remove_listener(struct ipc_context *ctx, const char *socket_path)
{
	if (!ctx || !socket_path || !socket_path[0])
		return -EINVAL;

	for (int i = 0; i < IPC_MAX_EXTRA_LISTENERS; i++) {
		if (ctx->extra[i].fd < 0 ||
		    strcmp(ctx->extra[i].path, socket_path) != 0)
			continue;

		if (ctx->epoll_fd >= 0)
			epoll_ctl(ctx->epoll_fd, EPOLL_CTL_DEL,
				  ctx->extra[i].fd, NULL);
		close(ctx->extra[i].fd);
		ctx->extra[i].fd = -1;
		unlink(ctx->extra[i].path);
		ctx->extra[i].path[0] = '\0';
		if (ctx->extra_count > 0)
			ctx->extra_count--;

		lota_info("IPC extra listener %s removed", socket_path);
		return 0;
	}

	return -ENOENT;
}

int ipc_is_listener(struct ipc_context *ctx, int fd)
{
	if (fd == ctx->listen_fd)
		return 1;
	for (int i = 0; i < IPC_MAX_EXTRA_LISTENERS; i++) {
		if (ctx->extra[i].fd >= 0 && ctx->extra[i].fd == fd)
			return 1;
	}
	return 0;
}

void ipc_set_dbus(struct ipc_context *ctx, struct dbus_context *dbus)
{
	int old_fd;
	int new_fd = -1;

	if (!ctx)
		return;

	old_fd = ctx->dbus_fd;
	if (dbus)
		new_fd = dbus_get_fd(dbus);

	if (ctx->epoll_fd >= 0 && old_fd >= 0 && old_fd != new_fd)
		epoll_ctl(ctx->epoll_fd, EPOLL_CTL_DEL, old_fd, NULL);

	ctx->dbus = dbus;
	ctx->dbus_fd = new_fd;

	if (ctx->epoll_fd >= 0 && new_fd >= 0) {
		struct epoll_event ev;

		memset(&ev, 0, sizeof(ev));
		ev.events = EPOLLIN;
		ev.data.fd = new_fd;

		if (epoll_ctl(ctx->epoll_fd, EPOLL_CTL_ADD, new_fd, &ev) < 0 &&
		    errno != EEXIST) {
			lota_warn("Failed to add D-Bus fd %d to epoll: %s",
				  new_fd, strerror(errno));
		}
	}
}
