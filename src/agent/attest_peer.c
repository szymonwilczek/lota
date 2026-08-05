/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * The attestation loop's client of the enforcement daemon's IPC socket.
 * See attest_peer.h for why the loop is a client and not a server.
 *
 * Blocking I/O with a short timeout rather than an epoll state machine:
 * the peer is a local socket on the same machine, the frames are a few hundred
 * bytes, and the loop has nothing else to do while the exchange is in flight.
 * The timeout is what keeps a wedged peer from holding the loop, and the
 * systemd watchdog is what catches it if one ever does.
 */

#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include "../../include/lota_ipc.h"
#include "attest_peer.h"
#include "journal.h"
#include "profile.h"

/* Long enough for a local round trip under load,
 * short enough that a wedged peer costs one attestation round
 * rather than the watchdog deadline */
#define ATTEST_PEER_IO_TIMEOUT_SEC 5

/* Daemon that is down stays down for a while;
 * retrying every round would fill the journal for a host that is deliberately
 * running enforcement-less */
#define ATTEST_PEER_RETRY_MS 30000

static uint64_t peer_monotonic_ms(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
		return 0;

	return (uint64_t)ts.tv_sec * 1000 + (uint64_t)(ts.tv_nsec / 1000000);
}

static void peer_id_to_hex(const uint8_t id[32], char *out, size_t out_len)
{
	for (size_t i = 0; i < 32 && (i * 2 + 3) <= out_len; i++)
		snprintf(out + i * 2, 3, "%02x", id[i]);
}

static void peer_id_from_hex(const char *hex, uint8_t out[32])
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

void attest_peer_init(struct attest_peer *peer)
{
	if (!peer)
		return;

	peer->fd = -1;
	peer->next_retry_ms = 0;
	peer->connected_once = false;
}

void attest_peer_close(struct attest_peer *peer)
{
	if (!peer || peer->fd < 0)
		return;

	close(peer->fd);
	peer->fd = -1;
}

/* Drop the connection and hold off before the next attempt */
static void peer_drop(struct attest_peer *peer)
{
	attest_peer_close(peer);
	peer->next_retry_ms = peer_monotonic_ms() + ATTEST_PEER_RETRY_MS;
}

static int peer_connect(struct attest_peer *peer)
{
	struct sockaddr_un addr;
	struct timeval tv = { .tv_sec = ATTEST_PEER_IO_TIMEOUT_SEC,
			      .tv_usec = 0 };
	int fd;

	if (peer->fd >= 0)
		return 0;

	if (peer_monotonic_ms() < peer->next_retry_ms)
		return -EAGAIN;

	fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -errno;

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	snprintf(addr.sun_path, sizeof(addr.sun_path), "%s",
		 LOTA_IPC_SOCKET_PATH);

	if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		int ret = -errno;

		close(fd);
		peer->next_retry_ms =
			peer_monotonic_ms() + ATTEST_PEER_RETRY_MS;
		return ret;
	}

	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

	peer->fd = fd;
	return 0;
}

static int peer_write_all(int fd, const uint8_t *buf, size_t len)
{
	size_t off = 0;

	while (off < len) {
		ssize_t n = write(fd, buf + off, len - off);

		if (n > 0) {
			off += (size_t)n;
			continue;
		}
		if (n < 0 && errno == EINTR)
			continue;
		return n < 0 ? -errno : -EPIPE;
	}

	return 0;
}

static int peer_read_all(int fd, uint8_t *buf, size_t len)
{
	size_t off = 0;

	while (off < len) {
		ssize_t n = read(fd, buf + off, len - off);

		if (n > 0) {
			off += (size_t)n;
			continue;
		}
		if (n < 0 && errno == EINTR)
			continue;
		return n < 0 ? -errno : -ECONNRESET;
	}

	return 0;
}

/*
 * Read one frame, skipping pushed notifications.
 *
 * Notification can arrive between the request and its answer
 * -- a title may open a session at any moment -- so a reply is whatever is not
 * a notify. The event itself needs no handling here: the sync in flight is already
 * carrying the state it announces.
 */
static int peer_read_reply(int fd, struct lota_ipc_response *resp,
			   uint8_t *payload, size_t payload_max)
{
	for (int frame = 0; frame < 8; frame++) {
		int ret = peer_read_all(fd, (uint8_t *)resp, sizeof(*resp));

		if (ret < 0)
			return ret;

		if (resp->magic != LOTA_IPC_MAGIC)
			return -EBADMSG;

		if (resp->payload_len > payload_max)
			return -EMSGSIZE;

		if (resp->payload_len) {
			ret = peer_read_all(fd, payload, resp->payload_len);
			if (ret < 0)
				return ret;
		}

		if (resp->result != LOTA_IPC_NOTIFY)
			return 0;
	}

	/* peer pushing notifications without ever answering is broken */
	return -EPROTO;
}

int attest_peer_fd(const struct attest_peer *peer)
{
	return peer ? peer->fd : -1;
}

bool attest_peer_drain(struct attest_peer *peer)
{
	bool woke = false;

	if (!peer || peer->fd < 0)
		return false;

	for (;;) {
		struct pollfd pfd = { .fd = peer->fd, .events = POLLIN };
		struct lota_ipc_response resp;
		struct lota_ipc_notify notify;
		uint8_t payload[LOTA_IPC_MAX_PAYLOAD];
		int ret;

		if (poll(&pfd, 1, 0) <= 0)
			return woke;

		ret = peer_read_all(peer->fd, (uint8_t *)&resp, sizeof(resp));
		if (ret < 0 || resp.magic != LOTA_IPC_MAGIC ||
		    resp.payload_len > sizeof(payload)) {
			peer_drop(peer);
			return woke;
		}

		if (resp.payload_len &&
		    peer_read_all(peer->fd, payload, resp.payload_len) < 0) {
			peer_drop(peer);
			return woke;
		}

		if (resp.result != LOTA_IPC_NOTIFY ||
		    resp.payload_len < sizeof(notify))
			continue;

		memcpy(&notify, payload, sizeof(notify));
		if (notify.events & LOTA_IPC_EVENT_PROFILE)
			woke = true;
	}
}

int attest_peer_sync(struct attest_peer *peer, struct attest_target *targets,
		     size_t count, const struct attest_peer_counters *counters)
{
	uint8_t req[LOTA_IPC_REQUEST_SIZE + LOTA_IPC_ATTEST_SYNC_MAX_SIZE];
	uint8_t payload[LOTA_IPC_MAX_PAYLOAD];
	struct lota_ipc_attest_sync_response out;
	struct lota_ipc_request *hdr = (void *)req;
	struct lota_ipc_attest_sync *sync;
	struct lota_ipc_attest_verdict *verdict;
	struct lota_ipc_response resp;
	uint32_t emitted = 0;
	size_t body;
	int ret;

	if (!peer || (count && !targets) || !counters)
		return -EINVAL;

	if (count > LOTA_IPC_MAX_PROFILES)
		return -E2BIG;

	ret = peer_connect(peer);
	if (ret < 0) {
		if (peer->connected_once) {
			lota_warn("Cannot reach the enforcement daemon on %s "
				  "(%s): reporting on, session gating off "
				  "until it answers",
				  LOTA_IPC_SOCKET_PATH, strerror(-ret));
			peer->connected_once = false;
		}
		return ret;
	}

	sync = (void *)(req + LOTA_IPC_REQUEST_SIZE);
	verdict = (void *)(req + LOTA_IPC_REQUEST_SIZE + sizeof(*sync));

	for (size_t i = 0; i < count; i++) {
		if (!targets[i].has_profile)
			continue;

		peer_id_from_hex(targets[i].paths.id,
				 verdict[emitted].profile_id);
		verdict[emitted].attested = targets[i].attested ? 1 : 0;
		memset(verdict[emitted].reserved, 0,
		       sizeof(verdict[emitted].reserved));
		verdict[emitted].valid_until = targets[i].valid_until;
		emitted++;
	}

	sync->count = emitted;
	sync->attest_count = counters->attest_count;
	sync->fail_count = counters->fail_count;
	sync->_reserved1 = 0;
	sync->last_attest_time = counters->last_attest_time;

	body = sizeof(*sync) + (size_t)emitted * sizeof(*verdict);

	hdr->magic = LOTA_IPC_MAGIC;
	hdr->version = LOTA_IPC_VERSION;
	hdr->cmd = LOTA_IPC_CMD_SYNC_ATTEST;
	hdr->payload_len = (uint32_t)body;

	ret = peer_write_all(peer->fd, req, LOTA_IPC_REQUEST_SIZE + body);
	if (ret < 0) {
		peer_drop(peer);
		return ret;
	}

	ret = peer_read_reply(peer->fd, &resp, payload, sizeof(payload));
	if (ret < 0) {
		peer_drop(peer);
		return ret;
	}

	if (resp.result != LOTA_IPC_OK) {
		/*
		 * Refusal is not transport failure, so the connection stays:
		 * the daemon answered, it just would not accept this peer.
		 * Dropping and retrying would turn one refusal into reconnect
		 * loop.
		 */
		lota_warn("The enforcement daemon refused the attestation "
			  "sync (result %u): session gating and runtime "
			  "enrollment are off",
			  (unsigned)resp.result);
		return -EACCES;
	}

	if (resp.payload_len < sizeof(out)) {
		peer_drop(peer);
		return -EBADMSG;
	}

	memcpy(&out, payload, sizeof(out));
	if (out.count > LOTA_IPC_MAX_PROFILES ||
	    resp.payload_len <
		    sizeof(out) +
			    (size_t)out.count *
				    sizeof(struct lota_ipc_profile_demand))
		return -EBADMSG;

	for (uint32_t i = 0; i < out.count; i++) {
		struct lota_ipc_profile_demand demand;
		char id[LOTA_PROFILE_ID_LEN];

		memcpy(&demand,
		       payload + sizeof(out) + (size_t)i * sizeof(demand),
		       sizeof(demand));
		peer_id_to_hex(demand.profile_id, id, sizeof(id));

		for (size_t j = 0; j < count; j++) {
			if (!targets[j].has_profile)
				continue;
			if (strcmp(targets[j].paths.id, id) != 0)
				continue;

			if (targets[j].sessions != (int)demand.sessions)
				targets[j].session_changed = true;
			targets[j].sessions = (int)demand.sessions;
			if (demand.enroll_pending)
				targets[j].enroll_pending = true;
			break;
		}
	}

	if (!peer->connected_once) {
		lota_info("Reporting state to the enforcement daemon on %s",
			  LOTA_IPC_SOCKET_PATH);
		peer->connected_once = true;
	}

	return 0;
}
