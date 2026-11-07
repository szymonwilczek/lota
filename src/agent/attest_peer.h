/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * The attestation loop's side of the state exchange with the enforcement
 * daemon, which owns LOTA_IPC_SOCKET_PATH: verdicts out, sessions and
 * enrollment requests in.
 *
 * With the daemon down the loop keeps attesting and retries the connection;
 * session counts stay as last synced.
 */

#ifndef LOTA_AGENT_ATTEST_PEER_H
#define LOTA_AGENT_ATTEST_PEER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "attest_targets.h"
#include "report_flags.h"

struct attest_peer {
	int fd; /* connection to the socket owner, -1 when down */
	uint64_t next_retry_ms; /* monotonic deadline before reconnecting */
	bool connected_once; /* arms the one warning a lost connection logs */
};

/* Tallies sent to the socket owner with each sync */
struct attest_peer_counters {
	uint32_t attest_count;
	uint32_t fail_count;
	uint64_t last_attest_time;
	uint32_t host_flags; /* LOTA_IPC_SYNC_HOST_FLAGS observed here */
};

void attest_peer_init(struct attest_peer *peer);
void attest_peer_close(struct attest_peer *peer);

/**
 * attest_peer_sync() - Trade state with the socket owner.
 * @peer: The connection, made on demand within its own retry deadline.
 * @targets: Each with a profile sends a verdict and takes back its session
 *           count and enrollment request; one the owner does not name is left
 *           alone.
 * @count: Length of @targets.
 * @counters: Tallies to send.
 *
 * Return: 0 when the exchange completed, or a negative errno.
 */
int attest_peer_sync(struct attest_peer *peer, struct attest_target *targets,
		     size_t count, const struct attest_peer_counters *counters);

/**
 * attest_peer_fd() - The descriptor to poll for pushed publisher events.
 * @peer: The connection.
 *
 * Return: the descriptor, -1 when the connection is down.
 */
int attest_peer_fd(const struct attest_peer *peer);

/**
 * attest_peer_drain() - Consume pushed notifications.
 * @peer: The connection; closing it schedules a reconnect.
 *
 * Return: true when a publisher event arrived: time to sync.
 */
bool attest_peer_drain(struct attest_peer *peer);

/**
 * attest_daemon_view() - Ask the socket owner for its mode and status word.
 * @out: The answer.
 *
 * Uses a connection of its own. Only an owner running as this process's user
 * is believed.
 *
 * Return: 0 with @out->answered set, or a negative errno with @out zeroed.
 */
int attest_daemon_view(struct enforcement_view *out);

#endif /* LOTA_AGENT_ATTEST_PEER_H */
