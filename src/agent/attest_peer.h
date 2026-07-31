/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * The attestation loop's side of the state exchange with the enforcement
 * daemon.
 *
 * Only one process can own LOTA_IPC_SOCKET_PATH, and the daemon owns it:
 * it is the always-on unit, it is what the packaged socket unit activates,
 * and it holds the BPF context, the enforcement policy digest and the boot
 * state a title asks about.
 * The loop therefore connects to that socket rather than binding it,
 * and trades what each side knows -- verdicts out, sessions and enrollment
 * requests in.
 *
 * Daemon that is not up yet, or is restarting, is not an error here:
 * the loop keeps attesting and retries the connection.
 * What it loses meanwhile is session gating, so a session-gated publisher
 * is not reported to, which is the safe direction for something whose whole
 * cost is exfiltration.
 */

#ifndef LOTA_AGENT_ATTEST_PEER_H
#define LOTA_AGENT_ATTEST_PEER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "attest_targets.h"

struct attest_peer {
	int fd; /* connection to the socket owner, -1 when down */
	uint64_t next_retry_ms; /* monotonic deadline before reconnecting */
	bool connected_once; /* so the first failure logs once, not per round */
};

/* State the socket owner keeps for the loop rather than the other way round */
struct attest_peer_counters {
	uint32_t attest_count;
	uint32_t fail_count;
	uint64_t last_attest_time;
};

void attest_peer_init(struct attest_peer *peer);
void attest_peer_close(struct attest_peer *peer);

/*
 * Trade state with the socket owner.
 *
 * Sends one verdict per target and applies what comes back onto the same array:
 * the session count each publisher currently has, and whether a title has asked
 * this host to enrol with one.
 * Publisher the owner does not know about is left alone.
 *
 * Connects on demand, honouring its own retry deadline, so caller may call this
 * every round without checking whether the daemon is up.
 *
 * Returns 0 when the exchange completed, or a negative errno.
 */
int attest_peer_sync(struct attest_peer *peer, struct attest_target *targets,
		     size_t count, const struct attest_peer_counters *counters);

/*
 * File descriptor to poll for pushed publisher events, or -1 when the connection
 * is down.
 * Readable means attest_peer_drain() has something to do.
 */
int attest_peer_fd(const struct attest_peer *peer);

/*
 * Consume pushed notifications.
 *
 * Returns true when a publisher event arrived, which is session opening or closing
 * or a title asking for an unenrolled publisher -- all reasons to stop sleeping
 * and sync now.
 * Closed connection returns false and schedules a reconnect.
 */
bool attest_peer_drain(struct attest_peer *peer);

#endif /* LOTA_AGENT_ATTEST_PEER_H */
