/* SPDX-License-Identifier: MIT */
/*
 * Unit tests for the IPC request payload-length table.
 *
 * The check runs before the dispatcher, so command whose payload size is not
 * listed is refused as bad request and its handler never runs.
 * Agent still answers, so the failure reads as working agent saying no
 * -- which is how live host came to refuse every publisher selection title made.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */
#include <stdio.h>

#include "../src/agent/ipc_payload.h"

static int g_failures;

#define CHECK(cond, msg)                                    \
	do {                                                \
		if (!(cond)) {                              \
			fprintf(stderr, "FAIL: %s\n", msg); \
			g_failures++;                       \
		} else {                                    \
			printf("PASS: %s\n", msg);          \
		}                                           \
	} while (0)

int main(void)
{
	printf("=== IPC payload length tests ===\n\n");

	CHECK(ipc_payload_len_valid(LOTA_IPC_CMD_PING, 0),
	      "PING carries nothing");
	CHECK(!ipc_payload_len_valid(LOTA_IPC_CMD_PING, 1),
	      "PING with a payload is refused");

	CHECK(ipc_payload_len_valid(LOTA_IPC_CMD_GET_TOKEN, 0),
	      "GET_TOKEN without a nonce is allowed");
	CHECK(ipc_payload_len_valid(LOTA_IPC_CMD_GET_TOKEN,
				    sizeof(struct lota_ipc_token_request)),
	      "GET_TOKEN with a nonce is allowed");

	CHECK(ipc_payload_len_valid(LOTA_IPC_CMD_SUBSCRIBE,
				    sizeof(struct lota_ipc_subscribe_request)),
	      "SUBSCRIBE carries its request");
	CHECK(ipc_payload_len_valid(LOTA_IPC_CMD_PROTECT_PID,
				    sizeof(struct lota_ipc_pid_request)),
	      "PROTECT_PID carries a pid");

	/*
	 * The one this file exists for.
	 * Title names its publisher by the 32-byte identity;
	 * refusing that length makes every publisher selection fail,
	 * and the SDK reports it as an unknown publisher.
	 */
	CHECK(ipc_payload_len_valid(LOTA_IPC_CMD_SET_PROFILE,
				    sizeof(struct lota_ipc_set_profile)),
	      "SET_PROFILE carries a publisher identity");
	CHECK(!ipc_payload_len_valid(LOTA_IPC_CMD_SET_PROFILE, 0),
	      "SET_PROFILE naming nobody is refused");
	CHECK(!ipc_payload_len_valid(LOTA_IPC_CMD_SET_PROFILE,
				     sizeof(struct lota_ipc_set_profile) + 1),
	      "SET_PROFILE with a longer payload is refused");

	CHECK(!ipc_payload_len_valid(0xdead, 4),
	      "an unknown command may not carry a payload");
	CHECK(ipc_payload_len_valid(0xdead, 0),
	      "an unknown command with no payload reaches the dispatcher");

	printf("\n%s\n", g_failures ? "FAILURES" : "All tests passed");
	return g_failures ? 1 : 0;
}
