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

#include "../src/agent/ipc_payload.h"

#include "test.h"

int main(void)
{
	test_begin("ipc payload len");

	TEST("PING carries nothing");
	if (!ipc_payload_len_valid(LOTA_IPC_CMD_PING, 0))
		FAIL("expected: ipc_payload_len_valid(LOTA_IPC_CMD_PING, 0)");
	TEST("PING with a payload is refused");
	if (ipc_payload_len_valid(LOTA_IPC_CMD_PING, 1))
		FAIL("expected: !ipc_payload_len_valid(LOTA_IPC_CMD_PING, 1)");

	TEST("GET_TOKEN without a nonce is allowed");
	if (!ipc_payload_len_valid(LOTA_IPC_CMD_GET_TOKEN, 0))
		FAIL("expected: ipc_payload_len_valid(LOTA_IPC_CMD_GET_TOKEN, "
		     "0)");
	TEST("GET_TOKEN with a nonce is allowed");
	if (!ipc_payload_len_valid(LOTA_IPC_CMD_GET_TOKEN,
				   sizeof(struct lota_ipc_token_request)))
		FAIL("expected: ipc_payload_len_valid(LOTA_IPC_CMD_GET_TOKEN, "
		     "sizeof(struct lota_ipc_token_request))");

	TEST("SUBSCRIBE carries its request");
	if (!ipc_payload_len_valid(LOTA_IPC_CMD_SUBSCRIBE,
				   sizeof(struct lota_ipc_subscribe_request)))
		FAIL("expected: ipc_payload_len_valid(LOTA_IPC_CMD_SUBSCRIBE, "
		     "sizeof(struct lota_ipc_subscribe_request))");
	TEST("PROTECT_PID carries a pid");
	if (!ipc_payload_len_valid(LOTA_IPC_CMD_PROTECT_PID,
				   sizeof(struct lota_ipc_pid_request)))
		FAIL("expected: ipc_payload_len_valid(LOTA_IPC_CMD_PROTECT_PID, "
		     "sizeof(struct lota_ipc_pid_request))");

	/*
	 * The one this file exists for.
	 * Title names its publisher by the 32-byte identity;
	 * refusing that length makes every publisher selection fail,
	 * and the SDK reports it as an unknown publisher.
	 */
	TEST("SET_PROFILE carries a publisher identity");
	if (!ipc_payload_len_valid(LOTA_IPC_CMD_SET_PROFILE,
				   sizeof(struct lota_ipc_set_profile)))
		FAIL("expected: ipc_payload_len_valid(LOTA_IPC_CMD_SET_PROFILE, "
		     "sizeof(struct lota_ipc_set_profile))");
	TEST("SET_PROFILE naming nobody is refused");
	if (ipc_payload_len_valid(LOTA_IPC_CMD_SET_PROFILE, 0))
		FAIL("expected: !ipc_payload_len_valid(LOTA_IPC_CMD_SET_PROFILE, "
		     "0)");
	TEST("SET_PROFILE with a longer payload is refused");
	if (ipc_payload_len_valid(LOTA_IPC_CMD_SET_PROFILE,
				  sizeof(struct lota_ipc_set_profile) + 1))
		FAIL("expected: !ipc_payload_len_valid(LOTA_IPC_CMD_SET_PROFILE, "
		     "sizeof(struct lota_ipc_set_profile) + 1)");

	/*
	 * SYNC_ATTEST is variable-length:
	 * the attestation loop reports one verdict per publisher it holds,
	 * and host that answers to nobody still syncs so the socket owner
	 * learns the list is empty.
	 */
	TEST("SYNC_ATTEST with no verdicts is allowed");
	if (!ipc_payload_len_valid(LOTA_IPC_CMD_SYNC_ATTEST,
				   sizeof(struct lota_ipc_attest_sync)))
		FAIL("expected: ipc_payload_len_valid(LOTA_IPC_CMD_SYNC_ATTEST, "
		     "sizeof(struct lota_ipc_attest_sync))");
	TEST("SYNC_ATTEST with one verdict is allowed");
	if (!ipc_payload_len_valid(
		    LOTA_IPC_CMD_SYNC_ATTEST,
		    sizeof(struct lota_ipc_attest_sync) +
			    sizeof(struct lota_ipc_attest_verdict)))
		FAIL("expected: ipc_payload_len_valid( "
		     "LOTA_IPC_CMD_SYNC_ATTEST, sizeof(struct "
		     "lota_ipc_attest_sync) + sizeof(struct "
		     "lota_ipc_attest_verdict))");
	TEST("SYNC_ATTEST with every publisher is allowed");
	if (!ipc_payload_len_valid(LOTA_IPC_CMD_SYNC_ATTEST,
				   LOTA_IPC_ATTEST_SYNC_MAX_SIZE))
		FAIL("expected: ipc_payload_len_valid(LOTA_IPC_CMD_SYNC_ATTEST, "
		     "LOTA_IPC_ATTEST_SYNC_MAX_SIZE)");
	TEST("SYNC_ATTEST past the publisher cap is refused");
	if (ipc_payload_len_valid(LOTA_IPC_CMD_SYNC_ATTEST,
				  LOTA_IPC_ATTEST_SYNC_MAX_SIZE + 1))
		FAIL("expected: !ipc_payload_len_valid(LOTA_IPC_CMD_SYNC_ATTEST, "
		     "LOTA_IPC_ATTEST_SYNC_MAX_SIZE + 1)");
	TEST("SYNC_ATTEST without its header is refused");
	if (ipc_payload_len_valid(LOTA_IPC_CMD_SYNC_ATTEST, 0))
		FAIL("expected: !ipc_payload_len_valid(LOTA_IPC_CMD_SYNC_ATTEST, "
		     "0)");
	TEST("SYNC_ATTEST with a partial verdict is refused");
	if (ipc_payload_len_valid(LOTA_IPC_CMD_SYNC_ATTEST,
				  sizeof(struct lota_ipc_attest_sync) + 1))
		FAIL("expected: !ipc_payload_len_valid(LOTA_IPC_CMD_SYNC_ATTEST, "
		     "sizeof(struct lota_ipc_attest_sync) + 1)");

	/*
	 * Player closing a hung title reaches this command, and the table
	 * is the first thing it meets.
	 * Refusing the length here would answer rescue attempt with bad request
	 * from a running agent.
	 */
	TEST("TERMINATE_PROTECTED carries a pid and a signal");
	if (!ipc_payload_len_valid(LOTA_IPC_CMD_TERMINATE_PROTECTED,
				   sizeof(struct lota_ipc_terminate_request)))
		FAIL("expected: ipc_payload_len_valid(LOTA_IPC_CMD_TERMINATE_PROTECTED, "
		     "sizeof(struct lota_ipc_terminate_request))");
	TEST("TERMINATE_PROTECTED naming nobody is refused");
	if (ipc_payload_len_valid(LOTA_IPC_CMD_TERMINATE_PROTECTED, 0))
		FAIL("expected: !ipc_payload_len_valid(LOTA_IPC_CMD_TERMINATE_PROTECTED, "
		     "0)");
	TEST("TERMINATE_PROTECTED without a signal is refused");
	if (ipc_payload_len_valid(LOTA_IPC_CMD_TERMINATE_PROTECTED,
				  sizeof(struct lota_ipc_pid_request)))
		FAIL("expected: !ipc_payload_len_valid(LOTA_IPC_CMD_TERMINATE_PROTECTED, "
		     "sizeof(struct lota_ipc_pid_request))");

	TEST("GET_REGISTRY carries a pid and a start");
	if (!ipc_payload_len_valid(LOTA_IPC_CMD_GET_REGISTRY,
				   sizeof(struct lota_ipc_registry_request)))
		FAIL("expected: ipc_payload_len_valid(LOTA_IPC_CMD_GET_REGISTRY, "
		     "sizeof(struct lota_ipc_registry_request))");
	TEST("GET_REGISTRY naming nobody is refused");
	if (ipc_payload_len_valid(LOTA_IPC_CMD_GET_REGISTRY, 0))
		FAIL("expected: !ipc_payload_len_valid(LOTA_IPC_CMD_GET_REGISTRY, "
		     "0)");
	TEST("GET_REGISTRY without a start is refused");
	if (ipc_payload_len_valid(LOTA_IPC_CMD_GET_REGISTRY,
				  sizeof(struct lota_ipc_pid_request)))
		FAIL("expected: !ipc_payload_len_valid(LOTA_IPC_CMD_GET_REGISTRY, "
		     "sizeof(struct lota_ipc_pid_request))");

	TEST("GET_BOOT_EVIDENCE carries nothing");
	if (!ipc_payload_len_valid(LOTA_IPC_CMD_GET_BOOT_EVIDENCE, 0))
		FAIL("expected: ipc_payload_len_valid(LOTA_IPC_CMD_GET_BOOT_EVIDENCE, "
		     "0)");
	TEST("GET_BOOT_EVIDENCE with a payload is refused");
	if (ipc_payload_len_valid(LOTA_IPC_CMD_GET_BOOT_EVIDENCE, 4))
		FAIL("expected: !ipc_payload_len_valid(LOTA_IPC_CMD_GET_BOOT_EVIDENCE, "
		     "4)");

	TEST("an unknown command may not carry a payload");
	if (ipc_payload_len_valid(0xdead, 4))
		FAIL("expected: !ipc_payload_len_valid(0xdead, 4)");
	TEST("an unknown command with no payload reaches the dispatcher");
	if (!ipc_payload_len_valid(0xdead, 0))
		FAIL("expected: ipc_payload_len_valid(0xdead, 0)");

	return test_end();
}
