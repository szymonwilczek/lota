/* SPDX-License-Identifier: MIT */
/*
 * How long a request payload may be, per IPC command.
 *
 * Split out of ipc.c so it can be exercised without linking the TPM and BPF halves
 * of the agent: the check runs before any handler, so command missing from it
 * is refused with LOTA_IPC_ERR_BAD_REQUEST and its handler never runs at all.
 *
 * That failure looks like working agent answering "no", which is why it needs
 * a test of its own.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */
#ifndef LOTA_IPC_PAYLOAD_H
#define LOTA_IPC_PAYLOAD_H

#include <stdbool.h>
#include <stdint.h>

#include "../../include/lota_ipc.h"

static inline bool ipc_payload_len_valid(uint32_t cmd, uint32_t payload_len)
{
	switch (cmd) {
	case LOTA_IPC_CMD_PING:
	case LOTA_IPC_CMD_GET_STATUS:
	case LOTA_IPC_CMD_SHUTDOWN:
		return payload_len == 0;

	case LOTA_IPC_CMD_GET_TOKEN:
		return payload_len == 0 ||
		       payload_len == sizeof(struct lota_ipc_token_request);

	case LOTA_IPC_CMD_SUBSCRIBE:
		return payload_len == sizeof(struct lota_ipc_subscribe_request);

	case LOTA_IPC_CMD_PROTECT_PID:
	case LOTA_IPC_CMD_UNPROTECT_PID:
		return payload_len == sizeof(struct lota_ipc_pid_request);

	case LOTA_IPC_CMD_SET_PROFILE:
		return payload_len == sizeof(struct lota_ipc_set_profile);

	default:
		/*
		 * Unknown command.
		 * Dispatcher returns LOTA_IPC_ERR_UNKNOWN_CMD regardless of
		 * payload contents, but non-zero payload still consumed up to
		 * LOTA_IPC_MAX_PAYLOAD bytes of recv_buf on the way in.
		 * Require zero payload here so the bad request is rejected
		 * as soon as the IPC header is parsed;
		 * the client gets the same LOTA_IPC_ERR_BAD_REQUEST it would
		 * get for any other malformed length, and the agent never reads
		 * the body off the socket.
		 */
		return payload_len == 0;
	}
}

#endif /* LOTA_IPC_PAYLOAD_H */
