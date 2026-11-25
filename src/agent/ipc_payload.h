/* SPDX-License-Identifier: MIT */
/*
 * How long a request payload may be, per IPC command.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */
#ifndef LOTA_IPC_PAYLOAD_H
#define LOTA_IPC_PAYLOAD_H

#include <stdbool.h>
#include <stdint.h>

#include "../../include/lota_ipc.h"

/**
 * ipc_payload_len_valid() - Whether a payload length fits its command.
 * @cmd: LOTA_IPC_CMD_* from the request header.
 * @payload_len: Payload length from the request header.
 *
 * A refused length is answered LOTA_IPC_ERR_BAD_REQUEST before any handler
 * runs, so a command missing from this switch reaches its handler only with an
 * empty payload.
 *
 * Return: true when @payload_len fits @cmd.
 */
static inline bool ipc_payload_len_valid(uint32_t cmd, uint32_t payload_len)
{
	switch (cmd) {
	case LOTA_IPC_CMD_PING:
	case LOTA_IPC_CMD_GET_STATUS:
	case LOTA_IPC_CMD_GET_BOOT_EVIDENCE:
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

	case LOTA_IPC_CMD_TERMINATE_PROTECTED:
		return payload_len == sizeof(struct lota_ipc_terminate_request);

	case LOTA_IPC_CMD_GET_REGISTRY:
		return payload_len == sizeof(struct lota_ipc_registry_request);

	case LOTA_IPC_CMD_SYNC_ATTEST:
		/*
		 * One verdict per publisher; a host that answers to nobody
		 * still syncs, with none. The cap is the publisher count a host
		 * can hold, not LOTA_IPC_MAX_PAYLOAD.
		 */
		if (payload_len < sizeof(struct lota_ipc_attest_sync))
			return false;
		if (payload_len > LOTA_IPC_ATTEST_SYNC_MAX_SIZE)
			return false;
		return (payload_len - sizeof(struct lota_ipc_attest_sync)) %
			       sizeof(struct lota_ipc_attest_verdict) ==
		       0;

	default:
		return payload_len == 0;
	}
}

#endif /* LOTA_IPC_PAYLOAD_H */
