/* SPDX-License-Identifier: MIT */
/*
 * lota-agent --status: what the running daemon answers to GET_STATUS,
 * as a person reads it.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */
#ifndef LOTA_AGENT_STATUS_CMD_H
#define LOTA_AGENT_STATUS_CMD_H

#include <stddef.h>
#include <stdint.h>

#include "../../include/lota_ipc.h"

/**
 * status_request() - Ask the daemon for its status.
 * @socket_path: The daemon's socket.
 * @out: Receives the answer.
 *
 * Return: 0, -EPROTO for an answer of another protocol version or size,
 * -EACCES when the daemon refuses, or another negative errno.
 */
int status_request(const char *socket_path, struct lota_ipc_status *out);

/**
 * status_flags_string() - Name the bits of a status flags word.
 * @flags: The word.
 * @buf: Receives the names, comma-separated.
 * @len: Size of @buf.
 *
 * Bits without a name print as one hex value, and an empty word as "none".
 */
void status_flags_string(uint32_t flags, char *buf, size_t len);

/**
 * status_policy_string() - Name the strict keys the host applies.
 * @s: The daemon's status.
 * @buf: Receives the names, or "none", with the reason when the LSM does not
 *       enforce.
 * @len: Size of @buf.
 */
void status_policy_string(const struct lota_ipc_status *s, char *buf,
			  size_t len);

/**
 * status_format() - Write the --status report.
 * @s: The daemon's status.
 * @buf: Receives one "Key: value" line per field.
 * @len: Size of @buf.
 */
void status_format(const struct lota_ipc_status *s, char *buf, size_t len);

#endif /* LOTA_AGENT_STATUS_CMD_H */
