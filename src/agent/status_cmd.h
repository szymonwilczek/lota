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

/* Ask the daemon on @socket_path; 0 or negative errno */
int status_request(const char *socket_path, struct lota_ipc_status *out);

/* Comma-separated names of @flags; a bit without a name prints as hex */
void status_flags_string(uint32_t flags, char *buf, size_t len);

/* The whole report, one "Key: value" line each */
void status_format(const struct lota_ipc_status *s, char *buf, size_t len);

#endif /* LOTA_AGENT_STATUS_CMD_H */
