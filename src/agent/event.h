/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
#ifndef LOTA_EVENT_H
#define LOTA_EVENT_H

#include <stddef.h>

/**
 * handle_exec_event() - Log one ring buffer record.
 * @ctx: Unused.
 * @data: A struct lota_exec_event.
 * @len: Size of @data; a shorter record is skipped.
 *
 * The ring buffer callback run_daemon() registers. A protected process
 * mapping code is re-measured, at most once a second per process.
 *
 * Return: 0.
 */
int handle_exec_event(void *ctx, void *data, size_t len);

#endif /* LOTA_EVENT_H */
