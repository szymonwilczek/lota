/* SPDX-License-Identifier: MIT */
/*
 * LOTA - TCG crypto-agile event log reader
 *
 * Copyright (C) 2026 Szymon Wilczek
 */
#ifndef LOTA_TCG_LOG_H
#define LOTA_TCG_LOG_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define TCG_EV_NO_ACTION 0x00000003u
#define TCG_EV_IPL 0x0000000Du

struct tcg_log {
	const uint8_t *data;
	size_t size;
	size_t off;
};

struct tcg_event {
	uint32_t pcr;
	uint32_t type;
	const uint8_t *sha256; /* NULL when the record has no SHA-256 digest */
	const uint8_t *data;
	uint32_t data_size;
};

/**
 * tcg_log_open() - Start reading a log.
 * @log: Reader state.
 * @data: The log.
 * @size: Its length.
 *
 * Skips the first record, whose data is not parsed.
 *
 * Return: 0, or -EINVAL when the log does not start with a legacy-format
 * EV_NO_ACTION record on PCR 0.
 */
int tcg_log_open(struct tcg_log *log, const uint8_t *data, size_t size);

/**
 * tcg_log_next() - Read the next record.
 * @log: Reader state.
 * @ev: Receives the record; its pointers point into the log.
 *
 * Return: 1 with @ev filled, 0 at the end of the log, or -EINVAL for a record
 * that does not parse.
 */
int tcg_log_next(struct tcg_log *log, struct tcg_event *ev);

#endif /* LOTA_TCG_LOG_H */
