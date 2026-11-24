/* SPDX-License-Identifier: MIT */
/*
 * LOTA - TCG crypto-agile event log reader
 *
 * The log comes from securityfs and is as long as the firmware made it,
 * so every count in it is read as a bound to check.
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

/*
 * tcg_log_open - start reading a log
 *
 * Skips the legacy Spec ID record that opens every crypto-agile log.
 * Returns 0, or -EINVAL when the log does not start with one.
 */
int tcg_log_open(struct tcg_log *log, const uint8_t *data, size_t size);

/*
 * tcg_log_next - read the next record
 *
 * Returns 1 and fills @ev, 0 at the end of the log, or -EINVAL for a record
 * that does not parse.
 */
int tcg_log_next(struct tcg_log *log, struct tcg_event *ev);

#endif /* LOTA_TCG_LOG_H */
