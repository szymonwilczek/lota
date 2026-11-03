/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * lota-bench - read a session file and check it against the schema
 *
 * Every key is known, every name is one of a fixed set and every text is
 * a struct bench_field, so a file that validates cannot carry a path or
 * an escape. A run must also be what its place in the session says: its
 * configuration, and the state of LOTA that configuration stands for.
 */

#ifndef LOTA_BENCH_VALIDATE_H
#define LOTA_BENCH_VALIDATE_H

#include <stddef.h>

#include "result.h"

/* every planned sample of a session; ~1 KiB each */
#define BENCH_SESSION_MAX_SAMPLES 43200

/* well past BENCH_SESSION_MAX_SAMPLES lines of every metric */
#define BENCH_RESULT_MAX_BYTES (64u << 20)

/*
 * bench_validate - read @buf into @d
 *
 * Returns 0, or -EINVAL with the first problem and its byte offset in
 * @err. Each run's samples point into @buf.
 */
int bench_validate(const char *buf, size_t len, struct bench_doc *d, char *err,
		   size_t errcap);

#endif /* LOTA_BENCH_VALIDATE_H */
