/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * lota-bench - check a result file against the schema
 *
 * Every key is known and every string is one of a fixed set, so a file
 * that validates cannot carry a path, a name or any other free text.
 */

#ifndef LOTA_BENCH_VALIDATE_H
#define LOTA_BENCH_VALIDATE_H

#include <stddef.h>

#include "result.h"

/* well past BENCH_MAX_SAMPLES lines of every metric at full width */
#define BENCH_RESULT_MAX_BYTES (64u << 20)

struct bench_validate_info {
	unsigned int interval_ms;
	unsigned int samples;
	enum bench_end end;
};

/*
 * bench_validate - whether @buf is a result lota-bench wrote
 *
 * Returns 0 and fills @info, or -EINVAL with the first problem and its
 * byte offset in @err.
 */
int bench_validate(const char *buf, size_t len,
		   struct bench_validate_info *info, char *err, size_t errcap);

#endif /* LOTA_BENCH_VALIDATE_H */
