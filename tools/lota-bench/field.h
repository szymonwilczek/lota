/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * lota-bench - the free text a session may carry
 *
 * A few named fields hold text: the title and its settings as the player
 * types them, the CPU and GPU names, the kernel release. Each is printable
 * ASCII of at most BENCH_FIELD_MAX bytes with no '/', '\' or '"', so it
 * cannot hold a path or an escape, whatever was read or typed.
 */

#ifndef LOTA_BENCH_FIELD_H
#define LOTA_BENCH_FIELD_H

#include <stdbool.h>
#include <stddef.h>

#define BENCH_FIELD_MAX 64

/* unset is written as null */
struct bench_field {
	char s[BENCH_FIELD_MAX + 1];
	bool set;
};

/*
 * bench_field_set - @len bytes of @src, cleaned
 *
 * A byte the field refuses becomes '_', a run of blanks one space, blanks
 * at either end go, and what is left is cut to BENCH_FIELD_MAX. The field
 * is left unset when nothing is left.
 */
void bench_field_set(struct bench_field *f, const char *src, size_t len);

/* whether @s is a field as bench_field_set() leaves one */
bool bench_field_ok(const char *s);

#endif /* LOTA_BENCH_FIELD_H */
