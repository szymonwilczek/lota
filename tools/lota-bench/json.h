/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * lota-bench - pull lexer for the JSON lota-bench writes
 *
 * Only what the writer emits is accepted: unsigned integers, true, false,
 * null, and strings of printable ASCII without escapes. Callers walk the
 * schema they expect, so nesting is bounded by the schema and nothing is
 * built in memory.
 */

#ifndef LOTA_BENCH_JSON_H
#define LOTA_BENCH_JSON_H

#include <stddef.h>
#include <stdint.h>

/* longest string any field holds */
#define JSON_STR_MAX 64

enum json_tok {
	JT_ERROR = 0,
	JT_END,
	JT_LBRACE,
	JT_RBRACE,
	JT_LBRACKET,
	JT_RBRACKET,
	JT_COLON,
	JT_COMMA,
	JT_STRING,
	JT_UINT,
	JT_TRUE,
	JT_FALSE,
	JT_NULL,
};

struct json_lex {
	const char *buf;
	size_t len;
	size_t pos;
	/* offset of the last token returned */
	size_t tok_at;
	/* a token json_peek() read and json_next() has not taken */
	int has_peek;
	enum json_tok peek_tok;
	size_t peek_at;
	/* value of the last JT_STRING / JT_UINT */
	char str[JSON_STR_MAX + 1];
	uint64_t num;
	/* why the last JT_ERROR */
	const char *err;
};

void json_init(struct json_lex *lx, const char *buf, size_t len);

enum json_tok json_next(struct json_lex *lx);
enum json_tok json_peek(struct json_lex *lx);

/* offset of the token json_next() returned last */
static inline size_t json_offset(const struct json_lex *lx)
{
	return lx->tok_at;
}

#endif /* LOTA_BENCH_JSON_H */
