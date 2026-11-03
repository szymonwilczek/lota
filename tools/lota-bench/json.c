/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * lota-bench - pull lexer for the JSON lota-bench writes
 */

#include <string.h>

#include "json.h"

void json_init(struct json_lex *lx, const char *buf, size_t len)
{
	memset(lx, 0, sizeof(*lx));
	lx->buf = buf;
	lx->len = len;
}

static enum json_tok fail(struct json_lex *lx, const char *why)
{
	lx->err = why;
	return JT_ERROR;
}

static int is_digit(char c)
{
	return c >= '0' && c <= '9';
}

/* a literal or number runs into the next token only through these */
static int continues_word(char c)
{
	return is_digit(c) || (c >= 'a' && c <= 'z') ||
	       (c >= 'A' && c <= 'Z') || c == '.' || c == '+' || c == '-' ||
	       c == '_';
}

static enum json_tok lex_string(struct json_lex *lx)
{
	size_t n = 0;

	lx->pos++;
	for (;;) {
		char c;

		if (lx->pos >= lx->len)
			return fail(lx, "unterminated string");
		c = lx->buf[lx->pos++];
		if (c == '"')
			break;
		if (c == '\\')
			return fail(lx, "escape in a string");
		if (c < 0x20 || c > 0x7e)
			return fail(lx, "byte outside printable ASCII");
		if (n == JSON_STR_MAX)
			return fail(lx, "string too long");
		lx->str[n++] = c;
	}
	lx->str[n] = '\0';
	return JT_STRING;
}

static enum json_tok lex_uint(struct json_lex *lx)
{
	uint64_t v = 0;

	if (lx->buf[lx->pos] == '0' && lx->pos + 1 < lx->len &&
	    is_digit(lx->buf[lx->pos + 1]))
		return fail(lx, "leading zero");
	while (lx->pos < lx->len && is_digit(lx->buf[lx->pos])) {
		if (__builtin_mul_overflow(v, 10, &v) ||
		    __builtin_add_overflow(v, lx->buf[lx->pos] - '0', &v))
			return fail(lx, "number does not fit 64 bits");
		lx->pos++;
	}
	if (lx->pos < lx->len && continues_word(lx->buf[lx->pos]))
		return fail(lx, "not an unsigned integer");
	lx->num = v;
	return JT_UINT;
}

static enum json_tok lex_word(struct json_lex *lx, const char *word,
			      enum json_tok tok)
{
	size_t n = strlen(word);

	if (lx->len - lx->pos < n || memcmp(lx->buf + lx->pos, word, n) != 0)
		return fail(lx, "unexpected character");
	lx->pos += n;
	if (lx->pos < lx->len && continues_word(lx->buf[lx->pos]))
		return fail(lx, "unexpected character");
	return tok;
}

static enum json_tok lex(struct json_lex *lx, size_t *at)
{
	char c;

	while (lx->pos < lx->len) {
		c = lx->buf[lx->pos];
		if (c != ' ' && c != '\t' && c != '\n' && c != '\r')
			break;
		lx->pos++;
	}
	*at = lx->pos;
	if (lx->pos >= lx->len)
		return JT_END;

	c = lx->buf[lx->pos];
	switch (c) {
	case '{':
		lx->pos++;
		return JT_LBRACE;
	case '}':
		lx->pos++;
		return JT_RBRACE;
	case '[':
		lx->pos++;
		return JT_LBRACKET;
	case ']':
		lx->pos++;
		return JT_RBRACKET;
	case ':':
		lx->pos++;
		return JT_COLON;
	case ',':
		lx->pos++;
		return JT_COMMA;
	case '"':
		return lex_string(lx);
	case 't':
		return lex_word(lx, "true", JT_TRUE);
	case 'f':
		return lex_word(lx, "false", JT_FALSE);
	case 'n':
		return lex_word(lx, "null", JT_NULL);
	case '-':
		return fail(lx, "negative number");
	default:
		if (is_digit(c))
			return lex_uint(lx);
		return fail(lx, "unexpected character");
	}
}

enum json_tok json_peek(struct json_lex *lx)
{
	if (!lx->has_peek) {
		lx->peek_tok = lex(lx, &lx->peek_at);
		lx->has_peek = 1;
	}
	return lx->peek_tok;
}

enum json_tok json_next(struct json_lex *lx)
{
	enum json_tok t = json_peek(lx);

	lx->has_peek = 0;
	lx->tok_at = lx->peek_at;
	return t;
}
