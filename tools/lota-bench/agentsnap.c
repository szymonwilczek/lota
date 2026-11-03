/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */

#include "agentsnap.h"

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "json.h"

/* the agent nests three deep; anything deeper is not its file */
#define SNAP_MAX_DEPTH 4

static int skip_value(struct json_lex *lx, int depth);

/* the rest of an object or array whose opening token is taken */
static int skip_members(struct json_lex *lx, enum json_tok close, int depth)
{
	enum json_tok t;
	bool first = true;

	if (depth > SNAP_MAX_DEPTH)
		return -EINVAL;
	for (;;) {
		if (json_peek(lx) == close && first) {
			json_next(lx);
			return 0;
		}
		if (close == JT_RBRACE) {
			if (json_next(lx) != JT_STRING)
				return -EINVAL;
			if (json_next(lx) != JT_COLON)
				return -EINVAL;
		}
		if (skip_value(lx, depth))
			return -EINVAL;
		first = false;
		t = json_next(lx);
		if (t == close)
			return 0;
		if (t != JT_COMMA)
			return -EINVAL;
	}
}

static int skip_value(struct json_lex *lx, int depth)
{
	switch (json_next(lx)) {
	case JT_STRING:
	case JT_UINT:
	case JT_TRUE:
	case JT_FALSE:
	case JT_NULL:
		return 0;
	case JT_LBRACE:
		return skip_members(lx, JT_RBRACE, depth + 1);
	case JT_LBRACKET:
		return skip_members(lx, JT_RBRACKET, depth + 1);
	default:
		return -EINVAL;
	}
}

/*
 * Walk an object whose '{' is taken, handing each key to @fn with the lexer
 * at its value; @fn returns 1 when it did not take the value
 */
static int walk_object(struct json_lex *lx, int depth,
		       int (*fn)(struct json_lex *, const char *, void *),
		       void *arg)
{
	char key[JSON_STR_MAX + 1];
	enum json_tok t;
	int ret;

	if (json_peek(lx) == JT_RBRACE) {
		json_next(lx);
		return 0;
	}
	for (;;) {
		if (json_next(lx) != JT_STRING)
			return -EINVAL;
		memcpy(key, lx->str, sizeof(key));
		if (json_next(lx) != JT_COLON)
			return -EINVAL;
		ret = fn(lx, key, arg);
		if (ret < 0)
			return ret;
		if (ret > 0 && skip_value(lx, depth))
			return -EINVAL;
		t = json_next(lx);
		if (t == JT_RBRACE)
			return 0;
		if (t != JT_COMMA)
			return -EINVAL;
	}
}

static int take_uint(struct json_lex *lx, uint64_t *out)
{
	if (json_next(lx) != JT_UINT)
		return -EINVAL;
	*out = lx->num;
	return 0;
}

/* a uint or null; @set says which */
static int take_opt(struct json_lex *lx, uint64_t *out, bool *set)
{
	if (json_peek(lx) == JT_NULL) {
		json_next(lx);
		*set = false;
		return 0;
	}
	*set = true;
	return take_uint(lx, out);
}

static int prog_key(struct json_lex *lx, const char *key, void *arg)
{
	struct bench_agent_snap *s = arg;
	uint64_t v;

	if (strcmp(key, "run_ns") && strcmp(key, "run_cnt"))
		return 1;
	if (take_uint(lx, &v))
		return -EINVAL;
	if (key[4] == 'n')
		s->run_ns += v;
	else
		s->run_cnt += v;
	return 0;
}

static int progs_value(struct json_lex *lx, struct bench_agent_snap *s)
{
	enum json_tok t;

	if (json_next(lx) != JT_LBRACKET)
		return -EINVAL;
	if (json_peek(lx) == JT_RBRACKET) {
		json_next(lx);
		return 0;
	}
	for (;;) {
		if (json_next(lx) != JT_LBRACE ||
		    walk_object(lx, 3, prog_key, s))
			return -EINVAL;
		t = json_next(lx);
		if (t == JT_RBRACKET)
			return 0;
		if (t != JT_COMMA)
			return -EINVAL;
	}
}

static int bpf_key(struct json_lex *lx, const char *key, void *arg)
{
	struct bench_agent_snap *s = arg;

	if (strcmp(key, "maps_memlock") == 0)
		return take_opt(lx, &s->memlock, &s->memlock_set);
	if (strcmp(key, "progs") == 0)
		return progs_value(lx, s);
	return 1;
}

static int protected_key(struct json_lex *lx, const char *key, void *arg)
{
	struct bench_agent_snap *s = arg;

	if (strcmp(key, "count"))
		return 1;
	s->protected_set = true;
	return take_uint(lx, &s->protected_count);
}

/* null, or an object walked by @fn */
static int nullable_object(struct json_lex *lx,
			   int (*fn)(struct json_lex *, const char *, void *),
			   struct bench_agent_snap *s, bool *present)
{
	enum json_tok t = json_next(lx);

	if (t == JT_NULL)
		return 0;
	if (t != JT_LBRACE)
		return -EINVAL;
	*present = true;
	return walk_object(lx, 2, fn, s);
}

static int top_key(struct json_lex *lx, const char *key, void *arg)
{
	struct bench_agent_snap *s = arg;
	bool ignored = false;

	if (strcmp(key, "seq") == 0)
		return take_uint(lx, &s->seq);
	if (strcmp(key, "bpf") == 0)
		return nullable_object(lx, bpf_key, s, &s->bpf);
	if (strcmp(key, "protected") == 0) {
		if (nullable_object(lx, protected_key, s, &ignored))
			return -EINVAL;
		return 0;
	}
	return 1;
}

int bench_agent_snap_parse(const char *buf, size_t len,
			   struct bench_agent_snap *s)
{
	struct json_lex lx;

	memset(s, 0, sizeof(*s));
	json_init(&lx, buf, len);
	if (json_next(&lx) != JT_LBRACE || walk_object(&lx, 1, top_key, s) ||
	    json_next(&lx) != JT_END) {
		memset(s, 0, sizeof(*s));
		return -EINVAL;
	}
	return 0;
}

int bench_agent_snap_read(int dirfd, const char *name,
			  struct bench_agent_snap *s)
{
	char buf[BENCH_AGENT_SNAP_MAX];
	struct stat st;
	size_t got = 0;
	int fd, ret;

	memset(s, 0, sizeof(*s));
	fd = openat(dirfd, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
	if (fd < 0)
		return -errno;
	if (fstat(fd, &st) || !S_ISREG(st.st_mode)) {
		close(fd);
		return -EINVAL;
	}
	for (;;) {
		ssize_t n = read(fd, buf + got, sizeof(buf) - got);

		if (n < 0 && errno == EINTR)
			continue;
		if (n < 0) {
			ret = -errno;
			close(fd);
			return ret;
		}
		if (n == 0)
			break;
		got += (size_t)n;
		if (got == sizeof(buf)) {
			close(fd);
			return -EFBIG;
		}
	}
	close(fd);
	return bench_agent_snap_parse(buf, got, s);
}
