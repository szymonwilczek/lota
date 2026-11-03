/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */

#include "status_cmd.h"

#include <errno.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include "../../include/lota.h"
#include "../../include/lota_flag_names.h"
#include "io_utils.h"

int status_request(const char *socket_path, struct lota_ipc_status *out)
{
	struct lota_ipc_request req = {
		.magic = LOTA_IPC_MAGIC,
		.version = LOTA_IPC_VERSION,
		.cmd = LOTA_IPC_CMD_GET_STATUS,
		.payload_len = 0,
	};
	struct lota_ipc_response resp;
	struct sockaddr_un addr;
	int fd, ret;

	if (strlen(socket_path) >= sizeof(addr.sun_path))
		return -ENAMETOOLONG;

	fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -errno;

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	memcpy(addr.sun_path, socket_path, strlen(socket_path));

	if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		ret = -errno;
		goto out;
	}

	ret = lota_write_full(fd, &req, sizeof(req));
	if (ret == 0)
		ret = lota_read_full(fd, &resp, sizeof(resp));
	if (ret)
		goto out;

	if (resp.magic != LOTA_IPC_MAGIC || resp.version != LOTA_IPC_VERSION ||
	    resp.payload_len != sizeof(*out)) {
		ret = -EPROTO;
		goto out;
	}
	if (resp.result != LOTA_IPC_OK) {
		ret = -EACCES;
		goto out;
	}
	ret = lota_read_full(fd, out, sizeof(*out));
out:
	close(fd);
	return ret;
}

static void append(char *buf, size_t len, size_t *pos, const char *fmt, ...)
	__attribute__((format(printf, 4, 5)));

static void append(char *buf, size_t len, size_t *pos, const char *fmt, ...)
{
	va_list ap;
	int n;

	if (*pos >= len)
		return;
	va_start(ap, fmt);
	n = vsnprintf(buf + *pos, len - *pos, fmt, ap);
	va_end(ap);
	if (n < 0)
		return;
	*pos = (size_t)n >= len - *pos ? len : *pos + (size_t)n;
}

static uint32_t names_of(const struct lota_flag_name *t, size_t count,
			 uint32_t flags, char *buf, size_t len, size_t *pos)
{
	uint32_t named = 0;
	size_t i;

	for (i = 0; i < count; i++) {
		if (!(flags & t[i].flag))
			continue;
		append(buf, len, pos, "%s%s", *pos ? "," : "", t[i].name);
		named |= t[i].flag;
	}
	return named;
}

void status_flags_string(uint32_t flags, char *buf, size_t len)
{
	uint32_t named;
	size_t pos = 0;

	if (len == 0)
		return;
	buf[0] = '\0';
	named = names_of(lota_flag_names, LOTA_FLAG_NAME_COUNT, flags, buf, len,
			 &pos);
	named |= names_of(lota_host_flag_names, LOTA_HOST_FLAG_NAME_COUNT,
			  flags, buf, len, &pos);
	if (flags & ~named)
		append(buf, len, &pos, "%s0x%" PRIx32, pos ? "," : "",
		       flags & ~named);
	if (pos == 0)
		append(buf, len, &pos, "none");
}

static const char *mode_name(uint8_t mode)
{
	switch (mode) {
	case LOTA_MODE_MONITOR:
		return "monitor";
	case LOTA_MODE_ENFORCE:
		return "enforce";
	}
	return NULL;
}

static void time_string(uint64_t t, const char *none, char *buf, size_t len)
{
	struct tm tm;
	time_t tt = (time_t)t;

	if (t == 0 || !gmtime_r(&tt, &tm) ||
	    strftime(buf, len, "%Y-%m-%d %H:%M:%S UTC", &tm) == 0)
		snprintf(buf, len, "%s", none);
}

void status_format(const struct lota_ipc_status *s, char *buf, size_t len)
{
	char flags[512], last[32], until[32];
	const char *mode = mode_name(s->mode);
	size_t pos = 0;

	if (len == 0)
		return;
	buf[0] = '\0';
	status_flags_string(s->flags, flags, sizeof(flags));
	time_string(s->last_attest_time, "never", last, sizeof(last));
	time_string(s->valid_until, "none", until, sizeof(until));

	if (mode)
		append(buf, len, &pos, "Mode:         %s\n", mode);
	else
		append(buf, len, &pos, "Mode:         unknown (%u)\n", s->mode);
	append(buf, len, &pos, "Flags:        %s\n", flags);
	append(buf, len, &pos, "Attested:     %s\n", last);
	append(buf, len, &pos, "Token until:  %s\n", until);
	append(buf, len, &pos,
	       "Attestations: %" PRIu32 " succeeded, %" PRIu32 " failed\n",
	       s->attest_count, s->fail_count);
}
