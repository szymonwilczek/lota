/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * LOTA Agent - BPF ring buffer event handler
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>

#include "../../include/lota.h"
#include "agent.h"
#include "event.h"
#include "hash_verify.h"
#include "ipc.h"
#include "journal.h"
#include "kill_report.h"
#include "path_validate.h"
#include "runtime_image_measure.h"
#include "lota_runtime_image_measure.h"

/* @buf holds LOTA_HASH_SIZE * 2 + 1 bytes */
static void format_sha256(const uint8_t hash[LOTA_HASH_SIZE], char *buf)
{
	for (int i = 0; i < LOTA_HASH_SIZE; i++)
		snprintf(buf + i * 2, 3, "%02x", hash[i]);
}

static bool hash_is_nonzero(const uint8_t hash[LOTA_HASH_SIZE])
{
	for (int i = 0; i < LOTA_HASH_SIZE; i++) {
		if (hash[i] != 0)
			return true;
	}
	return false;
}

/*
 * A process loading code emits one event per object, and each re-measure walks
 * the whole image. timestamp_ns is bpf_ktime_get_ns(), CLOCK_MONOTONIC.
 */
#define LOTA_RT_REMEASURE_COOLDOWN_NS (1000ULL * 1000 * 1000)

static struct rt_remeasure_slot {
	uint32_t pid;
	uint64_t last_ns;
	bool used;
} rt_remeasure_seen[LOTA_MAX_PROTECTED_PIDS];

/* a full table gives the slot of the oldest re-measure to a new pid */
static bool rt_remeasure_due(uint32_t pid, uint64_t now_ns)
{
	struct rt_remeasure_slot *victim = &rt_remeasure_seen[0];

	for (size_t i = 0; i < LOTA_MAX_PROTECTED_PIDS; i++) {
		struct rt_remeasure_slot *s = &rt_remeasure_seen[i];

		if (s->used && s->pid == pid) {
			if (now_ns - s->last_ns < LOTA_RT_REMEASURE_COOLDOWN_NS)
				return false;
			s->last_ns = now_ns;
			return true;
		}
		if (!victim->used)
			continue;
		if (!s->used || s->last_ns < victim->last_ns)
			victim = s;
	}

	victim->used = true;
	victim->pid = pid;
	victim->last_ns = now_ns;
	return true;
}

/* the journal only: a token measures the image again for its quote */
static void remeasure_protected_image(const struct lota_exec_event *event)
{
	uint8_t digest[LOTA_RUNTIME_IMAGE_DIGEST_SIZE];
	char hex[LOTA_RUNTIME_IMAGE_DIGEST_SIZE * 2 + 1];
	struct lota_runtime_measure_failure mfail;
	struct lota_runtime_measure_coverage cov;
	int ret;

	if (!rt_remeasure_due(event->tgid, event->timestamp_ns))
		return;

	ret = lota_runtime_measure_pid((pid_t)event->tgid, digest, &cov,
				       &mfail);
	if (ret < 0) {
		char reason[LOTA_RT_REASON_MAX];

		lota_rt_failure_reason(&mfail, ret, reason, sizeof(reason));
		lota_warn(
			"event-driven re-measure failed for protected pid=%u: %s",
			event->tgid, reason);
		return;
	}

	for (int i = 0; i < LOTA_RUNTIME_IMAGE_DIGEST_SIZE; i++)
		snprintf(hex + i * 2, 3, "%02x", digest[i]);

	lota_warn("event-driven re-measure: protected pid=%u image=%s (%u "
		  "object%s measured, %u unmeasurable)",
		  event->tgid, hex, cov.measured, cov.measured == 1 ? "" : "s",
		  cov.unmeasurable);
}

int handle_exec_event(void *ctx, void *data, size_t len)
{
	struct lota_exec_event event_copy;
	struct lota_exec_event *event = &event_copy;
	const char *event_type_str;
	uint8_t content_hash[LOTA_HASH_SIZE];
	char hash_hex[LOTA_HASH_SIZE * 2 + 1];
	char comm_safe[LOTA_MAX_COMM_LEN];
	char filename_safe[LOTA_MAX_PATH_LEN];
	int has_file = 0;
	bool is_exec = false;
	bool is_blocked = false;
	int hash_ret;
	(void)ctx;

	if (len < sizeof(event_copy))
		return 0;

	/* libbpf maps the record read-only */
	memcpy(&event_copy, data, sizeof(event_copy));
	event->comm[LOTA_MAX_COMM_LEN - 1] = '\0';
	event->filename[LOTA_MAX_PATH_LEN - 1] = '\0';

	/*
	 * Any process names its comm and its paths. The hash path opens the raw
	 * filename.
	 */
	lota_str_sanitize(event->comm, comm_safe, sizeof(comm_safe));
	lota_str_sanitize(event->filename, filename_safe,
			  sizeof(filename_safe));

	switch (event->event_type) {
	case LOTA_EVENT_EXEC:
		event_type_str = "EXEC";
		has_file = 1;
		is_exec = true;
		break;
	case LOTA_EVENT_EXEC_BLOCKED:
		event_type_str = "EXEC_BLOCKED";
		has_file = 1;
		is_exec = true;
		is_blocked = true;
		break;
	case LOTA_EVENT_MODULE_LOAD:
		event_type_str = "MODULE";
		has_file = 1;
		break;
	case LOTA_EVENT_MODULE_BLOCKED:
		event_type_str = "BLOCKED";
		has_file = 1;
		is_blocked = true;
		break;
	case LOTA_EVENT_MOUNT_BLOCKED:
		event_type_str = "MOUNT_BLOCKED";
		has_file = 1;
		is_blocked = true;
		break;
	case LOTA_EVENT_MMAP_EXEC:
		event_type_str = "MMAP_EXEC";
		has_file = 1;
		if (event->flags & LOTA_EVENT_FLAG_PROTECTED) {
			ipc_runtime_coverage_forget();
			remeasure_protected_image(event);
		}
		break;
	case LOTA_EVENT_MMAP_BLOCKED:
		event_type_str = "MMAP_BLOCKED";
		has_file = 1;
		is_blocked = true;
		if (event->flags & LOTA_EVENT_FLAG_PROTECTED) {
			ipc_runtime_coverage_forget();
			remeasure_protected_image(event);
		}
		break;
	case LOTA_EVENT_PTRACE:
		event_type_str =
			(event->flags & LOTA_EVENT_FLAG_INSIDE_INSTANCE) ?
				"PTRACE_INSIDE_INSTANCE" :
				"PTRACE";
		lota_info("[%llu] %s %s -> pid=%u: %s (pid=%u, uid=%u)",
			  (unsigned long long)event->timestamp_ns,
			  event_type_str, comm_safe, event->target_pid,
			  filename_safe, event->pid, event->uid);
		return 0;
	case LOTA_EVENT_PTRACE_BLOCKED:
		event_type_str = "PTRACE_BLOCKED";
		lota_info("[%llu] %s %s -> pid=%u: %s (pid=%u, uid=%u)",
			  (unsigned long long)event->timestamp_ns,
			  event_type_str, comm_safe, event->target_pid,
			  filename_safe, event->pid, event->uid);
		return 0;
	case LOTA_EVENT_KILL:
	case LOTA_EVENT_KILL_BLOCKED: {
		char kill_line[LOTA_MAX_COMM_LEN + 96];

		kill_report_line(kill_line, sizeof(kill_line),
				 event->event_type == LOTA_EVENT_KILL_BLOCKED,
				 comm_safe, event->target_pid, event->signal,
				 event->pid, event->uid);
		lota_info("[%llu] %s", (unsigned long long)event->timestamp_ns,
			  kill_line);
		return 0;
	}
	/* the writer saw only EPERM; name the pin */
	case LOTA_EVENT_MAPPED_WRITE_BLOCKED:
		lota_info(
			"[%llu] MAPPED_WRITE_BLOCKED %s -> %s (pid=%u, uid=%u)",
			(unsigned long long)event->timestamp_ns, comm_safe,
			filename_safe, event->pid, event->uid);
		return 0;
	/* the move also ended the agent; this is the record */
	case LOTA_EVENT_AGENT_MOVED:
		lota_warn("[%llu] AGENT_MOVED %s moved the agent pid=%u to %s "
			  "(pid=%u, uid=%u)",
			  (unsigned long long)event->timestamp_ns, comm_safe,
			  event->target_pid, filename_safe, event->pid,
			  event->uid);
		return 0;
	/* no signal, so no target pid: name the file instead */
	case LOTA_EVENT_KILL_GUARD_BLOCKED:
		lota_info("[%llu] KILL_BLOCKED %s -> %s (pid=%u, uid=%u)",
			  (unsigned long long)event->timestamp_ns, comm_safe,
			  filename_safe, event->pid, event->uid);
		return 0;
	case LOTA_EVENT_SETUID:
		lota_info("[%llu] SETUID %s: uid %u -> %u (pid=%u)",
			  (unsigned long long)event->timestamp_ns, comm_safe,
			  event->uid, event->target_uid, event->pid);
		return 0;
	case LOTA_EVENT_ANON_EXEC:
		event_type_str = "ANON_EXEC";
		break;
	case LOTA_EVENT_ANON_EXEC_BLOCKED:
		event_type_str = "ANON_EXEC_BLOCKED";
		break;
	default:
		event_type_str = "UNKNOWN";
		break;
	}

	if (has_file && event->filename[0] == '/') {
		if (is_exec && hash_is_nonzero(event->hash)) {
			format_sha256(event->hash, hash_hex);
			lota_info(
				"[%llu] %s %s: %s verity32=%s (pid=%u, uid=%u)",
				(unsigned long long)event->timestamp_ns,
				event_type_str, comm_safe, filename_safe,
				hash_hex, event->pid, event->uid);
			return 0;
		}

		/* /proc/<pid>/exe is still the old image */
		if (is_exec && is_blocked)
			goto log_no_hash;

		hash_ret = hash_verify_event(&g_agent.hash_ctx, event,
					     content_hash);
		if (hash_ret == 0) {
			format_sha256(content_hash, hash_hex);
			lota_info(
				"[%llu] %s %s: %s verity32=%s (pid=%u, uid=%u)",
				(unsigned long long)event->timestamp_ns,
				event_type_str, comm_safe, filename_safe,
				hash_hex, event->pid, event->uid);
			return 0;
		}
	}

log_no_hash:

	lota_info("[%llu] %s %s: %s (pid=%u, uid=%u)",
		  (unsigned long long)event->timestamp_ns, event_type_str,
		  comm_safe, filename_safe, event->pid, event->uid);

	return 0;
}
