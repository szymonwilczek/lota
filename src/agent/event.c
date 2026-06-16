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
#include "journal.h"
#include "runtime_image_measure.h"
#include "lota_runtime_image_measure.h"

/*
 * Format SHA-256 hex string into buffer.
 * buf must be at least 65 bytes (64 hex + NUL).
 */
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
 * Per-PID debounce for event-driven re-measurement.
 *
 * A protected process loading code (lazy dlopen at startup) emits one
 * executable-mapping event per object, and re-measuring the full image on
 * each one is O(objects^2) and floods the log. The re-measure is a
 * monitor/forensic complement to in-kernel enforcement, so coalescing a
 * burst behind a short cooldown loses no enforcement and still reports
 * drift promptly. The event timestamp is the kernel's CLOCK_MONOTONIC
 * reading, so it is the time source and no extra clock read is needed.
 */
#define LOTA_RT_REMEASURE_COOLDOWN_NS (1000ULL * 1000 * 1000)

static struct rt_remeasure_slot {
	uint32_t pid;
	uint64_t last_ns;
	bool used;
} rt_remeasure_seen[LOTA_MAX_PROTECTED_PIDS];

/*
 * Record that pid is about to be re-measured at now_ns and report whether
 * the cooldown has elapsed since its last re-measure. An untracked pid
 * claims a free slot, or evicts the least-recently-measured one when the
 * table is full (which also reclaims slots left by exited PIDs).
 */
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
			continue; /* already holding a free slot */
		if (!s->used || s->last_ns < victim->last_ns)
			victim = s;
	}

	victim->used = true;
	victim->pid = pid;
	victim->last_ns = now_ns;
	return true;
}

/*
 * Event-driven re-measurement.
 *
 * When a protected process changes its executable mappings (mmap or
 * mprotect of code pages), re-measure its image from the kernel side
 * immediately instead of waiting for the next periodic heartbeat. The
 * fresh, kernel-anchored digest is recorded in the audit stream so image
 * drift between heartbeats is observable as it happens; the value bound
 * under the quote is still produced on the next token request. In enforce
 * mode an untrusted mapping is already blocked at the source, so this is
 * the monitor-mode and forensic complement to that enforcement.
 */
static void remeasure_protected_image(const struct lota_exec_event *event)
{
	uint8_t digest[LOTA_RUNTIME_IMAGE_DIGEST_SIZE];
	char hex[LOTA_RUNTIME_IMAGE_DIGEST_SIZE * 2 + 1];
	int ret;

	if (!rt_remeasure_due(event->tgid, event->timestamp_ns))
		return;

	ret = lota_runtime_measure_pid((pid_t)event->tgid, digest);
	if (ret < 0) {
		lota_warn(
			"event-driven re-measure failed for protected pid=%u: %s",
			event->tgid, strerror(-ret));
		return;
	}

	for (int i = 0; i < LOTA_RUNTIME_IMAGE_DIGEST_SIZE; i++)
		snprintf(hex + i * 2, 3, "%02x", digest[i]);

	lota_warn("event-driven re-measure: protected pid=%u image=%s",
		  event->tgid, hex);
}

/*
 * Ring buffer event handler.
 *
 * For file-bearing events (EXEC, MODULE, MMAP), computes the SHA-256
 * content hash via the hash verification cache and logs it alongside
 * the event metadata.
 */
int handle_exec_event(void *ctx, void *data, size_t len)
{
	struct lota_exec_event event_copy;
	struct lota_exec_event *event = &event_copy;
	const char *event_type_str;
	uint8_t content_hash[LOTA_HASH_SIZE];
	char hash_hex[LOTA_HASH_SIZE * 2 + 1];
	int has_file = 0;
	bool is_exec = false;
	bool is_blocked = false;
	int hash_ret;
	(void)ctx;

	if (len < sizeof(event_copy))
		return 0;

	/*
	 * libbpf maps the ring buffer records read-only into the
	 * consumer's address space, so any write to the record
	 * delivered by ring_buffer__poll() raises SIGSEGV. Take a
	 * private copy before NUL-terminating the variable-length
	 * string fields; hash_verify_event() calls open(event->filename,
	 * ...) downstream and therefore needs the path NUL-terminated.
	 * BPF synthesises some filename values via __builtin_memcpy()
	 * without a trailing NUL, which is why the termination cannot
	 * be skipped entirely.
	 */
	memcpy(&event_copy, data, sizeof(event_copy));
	event->comm[LOTA_MAX_COMM_LEN - 1] = '\0';
	event->filename[LOTA_MAX_PATH_LEN - 1] = '\0';

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
	case LOTA_EVENT_MMAP_EXEC:
		event_type_str = "MMAP_EXEC";
		has_file = 1;
		if (event->flags & LOTA_EVENT_FLAG_PROTECTED)
			remeasure_protected_image(event);
		break;
	case LOTA_EVENT_MMAP_BLOCKED:
		event_type_str = "MMAP_BLOCKED";
		has_file = 1;
		is_blocked = true;
		if (event->flags & LOTA_EVENT_FLAG_PROTECTED)
			remeasure_protected_image(event);
		break;
	case LOTA_EVENT_PTRACE:
		event_type_str = "PTRACE";
		lota_info("[%llu] %s %s -> pid=%u: %s (pid=%u, uid=%u)",
			  (unsigned long long)event->timestamp_ns,
			  event_type_str, event->comm, event->target_pid,
			  event->filename, event->pid, event->uid);
		return 0;
	case LOTA_EVENT_PTRACE_BLOCKED:
		event_type_str = "PTRACE_BLOCKED";
		lota_info("[%llu] %s %s -> pid=%u: %s (pid=%u, uid=%u)",
			  (unsigned long long)event->timestamp_ns,
			  event_type_str, event->comm, event->target_pid,
			  event->filename, event->pid, event->uid);
		return 0;
	case LOTA_EVENT_KILL_BLOCKED:
		lota_info("[%llu] KILL_BLOCKED %s -> pid=%u (pid=%u, uid=%u)",
			  (unsigned long long)event->timestamp_ns, event->comm,
			  event->target_pid, event->pid, event->uid);
		return 0;
	case LOTA_EVENT_SETUID:
		lota_info("[%llu] SETUID %s: uid %u -> %u (pid=%u)",
			  (unsigned long long)event->timestamp_ns, event->comm,
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

	/*
	 * For events with a file path, attempt to resolve the content
	 * SHA-256 hash. This uses the LRU cache so unchanged files
	 * are not re-hashed on every event.
	 */
	if (has_file && event->filename[0] == '/') {
		if (is_exec && hash_is_nonzero(event->hash)) {
			format_sha256(event->hash, hash_hex);
			lota_info(
				"[%llu] %s %s: %s verity32=%s (pid=%u, uid=%u)",
				(unsigned long long)event->timestamp_ns,
				event_type_str, event->comm, event->filename,
				hash_hex, event->pid, event->uid);
			return 0;
		}

		/* never hash blocked exec events: /proc/<pid>/exe is not the
		 * new image */
		if (is_exec && is_blocked)
			goto log_no_hash;

		hash_ret = hash_verify_event(&g_agent.hash_ctx, event,
					     content_hash);
		if (hash_ret == 0) {
			format_sha256(content_hash, hash_hex);
			lota_info(
				"[%llu] %s %s: %s verity32=%s (pid=%u, uid=%u)",
				(unsigned long long)event->timestamp_ns,
				event_type_str, event->comm, event->filename,
				hash_hex, event->pid, event->uid);
			return 0;
		}
		/* hash failed -> fall through to log without hash */
	}

log_no_hash:

	lota_info("[%llu] %s %s: %s (pid=%u, uid=%u)",
		  (unsigned long long)event->timestamp_ns, event_type_str,
		  event->comm, event->filename, event->pid, event->uid);

	return 0;
}
