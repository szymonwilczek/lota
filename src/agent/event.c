/* SPDX-License-Identifier: MIT */
/*
 * LOTA Agent - BPF ring buffer event handler
 */

#include <stdint.h>
#include <stdio.h>

#include "../../include/lota.h"
#include "agent.h"
#include "event.h"
#include "hash_verify.h"
#include "journal.h"

/*
 * Format SHA-256 hex string into buffer.
 * buf must be at least 65 bytes (64 hex + NUL).
 */
static void format_sha256(const uint8_t hash[LOTA_HASH_SIZE], char *buf) {
  for (int i = 0; i < LOTA_HASH_SIZE; i++)
    snprintf(buf + i * 2, 3, "%02x", hash[i]);
}

/*
 * Ring buffer event handler.
 *
 * For file-bearing events (EXEC, MODULE, MMAP), computes the SHA-256
 * content hash via the hash verification cache and logs it alongside
 * the event metadata.
 */
int handle_exec_event(void *ctx, void *data, size_t len) {
  struct lota_exec_event *event = data;
  const char *event_type_str;
  uint8_t content_hash[LOTA_HASH_SIZE];
  char hash_hex[LOTA_HASH_SIZE * 2 + 1];
  int has_file = 0;
  int hash_ret;
  (void)ctx;

  if (len < sizeof(*event))
    return 0;

  switch (event->event_type) {
  case LOTA_EVENT_EXEC:
    event_type_str = "EXEC";
    has_file = 1;
    break;
  case LOTA_EVENT_EXEC_BLOCKED:
    event_type_str = "EXEC_BLOCKED";
    has_file = 1;
    break;
  case LOTA_EVENT_MODULE_LOAD:
    event_type_str = "MODULE";
    has_file = 1;
    break;
  case LOTA_EVENT_MODULE_BLOCKED:
    event_type_str = "BLOCKED";
    has_file = 1;
    break;
  case LOTA_EVENT_MMAP_EXEC:
    event_type_str = "MMAP_EXEC";
    has_file = 1;
    break;
  case LOTA_EVENT_MMAP_BLOCKED:
    event_type_str = "MMAP_BLOCKED";
    has_file = 1;
    break;
  case LOTA_EVENT_PTRACE:
    event_type_str = "PTRACE";
    lota_info("[%llu] %s %s -> pid=%u: %s (pid=%u, uid=%u)",
              (unsigned long long)event->timestamp_ns, event_type_str,
              event->comm, event->target_pid, event->filename, event->pid,
              event->uid);
    return 0;
  case LOTA_EVENT_PTRACE_BLOCKED:
    event_type_str = "PTRACE_BLOCKED";
    lota_info("[%llu] %s %s -> pid=%u: %s (pid=%u, uid=%u)",
              (unsigned long long)event->timestamp_ns, event_type_str,
              event->comm, event->target_pid, event->filename, event->pid,
              event->uid);
    return 0;
  case LOTA_EVENT_SETUID:
    lota_info("[%llu] SETUID %s: uid %u -> %u (pid=%u)",
              (unsigned long long)event->timestamp_ns, event->comm, event->uid,
              event->target_uid, event->pid);
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
    hash_ret = hash_verify_event(&g_hash_ctx, event, content_hash);
    if (hash_ret == 0) {
      format_sha256(content_hash, hash_hex);
      lota_info("[%llu] %s %s: %s sha256=%s (pid=%u, uid=%u)",
                (unsigned long long)event->timestamp_ns, event_type_str,
                event->comm, event->filename, hash_hex, event->pid, event->uid);
      return 0;
    }
    /* hash failed -> fall through to log without hash */
  }

  lota_info("[%llu] %s %s: %s (pid=%u, uid=%u)",
            (unsigned long long)event->timestamp_ns, event_type_str,
            event->comm, event->filename, event->pid, event->uid);

  return 0;
}
