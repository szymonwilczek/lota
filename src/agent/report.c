/* SPDX-License-Identifier: MIT */
/*
 * LOTA - Attestation Report Serialization
 * Implements variable-length wire format for attestation reports.
 *
 * Wire format:
 *   [lota_attestation_report]    (fixed 7444 bytes)
 *   [event_count: uint32_t]
 *   [lota_exec_event * event_count]
 *   [event_log_size: uint32_t]
 *   [tpm_event_log: uint8_t * event_log_size]
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>

#include "../../include/attestation.h"

size_t calculate_report_size(uint32_t event_count, uint32_t event_log_size) {
  size_t size = sizeof(struct lota_attestation_report);
  size_t events_size;

  /* BPF event section: count + events */
  events_size = (size_t)event_count * sizeof(struct lota_exec_event);
  if (event_count != 0 &&
      events_size / event_count != sizeof(struct lota_exec_event))
    return 0;

  if (size + sizeof(uint32_t) < size)
    return 0;
  size += sizeof(uint32_t); /* event_count */

  if (size + events_size < size)
    return 0;
  size += events_size;

  /* TPM event log section: size + data */
  if (size + sizeof(uint32_t) < size)
    return 0;
  size += sizeof(uint32_t); /* event_log_size */

  if (size + event_log_size < size)
    return 0;
  size += event_log_size;

  return size;
}

ssize_t serialize_report(const struct lota_attestation_report *report,
                         const struct lota_exec_event *events,
                         uint32_t event_count, const uint8_t *event_log,
                         uint32_t event_log_size, uint8_t *out_buf,
                         size_t out_buf_size) {
  size_t total;
  size_t offset = 0;

  if (!report || !out_buf)
    return -EINVAL;

  /* count without data pointer means no events */
  if (!events)
    event_count = 0;
  if (!event_log)
    event_log_size = 0;

  total = calculate_report_size(event_count, event_log_size);
  if (total == 0)
    return -EOVERFLOW;

  if (out_buf_size < total)
    return -ENOSPC;

  /* fixed report struct */
  memcpy(out_buf + offset, report, sizeof(*report));
  offset += sizeof(*report);

  /* BPF event section */
  memcpy(out_buf + offset, &event_count, sizeof(event_count));
  offset += sizeof(event_count);

  if (event_count > 0 && events) {
    size_t events_size = (size_t)event_count * sizeof(struct lota_exec_event);
    memcpy(out_buf + offset, events, events_size);
    offset += events_size;
  }

  /* TPM event log section */
  memcpy(out_buf + offset, &event_log_size, sizeof(event_log_size));
  offset += sizeof(event_log_size);

  if (event_log_size > 0 && event_log) {
    memcpy(out_buf + offset, event_log, event_log_size);
    offset += event_log_size;
  }

  return (ssize_t)offset;
}
