/* SPDX-License-Identifier: MIT */
/*
 * LOTA Agent - ESRT System Firmware entry.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#ifndef LOTA_AGENT_ESRT_H
#define LOTA_AGENT_ESRT_H

#include "../../include/attestation.h"

/**
 * esrt_read_system_firmware() - Read the ESRT System Firmware entry.
 * @out: the entry; present is 0 without one.
 *
 * Takes an entry of fw_type 1 whose fw_version reads. An unreadable
 * lowest_supported_fw_version reads as 0, an unparsable fw_class as zeros.
 *
 * Return: 0, also without an ESRT, or -EINVAL for a NULL @out.
 */
int esrt_read_system_firmware(struct lota_esrt *out);

/* esrt_read_system_firmware() on the ESRT entries directory at @base */
int esrt_read_system_firmware_path(const char *base, struct lota_esrt *out);

#endif /* LOTA_AGENT_ESRT_H */
