/* SPDX-License-Identifier: MIT */
/*
 * ESRT (EFI System Resource Table) System Firmware version read.
 *
 * Verifier's self-service re-anchor uses the firmware version as a monotonicity
 * (anti-rollback) signal.
 *
 * Many DIY boards expose no ESRT, so a missing table is reported as
 * "not present", not an error, and the verifier routes such hosts onto
 * the Low-Firmware-Assurance path.
 */

#ifndef LOTA_AGENT_ESRT_H
#define LOTA_AGENT_ESRT_H

#include "../../include/attestation.h"

/*
 * Fill out from the platform's ESRT System Firmware entry (fw_type == 1).
 * out->present is set to 1 when such an entry is found, 0 otherwise (no ESRT,
 * or only device-firmware entries).
 * Returns 0 on success (including the not-present case),
 * or a negative errno only on a bad argument.
 */
int esrt_read_system_firmware(struct lota_esrt *out);

/*
 * Path-parameterized variant behind the fixed-path wrapper above.
 * base is the ESRT entries directory (prod: /sys/firmware/efi/esrt/entries)
 * Lets tests point at a fixture tree.
 */
int esrt_read_system_firmware_path(const char *base, struct lota_esrt *out);

#endif /* LOTA_AGENT_ESRT_H */
