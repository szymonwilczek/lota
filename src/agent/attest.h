/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
#ifndef LOTA_ATTEST_H
#define LOTA_ATTEST_H

#include <stdint.h>

#define MIN_ATTEST_INTERVAL 10 /* 10 seconds */
#define MAX_BACKOFF_SECONDS 300 /* Max retry delay */

int export_policy(int mode);
int do_attest(const char *server, int port, const char *ca_cert,
	      int skip_verify, const uint8_t *pin_sha256);
int do_continuous_attest(const char *server, int port, const char *ca_cert,
			 int skip_verify, const uint8_t *pin_sha256,
			 int interval_sec, uint32_t aik_ttl);

/*
 * Publish the current AIK rotation state (generation, provisioned time,
 * next-rotation deadline, grace window, reenroll-required) over IPC / D-Bus
 * from the loaded AIK metadata. Safe to call once the IPC context exists and
 * the AIK metadata is loaded; a no-op until then.
 * aik_ttl mirrors the -aik-ttl / config value (0 selects the default).
 */
void publish_rotation_state(uint32_t aik_ttl);

#endif /* LOTA_ATTEST_H */
