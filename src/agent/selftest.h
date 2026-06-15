/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
#ifndef LOTA_SELFTEST_H
#define LOTA_SELFTEST_H

#include <stddef.h>
#include <stdint.h>

int test_tpm(void);
int test_iommu(void);
void print_hex(const char *label, const uint8_t *data, size_t len);

/*
 * Operator/root one-shots: seal a secret read from stdin to the current
 * PCR state and write the blob to stdout, or unseal a blob from stdin and
 * write the secret to stdout. Never exposed over the agent IPC socket.
 */
int do_seal(const char *pcr_str);
int do_unseal(void);

/*
 * AIK-auth at-rest lifecycle one-shots (root): adopt sealing on an
 * already-enrolled host, or recover after a boot-state change rotated the
 * sealed auth out of reach.
 */
int do_seal_aik_auth(void);
int do_reprovision_aik(void);

/*
 * Seal storage-primary persistence one-shots (root): persist the
 * deterministic seal primary at its handle to skip per-op CreatePrimary, or
 * evict it. Sealed blobs stay valid across both.
 */
int do_seal_persist_primary(void);
int do_seal_evict_primary(void);

#endif /* LOTA_SELFTEST_H */
