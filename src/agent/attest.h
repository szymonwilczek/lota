/* SPDX-License-Identifier: MIT */
#ifndef LOTA_ATTEST_H
#define LOTA_ATTEST_H

#include <stdint.h>

#define MIN_ATTEST_INTERVAL 10  /* 10 seconds */
#define MAX_BACKOFF_SECONDS 300 /* Max retry delay */

int export_policy(void);
int do_attest(const char *server, int port, const char *ca_cert,
              int skip_verify, const uint8_t *pin_sha256);
int do_continuous_attest(const char *server, int port, const char *ca_cert,
                         int skip_verify, const uint8_t *pin_sha256,
                         int interval_sec, uint32_t aik_ttl);

#endif /* LOTA_ATTEST_H */
