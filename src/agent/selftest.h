/* SPDX-License-Identifier: MIT */
#ifndef LOTA_SELFTEST_H
#define LOTA_SELFTEST_H

#include <stddef.h>
#include <stdint.h>

int test_tpm(void);
int test_iommu(void);
void print_hex(const char *label, const uint8_t *data, size_t len);

#endif /* LOTA_SELFTEST_H */
