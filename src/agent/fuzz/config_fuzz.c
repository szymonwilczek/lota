/* SPDX-License-Identifier: MIT */
/*
 * LOTA Agent - Config parser fuzz harness (LibFuzzer)
 *
 * Build:
 *   clang -fsanitize=fuzzer,address -g -O1 \
 *     -DTPM_AIK_HANDLE=0x81010002 -DLOTA_TPM_H \
 *     -include src/agent/config.h \
 *     src/agent/fuzz/config_fuzz.c src/agent/config.c \
 *     -o build/fuzz-config
 *
 * Run:
 *   ./build/fuzz-config -max_len=65536
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#include "../config.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  struct lota_config cfg;
  char tmppath[] = "/tmp/lota-cfg-fuzz-XXXXXX";
  int fd;
  FILE *tmp;

  /* cap input to prevent slow runs */
  if (size > 64 * 1024)
    return 0;

  fd = mkstemp(tmppath);
  if (fd < 0)
    return 0;

  tmp = fdopen(fd, "w");
  if (!tmp) {
    close(fd);
    unlink(tmppath);
    return 0;
  }

  fwrite(data, 1, size, tmp);
  fclose(tmp);

  /* suppress stderr output from config_load error messages */
  FILE *saved = stderr;
  stderr = fopen("/dev/null", "w");
  if (!stderr)
    stderr = saved;

  config_init(&cfg);
  config_load(&cfg, tmppath);

  if (stderr != saved)
    fclose(stderr);
  stderr = saved;

  unlink(tmppath);
  return 0;
}
