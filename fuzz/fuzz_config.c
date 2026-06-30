/* SPDX-License-Identifier: MIT */
/*
 * LOTA Agent - Config parser fuzz harness (LibFuzzer)
 *
 * Build:
 *   clang -fsanitize=fuzzer,address -g -O1 \
 *     -DTPM_AIK_HANDLE=0x81010002 -DLOTA_TPM_H \
 *     -include src/agent/config.h \
 *     fuzz/fuzz_config.c src/agent/config.c \
 *     -o build/fuzz-config
 *
 * Run:
 *   ./build/fuzz-config -max_len=65536
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../src/agent/config.h"

#define FZ_CHECK(cond)           \
	do {                     \
		if (!(cond))     \
			abort(); \
	} while (0)

/* every fixed char buffer the parser fills must stay NUL-terminated in range;
 * unterminated string would over-read in any later consumer */
static void check_terminated(const struct lota_config *cfg)
{
	FZ_CHECK(memchr(cfg->server, '\0', sizeof(cfg->server)) != NULL);
	FZ_CHECK(memchr(cfg->ca_cert, '\0', sizeof(cfg->ca_cert)) != NULL);
	FZ_CHECK(memchr(cfg->pin_sha256, '\0', sizeof(cfg->pin_sha256)) !=
		 NULL);
	FZ_CHECK(memchr(cfg->bpf_path, '\0', sizeof(cfg->bpf_path)) != NULL);
	FZ_CHECK(memchr(cfg->mode, '\0', sizeof(cfg->mode)) != NULL);
	FZ_CHECK(memchr(cfg->kernel_path, '\0', sizeof(cfg->kernel_path)) !=
		 NULL);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct lota_config cfg, cfg2;
	char tmppath[] = "/tmp/lota-cfg-fuzz-XXXXXX";
	int fd, rc1, rc2;
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
	rc1 = config_load(&cfg, tmppath);
	/* parsing the same file again must reach the same verdict and produce
	 * byte-identical struct:
	 * nondeterministic parser hides state that leaked across calls */
	config_init(&cfg2);
	rc2 = config_load(&cfg2, tmppath);

	if (stderr != saved)
		fclose(stderr);
	stderr = saved;
	unlink(tmppath);

	FZ_CHECK((rc1 == 0) == (rc2 == 0));
	if (rc1 == 0) {
		check_terminated(&cfg);
		FZ_CHECK(memcmp(&cfg, &cfg2, sizeof(cfg)) == 0);
	}
	return 0;
}
