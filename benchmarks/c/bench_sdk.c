/* SPDX-License-Identifier: MIT */
/*
 * bench_sdk.c - microbenchmarks for the pure-CPU LOTA SDK hot paths.
 *
 * These cover the operations a game client and a game server run per token /
 * per heartbeat without touching a TPM or the agent socket:
 *   - game-binding hash (SHA-256 over the executable image)
 *   - token serialize (client -> wire)
 *   - token parse (server side, no signature check)
 *
 * TPM-backed paths (GET_TOKEN, quote, ActivateCredential) and the agent IPC
 * round-trip are measured by the L2 macro suite (hyperfine over the swtpm
 * sandbox); see benchmarks/README.md.
 */
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>

#include "cbench.h"
#include "lota_anticheat.h"
#include "lota_gaming.h"
#include "lota_server.h"

struct sdk_ctx {
	char exe_path[256];
	size_t exe_bytes;
	struct lota_token tok;
	uint8_t ser[8192];
	size_t ser_len;
};

static void bench_game_binding_hash(void *c, size_t iters)
{
	struct sdk_ctx *x = c;
	uint8_t out[LOTA_AC_GAME_HASH_SIZE];
	for (size_t i = 0; i < iters; i++) {
		if (lota_ac_compute_game_binding_hash("lota-demo-CS2-clone",
						      x->exe_path, out) == 0)
			cbench_sink += out[0];
	}
}

static void bench_token_serialize(void *c, size_t iters)
{
	struct sdk_ctx *x = c;
	uint8_t buf[8192];
	size_t written = 0;
	for (size_t i = 0; i < iters; i++) {
		if (lota_token_serialize(&x->tok, buf, sizeof(buf), &written) ==
		    LOTA_OK)
			cbench_sink += buf[0] + written;
	}
}

static void bench_token_parse(void *c, size_t iters)
{
	struct sdk_ctx *x = c;
	struct lota_server_claims claims;
	for (size_t i = 0; i < iters; i++) {
		if (lota_server_parse_token(x->ser, x->ser_len, &claims) ==
		    LOTA_SERVER_OK)
			cbench_sink += claims.flags;
	}
}

/* Build a representative executable image so the hash measures real bytes. */
static int make_exe_file(struct sdk_ctx *x)
{
	size_t kib = cbench_envu("BENCH_EXE_KIB", 1024); /* 1 MiB default */
	x->exe_bytes = kib * 1024;

	snprintf(x->exe_path, sizeof(x->exe_path),
		 "/tmp/lota_bench_exe.XXXXXX");
	int fd = mkstemp(x->exe_path);
	if (fd < 0)
		return -1;

	uint8_t chunk[4096];
	for (size_t i = 0; i < sizeof(chunk); i++)
		chunk[i] = (uint8_t)(i * 31 + 7);

	size_t remaining = x->exe_bytes;
	while (remaining > 0) {
		size_t n =
		    remaining < sizeof(chunk) ? remaining : sizeof(chunk);
		if (write(fd, chunk, n) != (ssize_t)n) {
			close(fd);
			return -1;
		}
		remaining -= n;
	}
	close(fd);
	return 0;
}

static int build_token(struct sdk_ctx *x)
{
	memset(&x->tok, 0, sizeof(x->tok));
	x->tok.valid_until = (uint64_t)time(NULL) + 600;
	x->tok.flags = 0x07;
	for (size_t i = 0; i < sizeof(x->tok.nonce); i++)
		x->tok.nonce[i] = (uint8_t)(i + 1);
	x->tok.sig_alg = 0x0014;  /* TPM2_ALG_RSASSA */
	x->tok.hash_alg = 0x000B; /* TPM2_ALG_SHA256 */
	x->tok.pcr_mask = 0x4001; /* PCR0 + PCR14 */
	for (size_t i = 0; i < sizeof(x->tok.policy_digest); i++)
		x->tok.policy_digest[i] = (uint8_t)(i * 3);
	for (size_t i = 0; i < sizeof(x->tok.runtime_protect_digest); i++)
		x->tok.runtime_protect_digest[i] = (uint8_t)(i * 5);
	x->tok.runtime_protect_epoch = 42;
	x->tok.protect_pid_count = 0;
	x->tok.protected_pids = NULL;

	/* Representative TPMS_ATTEST blob (quote info ~ 100-130 bytes). */
	x->tok.attest_size = 120;
	x->tok.attest_data = malloc(x->tok.attest_size);
	if (!x->tok.attest_data)
		return -1;
	for (size_t i = 0; i < x->tok.attest_size; i++)
		x->tok.attest_data[i] = (uint8_t)(i * 7 + 1);

	/* RSA-2048 signature is 256 bytes. */
	x->tok.signature_len = 256;
	x->tok.signature = malloc(x->tok.signature_len);
	if (!x->tok.signature)
		return -1;
	for (size_t i = 0; i < x->tok.signature_len; i++)
		x->tok.signature[i] = (uint8_t)(i * 11 + 3);

	/* Serialize once so the parse benchmark has valid wire bytes. */
	if (lota_token_serialize(&x->tok, x->ser, sizeof(x->ser),
				 &x->ser_len) != LOTA_OK)
		return -1;
	return 0;
}

int main(void)
{
	struct sdk_ctx x;
	memset(&x, 0, sizeof(x));

	if (make_exe_file(&x) != 0) {
		fprintf(stderr, "bench_sdk: failed to stage exe file\n");
		return 1;
	}
	if (build_token(&x) != 0) {
		fprintf(stderr, "bench_sdk: failed to build token\n");
		unlink(x.exe_path);
		return 1;
	}

	fprintf(stderr, "suite=sdk exe_bytes=%zu token_wire=%zu\n", x.exe_bytes,
		x.ser_len);

	cbench_run("sdk", "game_binding_hash", bench_game_binding_hash, &x);
	cbench_run("sdk", "token_serialize", bench_token_serialize, &x);
	cbench_run("sdk", "token_parse", bench_token_parse, &x);

	free(x.tok.attest_data);
	free(x.tok.signature);
	unlink(x.exe_path);
	return 0;
}
