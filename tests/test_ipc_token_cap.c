// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
// LOTA - IPC token protected-PID capacity bound test
//
// Per-token protected-PID cap must reflect what actually fits the IPC payload:
// every protected PID costs its 4-byte value plus a 32-byte kernel image digest
// in a v2 token, on top of the header, a maximum quote and a maximum signature.
//
// If the advertised cap is larger than what fits, the runtime count guard can
// never fire before the payload overflows, so token issuance fails opaquely
// once the protected set grows past the real (much lower) limit.

#include "lota_ipc.h"

#include <stdint.h>
#include <stdio.h>

int main(void)
{
	const size_t per_pid = 4 + LOTA_IPC_TOKEN_IMAGE_DIGEST_SIZE;
	const size_t fixed = LOTA_IPC_TOKEN_HEADER_SIZE +
			     LOTA_IPC_TOKEN_MAX_ATTEST + LOTA_IPC_TOKEN_MAX_SIG;

	/* full protected set in the worst-case (v2) token must fit */
	size_t full = fixed + (size_t)LOTA_IPC_TOKEN_MAX_PROTECT_PIDS * per_pid;
	if (full > LOTA_IPC_MAX_PAYLOAD) {
		fprintf(stderr,
			"FAIL: cap %u over-advertised: worst-case token %zu > payload %u\n",
			(unsigned)LOTA_IPC_TOKEN_MAX_PROTECT_PIDS, full,
			(unsigned)LOTA_IPC_MAX_PAYLOAD);
		return 1;
	}

	/* cap must be the binding limit: one more PID must overflow */
	size_t over =
		fixed + ((size_t)LOTA_IPC_TOKEN_MAX_PROTECT_PIDS + 1) * per_pid;
	if (over <= LOTA_IPC_MAX_PAYLOAD) {
		fprintf(stderr,
			"FAIL: cap %u not tight: cap+1 still fits (%zu <= %u)\n",
			(unsigned)LOTA_IPC_TOKEN_MAX_PROTECT_PIDS, over,
			(unsigned)LOTA_IPC_MAX_PAYLOAD);
		return 1;
	}

	/* compile-time maximum token size must account for the same
	 * worst-case set and stay within the payload */
	if (LOTA_IPC_TOKEN_MAX_SIZE > LOTA_IPC_MAX_PAYLOAD) {
		fprintf(stderr,
			"FAIL: LOTA_IPC_TOKEN_MAX_SIZE %u > payload %u\n",
			(unsigned)LOTA_IPC_TOKEN_MAX_SIZE,
			(unsigned)LOTA_IPC_MAX_PAYLOAD);
		return 1;
	}

	printf("ipc token protected-PID cap: %u PIDs, worst-case %zu/%u bytes\n",
	       (unsigned)LOTA_IPC_TOKEN_MAX_PROTECT_PIDS, full,
	       (unsigned)LOTA_IPC_MAX_PAYLOAD);
	return 0;
}
