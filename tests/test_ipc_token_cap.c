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
//
// Bounds relate compile-time constants only, so they are enforced at build
// time with _Static_assert (matching src/agent/ipc.c)
// main() just reports the resulting cap

#include "lota_ipc.h"

#include <stddef.h>
#include <stdio.h>

#define LOTA_IPC_TOKEN_FIXED_SIZE                                 \
	(LOTA_IPC_TOKEN_HEADER_SIZE + LOTA_IPC_TOKEN_MAX_ATTEST + \
	 LOTA_IPC_TOKEN_MAX_SIG)

/* full protected set in the worst-case (v2) token must fit the payload */
_Static_assert(LOTA_IPC_TOKEN_FIXED_SIZE +
			       (size_t)LOTA_IPC_TOKEN_MAX_PROTECT_PIDS *
				       LOTA_IPC_TOKEN_PROTECT_ENTRY_SIZE <=
		       LOTA_IPC_MAX_PAYLOAD,
	       "worst-case v2 token must fit the IPC payload");

/* cap must be the binding limit: one more PID must overflow the payload */
_Static_assert(LOTA_IPC_TOKEN_FIXED_SIZE +
			       ((size_t)LOTA_IPC_TOKEN_MAX_PROTECT_PIDS + 1) *
				       LOTA_IPC_TOKEN_PROTECT_ENTRY_SIZE >
		       LOTA_IPC_MAX_PAYLOAD,
	       "protected-PID cap must be the binding limit");

/* compile-time maximum token size must stay within the payload too */
_Static_assert(LOTA_IPC_TOKEN_MAX_SIZE <= LOTA_IPC_MAX_PAYLOAD,
	       "advertised max token size must fit the IPC payload");

int main(void)
{
	size_t full = LOTA_IPC_TOKEN_FIXED_SIZE +
		      (size_t)LOTA_IPC_TOKEN_MAX_PROTECT_PIDS *
			      LOTA_IPC_TOKEN_PROTECT_ENTRY_SIZE;

	printf("ipc token protected-PID cap: %u PIDs, worst-case %zu/%u bytes\n",
	       (unsigned)LOTA_IPC_TOKEN_MAX_PROTECT_PIDS, full,
	       (unsigned)LOTA_IPC_MAX_PAYLOAD);
	return 0;
}
