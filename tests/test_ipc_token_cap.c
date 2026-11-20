// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
// LOTA - token protected-PID capacity bound test
//
// Per-token protected-PID cap must reflect what actually fits the IPC payload:
// every protected PID costs its 4-byte value plus a 32-byte registry digest
// in a token, on top of the header, a maximum quote and a maximum signature.
//
// If the advertised cap is larger than what fits, the runtime count guard can
// never fire before the payload overflows, so token issuance fails opaquely
// once the protected set grows past the real (much lower) limit.
//
// The wire cap and maximum size in lota_token.h must match what the agent
// produces. Bounds within one header are _Static_assert'ed; main() checks
// the two headers agree.

#include "lota_ipc.h"
#include "lota_token.h"
#include "test.h"

#include <stddef.h>

#define LOTA_IPC_TOKEN_FIXED_SIZE                                 \
	(LOTA_IPC_TOKEN_HEADER_SIZE + LOTA_IPC_TOKEN_MAX_ATTEST + \
	 LOTA_IPC_TOKEN_MAX_SIG)

/* full protected set in the worst-case token must fit the payload */
_Static_assert(LOTA_IPC_TOKEN_FIXED_SIZE +
			       (size_t)LOTA_IPC_TOKEN_MAX_PROTECT_PIDS *
				       LOTA_IPC_TOKEN_PROTECT_ENTRY_SIZE <=
		       LOTA_IPC_MAX_PAYLOAD,
	       "worst-case token must fit the IPC payload");

/* cap must be the binding limit: one more PID must overflow the payload */
_Static_assert(LOTA_IPC_TOKEN_FIXED_SIZE +
			       ((size_t)LOTA_IPC_TOKEN_MAX_PROTECT_PIDS + 1) *
				       LOTA_IPC_TOKEN_PROTECT_ENTRY_SIZE >
		       LOTA_IPC_MAX_PAYLOAD,
	       "protected-PID cap must be the binding limit");

/* compile-time maximum token size must stay within the payload too */
_Static_assert(LOTA_IPC_TOKEN_MAX_SIZE <= LOTA_IPC_MAX_PAYLOAD,
	       "advertised max token size must fit the IPC payload");

/* worst-case wire token the agent can produce at the IPC-derived cap */
#define LOTA_TOKEN_WORST_CASE_SIZE                                      \
	((size_t)LOTA_TOKEN_HEADER_SIZE +                               \
	 (size_t)LOTA_IPC_TOKEN_MAX_PROTECT_PIDS *                      \
		 (sizeof(uint32_t) + LOTA_TOKEN_REGISTRY_DIGEST_SIZE) + \
	 LOTA_IPC_TOKEN_MAX_ATTEST + LOTA_IPC_TOKEN_MAX_SIG)

int main(void)
{
	test_begin("ipc token cap");

	/* the wire cap is the IPC-derived cap */
	TEST("wire protected-PID cap is the IPC-derived cap");
	if (LOTA_TOKEN_MAX_PROTECT_PIDS != LOTA_IPC_TOKEN_MAX_PROTECT_PIDS)
		FAIL("wire cap %u, IPC-derived cap %u",
		     (unsigned)LOTA_TOKEN_MAX_PROTECT_PIDS,
		     (unsigned)LOTA_IPC_TOKEN_MAX_PROTECT_PIDS);
	TEST("wire PID list size is the IPC PID list size");
	if (LOTA_TOKEN_MAX_PID_LIST_SIZE != LOTA_IPC_TOKEN_MAX_PID_LIST_SIZE)
		FAIL("wire PID list %u, IPC PID list %u bytes",
		     (unsigned)LOTA_TOKEN_MAX_PID_LIST_SIZE,
		     (unsigned)LOTA_IPC_TOKEN_MAX_PID_LIST_SIZE);

	/* LOTA_TOKEN_MAX_SIZE must fit a full token */
	TEST("advertised token maximum fits the worst-case token");
	if ((size_t)LOTA_TOKEN_MAX_SIZE < LOTA_TOKEN_WORST_CASE_SIZE)
		FAIL("advertised max %u bytes, worst case %zu",
		     (unsigned)LOTA_TOKEN_MAX_SIZE,
		     (size_t)LOTA_TOKEN_WORST_CASE_SIZE);

	return test_end();
}
