/* SPDX-License-Identifier: MIT */
/*
 * Unit tests for the SDK's status-flag decoder.
 *
 * Title renders this string to tell player why the machine reads the way it does,
 * so flag missing from the table is a case the player is never shown.
 *
 * TOKEN_ONLY is the one that matters most: it is the only status bit whose meaning
 * is "nobody verifies here", which is not a failure, and dropping it turns that
 * case back into a bare NOT ATTESTED.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */
#include <string.h>

#include "../include/lota_gaming.h"

#include "test.h"

static int names(uint32_t flag, const char *want)
{
	char buf[256] = { 0 };

	/* returns the byte count written, negative on error */
	if (lota_flags_to_string(flag, buf, sizeof(buf)) < 0)
		return 0;
	return strstr(buf, want) != NULL;
}

int main(void)
{
	char buf[256] = { 0 };

	test_begin("flag names");

	TEST("ATTESTED is named");
	if (!names(LOTA_FLAG_ATTESTED, "ATTESTED"))
		FAIL("expected: names(LOTA_FLAG_ATTESTED, \"ATTESTED\")");
	TEST("TPM_OK is named");
	if (!names(LOTA_FLAG_TPM_OK, "TPM_OK"))
		FAIL("expected: names(LOTA_FLAG_TPM_OK, \"TPM_OK\")");
	TEST("IOMMU_OK is named");
	if (!names(LOTA_FLAG_IOMMU_OK, "IOMMU_OK"))
		FAIL("expected: names(LOTA_FLAG_IOMMU_OK, \"IOMMU_OK\")");
	TEST("BPF_LOADED is named");
	if (!names(LOTA_FLAG_BPF_LOADED, "BPF_LOADED"))
		FAIL("expected: names(LOTA_FLAG_BPF_LOADED, \"BPF_LOADED\")");
	TEST("SECURE_BOOT is named");
	if (!names(LOTA_FLAG_SECURE_BOOT, "SECURE_BOOT"))
		FAIL("expected: names(LOTA_FLAG_SECURE_BOOT, \"SECURE_BOOT\")");
	/* the one this file exists for */
	TEST("TOKEN_ONLY is named");
	if (!names(LOTA_FLAG_TOKEN_ONLY, "TOKEN_ONLY"))
		FAIL("expected: names(LOTA_FLAG_TOKEN_ONLY, \"TOKEN_ONLY\")");

	/*
	 * the case player actually sees on host whose publisher runs no verifier:
	 * the machine is healthy and nobody has judged it
	 */
	lota_flags_to_string(LOTA_FLAG_TPM_OK | LOTA_FLAG_BPF_LOADED |
				     LOTA_FLAG_SECURE_BOOT |
				     LOTA_FLAG_TOKEN_ONLY,
			     buf, sizeof(buf));
	TEST("a token-only host decodes as healthy and unjudged");
	if (!(strstr(buf, "TOKEN_ONLY") && !strstr(buf, "ATTESTED")))
		FAIL("expected: strstr(buf, \"TOKEN_ONLY\") && !strstr(buf, "
		     "\"ATTESTED\")");

	/*
	 * Protected process ended locally is a thing a player did, so the title
	 * showing them why the machine reads as it does has to be able to say it.
	 * Undecoded, the same host looks unexplained.
	 */
	TEST("PROTECTED_TERMINATED is named");
	if (!names(LOTA_FLAG_PROTECTED_TERMINATED, "PROTECTED_TERMINATED"))
		FAIL("expected: names(LOTA_FLAG_PROTECTED_TERMINATED, "
		     "\"PROTECTED_TERMINATED\")");

	lota_flags_to_string(LOTA_FLAG_ATTESTED | LOTA_FLAG_TPM_OK |
				     LOTA_FLAG_PROTECTED_TERMINATED,
			     buf, sizeof(buf));
	TEST("an attested host that ended a protected process decodes as both");
	if (!(strstr(buf, "ATTESTED") && strstr(buf, "PROTECTED_TERMINATED")))
		FAIL("expected: strstr(buf, \"ATTESTED\") && strstr(buf, "
		     "\"PROTECTED_TERMINATED\")");

	TEST("BENCH is named");
	if (!names(LOTA_FLAG_BENCH, "BENCH"))
		FAIL("expected: names(LOTA_FLAG_BENCH, \"BENCH\")");

	/* the policy a title reads off a token has to print as it reads */
	TEST("ENFORCE is named");
	if (!names(LOTA_FLAG_ENFORCE, "ENFORCE"))
		FAIL("expected: names(LOTA_FLAG_ENFORCE, \"ENFORCE\")");
	TEST("STRICT_MMAP is named");
	if (!names(LOTA_FLAG_STRICT_MMAP, "STRICT_MMAP"))
		FAIL("expected: names(LOTA_FLAG_STRICT_MMAP, \"STRICT_MMAP\")");
	TEST("STRICT_EXEC is named");
	if (!names(LOTA_FLAG_STRICT_EXEC, "STRICT_EXEC"))
		FAIL("expected: names(LOTA_FLAG_STRICT_EXEC, \"STRICT_EXEC\")");
	TEST("STRICT_MODULES is named");
	if (!names(LOTA_FLAG_STRICT_MODULES, "STRICT_MODULES"))
		FAIL("expected: names(LOTA_FLAG_STRICT_MODULES, "
		     "\"STRICT_MODULES\")");
	TEST("BLOCK_ANON_EXEC is named");
	if (!names(LOTA_FLAG_BLOCK_ANON_EXEC, "BLOCK_ANON_EXEC"))
		FAIL("expected: names(LOTA_FLAG_BLOCK_ANON_EXEC, "
		     "\"BLOCK_ANON_EXEC\")");
	TEST("BLOCK_PTRACE is named");
	if (!names(LOTA_FLAG_BLOCK_PTRACE, "BLOCK_PTRACE"))
		FAIL("expected: names(LOTA_FLAG_BLOCK_PTRACE, "
		     "\"BLOCK_PTRACE\")");
	TEST("AGENT_RESTARTED is named");
	if (!names(LOTA_FLAG_AGENT_RESTARTED, "AGENT_RESTARTED"))
		FAIL("expected: names(LOTA_FLAG_AGENT_RESTARTED, "
		     "\"AGENT_RESTARTED\")");
	TEST("REENROLLING is named");
	if (!names(LOTA_FLAG_REENROLLING, "REENROLLING"))
		FAIL("expected: names(LOTA_FLAG_REENROLLING, \"REENROLLING\")");
	TEST("EVENTS_LOST is named");
	if (!names(LOTA_FLAG_EVENTS_LOST, "EVENTS_LOST"))
		FAIL("expected: names(LOTA_FLAG_EVENTS_LOST, \"EVENTS_LOST\")");

	TEST("a buffer too small is refused rather than truncated silently");
	if (lota_flags_to_string(LOTA_FLAG_ATTESTED, buf, 2) !=
	    LOTA_ERR_BUFFER_TOO_SMALL)
		FAIL("expected: lota_flags_to_string(LOTA_FLAG_ATTESTED, buf, "
		     "2) == LOTA_ERR_BUFFER_TOO_SMALL");

	return test_end();
}
