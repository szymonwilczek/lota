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
#include <stdio.h>
#include <string.h>

#include "../include/lota_gaming.h"

static int g_failures;

#define CHECK(cond, msg)                                    \
	do {                                                \
		if (!(cond)) {                              \
			fprintf(stderr, "FAIL: %s\n", msg); \
			g_failures++;                       \
		} else {                                    \
			printf("PASS: %s\n", msg);          \
		}                                           \
	} while (0)

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

	printf("=== SDK flag decoder tests ===\n\n");

	CHECK(names(LOTA_FLAG_ATTESTED, "ATTESTED"), "ATTESTED is named");
	CHECK(names(LOTA_FLAG_TPM_OK, "TPM_OK"), "TPM_OK is named");
	CHECK(names(LOTA_FLAG_IOMMU_OK, "IOMMU_OK"), "IOMMU_OK is named");
	CHECK(names(LOTA_FLAG_BPF_LOADED, "BPF_LOADED"), "BPF_LOADED is named");
	CHECK(names(LOTA_FLAG_SECURE_BOOT, "SECURE_BOOT"),
	      "SECURE_BOOT is named");
	/* the one this file exists for */
	CHECK(names(LOTA_FLAG_TOKEN_ONLY, "TOKEN_ONLY"), "TOKEN_ONLY is named");

	/*
	 * the case player actually sees on host whose publisher runs no verifier:
	 * the machine is healthy and nobody has judged it
	 */
	lota_flags_to_string(LOTA_FLAG_TPM_OK | LOTA_FLAG_BPF_LOADED |
				     LOTA_FLAG_SECURE_BOOT |
				     LOTA_FLAG_TOKEN_ONLY,
			     buf, sizeof(buf));
	CHECK(strstr(buf, "TOKEN_ONLY") && !strstr(buf, "ATTESTED"),
	      "a token-only host decodes as healthy and unjudged");

	/*
	 * Protected process ended locally is a thing a player did, so the title
	 * showing them why the machine reads as it does has to be able to say it.
	 * Undecoded, the same host looks unexplained.
	 */
	CHECK(names(LOTA_FLAG_PROTECTED_TERMINATED, "PROTECTED_TERMINATED"),
	      "PROTECTED_TERMINATED is named");

	lota_flags_to_string(LOTA_FLAG_ATTESTED | LOTA_FLAG_TPM_OK |
				     LOTA_FLAG_PROTECTED_TERMINATED,
			     buf, sizeof(buf));
	CHECK(strstr(buf, "ATTESTED") && strstr(buf, "PROTECTED_TERMINATED"),
	      "an attested host that ended a protected process decodes as both");

	CHECK(lota_flags_to_string(LOTA_FLAG_ATTESTED, buf, 2) ==
		      LOTA_ERR_BUFFER_TOO_SMALL,
	      "a buffer too small is refused rather than truncated silently");

	printf("\n%s\n", g_failures ? "FAILURES" : "All tests passed");
	return g_failures ? 1 : 0;
}
