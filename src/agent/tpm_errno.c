/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * Rendering for the LOTA-private TPM error codes.
 *
 * Kept apart from tpm.c, which links the TSS2 stack, so the code that has to
 * print a TPM failure can be built into a test with no TPM behind it.
 * The codes themselves and the reason they exist are documented in tpm.h.
 */

#include <errno.h>
#include <string.h>

#include "tpm.h"

const char *tpm_strerror(int err)
{
	int code = err < 0 ? -err : err;
	switch (code) {
	case 0:
		return "success";
	case LOTA_ERR_TPM_LOCKED:
		return "TPM dictionary-attack lockout engaged";
	case LOTA_ERR_TPM_AUTH_FAIL:
		return "TPM authorization failed (increments DA lockout "
		       "counter)";
	case LOTA_ERR_TPM_POLICY_FAIL:
		return "TPM policy not satisfied (host not in the sealed "
		       "boot/PCR state)";
	default:
		return strerror(code);
	}
}
