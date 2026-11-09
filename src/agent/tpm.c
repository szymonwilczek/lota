/* SPDX-License-Identifier: MIT */
/*
 * LOTA - TPM 2.0 Operations Module
 * Implementation using libtss2-esys
 *
 * Copyright (C) 2026 Szymon Wilczek
 */
#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <tss2/tss2_esys.h>
#include <tss2/tss2_mu.h>
#include <tss2/tss2_tcti.h>
#include <tss2/tss2_tcti_device.h>
#include <tss2/tss2_tctildr.h>
#include <openssl/params.h>
#include <openssl/types.h>
#include <sys/types.h>

#include "../../include/lota_envelope.h"
#include "../../include/lota_seal.h"
#include "../../include/lota_tpm_nv.h"
#include "profile.h"
#include "quote.h"
#include "tpm.h"
#include "attestation.h"
#include "lota.h"

/* pcrSelect[i / 8] stays within the three-byte selection only below 24. */
_Static_assert(LOTA_PCR_COUNT <= 24,
	       "PCR selection bitmap holds 24 bits (3 bytes)");

#define HASH_READ_BUF_SIZE (64 * 1024)

static int tpm_get_prop(struct tpm_context *ctx, TPM2_PT prop,
			uint32_t *out_val);
static int tpm_aik_load_auth(struct tpm_context *ctx);
static int tpm_aik_save_auth(struct tpm_context *ctx,
			     const uint8_t auth[TPM_AIK_AUTH_SIZE]);
static int tpm_aik_save_auth_plaintext(struct tpm_context *ctx,
				       const uint8_t auth[TPM_AIK_AUTH_SIZE]);
static int tpm_aik_load_auth_plaintext(struct tpm_context *ctx);
static int tpm_aik_save_auth_sealed(struct tpm_context *ctx,
				    const uint8_t auth[TPM_AIK_AUTH_SIZE]);
static int tpm_aik_load_auth_sealed(struct tpm_context *ctx);
static int tpm_aik_auth_record_exists(struct tpm_context *ctx);
static int tpm_object_name(struct tpm_context *ctx, ESYS_TR object,
			   uint8_t *out, size_t out_max, uint16_t *out_len);
static void tpm_aik_report_auth_load_failure(struct tpm_context *ctx,
					     int load_rc);
static int tpm_aik_generate_auth(uint8_t auth[TPM_AIK_AUTH_SIZE]);
static int tpm_aik_reprovision_with_auth(struct tpm_context *ctx,
					 int had_existing_aik);
static int mkdirs(const char *path, mode_t mode);
static int tpm_aik_save_new_key_metadata(struct tpm_context *ctx);
static int aik_exists(struct tpm_context *ctx, ESYS_TR *handle_out);

/*
 * ESYS caches object metadata, Name included, per TPM handle number. A handle
 * left open keeps a stale Name, and once the object is replaced an open of that
 * number fails. Detach when the operation ends.
 *
 * Esys_EvictControl returns ESYS_TR_NONE after removing an object; closing that
 * makes the TSS print an error on stderr.
 */
static void tpm_tr_close(struct tpm_context *ctx, ESYS_TR *handle)
{
	if (!ctx || !ctx->esys_ctx || !handle || *handle == ESYS_TR_NONE)
		return;

	Esys_TR_Close(ctx->esys_ctx, handle);
}

static void secure_bzero(void *ptr, size_t len)
{
	if (!ptr || len == 0)
		return;
	OPENSSL_cleanse(ptr, len);
}

typedef int (*tpm_prop_reader_fn)(struct tpm_context *ctx, TPM2_PT prop,
				  uint32_t *out_val);
static tpm_prop_reader_fn g_tpm_prop_reader = tpm_get_prop;

static int tpm_read_prop(struct tpm_context *ctx, TPM2_PT prop,
			 uint32_t *out_val)
{
	return g_tpm_prop_reader(ctx, prop, out_val);
}

#define TPM_RC_LAYER_MASK 0x00FF0000U
#define TPM_RC_CODE_MASK 0x0000FFFFU
#define TPM_RC_FMT1_BIT 0x080U
#define TPM_RC_FMT1_BASE_MASK 0x0BFU /* bits 0-5 + FMT1 indicator */

/*
 * TPM_RETRY_BUDGET_MS bounds the total sleep of one retrying call,
 * which keeps it to a slice of the WatchdogSec= window.
 */
#define TPM_RETRY_MAX_ATTEMPTS 6U
#define TPM_RETRY_BASE_MS 25U
#define TPM_RETRY_CAP_MS 4000U
#define TPM_RETRY_BUDGET_MS 2000U

static bool tpm_rc_layer_is_tpm(TSS2_RC rc)
{
	uint32_t layer = rc & TPM_RC_LAYER_MASK;
	return layer == 0U || layer == TSS2_RESMGR_TPM_RC_LAYER;
}

static TSS2_RC tpm_rc_decode(TSS2_RC rc)
{
	TSS2_RC code = rc & TPM_RC_CODE_MASK;
	if (code & TPM_RC_FMT1_BIT)
		return code & TPM_RC_FMT1_BASE_MASK;
	return code;
}

static bool tss2_rc_is_lockout(TSS2_RC rc)
{
	if (!tpm_rc_layer_is_tpm(rc))
		return false;
	return tpm_rc_decode(rc) == TPM2_RC_LOCKOUT;
}

/*
 * ESYS reports a Name mismatch only as TSS2_ESYS_RC_GENERAL_FAILURE.
 * The code is broad, so the caller only reconnects once.
 */
static bool tss2_rc_is_stale_object_record(TSS2_RC rc)
{
	return rc == TSS2_ESYS_RC_GENERAL_FAILURE;
}

static bool tss2_rc_is_transient(TSS2_RC rc)
{
	if (rc == (TSS2_RC)TSS2_TCTI_RC_TRY_AGAIN)
		return true;

	if (!tpm_rc_layer_is_tpm(rc))
		return false;

	switch (tpm_rc_decode(rc)) {
	case TPM2_RC_RETRY:
	case TPM2_RC_YIELDED:
	case TPM2_RC_TESTING:
	case TPM2_RC_NV_RATE:
	case TPM2_RC_NV_UNAVAILABLE:
	case TPM2_RC_SESSION_MEMORY:
	case TPM2_RC_OBJECT_MEMORY:
	case TPM2_RC_MEMORY:
		return true;
	default:
		return false;
	}
}

static int tss2_rc_to_errno(TSS2_RC rc)
{
	if (rc == TSS2_RC_SUCCESS)
		return 0;

	switch (rc) {
	case TSS2_TCTI_RC_NO_CONNECTION:
	case TSS2_TCTI_RC_IO_ERROR:
		return -ENODEV;
	case TSS2_TCTI_RC_TRY_AGAIN:
		return -EAGAIN;
	case TSS2_ESYS_RC_BAD_REFERENCE:
		return -EINVAL;
	case TSS2_ESYS_RC_MEMORY:
		return -ENOMEM;
	default:
		break;
	}

	if (!tpm_rc_layer_is_tpm(rc))
		return -EIO;

	switch (tpm_rc_decode(rc)) {
	case TPM2_RC_LOCKOUT:
		return -LOTA_ERR_TPM_LOCKED;
	case TPM2_RC_RETRY:
	case TPM2_RC_YIELDED:
	case TPM2_RC_TESTING:
	case TPM2_RC_NV_RATE:
	case TPM2_RC_NV_UNAVAILABLE:
	case TPM2_RC_SESSION_MEMORY:
	case TPM2_RC_OBJECT_MEMORY:
	case TPM2_RC_MEMORY:
		return -EAGAIN;
	case TPM2_RC_HANDLE:
	case TPM2_RC_REFERENCE_H0:
		return -ENOENT;
	case TPM2_RC_AUTH_FAIL:
	case TPM2_RC_BAD_AUTH:
	case TPM2_RC_NV_AUTHORIZATION:
		return -LOTA_ERR_TPM_AUTH_FAIL;
	case TPM2_RC_VALUE:
	case TPM2_RC_SIZE:
		return -EINVAL;
	case TPM2_RC_NV_SPACE:
		return -ENOSPC;
	case TPM2_RC_POLICY_FAIL:
	case TPM2_RC_PCR_CHANGED:
		return -LOTA_ERR_TPM_POLICY_FAIL;
	default:
		return -EIO;
	}
}

static unsigned tpm_backoff_ms(unsigned attempt)
{
	unsigned ms = TPM_RETRY_BASE_MS << (attempt > 7 ? 7 : attempt);
	if (ms > TPM_RETRY_CAP_MS)
		ms = TPM_RETRY_CAP_MS;
	return ms;
}

static void tpm_sleep_ms(unsigned ms)
{
	struct timespec ts;
	ts.tv_sec = ms / 1000;
	ts.tv_nsec = (long)(ms % 1000) * 1000000L;

	while (nanosleep(&ts, &ts) == -1 && errno == EINTR)
		;
}

static void tpm_record_lockout(struct tpm_context *ctx)
{
	if (!ctx)
		return;

	ctx->lockout_event_count++;
	if (!ctx->lockout_active) {
		ctx->lockout_active = true;
		ctx->lockout_first_seen = time(NULL);
	}
}

/*
 * A call that needs no DA-protected authorization succeeds in lockout, so ask
 * the TPM before clearing. The flag is down during the read, which goes
 * through tpm_call_with_backoff() and so back here.
 */
static void tpm_clear_lockout(struct tpm_context *ctx)
{
	uint32_t perm = 0;

	if (!ctx || !ctx->lockout_active)
		return;

	ctx->lockout_active = false;
	if (tpm_read_prop(ctx, TPM2_PT_PERMANENT, &perm) != 0 ||
	    (perm & TPMA_PERMANENT_INLOCKOUT)) {
		ctx->lockout_active = true;
		return;
	}
	ctx->lockout_first_seen = 0;
}

/*
 * For Esys_* calls with no heap-allocated outputs. Calls that allocate use
 * tpm_call_with_backoff(), which frees the previous allocation before a retry.
 */
#define TPM_CALL_RETRY(ctx_, rc_var_, expr_)                          \
	do {                                                          \
		unsigned _tpm_attempt = 0;                            \
		unsigned _tpm_budget_ms = 0;                          \
		for (;;) {                                            \
			(rc_var_) = (expr_);                          \
			if ((rc_var_) == TSS2_RC_SUCCESS) {           \
				tpm_clear_lockout((ctx_));            \
				break;                                \
			}                                             \
			if (tss2_rc_is_lockout((rc_var_))) {          \
				tpm_record_lockout((ctx_));           \
				break;                                \
			}                                             \
			if (!tss2_rc_is_transient((rc_var_)) ||       \
			    _tpm_attempt >= TPM_RETRY_MAX_ATTEMPTS)   \
				break;                                \
			{                                             \
				unsigned _tpm_next_ms =               \
					tpm_backoff_ms(_tpm_attempt); \
				if (_tpm_budget_ms + _tpm_next_ms >   \
				    TPM_RETRY_BUDGET_MS)              \
					break;                        \
				tpm_sleep_ms(_tpm_next_ms);           \
				_tpm_budget_ms += _tpm_next_ms;       \
			}                                             \
			_tpm_attempt++;                               \
		}                                                     \
	} while (0)

#define LOTA_TPM_MAX_OUT_SLOTS 8U

typedef TSS2_RC (*tpm_esys_thunk)(void *userdata);

/*
 * Retry an Esys_* call that allocates outputs.
 *
 * @out_rc is optional and receives the last TSS2_RC. @slots holds up to
 * LOTA_TPM_MAX_OUT_SLOTS pointers, each at a variable @thunk fills. A non-NULL
 * variable is freed with Esys_Free() and reset to NULL before every attempt,
 * so a retry does not leak the previous allocation.
 *
 * Return: 0, the tss2_rc_to_errno() mapping of the last RC, or -EINVAL when
 * @thunk is NULL or there are too many slots.
 */
static int tpm_call_with_backoff_array(struct tpm_context *ctx,
				       tpm_esys_thunk thunk, void *userdata,
				       TSS2_RC *out_rc, void **slots[],
				       size_t out_slot_count)
{
	TSS2_RC rc = TSS2_RC_SUCCESS;
	unsigned attempt = 0;
	unsigned budget_used_ms = 0;
	size_t i;

	if (!thunk || out_slot_count > LOTA_TPM_MAX_OUT_SLOTS) {
		if (out_rc)
			*out_rc = TSS2_BASE_RC_BAD_REFERENCE;
		return -EINVAL;
	}

	for (;;) {
		for (i = 0; i < out_slot_count; i++) {
			if (slots[i] && *slots[i]) {
				Esys_Free(*slots[i]);
				*slots[i] = NULL;
			}
		}

		rc = thunk(userdata);

		if (rc == TSS2_RC_SUCCESS) {
			tpm_clear_lockout(ctx);
			break;
		}
		if (tss2_rc_is_lockout(rc)) {
			tpm_record_lockout(ctx);
			break;
		}
		if (!tss2_rc_is_transient(rc) ||
		    attempt >= TPM_RETRY_MAX_ATTEMPTS)
			break;

		unsigned next_ms = tpm_backoff_ms(attempt);
		if (budget_used_ms + next_ms > TPM_RETRY_BUDGET_MS)
			break;
		tpm_sleep_ms(next_ms);
		budget_used_ms += next_ms;
		attempt++;
	}

	if (out_rc)
		*out_rc = rc;
	return rc == TSS2_RC_SUCCESS ? 0 : tss2_rc_to_errno(rc);
}

static int tpm_call_with_backoff(struct tpm_context *ctx, tpm_esys_thunk thunk,
				 void *userdata, TSS2_RC *out_rc,
				 size_t out_slot_count, ...)
{
	void **slots[LOTA_TPM_MAX_OUT_SLOTS];
	size_t i;
	va_list ap;

	if (out_slot_count > LOTA_TPM_MAX_OUT_SLOTS) {
		if (out_rc)
			*out_rc = TSS2_BASE_RC_BAD_REFERENCE;
		return -EINVAL;
	}

	va_start(ap, out_slot_count);
	for (i = 0; i < out_slot_count; i++)
		slots[i] = va_arg(ap, void **);
	va_end(ap);

	return tpm_call_with_backoff_array(ctx, thunk, userdata, out_rc, slots,
					   out_slot_count);
}

struct esys_pcr_read_args {
	ESYS_CONTEXT *esys_ctx;
	const TPML_PCR_SELECTION *pcr_selection_in;
	UINT32 *pcr_update_counter_out;
	TPML_PCR_SELECTION **pcr_selection_out;
	TPML_DIGEST **pcr_values_out;
};

static TSS2_RC esys_pcr_read_thunk(void *u)
{
	struct esys_pcr_read_args *a = u;
	return Esys_PCR_Read(a->esys_ctx, ESYS_TR_NONE, ESYS_TR_NONE,
			     ESYS_TR_NONE, a->pcr_selection_in,
			     a->pcr_update_counter_out, a->pcr_selection_out,
			     a->pcr_values_out);
}

struct esys_create_primary_args {
	ESYS_CONTEXT *esys_ctx;
	ESYS_TR primary_handle;
	ESYS_TR shandle1;
	const TPM2B_SENSITIVE_CREATE *in_sensitive;
	const TPM2B_PUBLIC *in_public;
	const TPM2B_DATA *outside_info;
	const TPML_PCR_SELECTION *creation_pcr;
	ESYS_TR *object_handle_out;
	TPM2B_PUBLIC **out_public_out;
	TPM2B_CREATION_DATA **creation_data_out;
	TPM2B_DIGEST **creation_hash_out;
	TPMT_TK_CREATION **creation_ticket_out;
};

static TSS2_RC esys_create_primary_thunk(void *u)
{
	struct esys_create_primary_args *a = u;
	return Esys_CreatePrimary(a->esys_ctx, a->primary_handle, a->shandle1,
				  ESYS_TR_NONE, ESYS_TR_NONE, a->in_sensitive,
				  a->in_public, a->outside_info,
				  a->creation_pcr, a->object_handle_out,
				  a->out_public_out, a->creation_data_out,
				  a->creation_hash_out, a->creation_ticket_out);
}

struct esys_quote_args {
	ESYS_CONTEXT *esys_ctx;
	ESYS_TR sign_handle;
	ESYS_TR shandle1;
	const TPM2B_DATA *qualifying_data;
	const TPMT_SIG_SCHEME *in_scheme;
	const TPML_PCR_SELECTION *pcr_selection;
	TPM2B_ATTEST **quoted_out;
	TPMT_SIGNATURE **signature_out;
};

static TSS2_RC esys_quote_thunk(void *u)
{
	struct esys_quote_args *a = u;
	return Esys_Quote(a->esys_ctx, a->sign_handle, a->shandle1,
			  ESYS_TR_NONE, ESYS_TR_NONE, a->qualifying_data,
			  a->in_scheme, a->pcr_selection, a->quoted_out,
			  a->signature_out);
}

struct esys_read_clock_args {
	ESYS_CONTEXT *esys_ctx;
	TPMS_TIME_INFO **time_info_out;
};

static TSS2_RC esys_read_clock_thunk(void *u)
{
	struct esys_read_clock_args *a = u;
	return Esys_ReadClock(a->esys_ctx, ESYS_TR_NONE, ESYS_TR_NONE,
			      ESYS_TR_NONE, a->time_info_out);
}

struct esys_read_public_args {
	ESYS_CONTEXT *esys_ctx;
	ESYS_TR object_handle;
	TPM2B_PUBLIC **out_public_out;
	TPM2B_NAME **name_out;
	TPM2B_NAME **qualified_name_out;
};

static TSS2_RC esys_read_public_thunk(void *u)
{
	struct esys_read_public_args *a = u;
	return Esys_ReadPublic(a->esys_ctx, a->object_handle, ESYS_TR_NONE,
			       ESYS_TR_NONE, ESYS_TR_NONE, a->out_public_out,
			       a->name_out, a->qualified_name_out);
}

struct esys_get_capability_args {
	ESYS_CONTEXT *esys_ctx;
	TPM2_CAP capability;
	UINT32 property;
	UINT32 property_count;
	TPMI_YES_NO *more_data_out;
	TPMS_CAPABILITY_DATA **capability_data_out;
};

static TSS2_RC esys_get_capability_thunk(void *u)
{
	struct esys_get_capability_args *a = u;
	return Esys_GetCapability(a->esys_ctx, ESYS_TR_NONE, ESYS_TR_NONE,
				  ESYS_TR_NONE, a->capability, a->property,
				  a->property_count, a->more_data_out,
				  a->capability_data_out);
}

struct esys_nv_read_public_args {
	ESYS_CONTEXT *esys_ctx;
	ESYS_TR nv_index;
	TPM2B_NV_PUBLIC **nv_public_out;
	TPM2B_NAME **nv_name_out;
};

static TSS2_RC esys_nv_read_public_thunk(void *u)
{
	struct esys_nv_read_public_args *a = u;
	return Esys_NV_ReadPublic(a->esys_ctx, a->nv_index, ESYS_TR_NONE,
				  ESYS_TR_NONE, ESYS_TR_NONE, a->nv_public_out,
				  a->nv_name_out);
}

struct esys_nv_read_args {
	ESYS_CONTEXT *esys_ctx;
	ESYS_TR auth_handle;
	ESYS_TR nv_index;
	ESYS_TR shandle1;
	UINT16 size;
	UINT16 offset;
	TPM2B_MAX_NV_BUFFER **nv_data_out;
};

static TSS2_RC esys_nv_read_thunk(void *u)
{
	struct esys_nv_read_args *a = u;
	return Esys_NV_Read(a->esys_ctx, a->auth_handle, a->nv_index,
			    a->shandle1, ESYS_TR_NONE, ESYS_TR_NONE, a->size,
			    a->offset, a->nv_data_out);
}

bool tpm_is_locked_out(const struct tpm_context *ctx)
{
	return ctx && ctx->lockout_active;
}

void tpm_reset_lockout_state(struct tpm_context *ctx)
{
	if (!ctx)
		return;
	ctx->lockout_active = false;
	ctx->lockout_first_seen = 0;
}

#ifdef LOTA_TPM_TESTING
int tpm_test_rc_to_errno(uint32_t rc)
{
	return tss2_rc_to_errno((TSS2_RC)rc);
}
int tpm_test_rc_is_transient(uint32_t rc)
{
	return tss2_rc_is_transient((TSS2_RC)rc) ? 1 : 0;
}
int tpm_test_rc_is_lockout(uint32_t rc)
{
	return tss2_rc_is_lockout((TSS2_RC)rc) ? 1 : 0;
}

int tpm_test_call_with_backoff_array(struct tpm_context *ctx,
				     tpm_esys_thunk thunk, void *userdata,
				     uint32_t *out_rc, void **slots[],
				     size_t out_slot_count)
{
	TSS2_RC rc = TSS2_RC_SUCCESS;
	int ret = tpm_call_with_backoff_array(ctx, thunk, userdata, &rc, slots,
					      out_slot_count);
	if (out_rc)
		*out_rc = rc;
	return ret;
}
#endif

int tpm_init(struct tpm_context *ctx)
{
	TSS2_RC rc;
	size_t tcti_size;
	const char *tcti_conf;
	const char *aik_meta_path;

	if (!ctx)
		return -EINVAL;

	if (ctx->initialized || ctx->esys_ctx || ctx->tcti_ctx)
		tpm_cleanup(ctx);

	ctx->esys_ctx = NULL;
	ctx->tcti_ctx = NULL;
	ctx->tcti_from_loader = false;
	ctx->initialized = false;
	memset(&ctx->aik_meta, 0, sizeof(ctx->aik_meta));
	ctx->aik_meta_loaded = false;
	memset(ctx->aik_auth, 0, sizeof(ctx->aik_auth));
	ctx->aik_auth_loaded = false;
	memset(ctx->aik_object_name, 0, sizeof(ctx->aik_object_name));
	ctx->aik_object_name_size = 0;
	ctx->aik_object_replaced = false;
	memset(ctx->prev_aik_public, 0, sizeof(ctx->prev_aik_public));
	ctx->prev_aik_public_size = 0;
	ctx->grace_deadline = 0;
	ctx->lockout_active = false;
	ctx->lockout_first_seen = 0;
	ctx->lockout_event_count = 0;
	memset(ctx->self_hash, 0, sizeof(ctx->self_hash));
	ctx->self_hash_ready = false;
	ctx->boot_commitment_locked = false;

	/*
	 * Developer and demo overrides. The persistent daemon leaves
	 * allow_env_tpm_overrides false, so its environment cannot
	 * redirect the AIK key store or the TPM endpoint.
	 */
	aik_meta_path = ctx->allow_env_tpm_overrides ?
				getenv("LOTA_AIK_META_PATH") :
				NULL;
	ctx->aik_meta_path_from_env = false;
	if (aik_meta_path && aik_meta_path[0]) {
		if (aik_meta_path[0] != '/')
			return -EINVAL;
		if (strstr(aik_meta_path, ".."))
			return -EINVAL;
		for (const char *p = aik_meta_path; *p; p++) {
			char c = *p;
			bool ok = (c >= 'A' && c <= 'Z') ||
				  (c >= 'a' && c <= 'z') ||
				  (c >= '0' && c <= '9') || c == '/' ||
				  c == '.' || c == '_' || c == '-';
			if (!ok)
				return -EINVAL;
		}
		if (snprintf(ctx->aik_meta_path, sizeof(ctx->aik_meta_path),
			     "%s",
			     aik_meta_path) >= (int)sizeof(ctx->aik_meta_path))
			return -ENAMETOOLONG;
		ctx->aik_meta_path_from_env = true;
	}

	tcti_conf = ctx->allow_env_tpm_overrides ? getenv("LOTA_TCTI") : NULL;
	if (tcti_conf && tcti_conf[0]) {
		rc = Tss2_TctiLdr_Initialize(tcti_conf, &ctx->tcti_ctx);
		if (rc != TSS2_RC_SUCCESS)
			return tss2_rc_to_errno(rc);
		ctx->tcti_from_loader = true;
	} else {
		rc = Tss2_Tcti_Device_Init(NULL, &tcti_size, TPM_DEVICE_PATH);
		if (rc != TSS2_RC_SUCCESS)
			return tss2_rc_to_errno(rc);

		ctx->tcti_ctx = calloc(1, tcti_size);
		if (!ctx->tcti_ctx)
			return -ENOMEM;

		rc = Tss2_Tcti_Device_Init(ctx->tcti_ctx, &tcti_size,
					   TPM_DEVICE_PATH);
		if (rc != TSS2_RC_SUCCESS) {
			free(ctx->tcti_ctx);
			ctx->tcti_ctx = NULL;
			return tss2_rc_to_errno(rc);
		}
	}

	rc = Esys_Initialize(&ctx->esys_ctx, ctx->tcti_ctx, NULL);
	if (rc != TSS2_RC_SUCCESS) {
		if (ctx->tcti_from_loader) {
			Tss2_TctiLdr_Finalize(&ctx->tcti_ctx);
		} else {
			Tss2_Tcti_Finalize(ctx->tcti_ctx);
			free(ctx->tcti_ctx);
		}
		ctx->tcti_ctx = NULL;
		ctx->tcti_from_loader = false;
		return tss2_rc_to_errno(rc);
	}

	ctx->initialized = true;

	if (!ctx->aik_handle)
		ctx->aik_handle = TPM_AIK_HANDLE;

	return 0;
}

void tpm_cleanup(struct tpm_context *ctx)
{
	if (!ctx)
		return;

	if (ctx->esys_ctx) {
		Esys_Finalize(&ctx->esys_ctx);
		ctx->esys_ctx = NULL;
	}

	if (ctx->tcti_ctx) {
		if (ctx->tcti_from_loader) {
			Tss2_TctiLdr_Finalize(&ctx->tcti_ctx);
		} else {
			Tss2_Tcti_Finalize(ctx->tcti_ctx);
			free(ctx->tcti_ctx);
		}
		ctx->tcti_ctx = NULL;
	}
	ctx->tcti_from_loader = false;

	memset(ctx->aik_auth, 0, sizeof(ctx->aik_auth));
	ctx->aik_auth_loaded = false;
	memset(ctx->aik_object_name, 0, sizeof(ctx->aik_object_name));
	ctx->aik_object_name_size = 0;
	ctx->aik_object_replaced = false;

	memset(ctx->self_hash, 0, sizeof(ctx->self_hash));
	ctx->self_hash_ready = false;
	ctx->boot_commitment_locked = false;

	ctx->initialized = false;
}

int tpm_get_self_hash(const struct tpm_context *ctx, uint8_t out[])
{
	if (!ctx || !out)
		return -EINVAL;
	if (!ctx->self_hash_ready)
		return -ENODATA;
	memcpy(out, ctx->self_hash, LOTA_HASH_SIZE);
	return 0;
}

int tpm_self_test(struct tpm_context *ctx)
{
	TSS2_RC rc;

	if (!ctx || !ctx->initialized)
		return -EINVAL;

	TPM_CALL_RETRY(ctx, rc,
		       Esys_SelfTest(ctx->esys_ctx, ESYS_TR_NONE, ESYS_TR_NONE,
				     ESYS_TR_NONE, TPM2_YES));

	return tss2_rc_to_errno(rc);
}

int tpm_read_pcr(struct tpm_context *ctx, uint32_t pcr_index,
		 TPM2_ALG_ID hash_alg, uint8_t *value)
{
	TSS2_RC rc;
	TPML_PCR_SELECTION pcr_selection;
	TPML_DIGEST *pcr_values = NULL;
	uint32_t pcr_update_counter;
	TPML_PCR_SELECTION *pcr_selection_out = NULL;

	if (!ctx || !ctx->initialized || !value)
		return -EINVAL;

	if (pcr_index >= LOTA_PCR_COUNT)
		return -EINVAL;

	memset(&pcr_selection, 0, sizeof(pcr_selection));
	pcr_selection.count = 1;
	pcr_selection.pcrSelections[0].hash = hash_alg;
	pcr_selection.pcrSelections[0].sizeofSelect = 3; /* 24 PCRs = 3 bytes */

	pcr_selection.pcrSelections[0].pcrSelect[pcr_index / 8] =
		(1 << (pcr_index % 8));

	{
		struct esys_pcr_read_args args = {
			.esys_ctx = ctx->esys_ctx,
			.pcr_selection_in = &pcr_selection,
			.pcr_update_counter_out = &pcr_update_counter,
			.pcr_selection_out = &pcr_selection_out,
			.pcr_values_out = &pcr_values,
		};
		int call_ret = tpm_call_with_backoff(
			ctx, esys_pcr_read_thunk, &args, &rc, 2,
			(void **)&pcr_selection_out, (void **)&pcr_values);
		if (call_ret < 0)
			return call_ret;
	}

	if (!pcr_values || pcr_values->count == 0) {
		Esys_Free(pcr_values);
		Esys_Free(pcr_selection_out);
		return -ENODATA;
	}

	if (pcr_values->digests[0].size != LOTA_HASH_SIZE) {
		Esys_Free(pcr_values);
		Esys_Free(pcr_selection_out);
		return -EIO;
	}
	memcpy(value, pcr_values->digests[0].buffer, LOTA_HASH_SIZE);

	Esys_Free(pcr_values);
	Esys_Free(pcr_selection_out);

	return 0;
}

int tpm_read_pcrs_batch(struct tpm_context *ctx, uint32_t pcr_mask,
			uint8_t values[LOTA_PCR_COUNT][LOTA_HASH_SIZE])
{
	TSS2_RC rc;
	TPML_PCR_SELECTION pcr_selection;
	TPML_DIGEST *pcr_values = NULL;
	uint32_t pcr_update_counter;
	TPML_PCR_SELECTION *pcr_selection_out = NULL;
	uint32_t digest_idx = 0;
	uint32_t i;

	if (!ctx || !values)
		return -EINVAL;

	memset(values, 0, LOTA_PCR_COUNT * LOTA_HASH_SIZE);

	if (pcr_mask == 0)
		return 0;

	memset(&pcr_selection, 0, sizeof(pcr_selection));
	pcr_selection.count = 1;
	pcr_selection.pcrSelections[0].hash = TPM_HASH_ALG;
	pcr_selection.pcrSelections[0].sizeofSelect = 3; /* 24 PCRs = 3 bytes */

	pcr_selection.pcrSelections[0].pcrSelect[0] =
		(uint8_t)(pcr_mask & 0xFF);
	pcr_selection.pcrSelections[0].pcrSelect[1] =
		(uint8_t)((pcr_mask >> 8) & 0xFF);
	pcr_selection.pcrSelections[0].pcrSelect[2] =
		(uint8_t)((pcr_mask >> 16) & 0xFF);

	{
		struct esys_pcr_read_args args = {
			.esys_ctx = ctx->esys_ctx,
			.pcr_selection_in = &pcr_selection,
			.pcr_update_counter_out = &pcr_update_counter,
			.pcr_selection_out = &pcr_selection_out,
			.pcr_values_out = &pcr_values,
		};
		int call_ret = tpm_call_with_backoff(
			ctx, esys_pcr_read_thunk, &args, &rc, 2,
			(void **)&pcr_selection_out, (void **)&pcr_values);
		if (call_ret < 0)
			return call_ret;
	}

	if (!pcr_values || !pcr_selection_out ||
	    pcr_selection_out->count == 0) {
		Esys_Free(pcr_values);
		Esys_Free(pcr_selection_out);
		return -ENODATA;
	}

	for (i = 0; i < LOTA_PCR_COUNT; i++) {
		uint8_t sel =
			pcr_selection_out->pcrSelections[0].pcrSelect[i / 8];
		if (!(sel & (1U << (i % 8))))
			continue;

		if (digest_idx >= pcr_values->count) {
			Esys_Free(pcr_values);
			Esys_Free(pcr_selection_out);
			return -EIO;
		}

		if (pcr_values->digests[digest_idx].size != LOTA_HASH_SIZE) {
			Esys_Free(pcr_values);
			Esys_Free(pcr_selection_out);
			return -EIO;
		}
		memcpy(values[i], pcr_values->digests[digest_idx].buffer,
		       LOTA_HASH_SIZE);
		digest_idx++;
	}

	Esys_Free(pcr_values);
	Esys_Free(pcr_selection_out);

	return 0;
}

/*
 * Check whether the TPM holds an object at a handle: a persistent key or an NV
 * index. Asking first keeps an optional read quiet: the TSS2 library prints the
 * error of a failed Esys call at whoever ran the command.
 *
 * Returns: 1 if it exists, 0 if not, negative errno on error
 */
static int tpm_handle_in_use(struct tpm_context *ctx, uint32_t handle)
{
	TPMS_CAPABILITY_DATA *capability_data = NULL;
	TPMI_YES_NO more_data = TPM2_NO;
	int found = 0;
	TSS2_RC rc;
	int ret;

	{
		struct esys_get_capability_args args = {
			.esys_ctx = ctx->esys_ctx,
			.capability = TPM2_CAP_HANDLES,
			.property = handle,
			.property_count = 1,
			.more_data_out = &more_data,
			.capability_data_out = &capability_data,
		};
		ret = tpm_call_with_backoff(ctx, esys_get_capability_thunk,
					    &args, &rc, 1,
					    (void **)&capability_data);
		if (ret < 0)
			return ret;
	}

	if (!capability_data ||
	    capability_data->capability != TPM2_CAP_HANDLES) {
		Esys_Free(capability_data);
		return -EIO;
	}

	for (uint32_t i = 0; i < capability_data->data.handles.count; i++) {
		if (capability_data->data.handles.handle[i] == handle) {
			found = 1;
			break;
		}
	}
	Esys_Free(capability_data);
	return found;
}

static int tpm_read_property(struct tpm_context *ctx, TPM2_PT property,
			     uint32_t *out)
{
	TPMS_CAPABILITY_DATA *capability_data = NULL;
	TPMI_YES_NO more_data = TPM2_NO;
	TSS2_RC rc;
	int ret;

	{
		struct esys_get_capability_args args = {
			.esys_ctx = ctx->esys_ctx,
			.capability = TPM2_CAP_TPM_PROPERTIES,
			.property = property,
			.property_count = 1,
			.more_data_out = &more_data,
			.capability_data_out = &capability_data,
		};
		ret = tpm_call_with_backoff(ctx, esys_get_capability_thunk,
					    &args, &rc, 1,
					    (void **)&capability_data);
		if (ret < 0)
			return ret;
	}

	if (!capability_data ||
	    capability_data->capability != TPM2_CAP_TPM_PROPERTIES ||
	    capability_data->data.tpmProperties.count < 1 ||
	    capability_data->data.tpmProperties.tpmProperty[0].property !=
		    property) {
		Esys_Free(capability_data);
		return -ENOTSUP;
	}

	*out = capability_data->data.tpmProperties.tpmProperty[0].value;
	Esys_Free(capability_data);
	return 0;
}

int tpm_handle_holds_object(struct tpm_context *ctx, uint32_t handle)
{
	if (!ctx || !ctx->esys_ctx || !ctx->initialized || handle == 0)
		return -EINVAL;

	return tpm_handle_in_use(ctx, handle);
}

int tpm_persistent_slots(struct tpm_context *ctx, uint32_t *used,
			 uint32_t *total)
{
	uint32_t in_use = 0;
	uint32_t available = 0;
	int ret;

	if (!ctx || !ctx->esys_ctx || !ctx->initialized || !used || !total)
		return -EINVAL;

	ret = tpm_read_property(ctx, TPM2_PT_HR_PERSISTENT, &in_use);
	if (ret < 0)
		return ret;

	ret = tpm_read_property(ctx, TPM2_PT_HR_PERSISTENT_AVAIL, &available);
	if (ret < 0)
		return ret;

	*used = in_use;
	*total = in_use + available;
	return 0;
}

static void tpm_forget_bound_aik(struct tpm_context *ctx)
{
	memset(&ctx->aik_meta, 0, sizeof(ctx->aik_meta));
	ctx->aik_meta_loaded = false;
	secure_bzero(ctx->aik_auth, sizeof(ctx->aik_auth));
	ctx->aik_auth_loaded = false;
	memset(ctx->aik_object_name, 0, sizeof(ctx->aik_object_name));
	ctx->aik_object_name_size = 0;
}

/* Nothing seen yet is not a change: the first look records the Name. */
static bool aik_object_changed(const uint8_t *seen, uint16_t seen_len,
			       const uint8_t *live, uint16_t live_len)
{
	if (seen_len == 0 || live_len == 0)
		return false;

	if (seen_len != live_len)
		return true;

	return memcmp(seen, live, seen_len) != 0;
}

/*
 * The handle alone is not an identity: --forget-publisher frees a number
 * and the next publisher provisioned can reuse it.
 */
static bool aik_binding_survives(const char *bound_id, uint32_t bound_handle,
				 const char *new_id, uint32_t new_handle)
{
	if (!bound_id || !new_id)
		return false;

	if (bound_handle != new_handle)
		return false;

	return strcmp(bound_id, new_id) == 0;
}

/*
 * Drop everything cached for the key when the object at the AIK handle differs
 * from the Name recorded here. The rotation record and the userAuth belong to
 * one key; a replaced object leaves them describing a key the TPM no longer
 * holds.
 */
static void aik_note_object(struct tpm_context *ctx, ESYS_TR object)
{
	TPM2B_NAME *name = NULL;

	if (Esys_TR_GetName(ctx->esys_ctx, object, &name) != TSS2_RC_SUCCESS)
		return;
	if (!name)
		return;
	if (name->size > sizeof(ctx->aik_object_name)) {
		Esys_Free(name);
		return;
	}

	if (aik_object_changed(ctx->aik_object_name, ctx->aik_object_name_size,
			       name->name, name->size)) {
		tpm_forget_bound_aik(ctx);
		ctx->aik_object_replaced = true;
	}

	memcpy(ctx->aik_object_name, name->name, name->size);
	ctx->aik_object_name_size = name->size;
	Esys_Free(name);
}

/*
 * Only the ESYS object cache goes stale: keep the TCTI and replace the session.
 * The rest of the context (self-measurement, PCR 14 verdict, profile binding)
 * survives.
 */
static int tpm_esys_reconnect(struct tpm_context *ctx)
{
	TSS2_RC rc;

	if (!ctx || !ctx->initialized || !ctx->esys_ctx || !ctx->tcti_ctx)
		return -EINVAL;

	Esys_Finalize(&ctx->esys_ctx);
	rc = Esys_Initialize(&ctx->esys_ctx, ctx->tcti_ctx, NULL);
	if (rc != TSS2_RC_SUCCESS) {
		ctx->esys_ctx = NULL;
		ctx->initialized = false;
		return tss2_rc_to_errno(rc);
	}

	tpm_forget_bound_aik(ctx);
	return 0;
}

bool tpm_aik_object_replaced(struct tpm_context *ctx)
{
	bool replaced;

	if (!ctx)
		return false;

	replaced = ctx->aik_object_replaced;
	ctx->aik_object_replaced = false;
	return replaced;
}

bool tpm_aik_key_is_shared(const struct tpm_context *ctx)
{
	if (!ctx || !ctx->aik_profile_id[0] || !ctx->aik_meta_loaded)
		return false;

	return ctx->aik_meta.key_derivation !=
	       TPM_AIK_KEY_DERIVATION_PER_PUBLISHER;
}

int tpm_aik_key_present(struct tpm_context *ctx)
{
	int ret;

	if (!ctx || !ctx->initialized)
		return -EINVAL;

	if (!ctx->esys_ctx)
		return 0;

	ret = aik_exists(ctx, NULL);
	if (ret < 0)
		return ret;

	return ret == 1 ? 1 : 0;
}

bool tpm_aik_replacing_shared_key(const struct tpm_context *ctx,
				  int key_present)
{
	if (key_present != 1)
		return false;

	return tpm_aik_key_is_shared(ctx);
}

bool tpm_aik_provisioning_orphans_cert(int key_present, bool cert_stored,
				       int cert_match)
{
	/*
	 * Negative: the TPM could not answer, which does not show a lost key.
	 */
	if (key_present != 0)
		return false;

	if (!cert_stored)
		return false;

	return cert_match == -EKEYREJECTED;
}

void tpm_aik_allow_shared_key_replace(struct tpm_context *ctx, bool allow)
{
	if (ctx)
		ctx->aik_allow_shared_key_replace = allow;
}

int tpm_aik_profile_unique(const char *profile_id, uint8_t out[LOTA_HASH_SIZE],
			   uint16_t *out_len)
{
	if (!out || !out_len)
		return -EINVAL;

	memset(out, 0, LOTA_HASH_SIZE);
	*out_len = 0;

	if (!profile_id || !profile_id[0])
		return 0;

	if (strlen(profile_id) != LOTA_PROFILE_ID_LEN - 1)
		return -EINVAL;

	for (size_t i = 0; i < LOTA_HASH_SIZE; i++) {
		unsigned int byte;

		if (sscanf(profile_id + i * 2, "%2x", &byte) != 1) {
			memset(out, 0, LOTA_HASH_SIZE);
			return -EINVAL;
		}
		out[i] = (uint8_t)byte;
	}

	*out_len = LOTA_HASH_SIZE;
	return 0;
}

int tpm_bind_profile(struct tpm_context *ctx, const struct profile_paths *paths)
{
	uint32_t candidates[TPM_AIK_PROFILE_HANDLE_COUNT];
	char previous_meta_path[sizeof(ctx->aik_meta_path)];
	char previous_profile_id[sizeof(ctx->aik_profile_id)];
	uint32_t previous_handle;
	size_t candidate_count = 0;
	uint32_t handle = 0;
	int ret;

	if (!ctx || !ctx->initialized || !paths || !paths->aik_meta[0])
		return -EINVAL;

	previous_handle = ctx->aik_handle;
	snprintf(previous_profile_id, sizeof(previous_profile_id), "%s",
		 ctx->aik_profile_id);
	snprintf(previous_meta_path, sizeof(previous_meta_path), "%s",
		 ctx->aik_meta_path);
	snprintf(ctx->aik_profile_id, sizeof(ctx->aik_profile_id), "%s",
		 paths->id);

	if (!ctx->aik_meta_path_from_env) {
		if (strlen(paths->aik_meta) >= sizeof(ctx->aik_meta_path)) {
			ret = -ENAMETOOLONG;
			goto restore;
		}
		snprintf(ctx->aik_meta_path, sizeof(ctx->aik_meta_path), "%s",
			 paths->aik_meta);
		if (strcmp(previous_meta_path, ctx->aik_meta_path) != 0)
			tpm_forget_bound_aik(ctx);
	}

	ret = profile_aik_handle_load(paths, &handle);
	if (ret == 0) {
		if (!aik_binding_survives(previous_profile_id, previous_handle,
					  paths->id, handle))
			tpm_forget_bound_aik(ctx);
		ctx->aik_handle = handle;
		return 0;
	}
	if (ret != -ENOENT)
		goto restore;

	/*
	 * Skip handles the TPM already holds: an unrecorded object is somebody
	 * else's or a wiped profile's, and evicting it is not this agent's
	 * call.
	 */
	ret = profile_aik_handle_candidates(
		LOTA_PROFILE_BASE_DIR, TPM_AIK_PROFILE_HANDLE_BASE,
		TPM_AIK_PROFILE_HANDLE_COUNT, candidates,
		sizeof(candidates) / sizeof(candidates[0]), &candidate_count);
	if (ret < 0)
		goto restore;

	for (size_t i = 0; i < candidate_count; i++) {
		ret = tpm_handle_in_use(ctx, candidates[i]);
		if (ret < 0)
			goto restore;
		if (ret == 1)
			continue;

		ret = profile_aik_handle_save(paths, candidates[i]);
		if (ret < 0)
			goto restore;
		if (!aik_binding_survives(previous_profile_id, previous_handle,
					  paths->id, candidates[i]))
			tpm_forget_bound_aik(ctx);
		ctx->aik_handle = candidates[i];
		return 0;
	}

	ret = -ENOSPC;

restore:
	/*
	 * A caller that survives a failed bind must not write this publisher's
	 * metadata under the previous publisher's handle.
	 */
	snprintf(ctx->aik_meta_path, sizeof(ctx->aik_meta_path), "%s",
		 previous_meta_path);
	ctx->aik_handle = previous_handle;
	tpm_forget_bound_aik(ctx);
	return ret;
}

static int aik_exists(struct tpm_context *ctx, ESYS_TR *handle_out)
{
	TSS2_RC rc;
	TPMS_CAPABILITY_DATA *capability_data = NULL;
	TPMI_YES_NO more_data = TPM2_NO;
	ESYS_TR key_handle = ESYS_TR_NONE;
	int found = 0;
	int ret;

	{
		struct esys_get_capability_args args = {
			.esys_ctx = ctx->esys_ctx,
			.capability = TPM2_CAP_HANDLES,
			.property = ctx->aik_handle,
			.property_count = 1,
			.more_data_out = &more_data,
			.capability_data_out = &capability_data,
		};
		ret = tpm_call_with_backoff(ctx, esys_get_capability_thunk,
					    &args, &rc, 1,
					    (void **)&capability_data);
		if (ret < 0)
			return ret;
	}

	if (!capability_data ||
	    capability_data->capability != TPM2_CAP_HANDLES) {
		Esys_Free(capability_data);
		return -EIO;
	}

	for (uint32_t i = 0; i < capability_data->data.handles.count; i++) {
		if (capability_data->data.handles.handle[i] ==
		    ctx->aik_handle) {
			found = 1;
			break;
		}
	}
	Esys_Free(capability_data);

	if (!found)
		return 0;

	if (!handle_out)
		return 1;

	TPM_CALL_RETRY(ctx, rc,
		       Esys_TR_FromTPMPublic(ctx->esys_ctx, ctx->aik_handle,
					     ESYS_TR_NONE, ESYS_TR_NONE,
					     ESYS_TR_NONE, &key_handle));
	if (rc == TSS2_RC_SUCCESS) {
		aik_note_object(ctx, key_handle);
		if (handle_out)
			*handle_out = key_handle;
		return 1;
	}

	if (tpm_rc_layer_is_tpm(rc) && tpm_rc_decode(rc) == TPM2_RC_HANDLE)
		return 0;

	/*
	 * A session that holds a record of an object this handle no longer
	 * carries fails the open while the TPM accepts it: reopen the session
	 * once and ask again.
	 */
	if (tss2_rc_is_stale_object_record(rc)) {
		ret = tpm_esys_reconnect(ctx);
		if (ret < 0)
			return ret;

		TPM_CALL_RETRY(
			ctx, rc,
			Esys_TR_FromTPMPublic(ctx->esys_ctx, ctx->aik_handle,
					      ESYS_TR_NONE, ESYS_TR_NONE,
					      ESYS_TR_NONE, &key_handle));
		if (rc == TSS2_RC_SUCCESS) {
			aik_note_object(ctx, key_handle);
			*handle_out = key_handle;
			return 1;
		}
	}

	return tss2_rc_to_errno(rc);
}

/* The caller persists or flushes the transient handle it gets back. */
static int create_aik_primary(struct tpm_context *ctx, ESYS_TR *out_handle,
			      const uint8_t aik_auth[TPM_AIK_AUTH_SIZE])
{
	TSS2_RC rc;
	TPM2B_PUBLIC *out_public = NULL;
	TPM2B_CREATION_DATA *creation_data = NULL;
	TPM2B_DIGEST *creation_hash = NULL;
	TPMT_TK_CREATION *creation_ticket = NULL;

	TPM2B_PUBLIC in_public = {
	    .size = 0,
	    .publicArea =
		{
		    .type = TPM2_ALG_RSA,
		    .nameAlg = TPM2_ALG_SHA256,
		    .objectAttributes =
			(TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT |
			 TPMA_OBJECT_SENSITIVEDATAORIGIN |
			 TPMA_OBJECT_USERWITHAUTH | TPMA_OBJECT_RESTRICTED |
			 TPMA_OBJECT_SIGN_ENCRYPT),
		    .authPolicy = {.size = 0},
		    .parameters.rsaDetail =
			{
			    .symmetric = {.algorithm = TPM2_ALG_NULL},
			    .scheme =
				{
				    .scheme = TPM2_ALG_RSASSA,
				    .details.rsassa.hashAlg = TPM2_ALG_SHA256,
				},
			    .keyBits = 2048,
			    .exponent = 0, /* default: 65537 */
			},
		    .unique.rsa = {.size = 0},
		},
	};

	TPM2B_SENSITIVE_CREATE in_sensitive = {
	    .size = 0,
	    .sensitive =
		{
		    .userAuth = {.size = TPM_AIK_AUTH_SIZE},
		    .data = {.size = 0},
		},
	};
	uint8_t unique[LOTA_HASH_SIZE];
	uint16_t unique_len = 0;
	int unique_ret;

	if (!aik_auth)
		return -EINVAL;

	/*
	 * TPM2_CreatePrimary derives the key from the hierarchy seed and the
	 * template; userAuth is not part of that, so without this every
	 * publisher's certificate carries the same public key.
	 */
	unique_ret = tpm_aik_profile_unique(ctx->aik_profile_id, unique,
					    &unique_len);
	if (unique_ret < 0)
		return unique_ret;
	if (unique_len > 0) {
		in_public.publicArea.unique.rsa.size = unique_len;
		memcpy(in_public.publicArea.unique.rsa.buffer, unique,
		       unique_len);
	}

	memcpy(in_sensitive.sensitive.userAuth.buffer, aik_auth,
	       TPM_AIK_AUTH_SIZE);

	TPM2B_DATA outside_info = { .size = 0 };
	TPML_PCR_SELECTION creation_pcr = { .count = 0 };

	{
		struct esys_create_primary_args args = {
			.esys_ctx = ctx->esys_ctx,
			.primary_handle = ESYS_TR_RH_OWNER,
			.shandle1 = ESYS_TR_PASSWORD,
			.in_sensitive = &in_sensitive,
			.in_public = &in_public,
			.outside_info = &outside_info,
			.creation_pcr = &creation_pcr,
			.object_handle_out = out_handle,
			.out_public_out = &out_public,
			.creation_data_out = &creation_data,
			.creation_hash_out = &creation_hash,
			.creation_ticket_out = &creation_ticket,
		};
		int call_ret = tpm_call_with_backoff(
			ctx, esys_create_primary_thunk, &args, &rc, 4,
			(void **)&out_public, (void **)&creation_data,
			(void **)&creation_hash, (void **)&creation_ticket);
		Esys_Free(out_public);
		Esys_Free(creation_data);
		Esys_Free(creation_hash);
		Esys_Free(creation_ticket);
		if (call_ret < 0)
			return call_ret;
	}

	return 0;
}

static void tpm_prop_u32_to_ascii(uint32_t prop, char out[4])
{
	out[0] = (char)((prop >> 24) & 0xFF);
	out[1] = (char)((prop >> 16) & 0xFF);
	out[2] = (char)((prop >> 8) & 0xFF);
	out[3] = (char)(prop & 0xFF);
}

static int tpm_verify_device_identity(struct tpm_context *ctx)
{
	uint32_t manufacturer = 0;
	uint32_t fw1 = 0;
	uint32_t fw2 = 0;
	uint32_t vendor_parts[4] = { 0 };
	char vendor[17] = { 0 };
	char vendor_upper[17] = { 0 };
	int ret;

	ret = tpm_read_prop(ctx, TPM2_PT_MANUFACTURER, &manufacturer);
	if (ret < 0)
		return ret;

	ret = tpm_read_prop(ctx, TPM2_PT_FIRMWARE_VERSION_1, &fw1);
	if (ret < 0)
		return ret;

	ret = tpm_read_prop(ctx, TPM2_PT_FIRMWARE_VERSION_2, &fw2);
	if (ret < 0)
		return ret;

	if (manufacturer == 0 || (fw1 == 0 && fw2 == 0))
		return -EACCES;

	ret = tpm_read_prop(ctx, TPM2_PT_VENDOR_STRING_1, &vendor_parts[0]);
	if (ret < 0)
		return ret;
	ret = tpm_read_prop(ctx, TPM2_PT_VENDOR_STRING_2, &vendor_parts[1]);
	if (ret < 0)
		return ret;
	ret = tpm_read_prop(ctx, TPM2_PT_VENDOR_STRING_3, &vendor_parts[2]);
	if (ret < 0)
		return ret;
	ret = tpm_read_prop(ctx, TPM2_PT_VENDOR_STRING_4, &vendor_parts[3]);
	if (ret < 0)
		return ret;

	for (int i = 0; i < 4; i++)
		tpm_prop_u32_to_ascii(vendor_parts[i], vendor + (i * 4));

	for (int i = 0; i < 16; i++) {
		char c = vendor[i];
		if (c >= 'a' && c <= 'z')
			c = (char)(c - ('a' - 'A'));
		vendor_upper[i] = c;
	}

	if (strstr(vendor_upper, "SWTPM") || strstr(vendor_upper, "SW TPM") ||
	    strstr(vendor_upper, "SIMULATOR") || strstr(vendor_upper, "QEMU")) {
		return -EACCES;
	}

	return 0;
}

#ifdef LOTA_TPM_TESTING
void tpm_test_set_prop_reader(tpm_test_prop_reader_fn reader)
{
	g_tpm_prop_reader = reader ? reader : tpm_get_prop;
}

void tpm_test_reset_prop_reader(void)
{
	g_tpm_prop_reader = tpm_get_prop;
}
#endif

static int tpm_aik_save_new_key_metadata(struct tpm_context *ctx)
{
	time_t now;

	if (!ctx || !ctx->initialized)
		return -EINVAL;

	now = time(NULL);

	if (!ctx->aik_meta_loaded) {
		memset(&ctx->aik_meta, 0, sizeof(ctx->aik_meta));
		ctx->aik_meta.magic = TPM_AIK_META_MAGIC;
		ctx->aik_meta.version = TPM_AIK_META_VERSION;
		ctx->aik_meta.generation = 1;
		ctx->aik_meta.last_rotated_at = 0;
	} else if (ctx->aik_meta.magic != TPM_AIK_META_MAGIC ||
		   ctx->aik_meta.version != TPM_AIK_META_VERSION) {
		return -EINVAL;
	} else if (ctx->aik_meta.generation == 0) {
		ctx->aik_meta.generation = 1;
	}

	ctx->aik_meta.provisioned_at = (int64_t)now;
	ctx->aik_meta.key_derivation =
		ctx->aik_profile_id[0] ? TPM_AIK_KEY_DERIVATION_PER_PUBLISHER :
					 TPM_AIK_KEY_DERIVATION_SHARED;
	ctx->aik_meta_loaded = true;

	return tpm_aik_save_metadata(ctx);
}

#ifdef LOTA_TPM_TESTING
int tpm_test_save_new_key_metadata(struct tpm_context *ctx)
{
	return tpm_aik_save_new_key_metadata(ctx);
}
#endif

int tpm_provision_aik(struct tpm_context *ctx)
{
	int ret;

	if (!ctx || !ctx->initialized)
		return -EINVAL;

	ret = tpm_verify_device_identity(ctx);
	if (ret < 0)
		return ret;

	ret = aik_exists(ctx, NULL);
	if (ret < 0)
		return ret;

	if (ret == 1) {
		int load_rc = tpm_aik_load_auth(ctx);
		if (load_rc == 0) {
			/*
			 * Replacing a shared key invalidates the certificate
			 * that names it.
			 */
			if (tpm_aik_key_is_shared(ctx)) {
				if (!ctx->aik_allow_shared_key_replace)
					return -ENOTSUP;

				ret = tpm_aik_reprovision_with_auth(ctx, 1);
				if (ret < 0)
					return ret;
				return tpm_aik_save_new_key_metadata(ctx);
			}
			return 0;
		}

		/*
		 * Rotate only when no record exists. A record that fails to
		 * load may belong to a working key, and replacing that key
		 * orphans its certificate.
		 */
		if (tpm_aik_load_failure_blocks_reprovision(load_rc) ||
		    tpm_aik_auth_record_exists(ctx) == 1) {
			tpm_aik_report_auth_load_failure(ctx, load_rc);
			return load_rc;
		}

		ret = tpm_aik_reprovision_with_auth(ctx, 1);
		if (ret < 0)
			return ret;

		return tpm_aik_save_new_key_metadata(ctx);
	}

	ret = tpm_aik_reprovision_with_auth(ctx, 0);
	if (ret < 0)
		return ret;

	return tpm_aik_save_new_key_metadata(ctx);
}

/*
 * A loaded record keeps its generation: a bump marks the certificate
 * over the key stale.
 */
static int tpm_aik_save_auth_rotation_metadata(struct tpm_context *ctx)
{
	if (!ctx || !ctx->initialized)
		return -EINVAL;

	if (!ctx->aik_meta_loaded)
		return tpm_aik_save_new_key_metadata(ctx);
	if (ctx->aik_meta.magic != TPM_AIK_META_MAGIC ||
	    ctx->aik_meta.version != TPM_AIK_META_VERSION)
		return -EINVAL;

	return tpm_aik_save_metadata(ctx);
}

int tpm_reprovision_aik(struct tpm_context *ctx, bool *out_key_changed)
{
	uint8_t before[sizeof(((TPM2B_NAME *)0)->name)];
	uint8_t after[sizeof(before)];
	uint16_t before_len = 0;
	uint16_t after_len = 0;
	ESYS_TR key_handle = ESYS_TR_NONE;
	bool key_changed = true;
	bool had_name = false;
	int had;
	int ret;

	if (!ctx || !ctx->initialized)
		return -EINVAL;

	if (out_key_changed)
		*out_key_changed = false;

	had = aik_exists(ctx, &key_handle);
	if (had < 0)
		return had;
	if (had == 1) {
		ret = tpm_object_name(ctx, key_handle, before, sizeof(before),
				      &before_len);
		tpm_tr_close(ctx, &key_handle);
		if (ret < 0)
			return ret;
		had_name = true;
	}

	ret = tpm_aik_reprovision_with_auth(ctx, had == 1 ? 1 : 0);
	if (ret < 0)
		return ret;

	/* same seed and template give the same key: compare Names */
	if (had_name) {
		key_handle = ESYS_TR_NONE;
		ret = aik_exists(ctx, &key_handle);
		if (ret < 0)
			return ret;
		if (ret == 1) {
			ret = tpm_object_name(ctx, key_handle, after,
					      sizeof(after), &after_len);
			tpm_tr_close(ctx, &key_handle);
			if (ret < 0)
				return ret;
			key_changed = before_len != after_len ||
				      memcmp(before, after, before_len) != 0;
		}
	}

	if (out_key_changed)
		*out_key_changed = key_changed;

	if (key_changed)
		return tpm_aik_save_new_key_metadata(ctx);

	return tpm_aik_save_auth_rotation_metadata(ctx);
}

int tpm_quote(struct tpm_context *ctx, const uint8_t *nonce, uint32_t pcr_mask,
	      struct tpm_quote_response *response)
{
	TSS2_RC rc;
	int ret;
	ESYS_TR key_handle = ESYS_TR_NONE;
	TPM2B_DATA qualifying_data;
	TPMT_SIG_SCHEME in_scheme;
	TPML_PCR_SELECTION pcr_selection;
	TPM2B_ATTEST *quoted = NULL;
	TPMT_SIGNATURE *signature = NULL;
	uint32_t i;

	if (!ctx || !ctx->initialized || !nonce || !response)
		return -EINVAL;

	memset(response, 0, sizeof(*response));

	ret = aik_exists(ctx, &key_handle);
	if (ret < 0)
		return ret;
	if (ret == 0)
		return -ENOKEY;

	if (!ctx->aik_auth_loaded) {
		ret = tpm_aik_load_auth(ctx);
		if (ret < 0)
			goto out;
	}

	{
		TPM2B_AUTH auth_value = { .size = TPM_AIK_AUTH_SIZE };
		memcpy(auth_value.buffer, ctx->aik_auth, TPM_AIK_AUTH_SIZE);
		TPM_CALL_RETRY(ctx, rc,
			       Esys_TR_SetAuth(ctx->esys_ctx, key_handle,
					       &auth_value));
		secure_bzero(auth_value.buffer, sizeof(auth_value.buffer));
		if (rc != TSS2_RC_SUCCESS) {
			ret = tss2_rc_to_errno(rc);
			goto out;
		}
	}

	response->pcr_mask = pcr_mask;
	response->hash_alg = TPM2_ALG_NULL;

	ret = tpm_read_pcrs_batch(ctx, pcr_mask, response->pcr_values);
	if (ret < 0)
		goto out;

	qualifying_data.size = LOTA_NONCE_SIZE;
	memcpy(qualifying_data.buffer, nonce, LOTA_NONCE_SIZE);

	in_scheme.scheme = TPM2_ALG_NULL;

	memset(&pcr_selection, 0, sizeof(pcr_selection));
	pcr_selection.count = 1;
	pcr_selection.pcrSelections[0].hash = TPM_HASH_ALG;
	pcr_selection.pcrSelections[0].sizeofSelect = 3;

	for (i = 0; i < LOTA_PCR_COUNT; i++) {
		if (pcr_mask & (1U << i))
			pcr_selection.pcrSelections[0].pcrSelect[i / 8] |=
				(1 << (i % 8));
	}

	{
		struct esys_quote_args args = {
			.esys_ctx = ctx->esys_ctx,
			.sign_handle = key_handle,
			.shandle1 = ESYS_TR_PASSWORD,
			.qualifying_data = &qualifying_data,
			.in_scheme = &in_scheme,
			.pcr_selection = &pcr_selection,
			.quoted_out = &quoted,
			.signature_out = &signature,
		};
		int call_ret = tpm_call_with_backoff(ctx, esys_quote_thunk,
						     &args, &rc, 2,
						     (void **)&quoted,
						     (void **)&signature);
		secure_bzero(qualifying_data.buffer,
			     sizeof(qualifying_data.buffer));
		if (call_ret < 0) {
			ret = call_ret;
			goto out;
		}
	}

	if (quoted->size > LOTA_MAX_ATTEST_SIZE) {
		ret = -ENOSPC;
		goto out;
	}
	memcpy(response->attest_data, quoted->attestationData, quoted->size);
	response->attest_size = quoted->size;
	response->sig_alg = signature->sigAlg;

	if (signature->sigAlg == TPM2_ALG_RSASSA) {
		size_t sig_size = signature->signature.rsassa.sig.size;
		response->hash_alg = signature->signature.rsassa.hash;
		if (sig_size > LOTA_MAX_SIG_SIZE) {
			ret = -ENOSPC;
			goto out;
		}
		memcpy(response->signature,
		       signature->signature.rsassa.sig.buffer, sig_size);
		response->signature_size = (uint16_t)sig_size;
	} else if (signature->sigAlg == TPM2_ALG_RSAPSS) {
		size_t sig_size = signature->signature.rsapss.sig.size;
		response->hash_alg = signature->signature.rsapss.hash;
		if (sig_size > LOTA_MAX_SIG_SIZE) {
			ret = -ENOSPC;
			goto out;
		}
		memcpy(response->signature,
		       signature->signature.rsapss.sig.buffer, sig_size);
		response->signature_size = (uint16_t)sig_size;
	} else {
		ret = -ENOTSUP;
		goto out;
	}

	ret = 0;

out:
	if (quoted) {
		secure_bzero(quoted->attestationData,
			     sizeof(quoted->attestationData));
		Esys_Free(quoted);
	}
	if (signature) {
		secure_bzero(signature, sizeof(*signature));
		Esys_Free(signature);
	}
	tpm_tr_close(ctx, &key_handle);
	return ret;
}

int tpm_hash_fd(int fd, uint8_t *hash)
{
	ssize_t n;
	EVP_MD_CTX *md_ctx;
	uint8_t *buf;
	unsigned int hash_len;
	int ret = 0;
	struct stat st;
	uint64_t remaining;

	if (fd < 0 || !hash)
		return -EINVAL;

	if (fstat(fd, &st) != 0)
		return -errno;

	if (!S_ISREG(st.st_mode))
		return -EINVAL;

	if (st.st_size < 0)
		return -EIO;

	remaining = (uint64_t)st.st_size;

	buf = malloc(HASH_READ_BUF_SIZE);
	if (!buf)
		return -ENOMEM;

	md_ctx = EVP_MD_CTX_new();
	if (!md_ctx) {
		free(buf);
		return -ENOMEM;
	}

	if (EVP_DigestInit_ex(md_ctx, EVP_sha256(), NULL) != 1) {
		ret = -EIO;
		goto cleanup;
	}

	while (remaining > 0) {
		size_t to_read = HASH_READ_BUF_SIZE;
		if (remaining < to_read)
			to_read = (size_t)remaining;

		n = read(fd, buf, to_read);
		if (n > 0) {
			if (EVP_DigestUpdate(md_ctx, buf, (size_t)n) != 1) {
				ret = -EIO;
				goto cleanup;
			}
			remaining -= (uint64_t)n;
			continue;
		}

		if (n == 0) {
			ret = -EIO;
			goto cleanup;
		}

		if (errno == EINTR)
			continue;

		ret = -errno;
		goto cleanup;
	}

	{
		uint8_t probe;
		n = read(fd, &probe, 1);
		if (n > 0) {
			ret = -EIO;
			goto cleanup;
		}
		if (n < 0 && errno != EINTR) {
			ret = -errno;
			goto cleanup;
		}
	}

	if (EVP_DigestFinal_ex(md_ctx, hash, &hash_len) != 1) {
		ret = -EIO;
		goto cleanup;
	}

cleanup:
	EVP_MD_CTX_free(md_ctx);
	free(buf);

	return ret;
}

int tpm_hash_file(const char *path, uint8_t *hash)
{
	int fd;
	int ret;
	struct stat st;

	if (!path || !hash)
		return -EINVAL;

	fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
	if (fd < 0)
		return -errno;

	if (fstat(fd, &st) != 0) {
		ret = -errno;
		close(fd);
		return ret;
	}

	if (!S_ISREG(st.st_mode)) {
		close(fd);
		return -EINVAL;
	}

	ret = tpm_hash_fd(fd, hash);
	close(fd);

	return ret;
}

int tpm_set_kernel_path(struct tpm_context *ctx, const char *path)
{
	size_t len;

	if (!ctx)
		return -EINVAL;

	if (!path || !path[0]) {
		ctx->kernel_path_override[0] = '\0';
		return 0;
	}

	if (path[0] != '/')
		return -EINVAL;

	len = strlen(path);
	if (len >= sizeof(ctx->kernel_path_override))
		return -ENAMETOOLONG;

	memcpy(ctx->kernel_path_override, path, len + 1);
	return 0;
}

bool tpm_kernel_path_is_overridden(const struct tpm_context *ctx)
{
	return ctx && ctx->kernel_path_override[0] != '\0';
}

int tpm_get_current_kernel_path(struct tpm_context *ctx, char *buf,
				size_t buf_len)
{
	struct utsname uname_buf;
	int ret;

	if (!ctx || !buf || buf_len == 0)
		return -EINVAL;

	if (ctx->kernel_path_override[0]) {
		ret = snprintf(buf, buf_len, "%s", ctx->kernel_path_override);
		if (ret < 0 || (size_t)ret >= buf_len)
			return -ENAMETOOLONG;

		if (access(buf, R_OK) != 0)
			return -errno;

		return 0;
	}

	ret = uname(&uname_buf);
	if (ret < 0)
		return -errno;

	ret = snprintf(buf, buf_len, "/boot/vmlinuz-%s", uname_buf.release);
	if (ret < 0 || (size_t)ret >= buf_len)
		return -ENAMETOOLONG;

	if (access(buf, R_OK) != 0)
		return -errno;

	return 0;
}

int tpm_pcr_extend(struct tpm_context *ctx, uint32_t pcr_index,
		   const uint8_t *digest)
{
	TSS2_RC rc;
	ESYS_TR pcr_handle;
	TPML_DIGEST_VALUES digests;

	if (!ctx || !ctx->initialized || !digest)
		return -EINVAL;

	if (pcr_index >= LOTA_PCR_COUNT)
		return -EINVAL;

	pcr_handle = ESYS_TR_PCR0 + pcr_index;

	memset(&digests, 0, sizeof(digests));
	digests.count = 1;
	digests.digests[0].hashAlg = TPM_HASH_ALG;
	memcpy(digests.digests[0].digest.sha256, digest, LOTA_HASH_SIZE);

	TPM_CALL_RETRY(ctx, rc,
		       Esys_PCR_Extend(ctx->esys_ctx, pcr_handle,
				       ESYS_TR_PASSWORD, ESYS_TR_NONE,
				       ESYS_TR_NONE, &digests));
	if (rc != TSS2_RC_SUCCESS)
		return tss2_rc_to_errno(rc);

	return 0;
}

#define TPM_BOOT_COMMITMENT_TAG "LOTA-PCR14-BOOT-COMMITMENT-v1"

/*
 * Mirrors src/initramfs/lota-pcr14-lock.c and
 * src/verifier/verify/baseline.go::initramfsLockTag. Change all three together,
 * or the verifier refuses a freshly locked host.
 */
#define TPM_INITRAMFS_LOCK_TAG "LOTA-PCR14-INITRAMFS-LOCK-v1"

/* Mirrors LOTA_PCR_SELF in agent.h, which this file does not include. */
#define TPM_BOOT_COMMITMENT_PCR 14

enum tpm_boot_commitment_outcome
tpm_boot_commitment_outcome(enum tpm_pcr14_state state)
{
	if (state == TPM_PCR14_ALREADY_COMMITTED)
		return TPM_BOOT_COMMITMENT_ALREADY_HELD;
	return TPM_BOOT_COMMITMENT_EXTENDED;
}

int tpm_boot_commitment_digest(const uint8_t self_hash[], uint8_t out_digest[])
{
	if (!self_hash || !out_digest)
		return -EINVAL;

	EVP_MD_CTX *md = EVP_MD_CTX_new();
	if (!md)
		return -ENOMEM;

	int ok = EVP_DigestInit_ex(md, EVP_sha256(), NULL) == 1 &&
		 EVP_DigestUpdate(md, TPM_BOOT_COMMITMENT_TAG,
				  sizeof(TPM_BOOT_COMMITMENT_TAG) - 1) == 1 &&
		 EVP_DigestUpdate(md, self_hash, LOTA_HASH_SIZE) == 1 &&
		 EVP_DigestFinal_ex(md, out_digest, NULL) == 1;
	EVP_MD_CTX_free(md);

	if (!ok)
		return -EIO;
	return 0;
}

int tpm_initramfs_lock_digest(uint8_t out_digest[])
{
	if (!out_digest)
		return -EINVAL;

	EVP_MD_CTX *md = EVP_MD_CTX_new();
	if (!md)
		return -ENOMEM;

	int ok = EVP_DigestInit_ex(md, EVP_sha256(), NULL) == 1 &&
		 EVP_DigestUpdate(md, TPM_INITRAMFS_LOCK_TAG,
				  sizeof(TPM_INITRAMFS_LOCK_TAG) - 1) == 1 &&
		 EVP_DigestFinal_ex(md, out_digest, NULL) == 1;
	EVP_MD_CTX_free(md);
	return ok ? 0 : -EIO;
}

int tpm_clock_state_load(const struct tpm_context *ctx,
			 struct lota_clock_state *out)
{
	if (!ctx || !out)
		return -EINVAL;

	const char *path = ctx->clock_state_path[0] ? ctx->clock_state_path :
						      TPM_CLOCK_STATE_PATH;

	int fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		if (errno == ENOENT)
			return -ENOENT;
		return -errno;
	}

	struct lota_clock_state wire;
	ssize_t n = read(fd, &wire, sizeof(wire));
	int saved_errno = errno;
	close(fd);

	if (n < 0)
		return -saved_errno;
	if ((size_t)n != sizeof(wire))
		return -EINVAL;

	uint32_t magic = le32toh(wire.magic);
	uint32_t version = le32toh(wire.version);
	if (magic != TPM_CLOCK_STATE_MAGIC)
		return -EINVAL;
	if (version != TPM_CLOCK_STATE_VERSION)
		return -EINVAL;

	out->magic = magic;
	out->version = version;
	out->reset_count = le32toh(wire.reset_count);
	out->restart_count = le32toh(wire.restart_count);
	memcpy(out->pcr14, wire.pcr14, sizeof(out->pcr14));
	memcpy(out->self_hash, wire.self_hash, sizeof(out->self_hash));
	out->saved_at = (int64_t)le64toh((uint64_t)wire.saved_at);
	out->flags = wire.flags;
	memset(out->_reserved, 0, sizeof(out->_reserved));
	return 0;
}

int tpm_clock_state_save(const struct tpm_context *ctx,
			 const struct lota_clock_state *in)
{
	if (!ctx || !in)
		return -EINVAL;

	const char *path = ctx->clock_state_path[0] ? ctx->clock_state_path :
						      TPM_CLOCK_STATE_PATH;

	int ret = mkdirs(path, 0755);
	if (ret < 0)
		return ret;

	char tmp[PATH_MAX];
	int written = snprintf(tmp, sizeof(tmp), "%s.tmp.XXXXXX", path);
	if (written < 0 || (size_t)written >= sizeof(tmp))
		return -ENAMETOOLONG;

	int fd = mkstemp(tmp);
	if (fd < 0)
		return -errno;
	if (fchmod(fd, 0600) != 0) {
		ret = -errno;
		close(fd);
		unlink(tmp);
		return ret;
	}

	struct lota_clock_state wire;
	wire.magic = htole32(TPM_CLOCK_STATE_MAGIC);
	wire.version = htole32(TPM_CLOCK_STATE_VERSION);
	wire.reset_count = htole32(in->reset_count);
	wire.restart_count = htole32(in->restart_count);
	memcpy(wire.pcr14, in->pcr14, sizeof(wire.pcr14));
	memcpy(wire.self_hash, in->self_hash, sizeof(wire.self_hash));
	wire.saved_at = (int64_t)htole64((uint64_t)in->saved_at);
	wire.flags = in->flags;
	memset(wire._reserved, 0, sizeof(wire._reserved));

	ssize_t n = write(fd, &wire, sizeof(wire));
	if (n != (ssize_t)sizeof(wire)) {
		close(fd);
		unlink(tmp);
		return -EIO;
	}
	if (fsync(fd) != 0) {
		ret = -errno;
		close(fd);
		unlink(tmp);
		return ret;
	}
	close(fd);

	if (rename(tmp, path) != 0) {
		ret = -errno;
		unlink(tmp);
		return ret;
	}
	return 0;
}

static int sha256_two_block(const uint8_t block_a[LOTA_HASH_SIZE],
			    const uint8_t block_b[LOTA_HASH_SIZE],
			    uint8_t out[LOTA_HASH_SIZE])
{
	EVP_MD_CTX *md = EVP_MD_CTX_new();
	if (!md)
		return -ENOMEM;
	int ok = EVP_DigestInit_ex(md, EVP_sha256(), NULL) == 1 &&
		 EVP_DigestUpdate(md, block_a, LOTA_HASH_SIZE) == 1 &&
		 EVP_DigestUpdate(md, block_b, LOTA_HASH_SIZE) == 1 &&
		 EVP_DigestFinal_ex(md, out, NULL) == 1;
	EVP_MD_CTX_free(md);
	return ok ? 0 : -EIO;
}

#define UEFI_FIRMWARE_PATH "/sys/firmware/efi"

static bool firmware_is_uefi(const struct tpm_context *ctx)
{
	const char *path = (ctx && ctx->allow_env_tpm_overrides) ?
				   getenv("LOTA_UEFI_FIRMWARE_PATH") :
				   NULL;

	if (!path || !path[0])
		path = UEFI_FIRMWARE_PATH;

	return access(path, F_OK) == 0;
}

static void report_non_uefi(void)
{
	fprintf(stderr,
		"SECURITY: this host did not boot via UEFI (%s absent). "
		"LOTA requires UEFI measured boot: legacy BIOS/CSM "
		"measures neither the firmware and Secure Boot state "
		"the verifier pins nor the PCR14 baseline the boot "
		"commitment chains onto, so such a host cannot attest. "
		"Switch the firmware out of legacy/CSM mode and "
		"reinstall\n",
		UEFI_FIRMWARE_PATH);
}

int tpm_firmware_refuses_attestation(const struct tpm_context *ctx)
{
	if (firmware_is_uefi(ctx))
		return 0;

	report_non_uefi();
	return 1;
}

/*
 * Shim measures the MOK state into PCR14 before the initramfs runs, so the lock
 * helper records the value it saw at LOTA_PCR14_BASELINE_PATH on the /run tmpfs
 * and the agent anchors its derivations on it.
 *
 * @present, when given, receives whether a usable handoff was there: the
 * agent's evidence that the lock helper ran this boot. A short handoff counts
 * as absent.
 *
 * The baseline is not trust input: a tampered file makes the agent's own
 * derivations miss the real PCR14.
 *
 * Returns: 0 or negative errno; @out is zeroed when no usable handoff exists.
 */
static int read_pcr14_baseline(uint8_t out[LOTA_HASH_SIZE], int *present)
{
	memset(out, 0, LOTA_HASH_SIZE);
	if (present)
		*present = 0;

	int fd = open(LOTA_PCR14_BASELINE_PATH,
		      O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
	if (fd < 0) {
		if (errno == ENOENT)
			return 0;
		return -errno;
	}
	FILE *f = fdopen(fd, "rb");
	if (!f) {
		int err = -errno;
		close(fd);
		return err;
	}

	uint8_t buf[LOTA_HASH_SIZE];
	size_t n = fread(buf, 1, sizeof(buf), f);
	int read_err = ferror(f);
	fclose(f);

	if (read_err)
		return -EIO;
	if (n != LOTA_HASH_SIZE) {
		fprintf(stderr,
			"PCR14 boot-commitment: ignoring malformed baseline handoff "
			"(%zu bytes at %s)\n",
			n, LOTA_PCR14_BASELINE_PATH);
		memset(out, 0, LOTA_HASH_SIZE);
		return 0;
	}

	memcpy(out, buf, LOTA_HASH_SIZE);
	if (present)
		*present = 1;
	return 0;
}

/*
 * SHA-256(baseline || lock_commit): PCR14 after the lock helper and before the
 * agent's extend. Constant across boots for one baseline: nothing about this
 * boot enters it, which lets a verifier derive it from the event log alone.
 */
static int derive_lock_pcr14_value(const uint8_t baseline[LOTA_HASH_SIZE],
				   uint8_t out[LOTA_HASH_SIZE])
{
	uint8_t lock_commit[LOTA_HASH_SIZE];
	int ret = tpm_initramfs_lock_digest(lock_commit);
	if (ret < 0)
		return ret;
	return sha256_two_block(baseline, lock_commit, out);
}

int tpm_derive_locked_pcr14(const uint8_t self_hash[],
			    const uint8_t baseline[LOTA_HASH_SIZE],
			    uint8_t out[LOTA_HASH_SIZE])
{
	uint8_t lock_value[LOTA_HASH_SIZE];
	uint8_t boot_commit[LOTA_HASH_SIZE];
	int ret = derive_lock_pcr14_value(baseline, lock_value);
	if (ret < 0)
		return ret;
	ret = tpm_boot_commitment_digest(self_hash, boot_commit);
	if (ret < 0)
		return ret;
	return sha256_two_block(lock_value, boot_commit, out);
}

/*
 * Print resetCount and restartCount from TPM2_ReadClock, the pair an operator
 * can confirm with tpm2_readclock. A quote obfuscates clockInfo by an amount
 * unique to a signing key outside the endorsement hierarchy, which the AIK is.
 */
static void print_platform_clock(struct tpm_context *ctx, const char *prefix)
{
	TPMS_TIME_INFO *time_info = NULL;
	struct esys_read_clock_args args = {
		.esys_ctx = ctx->esys_ctx,
		.time_info_out = &time_info,
	};
	TSS2_RC rc;
	int ret;

	ret = tpm_call_with_backoff(ctx, esys_read_clock_thunk, &args, &rc, 1,
				    (void **)&time_info);
	if (ret < 0 || !time_info) {
		fprintf(stderr, "%s: unavailable (%s)\n", prefix,
			strerror(ret < 0 ? -ret : EIO));
		return;
	}

	fprintf(stderr, "%s: resetCount=%u restartCount=%u\n", prefix,
		(unsigned)time_info->clockInfo.resetCount,
		(unsigned)time_info->clockInfo.restartCount);
	Esys_Free(time_info);
}

/*
 * A failed save costs attribution on the next start, not this one,
 * so warn and carry on.
 */
static void save_commitment_snapshot(struct tpm_context *ctx,
				     const uint8_t pcr14[LOTA_HASH_SIZE],
				     const uint8_t self_hash[LOTA_HASH_SIZE],
				     uint32_t reset_count,
				     uint32_t restart_count)
{
	struct lota_clock_state snap = {
		.reset_count = reset_count,
		.restart_count = restart_count,
		.saved_at = (int64_t)time(NULL),
		.flags = LOTA_CLOCK_STATE_FLAG_INITRAMFS_LOCK,
	};
	int ret;

	memcpy(snap.pcr14, pcr14, LOTA_HASH_SIZE);
	memcpy(snap.self_hash, self_hash, LOTA_HASH_SIZE);

	ret = tpm_clock_state_save(ctx, &snap);
	if (ret < 0)
		fprintf(stderr,
			"PCR14 boot-commitment: clock-state save failed (%s); "
			"the next run will lose tamper attribution\n",
			tpm_strerror(ret));
}

enum tpm_pcr14_state tpm_classify_pcr14(const struct tpm_pcr14_observation *obs)
{
	if (!obs || !obs->current || !obs->baseline || !obs->lock_value ||
	    !obs->expected_locked || !obs->self_hash)
		return TPM_PCR14_UNATTRIBUTABLE;

	if (memcmp(obs->current, obs->lock_value, LOTA_HASH_SIZE) == 0)
		return TPM_PCR14_AWAITING_EXTEND;

	if (memcmp(obs->current, obs->expected_locked, LOTA_HASH_SIZE) == 0) {
		/*
		 * Normal for a restart within one boot and for a resume:
		 * the TPM restores PCRs across a deep suspend.
		 *
		 * After a hardware reset the helper leaves the lock value,
		 * so a commitment already present means something ran before
		 * the agent. Without a snapshot there is no earlier count to
		 * compare.
		 */
		if (obs->prev && obs->prev->reset_count < obs->reset_count)
			return TPM_PCR14_TAMPERED_BEFORE_START;
		return TPM_PCR14_ALREADY_COMMITTED;
	}

	if (memcmp(obs->current, obs->baseline, LOTA_HASH_SIZE) == 0)
		return TPM_PCR14_LOCK_MISSING;

	/*
	 * No lock ran this boot. On a shim host PCR14 holds the MOK measurement
	 * and the comparison above cannot see it: the baseline it needs is
	 * written by the helper that did not run.
	 *
	 * After both accepting branches, so this only chooses which refusal is
	 * reported.
	 */
	if (!obs->lock_ran)
		return TPM_PCR14_LOCK_MISSING;

	if (!obs->prev)
		return TPM_PCR14_UNATTRIBUTABLE;

	/*
	 * The agent poisons PCR14 on its way out of an operator-requested
	 * shutdown and records that it did.
	 */
	if ((obs->prev->flags & LOTA_CLOCK_STATE_FLAG_SHUTDOWN_POISON) &&
	    memcmp(obs->current, obs->prev->pcr14, LOTA_HASH_SIZE) == 0)
		return TPM_PCR14_SPENT_BY_SHUTDOWN;

	if (obs->prev->reset_count > obs->reset_count)
		return TPM_PCR14_STATE_ROLLBACK;

	if (obs->prev->reset_count < obs->reset_count)
		return TPM_PCR14_TAMPERED_BEFORE_START;

	if (memcmp(obs->current, obs->prev->pcr14, LOTA_HASH_SIZE) == 0) {
		if (memcmp(obs->prev->self_hash, obs->self_hash,
			   LOTA_HASH_SIZE) != 0)
			return TPM_PCR14_BINARY_CHANGED;
		return TPM_PCR14_HANDOFF_CHANGED;
	}

	return TPM_PCR14_MUTATED_IN_SESSION;
}

int tpm_extend_boot_commitment(struct tpm_context *ctx,
			       const uint8_t self_hash[])
{
	TSS2_RC rc;
	uint8_t commit[LOTA_HASH_SIZE];
	uint8_t current_pcr14[LOTA_HASH_SIZE];
	uint8_t lock_pcr14_value[LOTA_HASH_SIZE];
	uint8_t expected_locked_pcr14[LOTA_HASH_SIZE];
	uint32_t reset_count = 0;
	uint32_t restart_count = 0;
	int ret;

	if (!ctx || !ctx->initialized || !self_hash)
		return -EINVAL;

	/* bring-up already asked; this covers direct callers */
	if (!firmware_is_uefi(ctx)) {
		report_non_uefi();
		return -ENOTSUP;
	}

	ctx->boot_commitment_locked = false;

	/*
	 * From TPM2_ReadClock: a quote obfuscates clockInfo per signing key,
	 * so a snapshot written under one publisher's key would read as an
	 * attack to the next start under another's.
	 */
	{
		TPMS_TIME_INFO *time_info = NULL;
		struct esys_read_clock_args args = {
			.esys_ctx = ctx->esys_ctx,
			.time_info_out = &time_info,
		};
		int call_ret = tpm_call_with_backoff(ctx, esys_read_clock_thunk,
						     &args, &rc, 1,
						     (void **)&time_info);
		if (call_ret < 0)
			return call_ret;
		reset_count = time_info->clockInfo.resetCount;
		restart_count = time_info->clockInfo.restartCount;
		Esys_Free(time_info);
	}

	ret = tpm_boot_commitment_digest(self_hash, commit);
	if (ret < 0)
		return ret;

	uint8_t baseline[LOTA_HASH_SIZE];
	int lock_ran = 0;

	ret = read_pcr14_baseline(baseline, &lock_ran);
	if (ret < 0)
		return ret;

	ret = derive_lock_pcr14_value(baseline, lock_pcr14_value);
	if (ret < 0)
		return ret;
	ret = tpm_derive_locked_pcr14(self_hash, baseline,
				      expected_locked_pcr14);
	if (ret < 0)
		return ret;

	ret = tpm_read_pcr(ctx, TPM_BOOT_COMMITMENT_PCR, TPM_HASH_ALG,
			   current_pcr14);
	if (ret < 0)
		return ret;

	struct lota_clock_state prev = { 0 };
	int have_prev = 0;
	ret = tpm_clock_state_load(ctx, &prev);
	if (ret == 0)
		have_prev = 1;
	else if (ret != -ENOENT)
		fprintf(stderr,
			"PCR14 boot-commitment: clock-state load failed (%s); "
			"continuing without attribution\n",
			tpm_strerror(ret));

	struct tpm_pcr14_observation obs = {
		.current = current_pcr14,
		.baseline = baseline,
		.lock_value = lock_pcr14_value,
		.expected_locked = expected_locked_pcr14,
		.self_hash = self_hash,
		.reset_count = reset_count,
		.restart_count = restart_count,
		.prev = have_prev ? &prev : NULL,
		.lock_ran = lock_ran,
	};

	ctx->boot_commitment_state = tpm_classify_pcr14(&obs);

	switch (ctx->boot_commitment_state) {
	case TPM_PCR14_AWAITING_EXTEND:
		ret = tpm_pcr_extend(ctx, TPM_BOOT_COMMITMENT_PCR, commit);
		if (ret < 0)
			return ret;
		save_commitment_snapshot(ctx, expected_locked_pcr14, self_hash,
					 reset_count, restart_count);
		ctx->boot_commitment_locked = true;
		return 0;

	case TPM_PCR14_ALREADY_COMMITTED:
		save_commitment_snapshot(ctx, expected_locked_pcr14, self_hash,
					 reset_count, restart_count);
		ctx->boot_commitment_locked = true;
		return 0;

	case TPM_PCR14_SPENT_BY_SHUTDOWN:
		fprintf(stderr,
			"PCR14 was spent by a shutdown requested on this host "
			"(lota-agent --shutdown, or lota-install --pause). The "
			"boot commitment cannot be re-extended once it is "
			"poisoned, which is what makes a pause visible to every "
			"relying party. Reboot to attest again\n");
		return -EBADMSG;

	case TPM_PCR14_LOCK_MISSING:
		/*
		 * The verifier has no derivation for a commitment not chained
		 * onto the lock value, so extending here would produce a
		 * register nothing can validate.
		 */
		fprintf(stderr,
			"The initramfs lock helper did not run this boot, so "
			"PCR14 holds whatever the platform put there and no "
			"LOTA commitment. On a Secure Boot host that is shim's "
			"MOK measurement, which is why the register is not "
			"empty. Rebuild the initramfs of the kernel you booted "
			"(dracut -f --add lota, or dracut -f --regenerate-all "
			"for every installed kernel) and cold reboot; the boot "
			"commitment must chain onto the initramfs lock\n");
		return -EBADMSG;

	case TPM_PCR14_UNATTRIBUTABLE:
		fprintf(stderr,
			"SECURITY: PCR14 holds an unexpected value and no prior "
			"clock-state snapshot exists "
			"to attribute the cause. Possible explanations: "
			"(1) initramfs / boot loader extended PCR14 with a "
			"non-LOTA commitment; "
			"(2) local root extended PCR14 between cold boot and the "
			"agent reaching this code; "
			"(3) the clock-state file was deleted between runs. "
			"Cold reboot the host and consult systemd journal for "
			"tpm2_pcr_extend invocations before lota-agent's first "
			"quote\n");
		print_platform_clock(ctx, "PCR14 boot-commitment: TPM clock");
		return -EBADMSG;

	case TPM_PCR14_TAMPERED_BEFORE_START:
		fprintf(stderr,
			"SECURITY: PCR14 tampered between cold boot and agent "
			"start "
			"(resetCount advanced from %u to %u; last successful "
			"extend at %lld). A non-LOTA component extended PCR14 "
			"before lota-agent reached its self_measure() call. "
			"Cold reboot, then audit boot scripts and any tooling "
			"that touches /dev/tpmrm0 (tpm2-tools, IMA, integrity "
			"subsystem) and verify the udev rule labelling tpmrm0 "
			"with lota_tpm_device_t is loaded with SELinux enforcing\n",
			(unsigned)prev.reset_count, (unsigned)reset_count,
			(long long)prev.saved_at);
		return -EBADMSG;

	case TPM_PCR14_BINARY_CHANGED:
		fprintf(stderr, "SECURITY: PCR14 holds the boot commitment of "
				"a prior "
				"agent binary in this boot session; the "
				"agent binary has changed since that extend. "
				"PCR14 is "
				"non-resettable from userspace, so live "
				"upgrades cannot "
				"rebind it. Cold reboot to re-extend PCR14 "
				"against the "
				"current agent binary\n");
		print_platform_clock(ctx, "PCR14 boot-commitment: TPM clock");
		return -EBADMSG;

	case TPM_PCR14_HANDOFF_CHANGED:
		fprintf(stderr,
			"SECURITY: PCR14 holds exactly the value lota-agent "
			"recorded for this boot session and the agent binary is "
			"unchanged, but the boot commitment no longer derives "
			"from the baseline handoff at %s: that handoff is not "
			"the one this commitment was built on. The handoff is "
			"written once per boot by the initramfs helper "
			"(lota-pcr14-lock) and only read afterwards, so the "
			"likely cause is that it was replaced after the helper "
			"wrote it -- cold reboot to have the helper write it "
			"again, and check what has write access to /run/lota. "
			"One other cause leaves identical evidence and cannot "
			"be told apart from here: PCR14 extended by another "
			"writer and the snapshot at %s rewritten to match. If a "
			"cold reboot does not clear this, treat it as that one "
			"and audit both files' writers\n",
			LOTA_PCR14_BASELINE_PATH,
			ctx->clock_state_path[0] ? ctx->clock_state_path :
						   TPM_CLOCK_STATE_PATH);
		print_platform_clock(ctx, "PCR14 boot-commitment: TPM clock");
		return -EBADMSG;

	case TPM_PCR14_MUTATED_IN_SESSION:
		fprintf(stderr,
			"SECURITY: PCR14 no longer holds the value lota-agent "
			"extended in this boot session, and holds no value this "
			"boot could produce (last successful extend at %lld). "
			"Another writer extended PCR14 after lota-agent's last "
			"self_measure() and outside its control. Possible causes: "
			"(1) local root invoked tpm2_pcr_extend on /dev/tpmrm0; "
			"(2) another integrity subsystem (IMA, integrity-init, "
			"...) extended PCR14 from the OS. Audit auditd and the "
			"process table for the writer; cold reboot to restore a "
			"clean baseline\n",
			(long long)prev.saved_at);
		print_platform_clock(ctx, "PCR14 boot-commitment: TPM clock");
		return -EBADMSG;

	case TPM_PCR14_STATE_ROLLBACK:
		fprintf(stderr,
			"SECURITY: TPM reports resetCount=%u while the local "
			"snapshot recorded a higher value (%u). The TPM device or "
			"the persistent state file has been rolled back; refusing "
			"to attest\n",
			(unsigned)reset_count, (unsigned)prev.reset_count);
		return -EBADMSG;
	}

	return -EBADMSG;
}

int tpm_get_aik_public(struct tpm_context *ctx, uint8_t *buf, size_t buf_size,
		       size_t *out_size)
{
	TSS2_RC rc;
	int ret;
	ESYS_TR key_handle = ESYS_TR_NONE;
	TPM2B_PUBLIC *out_public = NULL;
	TPM2B_NAME *name = NULL;
	TPM2B_NAME *qualified_name = NULL;
	EVP_PKEY *pkey = NULL;
	EVP_PKEY_CTX *pctx = NULL;
	OSSL_PARAM_BLD *bld = NULL;
	OSSL_PARAM *params = NULL;
	BIGNUM *n = NULL;
	BIGNUM *e = NULL;
	int der_len = 0;

	if (!ctx || !ctx->initialized || !buf || !out_size)
		return -EINVAL;

	*out_size = 0;

	ret = aik_exists(ctx, &key_handle);
	if (ret < 0)
		return ret;
	if (ret == 0)
		return -ENOKEY;

	{
		struct esys_read_public_args args = {
			.esys_ctx = ctx->esys_ctx,
			.object_handle = key_handle,
			.out_public_out = &out_public,
			.name_out = &name,
			.qualified_name_out = &qualified_name,
		};
		ret = tpm_call_with_backoff(ctx, esys_read_public_thunk, &args,
					    &rc, 3, (void **)&out_public,
					    (void **)&name,
					    (void **)&qualified_name);
		if (ret < 0)
			goto cleanup;
	}

	if (out_public->publicArea.type != TPM2_ALG_RSA) {
		ret = -EINVAL;
		goto cleanup;
	}

	n = BN_bin2bn(out_public->publicArea.unique.rsa.buffer,
		      out_public->publicArea.unique.rsa.size, NULL);
	if (!n) {
		ret = -ENOMEM;
		goto cleanup;
	}

	uint32_t exp_val = out_public->publicArea.parameters.rsaDetail.exponent;
	if (exp_val == 0)
		exp_val = 65537; /* TPM default */

	e = BN_new();
	if (!e || !BN_set_word(e, exp_val)) {
		ret = -ENOMEM;
		goto cleanup;
	}

	bld = OSSL_PARAM_BLD_new();
	if (!bld) {
		ret = -ENOMEM;
		goto cleanup;
	}

	if (!OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_N, n) ||
	    !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_E, e)) {
		ret = -EINVAL;
		goto cleanup;
	}

	params = OSSL_PARAM_BLD_to_param(bld);
	if (!params) {
		ret = -ENOMEM;
		goto cleanup;
	}

	pctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
	if (!pctx) {
		ret = -ENOMEM;
		goto cleanup;
	}

	if (EVP_PKEY_fromdata_init(pctx) <= 0) {
		ret = -EINVAL;
		goto cleanup;
	}

	if (EVP_PKEY_fromdata(pctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) <= 0) {
		ret = -EINVAL;
		goto cleanup;
	}

	der_len = i2d_PUBKEY(pkey, NULL);
	if (der_len < 0) {
		ret = -EINVAL;
		goto cleanup;
	}

	if ((size_t)der_len > buf_size) {
		ret = -ENOSPC;
		goto cleanup;
	}

	unsigned char *p = buf;
	der_len = i2d_PUBKEY(pkey, &p);
	if (der_len < 0) {
		ret = -EINVAL;
		goto cleanup;
	}

	*out_size = der_len;
	ret = 0;

cleanup:
	if (pctx)
		EVP_PKEY_CTX_free(pctx);
	if (params)
		OSSL_PARAM_free(params);
	if (bld)
		OSSL_PARAM_BLD_free(bld);
	if (pkey)
		EVP_PKEY_free(pkey);
	if (n)
		BN_free(n);
	if (e)
		BN_free(e);
	if (out_public)
		Esys_Free(out_public);
	if (name)
		Esys_Free(name);
	if (qualified_name)
		Esys_Free(qualified_name);
	tpm_tr_close(ctx, &key_handle);

	return ret;
}

#define TPM_EK_RSA_HANDLE 0x81010001

static int tpm_load_ek(struct tpm_context *ctx, ESYS_TR *out_handle,
		       bool *out_transient);

int tpm_get_hardware_id(struct tpm_context *ctx, uint8_t *hardware_id)
{
	TSS2_RC rc;
	ESYS_TR ek_handle = ESYS_TR_NONE;
	bool ek_transient = false;
	TPM2B_PUBLIC *ek_public = NULL;
	TPM2B_NAME *ek_name = NULL;
	TPM2B_NAME *ek_qualified_name = NULL;
	EVP_MD_CTX *md_ctx = NULL;
	unsigned int hash_len;
	int ret = 0;

	if (!ctx || !ctx->initialized || !hardware_id)
		return -EINVAL;

	memset(hardware_id, 0, LOTA_HARDWARE_ID_SIZE);

	/*
	 * TPM2_Clear evicts the persistent handle and keeps the endorsement
	 * seed, so tpm_load_ek() recreates the same key.
	 */
	if (tpm_load_ek(ctx, &ek_handle, &ek_transient) < 0) {
		uint8_t aik_buf[LOTA_MAX_AIK_PUB_SIZE];
		size_t aik_size;

		ret = tpm_get_aik_public(ctx, aik_buf, sizeof(aik_buf),
					 &aik_size);
		if (ret < 0)
			return ret;

		md_ctx = EVP_MD_CTX_new();
		if (!md_ctx)
			return -ENOMEM;

		if (EVP_DigestInit_ex(md_ctx, EVP_sha256(), NULL) != 1 ||
		    EVP_DigestUpdate(md_ctx, aik_buf, aik_size) != 1 ||
		    EVP_DigestFinal_ex(md_ctx, hardware_id, &hash_len) != 1) {
			EVP_MD_CTX_free(md_ctx);
			return -EIO;
		}

		EVP_MD_CTX_free(md_ctx);
		return 1; /* AIK fallback */
	}

	{
		struct esys_read_public_args args = {
			.esys_ctx = ctx->esys_ctx,
			.object_handle = ek_handle,
			.out_public_out = &ek_public,
			.name_out = &ek_name,
			.qualified_name_out = &ek_qualified_name,
		};
		ret = tpm_call_with_backoff(ctx, esys_read_public_thunk, &args,
					    &rc, 3, (void **)&ek_public,
					    (void **)&ek_name,
					    (void **)&ek_qualified_name);
		if (ret < 0)
			goto cleanup;
	}

	md_ctx = EVP_MD_CTX_new();
	if (!md_ctx) {
		ret = -ENOMEM;
		goto cleanup;
	}

	if (EVP_DigestInit_ex(md_ctx, EVP_sha256(), NULL) != 1) {
		ret = -EIO;
		goto cleanup;
	}

	if (ek_public->publicArea.type == TPM2_ALG_RSA) {
		if (EVP_DigestUpdate(
			    md_ctx, ek_public->publicArea.unique.rsa.buffer,
			    ek_public->publicArea.unique.rsa.size) != 1) {
			ret = -EIO;
			goto cleanup;
		}
	} else if (ek_public->publicArea.type == TPM2_ALG_ECC) {
		if (EVP_DigestUpdate(
			    md_ctx, ek_public->publicArea.unique.ecc.x.buffer,
			    ek_public->publicArea.unique.ecc.x.size) != 1 ||
		    EVP_DigestUpdate(
			    md_ctx, ek_public->publicArea.unique.ecc.y.buffer,
			    ek_public->publicArea.unique.ecc.y.size) != 1) {
			ret = -EIO;
			goto cleanup;
		}
	} else {
		ret = -ENOTSUP;
		goto cleanup;
	}

	if (EVP_DigestFinal_ex(md_ctx, hardware_id, &hash_len) != 1) {
		ret = -EIO;
		goto cleanup;
	}

	ret = 0;

cleanup:
	if (md_ctx)
		EVP_MD_CTX_free(md_ctx);
	if (ek_public)
		Esys_Free(ek_public);
	if (ek_name)
		Esys_Free(ek_name);
	if (ek_qualified_name)
		Esys_Free(ek_qualified_name);
	if (ek_transient && ek_handle != ESYS_TR_NONE)
		Esys_FlushContext(ctx->esys_ctx, ek_handle);
	else if (!ek_transient)
		tpm_tr_close(ctx, &ek_handle);

	return ret;
}

/*
 * The attestation CA recomputes the AIK name from these exact bytes when
 * wrapping the activation credential, so this hands over the TPMT_PUBLIC
 * encoding.
 */
int tpm_get_aik_tpmt_public(struct tpm_context *ctx, uint8_t *buf,
			    size_t buf_size, size_t *out_size)
{
	TSS2_RC rc;
	int ret;
	ESYS_TR key_handle = ESYS_TR_NONE;
	TPM2B_PUBLIC *out_public = NULL;
	TPM2B_NAME *name = NULL;
	TPM2B_NAME *qualified_name = NULL;
	size_t off = 0;

	if (!ctx || !ctx->initialized || !buf || !out_size)
		return -EINVAL;

	*out_size = 0;

	ret = aik_exists(ctx, &key_handle);
	if (ret < 0)
		return ret;
	if (ret == 0)
		return -ENOKEY;

	{
		struct esys_read_public_args args = {
			.esys_ctx = ctx->esys_ctx,
			.object_handle = key_handle,
			.out_public_out = &out_public,
			.name_out = &name,
			.qualified_name_out = &qualified_name,
		};
		ret = tpm_call_with_backoff(ctx, esys_read_public_thunk, &args,
					    &rc, 3, (void **)&out_public,
					    (void **)&name,
					    (void **)&qualified_name);
		if (ret < 0)
			goto cleanup;
	}

	rc = Tss2_MU_TPMT_PUBLIC_Marshal(&out_public->publicArea, buf, buf_size,
					 &off);
	if (rc != TSS2_RC_SUCCESS) {
		ret = tss2_rc_to_errno(rc);
		goto cleanup;
	}
	*out_size = off;
	ret = 0;

cleanup:
	if (out_public)
		Esys_Free(out_public);
	if (name)
		Esys_Free(name);
	if (qualified_name)
		Esys_Free(qualified_name);
	tpm_tr_close(ctx, &key_handle);
	return ret;
}

/*
 * Well-known PolicySecret(TPM_RH_ENDORSEMENT) authPolicy digest for the SHA-256
 * RSA EK template. The EK is authorized with the endorsement hierarchy secret
 * through this policy, so ActivateCredential needs a matching policy session.
 */
static const uint8_t ek_rsa_auth_policy[32] = {
	0x83, 0x71, 0x97, 0x67, 0x44, 0x84, 0xb3, 0xf8, 0x1a, 0x90, 0xcc,
	0x8d, 0x46, 0xa5, 0xd7, 0x24, 0xfd, 0x52, 0xd7, 0x6e, 0x06, 0x52,
	0x0b, 0x64, 0xf2, 0xa1, 0xda, 0x1b, 0x33, 0x14, 0x69, 0xaa
};

/*
 * Populate the standard TCG RSA 2048 EK template. Reproducing it exactly
 * is what makes a recreated EK match the public key certified in the
 * manufacturer EK certificate the CA verified.
 */
static void ek_rsa_template(TPM2B_PUBLIC *tmpl)
{
	TPMS_RSA_PARMS *rsa;

	memset(tmpl, 0, sizeof(*tmpl));
	tmpl->publicArea.type = TPM2_ALG_RSA;
	tmpl->publicArea.nameAlg = TPM2_ALG_SHA256;
	tmpl->publicArea.objectAttributes =
		TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT |
		TPMA_OBJECT_SENSITIVEDATAORIGIN | TPMA_OBJECT_ADMINWITHPOLICY |
		TPMA_OBJECT_RESTRICTED | TPMA_OBJECT_DECRYPT;
	tmpl->publicArea.authPolicy.size = sizeof(ek_rsa_auth_policy);
	memcpy(tmpl->publicArea.authPolicy.buffer, ek_rsa_auth_policy,
	       sizeof(ek_rsa_auth_policy));

	rsa = &tmpl->publicArea.parameters.rsaDetail;
	rsa->symmetric.algorithm = TPM2_ALG_AES;
	rsa->symmetric.keyBits.aes = 128;
	rsa->symmetric.mode.aes = TPM2_ALG_CFB;
	rsa->scheme.scheme = TPM2_ALG_NULL;
	rsa->keyBits = 2048;
	rsa->exponent = 0;
	tmpl->publicArea.unique.rsa.size = 256;
}

/*
 * Resolve an EK handle. Prefer the persistent EK at the standard handle;
 * otherwise recreate the transient EK from the fixed template so its
 * public key still matches the certified EK.
 * Sets *out_transient when the caller must flush the handle.
 */
static int tpm_load_ek(struct tpm_context *ctx, ESYS_TR *out_handle,
		       bool *out_transient)
{
	TSS2_RC rc;
	ESYS_TR ek_handle = ESYS_TR_NONE;
	int ret;

	*out_handle = ESYS_TR_NONE;
	*out_transient = false;

	if (tpm_handle_in_use(ctx, TPM_EK_RSA_HANDLE) == 1) {
		TPM_CALL_RETRY(ctx, rc,
			       Esys_TR_FromTPMPublic(ctx->esys_ctx,
						     TPM_EK_RSA_HANDLE,
						     ESYS_TR_NONE, ESYS_TR_NONE,
						     ESYS_TR_NONE, &ek_handle));
		if (rc == TSS2_RC_SUCCESS) {
			*out_handle = ek_handle;
			return 0;
		}
	}

	{
		TPM2B_PUBLIC ek_template;
		TPM2B_SENSITIVE_CREATE in_sensitive = { .size = 0 };
		TPM2B_DATA outside = { .size = 0 };
		TPML_PCR_SELECTION pcr = { .count = 0 };
		TPM2B_PUBLIC *out_public = NULL;
		TPM2B_CREATION_DATA *creation_data = NULL;
		TPM2B_DIGEST *creation_hash = NULL;
		TPMT_TK_CREATION *creation_ticket = NULL;

		ek_rsa_template(&ek_template);

		struct esys_create_primary_args args = {
			.esys_ctx = ctx->esys_ctx,
			.primary_handle = ESYS_TR_RH_ENDORSEMENT,
			.shandle1 = ESYS_TR_PASSWORD,
			.in_sensitive = &in_sensitive,
			.in_public = &ek_template,
			.outside_info = &outside,
			.creation_pcr = &pcr,
			.object_handle_out = &ek_handle,
			.out_public_out = &out_public,
			.creation_data_out = &creation_data,
			.creation_hash_out = &creation_hash,
			.creation_ticket_out = &creation_ticket,
		};
		ret = tpm_call_with_backoff(ctx, esys_create_primary_thunk,
					    &args, &rc, 4, (void **)&out_public,
					    (void **)&creation_data,
					    (void **)&creation_hash,
					    (void **)&creation_ticket);
		Esys_Free(out_public);
		Esys_Free(creation_data);
		Esys_Free(creation_hash);
		Esys_Free(creation_ticket);
		if (ret < 0)
			return ret;
	}

	*out_handle = ek_handle;
	*out_transient = true;
	return 0;
}

struct esys_activate_args {
	ESYS_CONTEXT *esys_ctx;
	ESYS_TR activate_handle;
	ESYS_TR key_handle;
	ESYS_TR shandle1;
	ESYS_TR shandle2;
	const TPM2B_ID_OBJECT *credential_blob;
	const TPM2B_ENCRYPTED_SECRET *secret;
	TPM2B_DIGEST **cert_info_out;
};

static TSS2_RC esys_activate_thunk(void *u)
{
	struct esys_activate_args *a = u;
	return Esys_ActivateCredential(a->esys_ctx, a->activate_handle,
				       a->key_handle, a->shandle1, a->shandle2,
				       ESYS_TR_NONE, a->credential_blob,
				       a->secret, a->cert_info_out);
}

/*
 * Recover an attestation-CA credential. ActivateCredential succeeds only
 * when the AIK and the certified EK live in the same TPM, which is the
 * binding the EK certificate alone does not prove.
 * Recovered secret is returned to the CA as evidence of that binding.
 */
int tpm_activate_credential(struct tpm_context *ctx, const uint8_t *cred_blob,
			    size_t cred_blob_len, const uint8_t *enc_secret,
			    size_t enc_secret_len, uint8_t *out_secret,
			    size_t out_secret_max, size_t *out_secret_len)
{
	TSS2_RC rc;
	int ret;
	ESYS_TR aik_handle = ESYS_TR_NONE;
	ESYS_TR ek_handle = ESYS_TR_NONE;
	ESYS_TR policy_session = ESYS_TR_NONE;
	bool ek_transient = false;
	TPM2B_ID_OBJECT id_object;
	TPM2B_ENCRYPTED_SECRET secret_2b;
	TPM2B_DIGEST *cert_info = NULL;
	TPMT_SYM_DEF sym = { .algorithm = TPM2_ALG_NULL };
	size_t off;

	if (!ctx || !ctx->initialized || !cred_blob || !enc_secret ||
	    !out_secret || !out_secret_len)
		return -EINVAL;

	*out_secret_len = 0;
	memset(&id_object, 0, sizeof(id_object));
	memset(&secret_2b, 0, sizeof(secret_2b));

	off = 0;
	rc = Tss2_MU_TPM2B_ID_OBJECT_Unmarshal(cred_blob, cred_blob_len, &off,
					       &id_object);
	if (rc != TSS2_RC_SUCCESS)
		return -EINVAL;

	off = 0;
	rc = Tss2_MU_TPM2B_ENCRYPTED_SECRET_Unmarshal(
		enc_secret, enc_secret_len, &off, &secret_2b);
	if (rc != TSS2_RC_SUCCESS)
		return -EINVAL;

	ret = aik_exists(ctx, &aik_handle);
	if (ret < 0)
		return ret;
	if (ret == 0)
		return -ENOKEY;

	if (!ctx->aik_auth_loaded) {
		ret = tpm_aik_load_auth(ctx);
		if (ret < 0)
			goto cleanup;
	}
	{
		TPM2B_AUTH auth = { .size = TPM_AIK_AUTH_SIZE };
		memcpy(auth.buffer, ctx->aik_auth, TPM_AIK_AUTH_SIZE);
		TPM_CALL_RETRY(ctx, rc,
			       Esys_TR_SetAuth(ctx->esys_ctx, aik_handle,
					       &auth));
		secure_bzero(auth.buffer, sizeof(auth.buffer));
		if (rc != TSS2_RC_SUCCESS) {
			ret = tss2_rc_to_errno(rc);
			goto cleanup;
		}
	}

	ret = tpm_load_ek(ctx, &ek_handle, &ek_transient);
	if (ret < 0)
		goto cleanup;

	TPM_CALL_RETRY(ctx, rc,
		       Esys_StartAuthSession(ctx->esys_ctx, ESYS_TR_NONE,
					     ESYS_TR_NONE, ESYS_TR_NONE,
					     ESYS_TR_NONE, ESYS_TR_NONE, NULL,
					     TPM2_SE_POLICY, &sym,
					     TPM2_ALG_SHA256, &policy_session));
	if (rc != TSS2_RC_SUCCESS) {
		ret = tss2_rc_to_errno(rc);
		goto cleanup;
	}

	TPM_CALL_RETRY(ctx, rc,
		       Esys_PolicySecret(ctx->esys_ctx, ESYS_TR_RH_ENDORSEMENT,
					 policy_session, ESYS_TR_PASSWORD,
					 ESYS_TR_NONE, ESYS_TR_NONE, NULL, NULL,
					 NULL, 0, NULL, NULL));
	if (rc != TSS2_RC_SUCCESS) {
		ret = tss2_rc_to_errno(rc);
		goto cleanup;
	}

	{
		struct esys_activate_args args = {
			.esys_ctx = ctx->esys_ctx,
			.activate_handle = aik_handle,
			.key_handle = ek_handle,
			.shandle1 = ESYS_TR_PASSWORD,
			.shandle2 = policy_session,
			.credential_blob = &id_object,
			.secret = &secret_2b,
			.cert_info_out = &cert_info,
		};
		ret = tpm_call_with_backoff(ctx, esys_activate_thunk, &args,
					    &rc, 1, (void **)&cert_info);
		if (ret < 0)
			goto cleanup;
	}

	if (cert_info->size > out_secret_max) {
		ret = -ENOSPC;
		goto cleanup;
	}
	memcpy(out_secret, cert_info->buffer, cert_info->size);
	*out_secret_len = cert_info->size;
	ret = 0;

cleanup:
	if (cert_info) {
		secure_bzero(cert_info->buffer, sizeof(cert_info->buffer));
		Esys_Free(cert_info);
	}
	if (policy_session != ESYS_TR_NONE)
		Esys_FlushContext(ctx->esys_ctx, policy_session);
	if (ek_transient && ek_handle != ESYS_TR_NONE)
		Esys_FlushContext(ctx->esys_ctx, ek_handle);
	else if (!ek_transient)
		tpm_tr_close(ctx, &ek_handle);
	tpm_tr_close(ctx, &aik_handle);
	secure_bzero(&secret_2b, sizeof(secret_2b));
	return ret;
}

static int mkdirs(const char *path, mode_t mode)
{
	char tmp[PATH_MAX];
	char *p;
	size_t len;

	len = strlen(path);
	if (len == 0 || len >= sizeof(tmp))
		return -EINVAL;

	memcpy(tmp, path, len + 1);

	for (p = tmp + 1; *p; p++) {
		if (*p == '/') {
			*p = '\0';
			if (mkdir(tmp, mode) < 0 && errno != EEXIST)
				return -errno;
			*p = '/';
		}
	}
	return 0;
}

static int fsync_parent_dir(const char *path)
{
	char dir[PATH_MAX];
	const char *slash;
	int dfd;

	if (!path || !path[0])
		return -EINVAL;

	slash = strrchr(path, '/');
	if (!slash) {
		dir[0] = '.';
		dir[1] = '\0';
	} else if (slash == path) {
		dir[0] = '/';
		dir[1] = '\0';
	} else {
		size_t len = (size_t)(slash - path);
		if (len >= sizeof(dir))
			return -ENAMETOOLONG;
		memcpy(dir, path, len);
		dir[len] = '\0';
	}

	dfd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (dfd < 0)
		return -errno;

	if (fsync(dfd) < 0) {
		int ret = -errno;
		close(dfd);
		return ret;
	}

	close(dfd);
	return 0;
}

static int tpm_aik_auth_path_for_ctx(struct tpm_context *ctx, char *buf,
				     size_t buf_len)
{
	const char *meta_path;
	const char *slash;
	size_t dir_len;

	if (!ctx || !buf || buf_len == 0)
		return -EINVAL;

	meta_path = ctx->aik_meta_path[0] ? ctx->aik_meta_path :
					    TPM_AIK_META_PATH;
	slash = strrchr(meta_path, '/');
	if (!slash)
		return -EINVAL;

	if (slash == meta_path)
		dir_len = 1;
	else
		dir_len = (size_t)(slash - meta_path);

	if (dir_len + 1 + strlen(LOTA_PROFILE_AIK_AUTH_FILE) + 1 > buf_len)
		return -ENAMETOOLONG;

	memcpy(buf, meta_path, dir_len);
	buf[dir_len] = '\0';

	if (dir_len > 1)
		snprintf(buf + dir_len, buf_len - dir_len,
			 "/" LOTA_PROFILE_AIK_AUTH_FILE);
	else
		snprintf(buf + dir_len, buf_len - dir_len,
			 LOTA_PROFILE_AIK_AUTH_FILE);

	return 0;
}

static int tpm_aik_generate_auth(uint8_t auth[TPM_AIK_AUTH_SIZE])
{
	int attempt;

	if (!auth)
		return -EINVAL;

	for (attempt = 0; attempt < 4; attempt++) {
		if (RAND_bytes(auth, TPM_AIK_AUTH_SIZE) != 1)
			return -EIO;

		for (size_t i = 0; i < TPM_AIK_AUTH_SIZE; i++) {
			if (auth[i] != 0)
				return 0;
		}
	}

	return -EIO;
}

static int tpm_aik_save_auth_plaintext(struct tpm_context *ctx,
				       const uint8_t auth[TPM_AIK_AUTH_SIZE])
{
	char path[PATH_MAX];
	char tmp[PATH_MAX];
	int fd;
	int ret;
	ssize_t n;
	struct aik_auth_record rec;

	if (!ctx || !auth)
		return -EINVAL;

	ret = tpm_aik_auth_path_for_ctx(ctx, path, sizeof(path));
	if (ret < 0)
		return ret;

	ret = mkdirs(path, 0755);
	if (ret < 0)
		return ret;

	ret = snprintf(tmp, sizeof(tmp), "%s.tmp.XXXXXX", path);
	if (ret < 0 || (size_t)ret >= sizeof(tmp))
		return -ENAMETOOLONG;

	fd = mkstemp(tmp);
	if (fd < 0)
		return -errno;

	if (fchmod(fd, 0600) != 0) {
		ret = -errno;
		close(fd);
		unlink(tmp);
		return ret;
	}

	memset(&rec, 0, sizeof(rec));
	rec.magic = htole32(TPM_AIK_AUTH_MAGIC);
	rec.version = htole32(TPM_AIK_AUTH_VERSION);
	rec.size = htole16(TPM_AIK_AUTH_SIZE);
	memcpy(rec.auth, auth, TPM_AIK_AUTH_SIZE);

	n = write(fd, &rec, sizeof(rec));
	if (n != (ssize_t)sizeof(rec)) {
		secure_bzero(&rec, sizeof(rec));
		ret = -EIO;
		close(fd);
		unlink(tmp);
		return ret;
	}

	if (fsync(fd) != 0) {
		secure_bzero(&rec, sizeof(rec));
		ret = -errno;
		close(fd);
		unlink(tmp);
		return ret;
	}

	secure_bzero(&rec, sizeof(rec));
	close(fd);

	if (rename(tmp, path) != 0) {
		ret = -errno;
		unlink(tmp);
		return ret;
	}

	ret = fsync_parent_dir(path);
	if (ret < 0)
		return ret;

	return 0;
}

static int tpm_aik_load_auth_plaintext(struct tpm_context *ctx)
{
	char path[PATH_MAX];
	int fd;
	ssize_t n;
	struct aik_auth_record rec;
	uint16_t sz;
	int nonzero = 0;
	int ret;

	if (!ctx)
		return -EINVAL;

	ret = tpm_aik_auth_path_for_ctx(ctx, path, sizeof(path));
	if (ret < 0)
		return ret;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -errno;

	n = read(fd, &rec, sizeof(rec));
	close(fd);
	if (n != (ssize_t)sizeof(rec)) {
		secure_bzero(&rec, sizeof(rec));
		return -EIO;
	}

	if (le32toh(rec.magic) != TPM_AIK_AUTH_MAGIC) {
		secure_bzero(&rec, sizeof(rec));
		return -EINVAL;
	}
	if (le32toh(rec.version) != TPM_AIK_AUTH_VERSION) {
		secure_bzero(&rec, sizeof(rec));
		return -ENOTSUP;
	}

	sz = le16toh(rec.size);
	if (sz != TPM_AIK_AUTH_SIZE) {
		secure_bzero(&rec, sizeof(rec));
		return -EINVAL;
	}

	for (size_t i = 0; i < TPM_AIK_AUTH_SIZE; i++) {
		if (rec.auth[i] != 0) {
			nonzero = 1;
			break;
		}
	}
	if (!nonzero) {
		secure_bzero(&rec, sizeof(rec));
		return -EKEYREVOKED;
	}

	memcpy(ctx->aik_auth, rec.auth, TPM_AIK_AUTH_SIZE);
	ctx->aik_auth_loaded = true;
	secure_bzero(&rec, sizeof(rec));
	return 0;
}

static int tpm_aik_auth_sealed_path_for_ctx(struct tpm_context *ctx, char *buf,
					    size_t buf_len)
{
	const char *meta_path;
	const char *slash;
	size_t dir_len;

	if (!ctx || !buf || buf_len == 0)
		return -EINVAL;

	meta_path = ctx->aik_meta_path[0] ? ctx->aik_meta_path :
					    TPM_AIK_META_PATH;
	slash = strrchr(meta_path, '/');
	if (!slash)
		return -EINVAL;

	dir_len = (slash == meta_path) ? 1 : (size_t)(slash - meta_path);
	if (dir_len + 1 + strlen(LOTA_PROFILE_AIK_AUTH_SEALED_FILE) + 1 >
	    buf_len)
		return -ENAMETOOLONG;

	memcpy(buf, meta_path, dir_len);
	buf[dir_len] = '\0';
	if (dir_len > 1)
		snprintf(buf + dir_len, buf_len - dir_len,
			 "/" LOTA_PROFILE_AIK_AUTH_SEALED_FILE);
	else
		snprintf(buf + dir_len, buf_len - dir_len,
			 LOTA_PROFILE_AIK_AUTH_SEALED_FILE);
	return 0;
}

static int tpm_aik_save_auth_sealed(struct tpm_context *ctx,
				    const uint8_t auth[TPM_AIK_AUTH_SIZE])
{
	char path[PATH_MAX];
	char tmp[PATH_MAX];
	uint8_t blob[LOTA_SEAL_MAX_BLOB];
	size_t blob_len = 0;
	int fd;
	int ret;
	ssize_t n;

	if (!ctx || !auth)
		return -EINVAL;

	ret = tpm_aik_auth_sealed_path_for_ctx(ctx, path, sizeof(path));
	if (ret < 0)
		return ret;

	/*
	 * The platform mask: adding the boot commitment would bind the AIK
	 * authorization to the agent binary, so an agent upgrade would cost the
	 * host its authorization and, where seal_aik_auth_strict has dropped
	 * the plaintext, a re-enrollment with its publishers.
	 */
	ret = tpm_seal_secret(ctx, auth, TPM_AIK_AUTH_SIZE,
			      LOTA_SEAL_DEFAULT_PCR_MASK, blob, sizeof(blob),
			      &blob_len);
	if (ret < 0)
		return ret;

	ret = mkdirs(path, 0755);
	if (ret < 0)
		goto out;

	ret = snprintf(tmp, sizeof(tmp), "%s.tmp.XXXXXX", path);
	if (ret < 0 || (size_t)ret >= sizeof(tmp)) {
		ret = -ENAMETOOLONG;
		goto out;
	}

	fd = mkstemp(tmp);
	if (fd < 0) {
		ret = -errno;
		goto out;
	}
	if (fchmod(fd, 0600) != 0) {
		ret = -errno;
		close(fd);
		unlink(tmp);
		goto out;
	}

	n = write(fd, blob, blob_len);
	if (n != (ssize_t)blob_len) {
		ret = -EIO;
		close(fd);
		unlink(tmp);
		goto out;
	}
	if (fsync(fd) != 0) {
		ret = -errno;
		close(fd);
		unlink(tmp);
		goto out;
	}
	close(fd);

	if (rename(tmp, path) != 0) {
		ret = -errno;
		unlink(tmp);
		goto out;
	}
	ret = fsync_parent_dir(path);
out:
	secure_bzero(blob, sizeof(blob));
	return ret;
}

/*
 * Returns -ENOENT when no sealed file exists, so callers can fall back,
 * or -EPROTO if the unsealed length is not the expected auth size.
 */
static int tpm_aik_load_auth_sealed(struct tpm_context *ctx)
{
	char path[PATH_MAX];
	uint8_t blob[LOTA_SEAL_MAX_BLOB];
	uint8_t secret[LOTA_SEAL_MAX_SECRET];
	size_t secret_len = 0;
	ssize_t n;
	int fd;
	int ret;

	if (!ctx)
		return -EINVAL;

	ret = tpm_aik_auth_sealed_path_for_ctx(ctx, path, sizeof(path));
	if (ret < 0)
		return ret;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -errno;

	n = read(fd, blob, sizeof(blob));
	close(fd);
	if (n <= 0)
		return -EIO;

	ret = tpm_unseal_secret(ctx, blob, (size_t)n, secret, sizeof(secret),
				&secret_len);
	secure_bzero(blob, sizeof(blob));
	if (ret < 0)
		return ret;
	if (secret_len != TPM_AIK_AUTH_SIZE) {
		secure_bzero(secret, sizeof(secret));
		return -EPROTO;
	}

	memcpy(ctx->aik_auth, secret, TPM_AIK_AUTH_SIZE);
	ctx->aik_auth_loaded = true;
	secure_bzero(secret, sizeof(secret));
	return 0;
}

static int tpm_aik_save_auth(struct tpm_context *ctx,
			     const uint8_t auth[TPM_AIK_AUTH_SIZE])
{
	bool seal = ctx && (ctx->seal_aik_auth || ctx->seal_aik_auth_strict);
	int ret;

	if (!ctx || !auth)
		return -EINVAL;

	if (seal) {
		ret = tpm_aik_save_auth_sealed(ctx, auth);
		if (ret < 0)
			return ret;
	}

	if (ctx->seal_aik_auth_strict) {
		char path[PATH_MAX];
		if (tpm_aik_auth_path_for_ctx(ctx, path, sizeof(path)) == 0)
			unlink(path);
		return 0;
	}

	return tpm_aik_save_auth_plaintext(ctx, auth);
}

/*
 * In non-strict mode a missing or unusable sealed copy falls back to the
 * plaintext sidecar: a boot-state change moves the PCRs the blob was sealed to,
 * so it stops unsealing.
 */
static int tpm_aik_load_auth(struct tpm_context *ctx)
{
	if (!ctx)
		return -EINVAL;

	if (ctx->seal_aik_auth || ctx->seal_aik_auth_strict) {
		int ret = tpm_aik_load_auth_sealed(ctx);
		if (ret == 0)
			return 0;
		if (ctx->seal_aik_auth_strict)
			return ret; /* no plaintext fallback when hardened */
	}

	return tpm_aik_load_auth_plaintext(ctx);
}

int tpm_aik_load_failure_blocks_reprovision(int load_rc)
{
	if (load_rc == 0)
		return 0;

	return load_rc == -ENOENT ? 0 : 1;
}

static int tpm_object_name(struct tpm_context *ctx, ESYS_TR object,
			   uint8_t *out, size_t out_max, uint16_t *out_len)
{
	TPM2B_PUBLIC *out_public = NULL;
	TPM2B_NAME *qualified = NULL;
	TPM2B_NAME *name = NULL;
	TSS2_RC rc;
	int ret;

	struct esys_read_public_args args = {
		.esys_ctx = ctx->esys_ctx,
		.object_handle = object,
		.out_public_out = &out_public,
		.name_out = &name,
		.qualified_name_out = &qualified,
	};

	ret = tpm_call_with_backoff(ctx, esys_read_public_thunk, &args, &rc, 3,
				    (void **)&out_public, (void **)&name,
				    (void **)&qualified);
	if (ret < 0)
		return ret;

	if (!name || name->size == 0 || name->size > out_max) {
		ret = -EIO;
	} else {
		memcpy(out, name->name, name->size);
		*out_len = name->size;
		ret = 0;
	}

	Esys_Free(out_public);
	Esys_Free(name);
	Esys_Free(qualified);
	return ret;
}

/*
 * The AIK is a primary derived from the hierarchy seed and the publisher's
 * template, so re-derive it and compare Names; nothing on disk records which
 * object was put at the handle.
 */
int tpm_aik_handle_holds_profile_key(struct tpm_context *ctx)
{
	uint8_t at_handle[sizeof(((TPM2B_NAME *)0)->name)];
	uint8_t derived[sizeof(at_handle)];
	uint16_t at_handle_len = 0;
	uint16_t derived_len = 0;
	uint8_t zero_auth[TPM_AIK_AUTH_SIZE] = { 0 };
	ESYS_TR key_handle = ESYS_TR_NONE;
	ESYS_TR transient = ESYS_TR_NONE;
	int ret;

	if (!ctx || !ctx->initialized)
		return -EINVAL;

	ret = aik_exists(ctx, &key_handle);
	if (ret < 0)
		return ret;
	if (ret == 0)
		return 0; /* nothing at the handle */

	ret = tpm_object_name(ctx, key_handle, at_handle, sizeof(at_handle),
			      &at_handle_len);
	tpm_tr_close(ctx, &key_handle);
	if (ret < 0)
		return ret;

	/* userAuth is not part of the Name, so any auth will do */
	ret = create_aik_primary(ctx, &transient, zero_auth);
	if (ret < 0)
		return ret;

	ret = tpm_object_name(ctx, transient, derived, sizeof(derived),
			      &derived_len);
	Esys_FlushContext(ctx->esys_ctx, transient);
	if (ret < 0)
		return ret;

	if (at_handle_len != derived_len)
		return 0;

	return memcmp(at_handle, derived, at_handle_len) == 0 ? 1 : 0;
}

int tpm_aik_slot_census(struct tpm_context *ctx, const char *base_dir,
			struct profile_aik_slots *out)
{
	uint32_t recorded[LOTA_PROFILE_MAX_AIK_HANDLES];
	uint32_t in_use[LOTA_PROFILE_MAX_AIK_HANDLES];
	size_t recorded_count = 0;
	size_t in_use_count = 0;
	int ret;

	if (!ctx || !ctx->initialized || !out)
		return -EINVAL;

	ret = profile_aik_handles_recorded(
		base_dir ? base_dir : LOTA_PROFILE_BASE_DIR, recorded,
		sizeof(recorded) / sizeof(*recorded), &recorded_count);
	if (ret < 0)
		return ret;

	for (uint32_t i = 0; i < TPM_AIK_PROFILE_HANDLE_COUNT; i++) {
		uint32_t handle = TPM_AIK_PROFILE_HANDLE_BASE + i;

		ret = tpm_handle_in_use(ctx, handle);
		if (ret < 0)
			return ret;
		if (ret == 1)
			in_use[in_use_count++] = handle;
	}

	return profile_aik_slot_tally(TPM_AIK_PROFILE_HANDLE_BASE,
				      TPM_AIK_PROFILE_HANDLE_COUNT, recorded,
				      recorded_count, in_use, in_use_count,
				      out);
}

/*
 * The hardened loader skips the sidecar and reports -ENOENT while it is
 * present, so look for both files.
 */
static int tpm_aik_auth_record_exists(struct tpm_context *ctx)
{
	char path[PATH_MAX];

	if (!ctx)
		return -EINVAL;

	if (tpm_aik_auth_path_for_ctx(ctx, path, sizeof(path)) == 0 &&
	    access(path, F_OK) == 0)
		return 1;
	if (tpm_aik_auth_sealed_path_for_ctx(ctx, path, sizeof(path)) == 0 &&
	    access(path, F_OK) == 0)
		return 1;

	return 0;
}

/*
 * Report which record files exist and the version found,
 * so a newer-format record can be told from a damaged disk.
 */
static void tpm_aik_report_auth_load_failure(struct tpm_context *ctx,
					     int load_rc)
{
	struct aik_auth_record rec;
	char plain[PATH_MAX];
	char sealed[PATH_MAX];
	int have_plain = 0;
	int have_sealed = 0;
	ssize_t n = -1;
	int fd;

	if (!ctx)
		return;

	if (tpm_aik_auth_path_for_ctx(ctx, plain, sizeof(plain)) == 0)
		have_plain = access(plain, F_OK) == 0;
	if (tpm_aik_auth_sealed_path_for_ctx(ctx, sealed, sizeof(sealed)) == 0)
		have_sealed = access(sealed, F_OK) == 0;

	fprintf(stderr,
		"SECURITY: the attestation key's authorization could not be "
		"read (%s). The key is left as it is.\n",
		tpm_strerror(load_rc));

	if (have_plain) {
		fd = open(plain, O_RDONLY | O_CLOEXEC);
		if (fd >= 0) {
			n = read(fd, &rec, sizeof(rec));
			close(fd);
		}
	}
	if (n == (ssize_t)sizeof(rec)) {
		fprintf(stderr,
			"SECURITY: %s holds magic 0x%08X version %u; this "
			"build reads magic 0x%08X version %u.\n",
			plain, le32toh(rec.magic), le32toh(rec.version),
			TPM_AIK_AUTH_MAGIC, TPM_AIK_AUTH_VERSION);
		secure_bzero(&rec, sizeof(rec));
	} else if (have_plain) {
		fprintf(stderr,
			"SECURITY: %s is shorter than the record it holds.\n",
			plain);
	}
	if (have_sealed)
		fprintf(stderr, "SECURITY: the sealed copy %s is present.\n",
			sealed);

	if (have_plain && !have_sealed &&
	    (ctx->seal_aik_auth || ctx->seal_aik_auth_strict))
		fprintf(stderr,
			"SECURITY: run --seal-aik-auth to seal the record "
			"this host already has.\n");
	else
		fprintf(stderr,
			"SECURITY: restore the record, or replace the key "
			"deliberately with --forget-publisher, "
			"--allow-publisher and --enroll -- which issues a new "
			"certificate, because the current one names the key "
			"that is being replaced.\n");
}

int tpm_aik_reseal_auth(struct tpm_context *ctx)
{
	int ret;

	if (!ctx || !ctx->initialized)
		return -EINVAL;

	if (!ctx->aik_auth_loaded) {
		ret = tpm_aik_load_auth(ctx);
		if (ret < 0)
			return ret;
	}

	ret = tpm_aik_save_auth_sealed(ctx, ctx->aik_auth);
	if (ret < 0)
		return ret;

	if (ctx->seal_aik_auth_strict) {
		char path[PATH_MAX];
		if (tpm_aik_auth_path_for_ctx(ctx, path, sizeof(path)) == 0)
			unlink(path);
	}
	return 0;
}

static int tpm_aik_reprovision_with_auth(struct tpm_context *ctx,
					 int had_existing_aik)
{
	TSS2_RC rc;
	ESYS_TR old_handle = ESYS_TR_NONE;
	ESYS_TR primary_handle = ESYS_TR_NONE;
	ESYS_TR persistent_handle = ESYS_TR_NONE;
	uint8_t new_auth[TPM_AIK_AUTH_SIZE];
	int ret;

	if (!ctx || !ctx->initialized)
		return -EINVAL;

	ret = tpm_aik_generate_auth(new_auth);
	if (ret < 0)
		return ret;

	if (had_existing_aik) {
		ret = aik_exists(ctx, &old_handle);
		if (ret < 0)
			return ret;

		if (ret == 1) {
			TPM_CALL_RETRY(ctx, rc,
				       Esys_EvictControl(
					       ctx->esys_ctx, ESYS_TR_RH_OWNER,
					       old_handle, ESYS_TR_PASSWORD,
					       ESYS_TR_NONE, ESYS_TR_NONE,
					       ctx->aik_handle,
					       &persistent_handle));
			if (rc != TSS2_RC_SUCCESS) {
				tpm_tr_close(ctx, &old_handle);
				return tss2_rc_to_errno(rc);
			}
			tpm_tr_close(ctx, &persistent_handle);
		}
	}

	ret = create_aik_primary(ctx, &primary_handle, new_auth);
	if (ret < 0)
		return ret;

	TPM_CALL_RETRY(ctx, rc,
		       Esys_EvictControl(ctx->esys_ctx, ESYS_TR_RH_OWNER,
					 primary_handle, ESYS_TR_PASSWORD,
					 ESYS_TR_NONE, ESYS_TR_NONE,
					 ctx->aik_handle, &persistent_handle));
	Esys_FlushContext(ctx->esys_ctx, primary_handle);
	if (rc != TSS2_RC_SUCCESS)
		return tss2_rc_to_errno(rc);

	tpm_tr_close(ctx, &persistent_handle);

	ret = tpm_aik_save_auth(ctx, new_auth);
	if (ret < 0) {
		secure_bzero(new_auth, sizeof(new_auth));
		return ret;
	}

	memcpy(ctx->aik_auth, new_auth, TPM_AIK_AUTH_SIZE);
	ctx->aik_auth_loaded = true;
	secure_bzero(new_auth, sizeof(new_auth));
	return 0;
}

int tpm_aik_load_metadata(struct tpm_context *ctx)
{
	const char *path;
	int fd;
	ssize_t n;
	struct aik_metadata meta;

	if (!ctx || !ctx->initialized)
		return -EINVAL;

	path = ctx->aik_meta_path[0] ? ctx->aik_meta_path : TPM_AIK_META_PATH;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		if (errno != ENOENT)
			return -errno;

		{
			/*
			 * Unit tests exercise metadata persistence with no TPM,
			 * so esys_ctx may be NULL.
			 */
			if (ctx->esys_ctx) {
				int exists = aik_exists(ctx, NULL);
				if (exists < 0)
					return exists;
				if (exists == 1)
					return -EKEYREVOKED;
			}
		}

		/*
		 * These defaults stay in memory: a record on disk describes a
		 * key, and there is none yet. key_derivation is set because
		 * zero reads as TPM_AIK_KEY_DERIVATION_SHARED.
		 */
		memset(&ctx->aik_meta, 0, sizeof(ctx->aik_meta));
		ctx->aik_meta.magic = TPM_AIK_META_MAGIC;
		ctx->aik_meta.version = TPM_AIK_META_VERSION;
		ctx->aik_meta.generation = 1;
		ctx->aik_meta.provisioned_at = (int64_t)time(NULL);
		ctx->aik_meta.last_rotated_at = 0;
		ctx->aik_meta.key_derivation =
			TPM_AIK_KEY_DERIVATION_PER_PUBLISHER;
		ctx->aik_meta_loaded = true;

		return 0;
	}

	n = read(fd, &meta, sizeof(meta));
	close(fd);

	if (n != (ssize_t)sizeof(meta))
		return -EIO;

	meta.magic = le32toh(meta.magic);
	meta.version = le32toh(meta.version);
	meta.generation = le64toh(meta.generation);
	meta.provisioned_at = (int64_t)le64toh((uint64_t)meta.provisioned_at);
	meta.last_rotated_at = (int64_t)le64toh((uint64_t)meta.last_rotated_at);

	if (meta.magic != TPM_AIK_META_MAGIC)
		return -EINVAL;

	if (meta.version != TPM_AIK_META_VERSION)
		return -ENOTSUP;

	ctx->aik_meta = meta;
	ctx->aik_meta_loaded = true;
	return 0;
}

int tpm_aik_save_metadata(struct tpm_context *ctx)
{
	const char *path;
	int fd;
	ssize_t n;
	int ret;

	if (!ctx)
		return -EINVAL;

	path = ctx->aik_meta_path[0] ? ctx->aik_meta_path : TPM_AIK_META_PATH;

	ret = mkdirs(path, 0755);
	if (ret < 0)
		return ret;

	char tmp[PATH_MAX];
	ret = snprintf(tmp, sizeof(tmp), "%s.tmp.XXXXXX", path);
	if (ret < 0 || (size_t)ret >= sizeof(tmp))
		return -ENAMETOOLONG;

	fd = mkstemp(tmp);
	if (fd < 0)
		return -errno;

	struct aik_metadata wire;

	/*
	 * Zero first: every byte is written to disk, so a field the assignments
	 * miss would put a stack byte in the record.
	 */
	memset(&wire, 0, sizeof(wire));
	wire.magic = htole32(ctx->aik_meta.magic);
	wire.version = htole32(TPM_AIK_META_VERSION);
	wire.generation = htole64(ctx->aik_meta.generation);
	wire.provisioned_at =
		(int64_t)htole64((uint64_t)ctx->aik_meta.provisioned_at);
	wire.last_rotated_at =
		(int64_t)htole64((uint64_t)ctx->aik_meta.last_rotated_at);
	wire.key_derivation = ctx->aik_meta.key_derivation;

	n = write(fd, &wire, sizeof(wire));
	if (n != (ssize_t)sizeof(wire)) {
		close(fd);
		unlink(tmp);
		return -EIO;
	}

	if (fsync(fd) != 0) {
		ret = -errno;
		close(fd);
		unlink(tmp);
		return ret;
	}
	close(fd);

	if (rename(tmp, path) != 0) {
		ret = -errno;
		unlink(tmp);
		return ret;
	}

	ret = fsync_parent_dir(path);
	if (ret < 0)
		return ret;

	return 0;
}

int64_t tpm_aik_age(struct tpm_context *ctx)
{
	time_t now;

	if (!ctx || !ctx->aik_meta_loaded)
		return -EINVAL;

	now = time(NULL);
	return (int64_t)(now - (time_t)ctx->aik_meta.provisioned_at);
}

int tpm_aik_needs_rotation(struct tpm_context *ctx, uint32_t max_age_sec)
{
	int64_t age;

	if (!ctx || !ctx->aik_meta_loaded)
		return -EINVAL;

	if (max_age_sec == 0)
		max_age_sec = TPM_AIK_DEFAULT_TTL_SEC;

	age = tpm_aik_age(ctx);
	if (age < 0)
		return (int)age;

	return (age >= (int64_t)max_age_sec) ? 1 : 0;
}

int tpm_rotate_aik(struct tpm_context *ctx)
{
	int ret;
	size_t prev_size = 0;

	if (!ctx || !ctx->initialized || !ctx->aik_meta_loaded)
		return -EINVAL;

	ret = aik_exists(ctx, NULL);
	if (ret < 0)
		return ret;

	if (ret == 1) {
		ret = tpm_get_aik_public(ctx, ctx->prev_aik_public,
					 sizeof(ctx->prev_aik_public),
					 &prev_size);
		if (ret < 0) {
			prev_size = 0;
		}
		ctx->prev_aik_public_size = prev_size;

		ret = tpm_aik_reprovision_with_auth(ctx, 1);
		if (ret < 0)
			return ret;
	} else {
		ctx->prev_aik_public_size = 0;

		ret = tpm_provision_aik(ctx);
		if (ret < 0)
			return ret;
	}

	ctx->aik_meta.generation++;
	ctx->aik_meta.last_rotated_at = (int64_t)time(NULL);
	ctx->aik_meta.provisioned_at = ctx->aik_meta.last_rotated_at;

	ret = tpm_aik_save_metadata(ctx);
	if (ret < 0)
		return ret;

	if (ctx->prev_aik_public_size > 0) {
		ctx->grace_deadline = time(NULL) + TPM_AIK_GRACE_PERIOD_SEC;
	} else {
		ctx->grace_deadline = 0;
	}

	return 0;
}

int tpm_aik_in_grace_period(struct tpm_context *ctx)
{
	if (!ctx)
		return 0;

	if (ctx->grace_deadline == 0)
		return 0;

	if (time(NULL) >= ctx->grace_deadline) {
		ctx->grace_deadline = 0;
		ctx->prev_aik_public_size = 0;
		return 0;
	}

	return 1;
}

int tpm_aik_get_prev_public(struct tpm_context *ctx, uint8_t *buf,
			    size_t buf_size, size_t *out_size)
{
	if (!ctx || !buf || !out_size)
		return -EINVAL;

	*out_size = 0;

	if (!tpm_aik_in_grace_period(ctx))
		return -ENOENT;

	if (ctx->prev_aik_public_size == 0)
		return -ENOENT;

	if (buf_size < ctx->prev_aik_public_size)
		return -ENOSPC;

	memcpy(buf, ctx->prev_aik_public, ctx->prev_aik_public_size);
	*out_size = ctx->prev_aik_public_size;
	return 0;
}

int tpm_read_event_log(uint8_t *buf, size_t buf_size, size_t *out_size)
{
	int fd;
	ssize_t n;
	size_t total = 0;

	if (!buf || !out_size || buf_size == 0)
		return -EINVAL;

	*out_size = 0;

	fd = open(TPM_EVENTLOG_PATH_BIOS, O_RDONLY);
	if (fd < 0)
		return -errno;

	while (total < buf_size) {
		n = read(fd, buf + total, buf_size - total);
		if (n < 0) {
			int err = errno;
			close(fd);
			return -err;
		}
		if (n == 0)
			break;
		total += (size_t)n;
	}

	if (total == buf_size) {
		uint8_t probe;
		n = read(fd, &probe, 1);
		if (n > 0) {
			close(fd);
			*out_size = total;
			return -ENOSPC;
		}
	}

	close(fd);
	*out_size = total;
	return 0;
}

static int tpm_get_prop(struct tpm_context *ctx, TPM2_PT prop,
			uint32_t *out_val)
{
	TSS2_RC rc;
	TPMS_CAPABILITY_DATA *cap_data = NULL;
	TPMI_YES_NO more = TPM2_NO;

	if (!ctx || !ctx->initialized || !out_val)
		return -EINVAL;

	{
		struct esys_get_capability_args args = {
			.esys_ctx = ctx->esys_ctx,
			.capability = TPM2_CAP_TPM_PROPERTIES,
			.property = prop,
			.property_count = 1,
			.more_data_out = &more,
			.capability_data_out = &cap_data,
		};
		int call_ret = tpm_call_with_backoff(ctx,
						     esys_get_capability_thunk,
						     &args, &rc, 1,
						     (void **)&cap_data);
		if (call_ret < 0)
			return call_ret;
	}

	if (cap_data->data.tpmProperties.count == 0 ||
	    cap_data->data.tpmProperties.tpmProperty[0].property != prop) {
		Esys_Free(cap_data);
		return -ENOENT;
	}

	*out_val = cap_data->data.tpmProperties.tpmProperty[0].value;
	Esys_Free(cap_data);
	return 0;
}

static int tpm_nv_read_index(struct tpm_context *ctx, uint32_t index,
			     uint8_t *buf, size_t buf_size, size_t *out_size)
{
	TSS2_RC rc;
	ESYS_TR nv_handle = ESYS_TR_NONE;
	TPM2B_NV_PUBLIC *nv_public = NULL;
	TPM2B_NAME *nv_name = NULL;
	uint32_t max_nv_size = 1024; /* conservative default */
	uint32_t prop_val;
	int ret;

	if (!ctx || !ctx->initialized || !buf || !out_size)
		return -EINVAL;

	*out_size = 0;

	ret = tpm_handle_in_use(ctx, index);
	if (ret < 0)
		return ret;
	if (ret == 0)
		return -ENOENT;

	if (tpm_get_prop(ctx, TPM2_PT_NV_BUFFER_MAX, &prop_val) == 0) {
		max_nv_size = prop_val;
	}

	TPM_CALL_RETRY(ctx, rc,
		       Esys_TR_FromTPMPublic(ctx->esys_ctx, index, ESYS_TR_NONE,
					     ESYS_TR_NONE, ESYS_TR_NONE,
					     &nv_handle));
	if (rc != TSS2_RC_SUCCESS) {
		if (tpm_rc_layer_is_tpm(rc) &&
		    tpm_rc_decode(rc) == TPM2_RC_HANDLE)
			return -ENOENT; /* no certificate at this handle */
		return tss2_rc_to_errno(rc);
	}

	{
		struct esys_nv_read_public_args args = {
			.esys_ctx = ctx->esys_ctx,
			.nv_index = nv_handle,
			.nv_public_out = &nv_public,
			.nv_name_out = &nv_name,
		};
		int call_ret = tpm_call_with_backoff(
			ctx, esys_nv_read_public_thunk, &args, &rc, 2,
			(void **)&nv_public, (void **)&nv_name);
		if (call_ret < 0) {
			tpm_tr_close(ctx, &nv_handle);
			return call_ret;
		}
	}

	size_t data_size = nv_public->nvPublic.dataSize;
	Esys_Free(nv_public);
	Esys_Free(nv_name);

	if (data_size > buf_size) {
		tpm_tr_close(ctx, &nv_handle);
		return -ENOSPC;
	}

	uint16_t offset = 0;
	while (offset < data_size) {
		TPM2B_MAX_NV_BUFFER *nv_data = NULL;
		uint32_t size_to_read = data_size - offset;

		if (size_to_read > max_nv_size)
			size_to_read = max_nv_size;

		{
			struct esys_nv_read_args args = {
				.esys_ctx = ctx->esys_ctx,
				.auth_handle = ESYS_TR_RH_OWNER,
				.nv_index = nv_handle,
				.shandle1 = ESYS_TR_PASSWORD,
				.size = (uint16_t)size_to_read,
				.offset = offset,
				.nv_data_out = &nv_data,
			};
			int call_ret = tpm_call_with_backoff(ctx,
							     esys_nv_read_thunk,
							     &args, &rc, 1,
							     (void **)&nv_data);
			if (call_ret < 0) {
				tpm_tr_close(ctx, &nv_handle);
				return call_ret;
			}
		}

		int chunk_ret =
			lota_tpm_nv_chunk_check(nv_data->size, size_to_read);
		if (chunk_ret < 0) {
			Esys_Free(nv_data);
			tpm_tr_close(ctx, &nv_handle);
			return chunk_ret;
		}

		memcpy(buf + offset, nv_data->buffer, nv_data->size);
		offset += nv_data->size;
		Esys_Free(nv_data);
	}

	tpm_tr_close(ctx, &nv_handle);
	*out_size = data_size;
	return 0;
}

int tpm_get_ek_cert(struct tpm_context *ctx, uint8_t *buf, size_t buf_size,
		    size_t *out_size)
{
	return tpm_nv_read_index(ctx, TPM_EK_CERT_HANDLE, buf, buf_size,
				 out_size);
}

int tpm_get_ek_cert_chain(struct tpm_context *ctx, uint8_t *buf,
			  size_t buf_size, size_t *out_size)
{
	int present;

	if (!ctx || !ctx->initialized || !buf || !out_size)
		return -EINVAL;

	present = tpm_handle_in_use(ctx, TPM_EK_CERT_CHAIN_HANDLE);
	if (present < 0)
		return present;
	if (!present)
		return -ENOENT;

	return tpm_nv_read_index(ctx, TPM_EK_CERT_CHAIN_HANDLE, buf, buf_size,
				 out_size);
}

/*
 * Sealed keys. A secret is sealed under a deterministic restricted storage
 * primary in the owner hierarchy, with an authPolicy that requires the selected
 * PCRs to reproduce their seal-time values. The unseal session is salted by the
 * primary and carries response-parameter encryption, so the released secret is
 * not in clear on the TPM transport.
 */

/*
 * Deterministic restricted storage primary used to wrap sealed objects.
 * unique is left empty so the TPM derives the same key every time from the
 * owner seed and this template, letting unseal recreate it without any
 * persistent handle.
 */
static void seal_primary_template(TPM2B_PUBLIC *pub)
{
	memset(pub, 0, sizeof(*pub));
	pub->publicArea.type = TPM2_ALG_RSA;
	pub->publicArea.nameAlg = TPM2_ALG_SHA256;
	pub->publicArea.objectAttributes =
		TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT |
		TPMA_OBJECT_SENSITIVEDATAORIGIN | TPMA_OBJECT_USERWITHAUTH |
		TPMA_OBJECT_RESTRICTED | TPMA_OBJECT_DECRYPT;
	pub->publicArea.parameters.rsaDetail.symmetric.algorithm = TPM2_ALG_AES;
	pub->publicArea.parameters.rsaDetail.symmetric.keyBits.aes = 128;
	pub->publicArea.parameters.rsaDetail.symmetric.mode.aes = TPM2_ALG_CFB;
	pub->publicArea.parameters.rsaDetail.scheme.scheme = TPM2_ALG_NULL;
	pub->publicArea.parameters.rsaDetail.keyBits = 2048;
	pub->publicArea.parameters.rsaDetail.exponent = 0;
	pub->publicArea.unique.rsa.size = 0;
}

static int seal_create_primary_derive(struct tpm_context *ctx,
				      ESYS_TR *out_handle)
{
	TPM2B_PUBLIC in_public;
	TPM2B_SENSITIVE_CREATE in_sensitive = { .size = 0 };
	TPM2B_DATA outside_info = { .size = 0 };
	TPML_PCR_SELECTION creation_pcr = { .count = 0 };
	TPM2B_PUBLIC *out_public = NULL;
	TPM2B_CREATION_DATA *creation_data = NULL;
	TPM2B_DIGEST *creation_hash = NULL;
	TPMT_TK_CREATION *creation_ticket = NULL;
	TSS2_RC rc;
	int ret;

	seal_primary_template(&in_public);

	struct esys_create_primary_args args = {
		.esys_ctx = ctx->esys_ctx,
		.primary_handle = ESYS_TR_RH_OWNER,
		.shandle1 = ESYS_TR_PASSWORD,
		.in_sensitive = &in_sensitive,
		.in_public = &in_public,
		.outside_info = &outside_info,
		.creation_pcr = &creation_pcr,
		.object_handle_out = out_handle,
		.out_public_out = &out_public,
		.creation_data_out = &creation_data,
		.creation_hash_out = &creation_hash,
		.creation_ticket_out = &creation_ticket,
	};
	ret = tpm_call_with_backoff(ctx, esys_create_primary_thunk, &args, &rc,
				    4, (void **)&out_public,
				    (void **)&creation_data,
				    (void **)&creation_hash,
				    (void **)&creation_ticket);
	Esys_Free(out_public);
	Esys_Free(creation_data);
	Esys_Free(creation_hash);
	Esys_Free(creation_ticket);
	return ret;
}

/*
 * Resolve the persistent seal storage primary at TPM_SEAL_PRIMARY_HANDLE.
 * Returns 1 and sets *out_handle when present, 0 when absent, negative errno
 * on error.
 */
static int seal_primary_lookup_persistent(struct tpm_context *ctx,
					  ESYS_TR *out_handle)
{
	ESYS_TR handle = ESYS_TR_NONE;
	TSS2_RC rc;
	int ret;

	ret = tpm_handle_in_use(ctx, TPM_SEAL_PRIMARY_HANDLE);
	if (ret < 0)
		return ret;
	if (ret == 0)
		return 0;

	TPM_CALL_RETRY(ctx, rc,
		       Esys_TR_FromTPMPublic(ctx->esys_ctx,
					     TPM_SEAL_PRIMARY_HANDLE,
					     ESYS_TR_NONE, ESYS_TR_NONE,
					     ESYS_TR_NONE, &handle));
	if (rc == TSS2_RC_SUCCESS) {
		*out_handle = handle;
		return 1;
	}
	if (tpm_rc_layer_is_tpm(rc) && tpm_rc_decode(rc) == TPM2_RC_HANDLE)
		return 0;
	return tss2_rc_to_errno(rc);
}

/*
 * Acquire a seal storage primary. When the operator opted into a persistent
 * primary and one exists, reuse it (no CreatePrimary); otherwise derive it
 * per op. *persistent records which, so the caller releases it correctly.
 */
static int seal_acquire_primary(struct tpm_context *ctx, ESYS_TR *out_handle,
				bool *persistent)
{
	*persistent = false;

	if (ctx->seal_persistent_primary) {
		int ret = seal_primary_lookup_persistent(ctx, out_handle);
		if (ret < 0)
			return ret;
		if (ret == 1) {
			*persistent = true;
			return 0;
		}
	}
	return seal_create_primary_derive(ctx, out_handle);
}

/*
 * Release a primary obtained from seal_acquire_primary().
 * A derived (transient) primary is flushed; a persistent one is only detached
 * from the ESYS context (Esys_TR_Close) -- flushing a persistent object is an
 * error and would not evict it anyway.
 */
static void seal_release_primary(struct tpm_context *ctx, ESYS_TR handle,
				 bool persistent)
{
	if (handle == ESYS_TR_NONE)
		return;
	if (persistent)
		tpm_tr_close(ctx, &handle);
	else
		Esys_FlushContext(ctx->esys_ctx, handle);
}

/* Build a single-bank SHA-256 PCR selection from a LOTA PCR mask. */
static void seal_mask_to_selection(uint32_t pcr_mask, TPML_PCR_SELECTION *sel)
{
	memset(sel, 0, sizeof(*sel));
	sel->count = 1;
	sel->pcrSelections[0].hash = TPM_HASH_ALG;
	sel->pcrSelections[0].sizeofSelect = 3;
	for (uint32_t i = 0; i < LOTA_PCR_COUNT; i++) {
		if (pcr_mask & (1U << i))
			sel->pcrSelections[0].pcrSelect[i / 8] |=
				(uint8_t)(1U << (i % 8));
	}
}

struct esys_create_args {
	ESYS_CONTEXT *esys_ctx;
	ESYS_TR parent;
	ESYS_TR shandle1;
	const TPM2B_SENSITIVE_CREATE *in_sensitive;
	const TPM2B_PUBLIC *in_public;
	const TPM2B_DATA *outside_info;
	const TPML_PCR_SELECTION *creation_pcr;
	TPM2B_PRIVATE **out_private_out;
	TPM2B_PUBLIC **out_public_out;
	TPM2B_CREATION_DATA **creation_data_out;
	TPM2B_DIGEST **creation_hash_out;
	TPMT_TK_CREATION **creation_ticket_out;
};

static TSS2_RC esys_create_thunk(void *u)
{
	struct esys_create_args *a = u;
	return Esys_Create(a->esys_ctx, a->parent, a->shandle1, ESYS_TR_NONE,
			   ESYS_TR_NONE, a->in_sensitive, a->in_public,
			   a->outside_info, a->creation_pcr, a->out_private_out,
			   a->out_public_out, a->creation_data_out,
			   a->creation_hash_out, a->creation_ticket_out);
}

struct esys_policy_get_digest_args {
	ESYS_CONTEXT *esys_ctx;
	ESYS_TR session;
	TPM2B_DIGEST **digest_out;
};

static TSS2_RC esys_policy_get_digest_thunk(void *u)
{
	struct esys_policy_get_digest_args *a = u;
	return Esys_PolicyGetDigest(a->esys_ctx, a->session, ESYS_TR_NONE,
				    ESYS_TR_NONE, ESYS_TR_NONE, a->digest_out);
}

struct esys_unseal_args {
	ESYS_CONTEXT *esys_ctx;
	ESYS_TR item;
	ESYS_TR session;
	TPM2B_SENSITIVE_DATA **data_out;
};

static TSS2_RC esys_unseal_thunk(void *u)
{
	struct esys_unseal_args *a = u;
	return Esys_Unseal(a->esys_ctx, a->item, a->session, ESYS_TR_NONE,
			   ESYS_TR_NONE, a->data_out);
}

/*
 * Compute the authPolicy digest a sealed object must carry to require the
 * given PCR selection. A trial policy session folds the current PCR values
 * into the digest; the same PolicyPCR at unseal time only reproduces it
 * when the PCRs match.
 */
static int seal_compute_policy_digest(struct tpm_context *ctx,
				      const TPML_PCR_SELECTION *sel,
				      TPM2B_DIGEST *out_policy)
{
	TPMT_SYM_DEF sym = { .algorithm = TPM2_ALG_NULL };
	ESYS_TR session = ESYS_TR_NONE;
	TPM2B_DIGEST *policy = NULL;
	TSS2_RC rc;
	int ret;

	TPM_CALL_RETRY(ctx, rc,
		       Esys_StartAuthSession(
			       ctx->esys_ctx, ESYS_TR_NONE, ESYS_TR_NONE,
			       ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, NULL,
			       TPM2_SE_TRIAL, &sym, TPM2_ALG_SHA256, &session));
	if (rc != TSS2_RC_SUCCESS)
		return tss2_rc_to_errno(rc);

	TPM_CALL_RETRY(ctx, rc,
		       Esys_PolicyPCR(ctx->esys_ctx, session, ESYS_TR_NONE,
				      ESYS_TR_NONE, ESYS_TR_NONE, NULL, sel));
	if (rc != TSS2_RC_SUCCESS) {
		ret = tss2_rc_to_errno(rc);
		goto out;
	}

	{
		struct esys_policy_get_digest_args args = {
			.esys_ctx = ctx->esys_ctx,
			.session = session,
			.digest_out = &policy,
		};
		ret = tpm_call_with_backoff(ctx, esys_policy_get_digest_thunk,
					    &args, &rc, 1, (void **)&policy);
		if (ret < 0)
			goto out;
	}

	if (policy->size > sizeof(out_policy->buffer)) {
		ret = -EOVERFLOW;
		goto out;
	}
	out_policy->size = policy->size;
	memcpy(out_policy->buffer, policy->buffer, policy->size);
	ret = 0;
out:
	Esys_Free(policy);
	if (session != ESYS_TR_NONE)
		Esys_FlushContext(ctx->esys_ctx, session);
	return ret;
}

/*
 * Diagnostic composite: SHA-256 over the selected PCR values in ascending
 * index order. Recorded in the blob so an operator can see which PCR state
 * a secret was sealed against. Not security-critical; the authPolicy is
 * the binding.
 */
static int seal_compute_pcr_digest(struct tpm_context *ctx, uint32_t pcr_mask,
				   uint8_t out[LOTA_SEAL_PCR_DIGEST_SIZE])
{
	EVP_MD_CTX *md = EVP_MD_CTX_new();
	unsigned int out_len = LOTA_SEAL_PCR_DIGEST_SIZE;
	int ret = -EIO;

	if (!md)
		return -ENOMEM;
	if (EVP_DigestInit_ex(md, EVP_sha256(), NULL) != 1)
		goto out;

	for (uint32_t i = 0; i < LOTA_PCR_COUNT; i++) {
		uint8_t value[LOTA_HASH_SIZE];
		if (!(pcr_mask & (1U << i)))
			continue;
		ret = tpm_read_pcr(ctx, i, TPM_HASH_ALG, value);
		if (ret < 0)
			goto out;
		if (EVP_DigestUpdate(md, value, sizeof(value)) != 1) {
			ret = -EIO;
			goto out;
		}
	}

	if (EVP_DigestFinal_ex(md, out, &out_len) != 1) {
		ret = -EIO;
		goto out;
	}
	ret = 0;
out:
	EVP_MD_CTX_free(md);
	return ret;
}

int tpm_seal_secret(struct tpm_context *ctx, const uint8_t *secret,
		    size_t secret_len, uint32_t pcr_mask, uint8_t *out,
		    size_t out_cap, size_t *out_len)
{
	ESYS_TR primary = ESYS_TR_NONE;
	bool primary_persistent = false;
	TPM2B_PUBLIC in_public = { .size = 0 };
	TPM2B_SENSITIVE_CREATE in_sensitive = { .size = 0 };
	TPM2B_DATA outside_info = { .size = 0 };
	TPML_PCR_SELECTION creation_pcr = { .count = 0 };
	TPML_PCR_SELECTION sel;
	TPM2B_DIGEST policy = { .size = 0 };
	TPM2B_PRIVATE *out_private = NULL;
	TPM2B_PUBLIC *out_public = NULL;
	TPM2B_CREATION_DATA *creation_data = NULL;
	TPM2B_DIGEST *creation_hash = NULL;
	TPMT_TK_CREATION *creation_ticket = NULL;
	uint8_t pub_buf[LOTA_SEAL_MAX_PUB];
	uint8_t priv_buf[LOTA_SEAL_MAX_PRIV];
	size_t pub_off = 0, priv_off = 0;
	struct lota_seal_meta meta;
	TSS2_RC rc;
	int ret;

	if (!ctx || !ctx->esys_ctx || !ctx->initialized || !secret || !out ||
	    !out_len)
		return -EINVAL;
	if (secret_len == 0 || secret_len > LOTA_SEAL_MAX_SECRET)
		return -EINVAL;
	if (pcr_mask == 0)
		pcr_mask = LOTA_SEAL_DEFAULT_PCR_MASK;
	if (lota_seal_validate_pcr_mask(pcr_mask) != 0)
		return -EINVAL;

	seal_mask_to_selection(pcr_mask, &sel);

	ret = seal_acquire_primary(ctx, &primary, &primary_persistent);
	if (ret < 0)
		return ret;

	ret = seal_compute_policy_digest(ctx, &sel, &policy);
	if (ret < 0)
		goto out;

	in_public.publicArea.type = TPM2_ALG_KEYEDHASH;
	in_public.publicArea.nameAlg = TPM2_ALG_SHA256;
	in_public.publicArea.objectAttributes = TPMA_OBJECT_FIXEDTPM |
						TPMA_OBJECT_FIXEDPARENT;
	in_public.publicArea.authPolicy.size = policy.size;
	memcpy(in_public.publicArea.authPolicy.buffer, policy.buffer,
	       policy.size);
	in_public.publicArea.parameters.keyedHashDetail.scheme.scheme =
		TPM2_ALG_NULL;

	in_sensitive.sensitive.userAuth.size = 0;
	in_sensitive.sensitive.data.size = (uint16_t)secret_len;
	memcpy(in_sensitive.sensitive.data.buffer, secret, secret_len);

	{
		struct esys_create_args args = {
			.esys_ctx = ctx->esys_ctx,
			.parent = primary,
			.shandle1 = ESYS_TR_PASSWORD,
			.in_sensitive = &in_sensitive,
			.in_public = &in_public,
			.outside_info = &outside_info,
			.creation_pcr = &creation_pcr,
			.out_private_out = &out_private,
			.out_public_out = &out_public,
			.creation_data_out = &creation_data,
			.creation_hash_out = &creation_hash,
			.creation_ticket_out = &creation_ticket,
		};
		ret = tpm_call_with_backoff(ctx, esys_create_thunk, &args, &rc,
					    5, (void **)&out_private,
					    (void **)&out_public,
					    (void **)&creation_data,
					    (void **)&creation_hash,
					    (void **)&creation_ticket);
		if (ret < 0)
			goto out;
	}

	rc = Tss2_MU_TPM2B_PUBLIC_Marshal(out_public, pub_buf, sizeof(pub_buf),
					  &pub_off);
	if (rc != TSS2_RC_SUCCESS || pub_off == 0) {
		ret = -EIO;
		goto out;
	}
	rc = Tss2_MU_TPM2B_PRIVATE_Marshal(out_private, priv_buf,
					   sizeof(priv_buf), &priv_off);
	if (rc != TSS2_RC_SUCCESS || priv_off == 0) {
		ret = -EIO;
		goto out;
	}

	memset(&meta, 0, sizeof(meta));
	meta.pcr_mask = pcr_mask;
	meta.pcr_alg = LOTA_SEAL_PCR_ALG_SHA256;
	meta.pub_len = (uint16_t)pub_off;
	meta.priv_len = (uint16_t)priv_off;
	ret = seal_compute_pcr_digest(ctx, pcr_mask, meta.pcr_digest);
	if (ret < 0)
		goto out;

	{
		size_t total =
			(size_t)LOTA_SEAL_HEADER_SIZE + pub_off + priv_off;
		if (total > out_cap) {
			ret = -ENOSPC;
			goto out;
		}
		ret = lota_seal_serialize_header(out, &meta);
		if (ret < 0)
			goto out;
		memcpy(out + LOTA_SEAL_HEADER_SIZE, pub_buf, pub_off);
		memcpy(out + LOTA_SEAL_HEADER_SIZE + pub_off, priv_buf,
		       priv_off);
		*out_len = total;
		ret = 0;
	}

out:
	secure_bzero(in_sensitive.sensitive.data.buffer,
		     sizeof(in_sensitive.sensitive.data.buffer));
	secure_bzero(priv_buf, sizeof(priv_buf));
	Esys_Free(out_private);
	Esys_Free(out_public);
	Esys_Free(creation_data);
	Esys_Free(creation_hash);
	Esys_Free(creation_ticket);
	seal_release_primary(ctx, primary, primary_persistent);
	return ret;
}

int tpm_unseal_secret(struct tpm_context *ctx, const uint8_t *blob,
		      size_t blob_len, uint8_t *out_secret, size_t out_cap,
		      size_t *out_len)
{
	struct lota_seal_meta meta;
	size_t body_off = 0;
	TPM2B_PUBLIC sealed_public = { .size = 0 };
	TPM2B_PRIVATE sealed_private = { .size = 0 };
	TPML_PCR_SELECTION sel;
	ESYS_TR primary = ESYS_TR_NONE;
	bool primary_persistent = false;
	ESYS_TR sealed = ESYS_TR_NONE;
	ESYS_TR session = ESYS_TR_NONE;
	TPM2B_SENSITIVE_DATA *data = NULL;
	TPMT_SYM_DEF sym = {
		.algorithm = TPM2_ALG_AES,
		.keyBits.aes = 128,
		.mode.aes = TPM2_ALG_CFB,
	};
	size_t off;
	TSS2_RC rc;
	int ret;

	if (!ctx || !ctx->esys_ctx || !ctx->initialized || !blob ||
	    !out_secret || !out_len)
		return -EINVAL;

	ret = lota_seal_parse_header(blob, blob_len, &meta, &body_off);
	if (ret < 0)
		return ret;

	/* a body that does not unmarshal is a bad file: -EBADMSG, not -EINVAL */
	off = body_off;
	rc = Tss2_MU_TPM2B_PUBLIC_Unmarshal(blob, blob_len, &off,
					    &sealed_public);
	if (rc != TSS2_RC_SUCCESS || off != body_off + meta.pub_len)
		return -EBADMSG;
	rc = Tss2_MU_TPM2B_PRIVATE_Unmarshal(blob, blob_len, &off,
					     &sealed_private);
	if (rc != TSS2_RC_SUCCESS || off != blob_len)
		return -EBADMSG;

	seal_mask_to_selection(meta.pcr_mask, &sel);

	ret = seal_acquire_primary(ctx, &primary, &primary_persistent);
	if (ret < 0)
		return ret;

	TPM_CALL_RETRY(ctx, rc,
		       Esys_Load(ctx->esys_ctx, primary, ESYS_TR_PASSWORD,
				 ESYS_TR_NONE, ESYS_TR_NONE, &sealed_private,
				 &sealed_public, &sealed));
	if (rc != TSS2_RC_SUCCESS) {
		ret = tss2_rc_to_errno(rc);
		goto out;
	}

	/*
	 * Policy session salted by the primary and carrying response-parameter
	 * encryption, so the unsealed secret is encrypted on the TPM transport.
	 */
	TPM_CALL_RETRY(ctx, rc,
		       Esys_StartAuthSession(ctx->esys_ctx, primary,
					     ESYS_TR_NONE, ESYS_TR_NONE,
					     ESYS_TR_NONE, ESYS_TR_NONE, NULL,
					     TPM2_SE_POLICY, &sym,
					     TPM2_ALG_SHA256, &session));
	if (rc != TSS2_RC_SUCCESS) {
		ret = tss2_rc_to_errno(rc);
		goto out;
	}

	TPM_CALL_RETRY(ctx, rc,
		       Esys_TRSess_SetAttributes(ctx->esys_ctx, session,
						 TPMA_SESSION_CONTINUESESSION |
							 TPMA_SESSION_ENCRYPT,
						 TPMA_SESSION_CONTINUESESSION |
							 TPMA_SESSION_ENCRYPT));
	if (rc != TSS2_RC_SUCCESS) {
		ret = tss2_rc_to_errno(rc);
		goto out;
	}

	TPM_CALL_RETRY(ctx, rc,
		       Esys_PolicyPCR(ctx->esys_ctx, session, ESYS_TR_NONE,
				      ESYS_TR_NONE, ESYS_TR_NONE, NULL, &sel));
	if (rc != TSS2_RC_SUCCESS) {
		ret = tss2_rc_to_errno(rc);
		goto out;
	}

	{
		struct esys_unseal_args args = {
			.esys_ctx = ctx->esys_ctx,
			.item = sealed,
			.session = session,
			.data_out = &data,
		};
		ret = tpm_call_with_backoff(ctx, esys_unseal_thunk, &args, &rc,
					    1, (void **)&data);
		if (ret < 0)
			goto out;
	}

	if (data->size > out_cap) {
		ret = -ENOSPC;
		goto out;
	}
	memcpy(out_secret, data->buffer, data->size);
	*out_len = data->size;
	ret = 0;

out:
	if (data) {
		secure_bzero(data->buffer, sizeof(data->buffer));
		Esys_Free(data);
	}
	if (session != ESYS_TR_NONE)
		Esys_FlushContext(ctx->esys_ctx, session);
	if (sealed != ESYS_TR_NONE)
		Esys_FlushContext(ctx->esys_ctx, sealed);
	seal_release_primary(ctx, primary, primary_persistent);
	return ret;
}

int tpm_seal_secret_envelope(struct tpm_context *ctx, const uint8_t *payload,
			     size_t payload_len, uint32_t pcr_mask,
			     uint8_t *out, size_t out_cap, size_t *out_len)
{
	uint8_t kek[LOTA_ENVELOPE_KEK_SIZE];
	uint8_t kek_blob[LOTA_SEAL_MAX_BLOB];
	size_t kek_blob_len = 0;
	struct lota_envelope_meta meta;
	const size_t header_off = LOTA_ENVELOPE_HEADER_SIZE;
	size_t total;
	int ret;

	if (!ctx || !ctx->esys_ctx || !ctx->initialized || !payload || !out ||
	    !out_len)
		return -EINVAL;
	if (payload_len == 0 || payload_len > LOTA_ENVELOPE_MAX_PAYLOAD)
		return -EINVAL;
	if (pcr_mask == 0)
		pcr_mask = LOTA_SEAL_DEFAULT_PCR_MASK;
	if (lota_seal_validate_pcr_mask(pcr_mask) != 0)
		return -EINVAL;

	memset(&meta, 0, sizeof(meta));
	if (RAND_bytes(kek, sizeof(kek)) != 1)
		return -EIO;
	if (RAND_bytes(meta.nonce, sizeof(meta.nonce)) != 1) {
		ret = -EIO;
		goto out_kek;
	}

	ret = tpm_seal_secret(ctx, kek, sizeof(kek), pcr_mask, kek_blob,
			      sizeof(kek_blob), &kek_blob_len);
	if (ret < 0)
		goto out_kek;
	if (kek_blob_len == 0 || kek_blob_len > LOTA_SEAL_MAX_BLOB) {
		ret = -EIO;
		goto out_kek;
	}

	meta.kek_blob_len = (uint16_t)kek_blob_len;
	meta.payload_len = (uint32_t)payload_len;

	total = header_off + kek_blob_len + payload_len;
	if (total > out_cap) {
		ret = -ENOSPC;
		goto out_kek;
	}

	/*
	 * Lay out header (tag still zero) then the sealed-KEK blob, then feed
	 * both as AEAD additional data so neither the framing nor the bound
	 * KEK can be swapped without failing the tag check at open time.
	 */
	ret = lota_envelope_serialize_header(out, &meta);
	if (ret < 0)
		goto out_kek;
	memcpy(out + header_off, kek_blob, kek_blob_len);

	ret = lota_envelope_aead_seal(
		kek, meta.nonce, out, header_off + kek_blob_len, payload,
		payload_len, out + header_off + kek_blob_len, meta.tag);
	if (ret < 0)
		goto out_kek;

	memcpy(out + 28, meta.tag, LOTA_ENVELOPE_TAG_SIZE);
	*out_len = total;
	ret = 0;

out_kek:
	secure_bzero(kek, sizeof(kek));
	return ret;
}

int tpm_unseal_secret_envelope(struct tpm_context *ctx, const uint8_t *blob,
			       size_t blob_len, uint8_t *out, size_t out_cap,
			       size_t *out_len)
{
	struct lota_envelope_meta meta;
	size_t body_off = 0;
	uint8_t kek[LOTA_ENVELOPE_KEK_SIZE];
	size_t kek_len = 0;
	uint8_t aad[LOTA_ENVELOPE_HEADER_SIZE + LOTA_SEAL_MAX_BLOB];
	size_t aad_len;
	const uint8_t *kek_blob;
	const uint8_t *ct;
	int ret;

	if (!ctx || !ctx->esys_ctx || !ctx->initialized || !blob || !out ||
	    !out_len)
		return -EINVAL;

	ret = lota_envelope_parse_header(blob, blob_len, &meta, &body_off);
	if (ret < 0)
		return ret;
	if (meta.payload_len > out_cap)
		return -ENOSPC;

	kek_blob = blob + body_off;
	ct = blob + body_off + meta.kek_blob_len;

	ret = tpm_unseal_secret(ctx, kek_blob, meta.kek_blob_len, kek,
				sizeof(kek), &kek_len);
	if (ret < 0)
		return ret;
	if (kek_len != LOTA_ENVELOPE_KEK_SIZE) {
		ret = -EINVAL;
		goto out_kek;
	}

	/*
	 * Rebuild the AAD exactly as the seal path authenticated it: the
	 * header with its tag field zeroed, followed by the sealed-KEK blob.
	 */
	aad_len = body_off + meta.kek_blob_len;
	memcpy(aad, blob, aad_len);
	memset(aad + 28, 0, LOTA_ENVELOPE_TAG_SIZE);

	ret = lota_envelope_aead_open(kek, meta.nonce, aad, aad_len, ct,
				      meta.payload_len, meta.tag, out);
	if (ret < 0)
		goto out_kek;

	*out_len = meta.payload_len;
	ret = 0;

out_kek:
	secure_bzero(kek, sizeof(kek));
	return ret;
}

int tpm_seal_persist_primary(struct tpm_context *ctx, bool *already)
{
	ESYS_TR primary = ESYS_TR_NONE;
	ESYS_TR existing = ESYS_TR_NONE;
	ESYS_TR persistent = ESYS_TR_NONE;
	TSS2_RC rc;
	int ret;

	if (already)
		*already = false;
	if (!ctx || !ctx->esys_ctx || !ctx->initialized)
		return -EINVAL;

	ret = seal_primary_lookup_persistent(ctx, &existing);
	if (ret < 0)
		return ret;
	if (ret == 1) {
		tpm_tr_close(ctx, &existing);
		if (already)
			*already = true;
		return 0;
	}

	ret = seal_create_primary_derive(ctx, &primary);
	if (ret < 0)
		return ret;

	TPM_CALL_RETRY(ctx, rc,
		       Esys_EvictControl(ctx->esys_ctx, ESYS_TR_RH_OWNER,
					 primary, ESYS_TR_PASSWORD,
					 ESYS_TR_NONE, ESYS_TR_NONE,
					 TPM_SEAL_PRIMARY_HANDLE, &persistent));
	Esys_FlushContext(ctx->esys_ctx, primary);
	if (rc != TSS2_RC_SUCCESS)
		return tss2_rc_to_errno(rc);

	tpm_tr_close(ctx, &persistent);
	return 0;
}

int tpm_evict_profile_aik(struct tpm_context *ctx, uint32_t handle)
{
	ESYS_TR existing = ESYS_TR_NONE;
	ESYS_TR persistent = ESYS_TR_NONE;
	TSS2_RC rc;
	int ret;

	if (!ctx || !ctx->esys_ctx || !ctx->initialized || handle == 0)
		return -EINVAL;

	ret = tpm_handle_in_use(ctx, handle);
	if (ret < 0)
		return ret;
	if (ret == 0)
		return -ENOENT;

	TPM_CALL_RETRY(ctx, rc,
		       Esys_TR_FromTPMPublic(ctx->esys_ctx, handle,
					     ESYS_TR_NONE, ESYS_TR_NONE,
					     ESYS_TR_NONE, &existing));
	if (rc != TSS2_RC_SUCCESS)
		return tss2_rc_to_errno(rc);

	TPM_CALL_RETRY(ctx, rc,
		       Esys_EvictControl(ctx->esys_ctx, ESYS_TR_RH_OWNER,
					 existing, ESYS_TR_PASSWORD,
					 ESYS_TR_NONE, ESYS_TR_NONE, handle,
					 &persistent));
	if (rc != TSS2_RC_SUCCESS) {
		tpm_tr_close(ctx, &existing);
		return tss2_rc_to_errno(rc);
	}

	tpm_tr_close(ctx, &persistent);
	return 0;
}

int tpm_seal_evict_primary(struct tpm_context *ctx)
{
	ESYS_TR existing = ESYS_TR_NONE;
	ESYS_TR persistent = ESYS_TR_NONE;
	TSS2_RC rc;
	int ret;

	if (!ctx || !ctx->esys_ctx || !ctx->initialized)
		return -EINVAL;

	ret = seal_primary_lookup_persistent(ctx, &existing);
	if (ret < 0)
		return ret;
	if (ret == 0)
		return -ENOENT;

	TPM_CALL_RETRY(ctx, rc,
		       Esys_EvictControl(ctx->esys_ctx, ESYS_TR_RH_OWNER,
					 existing, ESYS_TR_PASSWORD,
					 ESYS_TR_NONE, ESYS_TR_NONE,
					 TPM_SEAL_PRIMARY_HANDLE, &persistent));
	if (rc != TSS2_RC_SUCCESS) {
		tpm_tr_close(ctx, &existing);
		return tss2_rc_to_errno(rc);
	}

	tpm_tr_close(ctx, &persistent);
	return 0;
}

#ifdef LOTA_TPM_TESTING
int tpm_test_rc_is_stale_object_record(uint32_t rc)
{
	return tss2_rc_is_stale_object_record((TSS2_RC)rc) ? 1 : 0;
}

int tpm_test_aik_object_changed(const uint8_t *seen, uint16_t seen_len,
				const uint8_t *live, uint16_t live_len)
{
	return aik_object_changed(seen, seen_len, live, live_len) ? 1 : 0;
}

int tpm_test_aik_binding_survives(const char *bound_id, uint32_t bound_handle,
				  const char *new_id, uint32_t new_handle)
{
	return aik_binding_survives(bound_id, bound_handle, new_id,
				    new_handle) ?
		       1 :
		       0;
}

int tpm_test_pcr_mask_to_selection(uint32_t pcr_mask, uint8_t out_select[3],
				   uint32_t *out_count)
{
	TPML_PCR_SELECTION sel;

	if (!out_select || !out_count)
		return -EINVAL;
	seal_mask_to_selection(pcr_mask, &sel);
	if (sel.count != 1)
		return -EINVAL;
	out_select[0] = sel.pcrSelections[0].pcrSelect[0];
	out_select[1] = sel.pcrSelections[0].pcrSelect[1];
	out_select[2] = sel.pcrSelections[0].pcrSelect[2];
	*out_count = sel.count;
	return 0;
}

int tpm_test_aik_save_auth(struct tpm_context *ctx,
			   const uint8_t auth[TPM_AIK_AUTH_SIZE])
{
	return tpm_aik_save_auth(ctx, auth);
}

int tpm_test_aik_load_auth(struct tpm_context *ctx)
{
	return tpm_aik_load_auth(ctx);
}

int tpm_test_aik_plaintext_path(struct tpm_context *ctx, char *buf, size_t len)
{
	return tpm_aik_auth_path_for_ctx(ctx, buf, len);
}

int tpm_test_aik_sealed_path(struct tpm_context *ctx, char *buf, size_t len)
{
	return tpm_aik_auth_sealed_path_for_ctx(ctx, buf, len);
}

int tpm_test_aik_auth_record_exists(struct tpm_context *ctx)
{
	return tpm_aik_auth_record_exists(ctx);
}
#endif /* LOTA_TPM_TESTING */
