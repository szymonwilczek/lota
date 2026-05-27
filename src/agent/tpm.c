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
#include <openssl/encoder.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

#include <tss2/tss2_esys.h>
#include <tss2/tss2_mu.h>
#include <tss2/tss2_tcti.h>
#include <tss2/tss2_tcti_device.h>
#include <tss2/tss2_tctildr.h>

#include "quote.h"
#include "tpm.h"

/* Read buffer size for file hashing */
#define HASH_READ_BUF_SIZE (64 * 1024)

static int tpm_get_prop(struct tpm_context *ctx, TPM2_PT prop,
			uint32_t *out_val);
static int tpm_aik_load_auth(struct tpm_context *ctx);
static int tpm_aik_save_auth(struct tpm_context *ctx,
			     const uint8_t auth[TPM_AIK_AUTH_SIZE]);
static int tpm_aik_generate_auth(uint8_t auth[TPM_AIK_AUTH_SIZE]);
static int tpm_aik_reprovision_with_auth(struct tpm_context *ctx,
					 int had_existing_aik);
static int mkdirs(const char *path, mode_t mode);

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

/*
 * TPM 2.0 return-code dispatch.
 *
 * The TSS2 stack layers status into the high byte of TSS2_RC (bits 16-23);
 * resource manager and TPM-origin codes are accepted, anything else is
 * treated as opaque transport failure. Format-1 TPM codes embed parameter,
 * handle, and session indices in bits 6-11; the dispatch strips that
 * scratch space so callers can pattern-match against the bare TCG code.
 */

#define TPM_RC_LAYER_MASK 0x00FF0000U
#define TPM_RC_CODE_MASK 0x0000FFFFU
#define TPM_RC_FMT1_BIT 0x080U
#define TPM_RC_FMT1_BASE_MASK 0x0BFU /* bits 0-5 + FMT1 indicator */

/*
 * Backoff parameters for transient TPM errors (RETRY/YIELDED/NV_RATE/...).
 *
 * TPM_RETRY_MAX_ATTEMPTS caps the geometric retry count. TPM_RETRY_BASE_MS
 * is the first sleep, doubled on each retry up to TPM_RETRY_CAP_MS. The
 * cumulative sleep over MAX_ATTEMPTS attempts is also bounded by
 * TPM_RETRY_BUDGET_MS so a single tpm_call_with_backoff() invocation
 * cannot consume an unbounded slice of the systemd WatchdogSec= window.
 * Pinging the watchdog from inside the backoff loop would lie to
 * systemd while the process is wedged; clamping the budget instead
 * lets the daemon loop's existing inter-round ping fire on schedule.
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

/*
 * Helper: Convert TSS2 return code to errno.
 *
 * LOCKOUT is surfaced as -LOTA_ERR_TPM_LOCKED, a LOTA-private value
 * documented in tpm.h. The POSIX errno table has no entry that
 * honestly describes a TPM dictionary-attack lockout: -EOWNERDEAD
 * means "robust mutex owner died" and would mislead anyone reading
 * strace output or syslog, -EACCES is associated with file-
 * permission failures. The private code lives outside the 1..4095
 * range glibc/kernel use so it cannot collide; log sites print it
 * via tpm_strerror() and dispatch sites use the tpm_is_locked_out()
 * predicate that inspects the sticky TSS2_RC, not the errno return.
 *
 * Transient codes map to -EAGAIN; format-1 auth/handle/value errors
 * keep their familiar errno mapping.
 */
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
		/*
		 * Every auth failure also bumps the TPM dictionary-attack
		 * counter; repeated occurrences walk the platform into
		 * TPM2_RC_LOCKOUT. Surfacing the dedicated LOTA code instead
		 * of -EACCES keeps operator triage on the right runbook (audit
		 * the caller's auth source, do not blame SELinux) and lets the
		 * tpm_strerror() log line call out the DA-counter implication.
		 */
		return -LOTA_ERR_TPM_AUTH_FAIL;
	case TPM2_RC_VALUE:
	case TPM2_RC_SIZE:
		return -EINVAL;
	default:
		return -EIO;
	}
}

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
	default:
		return strerror(code);
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

static void tpm_clear_lockout(struct tpm_context *ctx)
{
	if (!ctx || !ctx->lockout_active)
		return;

	ctx->lockout_active = false;
	ctx->lockout_first_seen = 0;
}

/*
 * Run an Esys_* call with retry/backoff for transient errors and sticky
 * lockout accounting. Non-transient errors break the loop immediately so
 * the caller can dispatch on the returned TSS2_RC.
 *
 * ctx_ may be NULL when invoked from contexts that do not yet hold a
 * struct tpm_context (e.g. early initialization).
 *
 * The macro is restricted to Esys_* calls that do NOT populate
 * heap-allocated TSS2 output pointers (Esys_PCR_Extend, Esys_SelfTest,
 * Esys_TR_SetAuth, Esys_TR_FromTPMPublic, Esys_EvictControl). Call
 * sites that receive allocated outputs (Esys_PCR_Read, Esys_Quote,
 * Esys_ReadClock, Esys_ReadPublic, Esys_NV_*, Esys_GetCapability,
 * Esys_CreatePrimary) MUST use tpm_call_with_backoff() so a transient
 * retry frees the previous allocation instead of overwriting the
 * pointer and leaking it.
 */
#define TPM_CALL_RETRY(ctx_, rc_var_, expr_)                                   \
	do {                                                                   \
		unsigned _tpm_attempt = 0;                                     \
		unsigned _tpm_budget_ms = 0;                                   \
		for (;;) {                                                     \
			(rc_var_) = (expr_);                                   \
			if ((rc_var_) == TSS2_RC_SUCCESS) {                    \
				tpm_clear_lockout((ctx_));                     \
				break;                                         \
			}                                                      \
			if (tss2_rc_is_lockout((rc_var_))) {                   \
				tpm_record_lockout((ctx_));                    \
				break;                                         \
			}                                                      \
			if (!tss2_rc_is_transient((rc_var_)) ||                \
			    _tpm_attempt >= TPM_RETRY_MAX_ATTEMPTS)            \
				break;                                         \
			{                                                      \
				unsigned _tpm_next_ms =                        \
				    tpm_backoff_ms(_tpm_attempt);              \
				if (_tpm_budget_ms + _tpm_next_ms >            \
				    TPM_RETRY_BUDGET_MS)                       \
					break;                                 \
				tpm_sleep_ms(_tpm_next_ms);                    \
				_tpm_budget_ms += _tpm_next_ms;                \
			}                                                      \
			_tpm_attempt++;                                        \
		}                                                              \
	} while (0)

/*
 * Output-slot capacity for tpm_call_with_backoff(). Esys_CreatePrimary
 * publishes four allocated pointers (outPublic, creationData,
 * creationHash, creationTicket); other Esys_* calls use fewer. Bump
 * if a future TSS2 entry point exceeds this.
 */
#define LOTA_TPM_MAX_OUT_SLOTS 8U

/*
 * Caller-supplied callback that issues a single Esys_*() invocation
 * and returns the raw TSS2_RC. The cookie is forwarded verbatim from
 * tpm_call_with_backoff() so call sites can bundle the TSS2 arguments
 * into a small per-site struct without resorting to global state.
 */
typedef TSS2_RC (*tpm_esys_thunk)(void *userdata);

/*
 * tpm_call_with_backoff - retry an Esys_* invocation while keeping
 * heap-allocated TSS2 output pointers leak-free.
 *
 * @ctx:        TPM context; lockout sticky-state accounting is folded
 *              in. May be NULL when called pre-init.
 * @thunk:      Issues the actual Esys_* call. Returns the raw TSS2_RC.
 * @userdata:   Threaded into @thunk verbatim.
 * @out_rc:     Optional. On return, holds the last TSS2_RC observed
 *              (success, lockout, or the last non-transient code).
 * @out_slot_count: Number of variadic void** slots that follow. Must
 *              not exceed LOTA_TPM_MAX_OUT_SLOTS.
 * @...:        @out_slot_count void** pointers. Each points at a
 *              caller-owned variable that the thunk populates via the
 *              TSS2 API (e.g. (void **)&time_info for
 *              Esys_ReadClock's TPMS_TIME_INFO **). Before every
 *              call into @thunk - including the first - the helper
 *              walks the slots, invokes Esys_Free(*slot) when *slot
 *              is non-NULL, and resets *slot to NULL. The TSS2 API
 *              clobbers the slot unconditionally on the next call,
 *              so without this housekeeping a transient retry would
 *              overwrite the pointer and leak the previous
 *              allocation.
 *
 * Returns 0 when the underlying Esys_*() call eventually returned
 * TSS2_RC_SUCCESS, otherwise the tss2_rc_to_errno() mapping of the
 * last RC. -EINVAL when @thunk is NULL or @out_slot_count exceeds
 * the static cap.
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
		/*
		 * Free output pointers populated by the previous attempt. The
		 * libtss2 ABI documents Esys_Free() as NULL-safe, but the local
		 * guard keeps this routine defensible even when linked against
		 * a stripped-down TSS2 build.
		 */
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

		/*
		 * Bail before the next sleep would push the cumulative wall
		 * time past TPM_RETRY_BUDGET_MS. systemd treats a missed
		 * WATCHDOG=1 ping as a hung process; the outer attestation loop
		 * pings only between rounds, so any single TPM call that
		 * monopolizes more than a small slice of the watchdog window
		 * would let the process get killed mid-quote. The caller
		 * observes a transient RC in *out_rc and can retry on its own
		 * schedule once the watchdog has been serviced.
		 */
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

/*
 * Per-Esys_*() thunk bindings consumed by tpm_call_with_backoff().
 *
 * Each call site that allocates TSS2 output buffers builds the
 * matching struct on the stack, hands it to the helper, and lets the
 * helper drive the retry loop. The structs intentionally mirror the
 * exact subset of arguments each call needs (sessions left at
 * ESYS_TR_NONE are pinned inside the thunk so the caller does not
 * repeat them) so the call sites stay small while the helper retains
 * full control over the output-pointer lifetime.
 */

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
	return Esys_CreatePrimary(
	    a->esys_ctx, a->primary_handle, a->shandle1, ESYS_TR_NONE,
	    ESYS_TR_NONE, a->in_sensitive, a->in_public, a->outside_info,
	    a->creation_pcr, a->object_handle_out, a->out_public_out,
	    a->creation_data_out, a->creation_hash_out, a->creation_ticket_out);
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

	/* allow re-init after cleanup */
	if (ctx->initialized || ctx->esys_ctx || ctx->tcti_ctx)
		tpm_cleanup(ctx);

	/* reset runtime state */
	ctx->esys_ctx = NULL;
	ctx->tcti_ctx = NULL;
	ctx->tcti_from_loader = false;
	ctx->initialized = false;
	memset(&ctx->aik_meta, 0, sizeof(ctx->aik_meta));
	ctx->aik_meta_loaded = false;
	memset(ctx->aik_auth, 0, sizeof(ctx->aik_auth));
	ctx->aik_auth_loaded = false;
	memset(ctx->prev_aik_public, 0, sizeof(ctx->prev_aik_public));
	ctx->prev_aik_public_size = 0;
	ctx->grace_deadline = 0;
	ctx->lockout_active = false;
	ctx->lockout_first_seen = 0;
	ctx->lockout_event_count = 0;
	memset(ctx->self_hash, 0, sizeof(ctx->self_hash));
	ctx->self_hash_ready = false;
	ctx->boot_commitment_locked = false;

	aik_meta_path = getenv("LOTA_AIK_META_PATH");
	if (aik_meta_path && aik_meta_path[0]) {
		if (aik_meta_path[0] != '/')
			return -EINVAL;
		if (snprintf(ctx->aik_meta_path, sizeof(ctx->aik_meta_path),
			     "%s",
			     aik_meta_path) >= (int)sizeof(ctx->aik_meta_path))
			return -ENAMETOOLONG;
	}

	tcti_conf = getenv("LOTA_TCTI");
	if (tcti_conf && tcti_conf[0]) {
		rc = Tss2_TctiLdr_Initialize(tcti_conf, &ctx->tcti_ctx);
		if (rc != TSS2_RC_SUCCESS)
			return tss2_rc_to_errno(rc);
		ctx->tcti_from_loader = true;
	} else {
		/*
		 * Initialize TCTI context for device access.
		 * First call with NULL to get required size.
		 */
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

	/*
	 * Initialize ESYS context using the TCTI.
	 * ESYS provides high-level TPM 2.0 API.
	 */
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

	/* default AIK handle if not pre-configured */
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

	/*
	 * Run TPM self-test.
	 * fullTest=YES means run all diagnostics.
	 */
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

	/* PCR selection for single PCR */
	memset(&pcr_selection, 0, sizeof(pcr_selection));
	pcr_selection.count = 1;
	pcr_selection.pcrSelections[0].hash = hash_alg;
	pcr_selection.pcrSelections[0].sizeofSelect = 3; /* 24 PCRs = 3 bytes */

	/* set bit for requested pcr */
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

	/* copy pcr value to output */
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

	/* TPM-allocated memory */
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

	/* map returned digests to PCR indices in increasing order */
	for (i = 0; i < LOTA_PCR_COUNT && i < 24; i++) {
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
 * Check if AIK exists at persistent handle.
 * Returns: 1 if exists, 0 if not, negative errno on error
 */
static int aik_exists(struct tpm_context *ctx, ESYS_TR *handle_out)
{
	TSS2_RC rc;
	ESYS_TR key_handle = ESYS_TR_NONE;

	TPM_CALL_RETRY(ctx, rc,
		       Esys_TR_FromTPMPublic(ctx->esys_ctx, ctx->aik_handle,
					     ESYS_TR_NONE, ESYS_TR_NONE,
					     ESYS_TR_NONE, &key_handle));
	if (rc == TSS2_RC_SUCCESS) {
		if (handle_out)
			*handle_out = key_handle;
		return 1;
	}

	/* TPM2_RC_HANDLE indicates the persistent object is absent */
	if (tpm_rc_layer_is_tpm(rc) && tpm_rc_decode(rc) == TPM2_RC_HANDLE)
		return 0;

	return tss2_rc_to_errno(rc);
}

/*
 * create_aik_primary - Create a transient AIK primary key
 * @ctx: Initialized TPM context
 * @out_handle: Receives the transient key handle on success
 *
 * Creates an RSA 2048-bit restricted signing key under the Owner
 * Hierarchy.  The caller is responsible for persisting or flushing
 * the returned transient handle.
 *
 * Returns: 0 on success, negative errno on failure
 */
static int create_aik_primary(struct tpm_context *ctx, ESYS_TR *out_handle,
			      const uint8_t aik_auth[TPM_AIK_AUTH_SIZE])
{
	TSS2_RC rc;
	TPM2B_PUBLIC *out_public = NULL;
	TPM2B_CREATION_DATA *creation_data = NULL;
	TPM2B_DIGEST *creation_hash = NULL;
	TPMT_TK_CREATION *creation_ticket = NULL;

	/*
	 * RSA 2048-bit signing key template for attestation.
	 *
	 * Properties overview:
	 *   - fixedTPM: Key cannot be duplicated
	 *   - fixedParent: Cannot be moved to different parent
	 *   - sensitiveDataOrigin: TPM generated the private portion
	 *   - userWithAuth: Requires auth for use
	 *   - restricted: Can only sign TPM-generated data (quotes)
	 *   - sign: Signing key (not encryption)
	 */
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
	if (!aik_auth)
		return -EINVAL;

	memcpy(in_sensitive.sensitive.userAuth.buffer, aik_auth,
	       TPM_AIK_AUTH_SIZE);

	TPM2B_DATA outside_info = {.size = 0};
	TPML_PCR_SELECTION creation_pcr = {.count = 0};

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
	uint32_t vendor_parts[4] = {0};
	char vendor[17] = {0};
	char vendor_upper[17] = {0};
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
		/* existing key is accepted only when its non-empty auth is
		 * present */
		ret = tpm_aik_load_auth(ctx);
		if (ret == 0)
			return 0;

		/* missing/corrupt auth means the key is not safely usable */
		return tpm_aik_reprovision_with_auth(ctx, 1);
	}

	return tpm_aik_reprovision_with_auth(ctx, 0);
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
			return ret;
	}

	{
		TPM2B_AUTH auth_value = {.size = TPM_AIK_AUTH_SIZE};
		memcpy(auth_value.buffer, ctx->aik_auth, TPM_AIK_AUTH_SIZE);
		TPM_CALL_RETRY(
		    ctx, rc,
		    Esys_TR_SetAuth(ctx->esys_ctx, key_handle, &auth_value));
		secure_bzero(auth_value.buffer, sizeof(auth_value.buffer));
		if (rc != TSS2_RC_SUCCESS)
			return tss2_rc_to_errno(rc);
	}

	memcpy(response->nonce, nonce, LOTA_NONCE_SIZE);
	response->pcr_mask = pcr_mask;
	response->hash_alg = TPM2_ALG_NULL;

	ret = tpm_read_pcrs_batch(ctx, pcr_mask, response->pcr_values);
	if (ret < 0)
		return ret;

	qualifying_data.size = LOTA_NONCE_SIZE;
	memcpy(qualifying_data.buffer, nonce, LOTA_NONCE_SIZE);

	in_scheme.scheme = TPM2_ALG_NULL;

	memset(&pcr_selection, 0, sizeof(pcr_selection));
	pcr_selection.count = 1;
	pcr_selection.pcrSelections[0].hash = TPM_HASH_ALG;
	pcr_selection.pcrSelections[0].sizeofSelect = 3;

	for (i = 0; i < LOTA_PCR_COUNT && i < 24; i++) {
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
		int call_ret = tpm_call_with_backoff(
		    ctx, esys_quote_thunk, &args, &rc, 2, (void **)&quoted,
		    (void **)&signature);
		secure_bzero(qualifying_data.buffer,
			     sizeof(qualifying_data.buffer));
		if (call_ret < 0)
			return call_ret;
	}

	if (quoted->size > LOTA_MAX_ATTEST_SIZE) {
		secure_bzero(quoted->attestationData,
			     sizeof(quoted->attestationData));
		secure_bzero(signature, sizeof(*signature));
		Esys_Free(quoted);
		Esys_Free(signature);
		return -ENOSPC;
	}
	memcpy(response->attest_data, quoted->attestationData, quoted->size);
	response->attest_size = quoted->size;
	response->sig_alg = signature->sigAlg;

	if (signature->sigAlg == TPM2_ALG_RSASSA) {
		size_t sig_size = signature->signature.rsassa.sig.size;
		response->hash_alg = signature->signature.rsassa.hash;
		if (sig_size > LOTA_MAX_SIG_SIZE) {
			secure_bzero(quoted->attestationData,
				     sizeof(quoted->attestationData));
			secure_bzero(signature, sizeof(*signature));
			Esys_Free(quoted);
			Esys_Free(signature);
			return -ENOSPC;
		}
		memcpy(response->signature,
		       signature->signature.rsassa.sig.buffer, sig_size);
		response->signature_size = (uint16_t)sig_size;
	} else if (signature->sigAlg == TPM2_ALG_RSAPSS) {
		size_t sig_size = signature->signature.rsapss.sig.size;
		response->hash_alg = signature->signature.rsapss.hash;
		if (sig_size > LOTA_MAX_SIG_SIZE) {
			secure_bzero(quoted->attestationData,
				     sizeof(quoted->attestationData));
			secure_bzero(signature, sizeof(*signature));
			Esys_Free(quoted);
			Esys_Free(signature);
			return -ENOSPC;
		}
		memcpy(response->signature,
		       signature->signature.rsapss.sig.buffer, sig_size);
		response->signature_size = (uint16_t)sig_size;
	} else {
		secure_bzero(quoted->attestationData,
			     sizeof(quoted->attestationData));
		secure_bzero(signature, sizeof(*signature));
		Esys_Free(quoted);
		Esys_Free(signature);
		return -ENOTSUP;
	}

	secure_bzero(quoted->attestationData, sizeof(quoted->attestationData));
	secure_bzero(signature, sizeof(*signature));
	Esys_Free(quoted);
	Esys_Free(signature);

	return 0;
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
			/* file shrank mid-read (or unexpected short read) */
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
			/* file grew after initial stat snapshot */
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

	/* verify file exists */
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

	/*
	 * PCR handles in ESAPI are predefined constants.
	 * ESYS_TR_PCR0 through ESYS_TR_PCR31 map directly to PCR indices.
	 */
	pcr_handle = ESYS_TR_PCR0 + pcr_index;

	/*
	 * Prepare digest structure.
	 * Extend with SHA-256 only (matching PCR bank).
	 */
	memset(&digests, 0, sizeof(digests));
	digests.count = 1;
	digests.digests[0].hashAlg = TPM_HASH_ALG;
	memcpy(digests.digests[0].digest.sha256, digest, LOTA_HASH_SIZE);

	/*
	 * PCR_Extend operation.
	 * This cryptographically extends the PCR:
	 *   new_value = Hash(old_value || digest)
	 *
	 * PCRs 0-15 are typically locked after boot (platform auth).
	 * PCRs 16-23 are available for OS/application use.
	 * PCR 14 for LOTA self-measurement.
	 */
	TPM_CALL_RETRY(ctx, rc,
		       Esys_PCR_Extend(ctx->esys_ctx, pcr_handle,
				       ESYS_TR_PASSWORD, ESYS_TR_NONE,
				       ESYS_TR_NONE, &digests));
	if (rc != TSS2_RC_SUCCESS)
		return tss2_rc_to_errno(rc);

	return 0;
}

/*
 * Domain-separation tag for the PCR14 boot commitment.
 *
 * The string is intentionally version-tagged so a future revision can
 * change the derivation without colliding with deployed baselines: the
 * verifier advertises the matching challenge capability and the agent
 * reports the corresponding LOTA_REPORT_FLAG_BOOT_COMMITMENT_V1 bit.
 */
#define TPM_BOOT_COMMITMENT_TAG "LOTA-PCR14-BOOT-COMMITMENT-v1"

/*
 * Domain-separation tag for the PCR14 initramfs lock. Mirrors
 * src/initramfs/lota-pcr14-lock.c and
 * verifier/verify/baseline.go::initramfsLockTag; any change here must
 * be made in lock-step with both peers or the verifier will refuse to
 * authenticate a freshly locked host.
 */
#define TPM_INITRAMFS_LOCK_TAG "LOTA-PCR14-INITRAMFS-LOCK-v1"

/* PCR index used for the agent self-measurement and boot commitment.
 * Mirrors agent.h::LOTA_PCR_SELF without dragging the agent header into
 * the unit-test build (tpm.c is also linked from test_aik_rotation). */
#define TPM_BOOT_COMMITMENT_PCR 14

int tpm_boot_commitment_digest(const uint8_t self_hash[], uint32_t reset_count,
			       uint32_t restart_count, uint8_t out_digest[])
{
	if (!self_hash || !out_digest)
		return -EINVAL;

	uint8_t reset_be[4];
	uint8_t restart_be[4];
	reset_be[0] = (uint8_t)((reset_count >> 24) & 0xff);
	reset_be[1] = (uint8_t)((reset_count >> 16) & 0xff);
	reset_be[2] = (uint8_t)((reset_count >> 8) & 0xff);
	reset_be[3] = (uint8_t)(reset_count & 0xff);
	restart_be[0] = (uint8_t)((restart_count >> 24) & 0xff);
	restart_be[1] = (uint8_t)((restart_count >> 16) & 0xff);
	restart_be[2] = (uint8_t)((restart_count >> 8) & 0xff);
	restart_be[3] = (uint8_t)(restart_count & 0xff);

	EVP_MD_CTX *md = EVP_MD_CTX_new();
	if (!md)
		return -ENOMEM;

	int ok = EVP_DigestInit_ex(md, EVP_sha256(), NULL) == 1 &&
		 EVP_DigestUpdate(md, TPM_BOOT_COMMITMENT_TAG,
				  sizeof(TPM_BOOT_COMMITMENT_TAG) - 1) == 1 &&
		 EVP_DigestUpdate(md, self_hash, LOTA_HASH_SIZE) == 1 &&
		 EVP_DigestUpdate(md, reset_be, sizeof(reset_be)) == 1 &&
		 EVP_DigestUpdate(md, restart_be, sizeof(restart_be)) == 1 &&
		 EVP_DigestFinal_ex(md, out_digest, NULL) == 1;
	EVP_MD_CTX_free(md);

	if (!ok)
		return -EIO;
	return 0;
}

int tpm_initramfs_lock_digest(uint32_t reset_count, uint32_t restart_count,
			      uint8_t out_digest[])
{
	if (!out_digest)
		return -EINVAL;

	uint8_t reset_be[4];
	uint8_t restart_be[4];
	reset_be[0] = (uint8_t)((reset_count >> 24) & 0xff);
	reset_be[1] = (uint8_t)((reset_count >> 16) & 0xff);
	reset_be[2] = (uint8_t)((reset_count >> 8) & 0xff);
	reset_be[3] = (uint8_t)(reset_count & 0xff);
	restart_be[0] = (uint8_t)((restart_count >> 24) & 0xff);
	restart_be[1] = (uint8_t)((restart_count >> 16) & 0xff);
	restart_be[2] = (uint8_t)((restart_count >> 8) & 0xff);
	restart_be[3] = (uint8_t)(restart_count & 0xff);

	EVP_MD_CTX *md = EVP_MD_CTX_new();
	if (!md)
		return -ENOMEM;

	int ok = EVP_DigestInit_ex(md, EVP_sha256(), NULL) == 1 &&
		 EVP_DigestUpdate(md, TPM_INITRAMFS_LOCK_TAG,
				  sizeof(TPM_INITRAMFS_LOCK_TAG) - 1) == 1 &&
		 EVP_DigestUpdate(md, reset_be, sizeof(reset_be)) == 1 &&
		 EVP_DigestUpdate(md, restart_be, sizeof(restart_be)) == 1 &&
		 EVP_DigestFinal_ex(md, out_digest, NULL) == 1;
	EVP_MD_CTX_free(md);
	return ok ? 0 : -EIO;
}

int tpm_clock_state_load(const struct tpm_context *ctx,
			 struct lota_clock_state *out)
{
	if (!ctx || !out)
		return -EINVAL;

	const char *path = ctx->clock_state_path[0] ? ctx->clock_state_path
						    : TPM_CLOCK_STATE_PATH;

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

	const char *path = ctx->clock_state_path[0] ? ctx->clock_state_path
						    : TPM_CLOCK_STATE_PATH;

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

/*
 * sha256_two_block - SHA-256(block_a || block_b), each block exactly
 * LOTA_HASH_SIZE bytes. Used to derive both the post-extend PCR14
 * value (block_a = 0^32) and the lock-then-extend chain
 * (block_a = pcr14_after_lock).
 */
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

/*
 * derive_expected_pcr14 - SHA-256(0^32 || boot_commit). Final PCR14
 * value an agent observes when it extends boot commitment onto an
 * untouched PCR14 (no initramfs lock ran).
 */
static int derive_expected_pcr14(const uint8_t self_hash[],
				 uint32_t reset_count, uint32_t restart_count,
				 uint8_t out_pcr14[LOTA_HASH_SIZE])
{
	uint8_t commit[LOTA_HASH_SIZE];
	uint8_t zero[LOTA_HASH_SIZE] = {0};
	int ret = tpm_boot_commitment_digest(self_hash, reset_count,
					     restart_count, commit);
	if (ret < 0)
		return ret;
	return sha256_two_block(zero, commit, out_pcr14);
}

/*
 * derive_lock_pcr14_value - SHA-256(0^32 || lock_commit). The exact
 * PCR14 value PCR14 carries when the initramfs lock helper ran but
 * the agent has not extended its own commitment yet.
 */
static int derive_lock_pcr14_value(uint32_t reset_count, uint32_t restart_count,
				   uint8_t out[LOTA_HASH_SIZE])
{
	uint8_t lock_commit[LOTA_HASH_SIZE];
	uint8_t zero[LOTA_HASH_SIZE] = {0};
	int ret =
	    tpm_initramfs_lock_digest(reset_count, restart_count, lock_commit);
	if (ret < 0)
		return ret;
	return sha256_two_block(zero, lock_commit, out);
}

/*
 * derive_expected_locked_pcr14 - final PCR14 after the lock-then-extend
 * chain: SHA-256(lock_value || boot_commit). Used by both the warm-
 * restart match (when the agent re-runs in a locked boot session) and
 * the post-extend state save.
 */
static int derive_expected_locked_pcr14(const uint8_t self_hash[],
					uint32_t reset_count,
					uint32_t restart_count,
					uint8_t out[LOTA_HASH_SIZE])
{
	uint8_t lock_value[LOTA_HASH_SIZE];
	uint8_t boot_commit[LOTA_HASH_SIZE];
	int ret =
	    derive_lock_pcr14_value(reset_count, restart_count, lock_value);
	if (ret < 0)
		return ret;
	ret = tpm_boot_commitment_digest(self_hash, reset_count, restart_count,
					 boot_commit);
	if (ret < 0)
		return ret;
	return sha256_two_block(lock_value, boot_commit, out);
}

int tpm_extend_boot_commitment(struct tpm_context *ctx,
			       const uint8_t self_hash[])
{
	TSS2_RC rc;
	TPMS_TIME_INFO *time_info = NULL;
	uint8_t commit[LOTA_HASH_SIZE];
	uint8_t current_pcr14[LOTA_HASH_SIZE];
	uint8_t expected_pcr14[LOTA_HASH_SIZE];
	uint8_t lock_pcr14_value[LOTA_HASH_SIZE];
	uint8_t expected_locked_pcr14[LOTA_HASH_SIZE];
	uint8_t zero_pcr14[LOTA_HASH_SIZE] = {0};
	int ret;

	if (!ctx || !ctx->initialized || !self_hash)
		return -EINVAL;

	/*
	 * boot_commitment_locked is recomputed on every call: a stale
	 * "true" value from a previous attempt could mislead the
	 * attestation report builder if the new call took the unlocked
	 * branch (e.g. operator removed the dracut module between runs).
	 */
	ctx->boot_commitment_locked = false;

	{
		struct esys_read_clock_args args = {
		    .esys_ctx = ctx->esys_ctx,
		    .time_info_out = &time_info,
		};
		int call_ret =
		    tpm_call_with_backoff(ctx, esys_read_clock_thunk, &args,
					  &rc, 1, (void **)&time_info);
		if (call_ret < 0)
			return call_ret;
	}

	uint32_t reset_count = time_info->clockInfo.resetCount;
	uint32_t restart_count = time_info->clockInfo.restartCount;
	Esys_Free(time_info);

	ret = tpm_boot_commitment_digest(self_hash, reset_count, restart_count,
					 commit);
	if (ret < 0)
		return ret;

	/*
	 * Three candidate PCR14 values the agent can legitimately observe:
	 *   expected_pcr14         = SHA-256(0^32 || boot_commit)
	 *     - unlocked host, agent extended boot commit on top of an
	 *       untouched PCR14
	 *   lock_pcr14_value       = SHA-256(0^32 || lock_commit)
	 *     - locked host where the initramfs helper ran but the agent
	 *       has not extended its own commitment yet
	 *   expected_locked_pcr14  = SHA-256(lock_value || boot_commit)
	 *     - locked host where both extends have occurred
	 * Anything else is treated as tamper and routed through the
	 * attribution logic below.
	 */
	ret = derive_expected_pcr14(self_hash, reset_count, restart_count,
				    expected_pcr14);
	if (ret < 0)
		return ret;
	ret = derive_lock_pcr14_value(reset_count, restart_count,
				      lock_pcr14_value);
	if (ret < 0)
		return ret;
	ret = derive_expected_locked_pcr14(
	    self_hash, reset_count, restart_count, expected_locked_pcr14);
	if (ret < 0)
		return ret;

	ret = tpm_read_pcr(ctx, TPM_BOOT_COMMITMENT_PCR, TPM_HASH_ALG,
			   current_pcr14);
	if (ret < 0)
		return ret;

	/*
	 * Load the previous on-disk snapshot for tamper attribution. -ENOENT
	 * (no prior state on this host) is non-fatal: a first-run agent has
	 * nothing to compare against but every later run does.
	 */
	struct lota_clock_state prev;
	int have_prev = 0;
	ret = tpm_clock_state_load(ctx, &prev);
	if (ret == 0)
		have_prev = 1;
	else if (ret != -ENOENT)
		fprintf(stderr,
			"PCR14 boot-commitment: clock-state load failed (%s); "
			"continuing without attribution\n",
			strerror(-ret));

	/*
	 * Locked-host branches handled before the legacy state machine
	 * so a host that just deployed the dracut module gets the
	 * lock-then-extend chain on its first run.
	 */
	if (memcmp(current_pcr14, lock_pcr14_value, LOTA_HASH_SIZE) == 0) {
		/*
		 * Initramfs lock ran; agent has not extended yet. Extend with
		 * the boot commitment on top so PCR14 ends at the two-hop
		 * value the verifier expects from FlagInitramfsLockV1 reports.
		 */
		ret = tpm_pcr_extend(ctx, TPM_BOOT_COMMITMENT_PCR, commit);
		if (ret < 0)
			return ret;
		struct lota_clock_state snap = {
		    .reset_count = reset_count,
		    .restart_count = restart_count,
		    .saved_at = (int64_t)time(NULL),
		    .flags = LOTA_CLOCK_STATE_FLAG_INITRAMFS_LOCK,
		};
		memcpy(snap.pcr14, expected_locked_pcr14, LOTA_HASH_SIZE);
		memcpy(snap.self_hash, self_hash, LOTA_HASH_SIZE);
		int save_ret = tpm_clock_state_save(ctx, &snap);
		if (save_ret < 0)
			fprintf(stderr,
				"PCR14 boot-commitment: clock-state save "
				"failed (%s); "
				"next run will lose tamper attribution\n",
				strerror(-save_ret));
		ctx->boot_commitment_locked = true;
		return 0;
	}

	if (memcmp(current_pcr14, expected_locked_pcr14, LOTA_HASH_SIZE) == 0) {
		/* Warm restart on a locked host - both extends already done. */
		struct lota_clock_state snap = {
		    .reset_count = reset_count,
		    .restart_count = restart_count,
		    .saved_at = (int64_t)time(NULL),
		    .flags = LOTA_CLOCK_STATE_FLAG_INITRAMFS_LOCK,
		};
		memcpy(snap.pcr14, expected_locked_pcr14, LOTA_HASH_SIZE);
		memcpy(snap.self_hash, self_hash, LOTA_HASH_SIZE);
		int save_ret = tpm_clock_state_save(ctx, &snap);
		if (save_ret < 0)
			fprintf(stderr,
				"PCR14 boot-commitment: clock-state refresh "
				"failed (%s)\n",
				strerror(-save_ret));
		ctx->boot_commitment_locked = true;
		return 0;
	}

	if (memcmp(current_pcr14, zero_pcr14, LOTA_HASH_SIZE) == 0) {
		/*
		 * Fresh boot: TPM reset, PCR14 still 0^32. If a prior snapshot
		 * exists and its resetCount matches the current one, the TPM
		 * apparently zeroed PCR14 without advancing resetCount - an
		 * abnormal state worth flagging (operator action with
		 * tpm2_pcr_reset on a debug PCR, kernel reload, ...).
		 */
		if (have_prev && prev.reset_count == reset_count) {
			fprintf(stderr,
				"SECURITY: PCR14 cleared while resetCount=%u "
				"unchanged "
				"since last extend (last saved %lld); refusing "
				"to attest "
				"without operator review\n",
				(unsigned)reset_count,
				(long long)prev.saved_at);
			return -EBADMSG;
		}
		ret = tpm_pcr_extend(ctx, TPM_BOOT_COMMITMENT_PCR, commit);
		if (ret < 0)
			return ret;
		struct lota_clock_state snap = {
		    .reset_count = reset_count,
		    .restart_count = restart_count,
		    .saved_at = (int64_t)time(NULL),
		};
		memcpy(snap.pcr14, expected_pcr14, LOTA_HASH_SIZE);
		memcpy(snap.self_hash, self_hash, LOTA_HASH_SIZE);
		int save_ret = tpm_clock_state_save(ctx, &snap);
		if (save_ret < 0)
			fprintf(stderr,
				"PCR14 boot-commitment: clock-state save "
				"failed (%s); "
				"next run will lose tamper attribution\n",
				strerror(-save_ret));
		return 0;
	}

	if (memcmp(current_pcr14, expected_pcr14, LOTA_HASH_SIZE) == 0) {
		/*
		 * Warm restart: PCR14 already bound to (self_hash, resetCount,
		 * restartCount). Refresh the snapshot so the saved_at stamp
		 * stays current and a corrupted file gets healed.
		 */
		struct lota_clock_state snap = {
		    .reset_count = reset_count,
		    .restart_count = restart_count,
		    .saved_at = (int64_t)time(NULL),
		};
		memcpy(snap.pcr14, expected_pcr14, LOTA_HASH_SIZE);
		memcpy(snap.self_hash, self_hash, LOTA_HASH_SIZE);
		int save_ret = tpm_clock_state_save(ctx, &snap);
		if (save_ret < 0)
			fprintf(stderr,
				"PCR14 boot-commitment: clock-state refresh "
				"failed (%s)\n",
				strerror(-save_ret));
		return 0;
	}

	/*
	 * PCR14 holds an unexpected value. Without prior state every cause
	 * collapses to a single -EBADMSG; with it we can attribute to one
	 * of three concrete operator scenarios so the journal entry tells
	 * the responder which runbook to follow.
	 */
	if (!have_prev) {
		fprintf(
		    stderr,
		    "SECURITY: PCR14 holds an unexpected value (resetCount=%u "
		    "restartCount=%u) and no prior clock-state snapshot exists "
		    "to attribute the cause. Possible explanations: "
		    "(1) initramfs / boot loader extended PCR14 with a "
		    "non-LOTA commitment; "
		    "(2) local root extended PCR14 between cold boot and the "
		    "agent reaching this code; "
		    "(3) the clock-state file was deleted between runs. "
		    "Cold reboot the host and consult systemd journal for "
		    "tpm2_pcr_extend invocations before lota-agent's first "
		    "quote\n",
		    (unsigned)reset_count, (unsigned)restart_count);
		return -EBADMSG;
	}

	if (prev.reset_count < reset_count) {
		/*
		 * Cold boot happened since the last agent run (resetCount
		 * advanced) and PCR14 is already non-zero before the agent
		 * could extend it. PCR14 should have been 0^32 at this point;
		 * something touched it between TPM_INIT and lota-agent startup.
		 */
		fprintf(
		    stderr,
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
	}

	if (prev.reset_count == reset_count) {
		/*
		 * Same boot session. Two sub-cases:
		 *
		 *  (a) PCR14 still holds the value lota-agent itself wrote
		 * during the previous run in this session, AND the agent binary
		 *      hash has changed since then. Live agent upgrade without
		 * a cold reboot: PCR14 cannot be rebound without resetCount
		 *      advancing, and the operator must reboot to re-extend.
		 *
		 *  (b) PCR14 differs from both the recomputed expected value
		 * AND the previously-saved snapshot value. Something mutated
		 *      PCR14 during the current boot session after the last
		 *      successful extend.
		 */
		int pcr_matches_prev =
		    memcmp(current_pcr14, prev.pcr14, LOTA_HASH_SIZE) == 0;
		int self_hash_changed =
		    memcmp(prev.self_hash, self_hash, LOTA_HASH_SIZE) != 0;

		if (pcr_matches_prev && self_hash_changed) {
			fprintf(stderr,
				"SECURITY: PCR14 holds the boot commitment of "
				"a prior "
				"agent binary in this boot session "
				"(resetCount=%u); the "
				"agent binary has changed since that extend. "
				"PCR14 is "
				"non-resettable from userspace, so live "
				"upgrades cannot "
				"rebind it. Cold reboot to re-extend PCR14 "
				"against the "
				"current agent binary\n",
				(unsigned)reset_count);
			return -EBADMSG;
		}

		fprintf(
		    stderr,
		    "SECURITY: PCR14 mutated during the current boot session "
		    "(resetCount=%u; last successful extend at %lld). Another "
		    "writer extended PCR14 after lota-agent's last "
		    "self_measure() and outside its control. Possible causes: "
		    "(1) local root invoked tpm2_pcr_extend on /dev/tpmrm0; "
		    "(2) another integrity subsystem (IMA, integrity-init, "
		    "...) extended PCR14 from the OS. Audit auditd and the "
		    "process table for the writer; cold reboot to restore a "
		    "clean baseline\n",
		    (unsigned)reset_count, (long long)prev.saved_at);
		return -EBADMSG;
	}

	/*
	 * prev.reset_count > reset_count: the TPM reports an OLDER reset
	 * count than what we previously persisted. The TPM device or the
	 * clock-state file is lying about platform identity; treat as
	 * tamper.
	 */
	fprintf(stderr,
		"SECURITY: TPM reports resetCount=%u while the local "
		"snapshot recorded a higher value (%u). The TPM device or "
		"the persistent state file has been rolled back; refusing "
		"to attest\n",
		(unsigned)reset_count, (unsigned)prev.reset_count);
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

	/* read public portion of AIK */
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

	/* verify its RSA */
	if (out_public->publicArea.type != TPM2_ALG_RSA) {
		ret = -EINVAL;
		goto cleanup;
	}

	/*
	 * Convert TPM RSA public key to OpenSSL EVP_PKEY.
	 */
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

	/*
	 * Encode as DER SubjectPublicKeyInfo using i2d_PUBKEY.
	 */
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

	return ret;
}

/*
 * Standard EK template handle for RSA 2048.
 * TCG EK Credential Profile specifies this as the standard location.
 */
#define TPM_EK_RSA_HANDLE 0x81010001

int tpm_get_hardware_id(struct tpm_context *ctx, uint8_t *hardware_id)
{
	TSS2_RC rc;
	ESYS_TR ek_handle = ESYS_TR_NONE;
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
	 * Try to read EK from standard persistent handle.
	 * Most TPMs have EK provisioned at 0x81010001.
	 */
	TPM_CALL_RETRY(ctx, rc,
		       Esys_TR_FromTPMPublic(ctx->esys_ctx, TPM_EK_RSA_HANDLE,
					     ESYS_TR_NONE, ESYS_TR_NONE,
					     ESYS_TR_NONE, &ek_handle));
	if (rc != TSS2_RC_SUCCESS) {
		/*
		 * EK not at standard handle - this is common.
		 * Fall back to using AIK fingerprint as hardware ID.
		 * Less ideal but still unique per TPM installation.
		 */
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

	/*
	 * Hash the EK public key modulus.
	 * For RSA, the modulus is the unique part.
	 */
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
		/* ECC: hash both X and Y coordinates */
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

	meta_path =
	    ctx->aik_meta_path[0] ? ctx->aik_meta_path : TPM_AIK_META_PATH;
	slash = strrchr(meta_path, '/');
	if (!slash)
		return -EINVAL;

	if (slash == meta_path)
		dir_len = 1;
	else
		dir_len = (size_t)(slash - meta_path);

	if (dir_len + 1 + strlen("aik_auth.dat") + 1 > buf_len)
		return -ENAMETOOLONG;

	memcpy(buf, meta_path, dir_len);
	buf[dir_len] = '\0';

	if (dir_len > 1)
		snprintf(buf + dir_len, buf_len - dir_len, "/aik_auth.dat");
	else
		snprintf(buf + dir_len, buf_len - dir_len, "aik_auth.dat");

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

static int tpm_aik_save_auth(struct tpm_context *ctx,
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

static int tpm_aik_load_auth(struct tpm_context *ctx)
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
			TPM_CALL_RETRY(
			    ctx, rc,
			    Esys_EvictControl(
				ctx->esys_ctx, ESYS_TR_RH_OWNER, old_handle,
				ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
				ctx->aik_handle, &persistent_handle));
			if (rc != TSS2_RC_SUCCESS)
				return tss2_rc_to_errno(rc);
			Esys_TR_Close(ctx->esys_ctx, &persistent_handle);
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

	Esys_TR_Close(ctx->esys_ctx, &persistent_handle);

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
			 * Unit tests intentionally exercise metadata
			 * persistence without a real TPM, so esys_ctx may be
			 * NULL; in that case skip the TPM existence check and
			 * initialize defaults.
			 */
			if (ctx->esys_ctx) {
				int exists = aik_exists(ctx, NULL);
				if (exists < 0)
					return exists;
				if (exists == 1)
					return -EKEYREVOKED;
			}
		}

		/* no AIK exists yet -> first run after install: initialize
		 * defaults */
		memset(&ctx->aik_meta, 0, sizeof(ctx->aik_meta));
		ctx->aik_meta.magic = TPM_AIK_META_MAGIC;
		ctx->aik_meta.version = TPM_AIK_META_VERSION;
		ctx->aik_meta.generation = 1;
		ctx->aik_meta.provisioned_at = (int64_t)time(NULL);
		ctx->aik_meta.last_rotated_at = 0;
		ctx->aik_meta_loaded = true;

		return tpm_aik_save_metadata(ctx);
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

	/* ensure parent directory exists */
	ret = mkdirs(path, 0755);
	if (ret < 0)
		return ret;

	/*
	 * write to a temporary file and rename atomically so that a
	 * crash between truncation and write cannot leave an empty
	 * metadata file
	 */
	char tmp[PATH_MAX];
	ret = snprintf(tmp, sizeof(tmp), "%s.tmp.XXXXXX", path);
	if (ret < 0 || (size_t)ret >= sizeof(tmp))
		return -ENAMETOOLONG;

	fd = mkstemp(tmp);
	if (fd < 0)
		return -errno;

	struct aik_metadata wire;
	wire.magic = htole32(ctx->aik_meta.magic);
	wire.version = htole32(ctx->aik_meta.version);
	wire.generation = htole64(ctx->aik_meta.generation);
	wire.provisioned_at =
	    (int64_t)htole64((uint64_t)ctx->aik_meta.provisioned_at);
	wire.last_rotated_at =
	    (int64_t)htole64((uint64_t)ctx->aik_meta.last_rotated_at);
	memset(wire._reserved, 0, sizeof(wire._reserved));

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

	/* export current AIK public key for grace period */
	ret = aik_exists(ctx, NULL);
	if (ret < 0)
		return ret;

	if (ret == 1) {
		ret = tpm_get_aik_public(ctx, ctx->prev_aik_public,
					 sizeof(ctx->prev_aik_public),
					 &prev_size);
		if (ret < 0) {
			/*
			 * cannot export old key -> grace period will be empty
			 * continue with rotation anyway
			 */
			prev_size = 0;
		}
		ctx->prev_aik_public_size = prev_size;

		/* reprovision rotates both AIK key material and its userAuth
		 * secret */
		ret = tpm_aik_reprovision_with_auth(ctx, 1);
		if (ret < 0)
			return ret;
	} else {
		ctx->prev_aik_public_size = 0;

		/* no existing AIK — provision from scratch */
		ret = tpm_provision_aik(ctx);
		if (ret < 0)
			return ret;
	}

	/* update metadata */
	ctx->aik_meta.generation++;
	ctx->aik_meta.last_rotated_at = (int64_t)time(NULL);
	ctx->aik_meta.provisioned_at = ctx->aik_meta.last_rotated_at;

	ret = tpm_aik_save_metadata(ctx);
	if (ret < 0)
		return ret;

	/* start grace period */
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
		/* grace period expired -> clear state */
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

	/*
	 * if the buffer is completely full, try to read one more byte.
	 * if data is available, the log was too large for the buffer
	 * and the caller cannot trust the content.
	 */
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

/*
 * Query TPM capability for a property.
 * Returns: 0 on success, negative errno on failure.
 */
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
		int call_ret =
		    tpm_call_with_backoff(ctx, esys_get_capability_thunk, &args,
					  &rc, 1, (void **)&cap_data);
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

int tpm_get_ek_cert(struct tpm_context *ctx, uint8_t *buf, size_t buf_size,
		    size_t *out_size)
{
	TSS2_RC rc;
	ESYS_TR nv_handle = ESYS_TR_NONE;
	TPM2B_NV_PUBLIC *nv_public = NULL;
	TPM2B_NAME *nv_name = NULL;
	uint32_t max_nv_size = 1024; /* conservative default */
	uint32_t prop_val;

	if (!ctx || !ctx->initialized || !buf || !out_size)
		return -EINVAL;

	*out_size = 0;

	/* query unlimited max NV buffer size */
	if (tpm_get_prop(ctx, TPM2_PT_NV_BUFFER_MAX, &prop_val) == 0) {
		max_nv_size = prop_val;
	}

	/* ESYS handle for NV index */
	TPM_CALL_RETRY(ctx, rc,
		       Esys_TR_FromTPMPublic(ctx->esys_ctx, TPM_EK_CERT_HANDLE,
					     ESYS_TR_NONE, ESYS_TR_NONE,
					     ESYS_TR_NONE, &nv_handle));
	if (rc != TSS2_RC_SUCCESS) {
		if (tpm_rc_layer_is_tpm(rc) &&
		    tpm_rc_decode(rc) == TPM2_RC_HANDLE)
			return -ENOENT; /* no certificate at this handle */
		return tss2_rc_to_errno(rc);
	}

	/* read NV public to get size */
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
		if (call_ret < 0)
			return call_ret;
	}

	size_t data_size = nv_public->nvPublic.dataSize;
	Esys_Free(nv_public);
	Esys_Free(nv_name);

	if (data_size > buf_size) {
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
			int call_ret = tpm_call_with_backoff(
			    ctx, esys_nv_read_thunk, &args, &rc, 1,
			    (void **)&nv_data);
			if (call_ret < 0)
				return call_ret;
		}

		memcpy(buf + offset, nv_data->buffer, nv_data->size);
		offset += nv_data->size;
		Esys_Free(nv_data);
	}

	*out_size = data_size;
	return 0;
}
