/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
#ifndef LOTA_SELFTEST_H
#define LOTA_SELFTEST_H

#include <errno.h>
#include <stddef.h>
#include <stdint.h>

/**
 * test_tpm() - Probe the TPM: --test-tpm.
 *
 * Reads PCRs 0, 1, 10 and 14, hashes the kernel and the agent, checks PCR 14
 * against this binary's commitment without extending it, and quotes with each
 * key the host attests with. It changes no key or record.
 *
 * Return: 0, -EIO when a step failed, or the tpm_init() error.
 */
int test_tpm(void);

/**
 * test_iommu() - Probe the IOMMU: --test-iommu.
 *
 * Return: 0 when iommu_verify_full() passes, 1 otherwise.
 */
int test_iommu(void);

/**
 * print_hex() - Print @label and up to 32 bytes of @data in hex.
 * @label: Prefix.
 * @data: Bytes.
 * @len: Length of @data; past 32 the line ends in "...".
 */
void print_hex(const char *label, const uint8_t *data, size_t len);

/**
 * enum selftest_aik_plan - What a probe does about the key at the AIK handle.
 * @SELFTEST_AIK_USE_EXISTING: a key is there; use it.
 * @SELFTEST_AIK_SKIP: the handle is free or the TPM could not be asked.
 *
 * A key created by a probe would outlive it and hold a persistent handle.
 */
enum selftest_aik_plan {
	SELFTEST_AIK_USE_EXISTING,
	SELFTEST_AIK_SKIP,
};

/**
 * selftest_aik_plan() - Plan for the key at the AIK handle.
 * @holds_object: tpm_handle_holds_object() for the handle.
 *
 * Return: SELFTEST_AIK_USE_EXISTING for 1, SELFTEST_AIK_SKIP otherwise.
 */
static inline enum selftest_aik_plan selftest_aik_plan(int holds_object)
{
	return holds_object == 1 ? SELFTEST_AIK_USE_EXISTING :
				   SELFTEST_AIK_SKIP;
}

/**
 * enum selftest_aik_load - What a probe does after loading the key's auth.
 * @SELFTEST_AIK_LOAD_QUOTE: the authorization loaded; quote.
 * @SELFTEST_AIK_LOAD_SKIP: no authorization record; the key is left as it is.
 * @SELFTEST_AIK_LOAD_FAIL: the load failed.
 */
enum selftest_aik_load {
	SELFTEST_AIK_LOAD_QUOTE,
	SELFTEST_AIK_LOAD_SKIP,
	SELFTEST_AIK_LOAD_FAIL,
};

/**
 * selftest_aik_load_plan() - Plan after tpm_load_aik().
 * @load_rc: tpm_load_aik() result.
 *
 * Return: QUOTE for 0, SKIP for -ENOENT, FAIL otherwise.
 */
static inline enum selftest_aik_load selftest_aik_load_plan(int load_rc)
{
	if (load_rc == 0)
		return SELFTEST_AIK_LOAD_QUOTE;
	return load_rc == -ENOENT ? SELFTEST_AIK_LOAD_SKIP :
				    SELFTEST_AIK_LOAD_FAIL;
}

/**
 * enum selftest_quote_key - Whose key --test-tpm quotes with.
 * @SELFTEST_QUOTE_PRE_PROFILE: the key TPM_AIK_META_PATH names.
 * @SELFTEST_QUOTE_PER_PUBLISHER: each publisher's own key.
 */
enum selftest_quote_key {
	SELFTEST_QUOTE_PRE_PROFILE,
	SELFTEST_QUOTE_PER_PUBLISHER,
};

/**
 * selftest_quote_key() - Whose key to quote with.
 * @keys_held: publishers_keys_held() over this host's profiles.
 *
 * Return: SELFTEST_QUOTE_PER_PUBLISHER when a publisher holds a key.
 */
static inline enum selftest_quote_key selftest_quote_key(size_t keys_held)
{
	return keys_held > 0 ? SELFTEST_QUOTE_PER_PUBLISHER :
			       SELFTEST_QUOTE_PRE_PROFILE;
}

/**
 * struct selftest_tally - Outcome of each step of a probe.
 * @passed: Steps that succeeded.
 * @failed: Steps that failed.
 * @skipped: Steps with nothing to run on; not failures.
 */
struct selftest_tally {
	int passed;
	int failed;
	int skipped;
};

/**
 * selftest_record() - Count one step.
 * @t: Tally.
 * @ret: The step's result; negative is a failure.
 */
static inline void selftest_record(struct selftest_tally *t, int ret)
{
	if (ret < 0)
		t->failed++;
	else
		t->passed++;
}

/**
 * selftest_skip() - Count one skipped step.
 * @t: Tally.
 */
static inline void selftest_skip(struct selftest_tally *t)
{
	t->skipped++;
}

/**
 * selftest_verdict() - Result of a whole probe.
 * @t: Tally.
 *
 * Return: -EIO when a step failed, else 0.
 */
static inline int selftest_verdict(const struct selftest_tally *t)
{
	return t->failed > 0 ? -EIO : 0;
}

/**
 * do_seal() - Seal stdin to the PCR state and write the blob to stdout.
 * @pcr_str: --seal-pcrs mask, or NULL for the tpm_seal_secret() default.
 *
 * Up to LOTA_SEAL_MAX_SECRET bytes go in one sealed object; up to
 * LOTA_ENVELOPE_MAX_PAYLOAD in an envelope.
 *
 * Return: exit code 0 or 1.
 */
int do_seal(const char *pcr_str);

/**
 * do_unseal() - Unseal a blob from stdin and write the secret to stdout.
 *
 * The framing is checked before the TPM is opened.
 *
 * Return: exit code 0 or 1; 1 when the PCR state differs from the sealed one.
 */
int do_unseal(void);

/**
 * do_seal_aik_auth() - Seal the userAuth of every attestation key.
 *
 * Walks each publisher holding a key, and the TPM_AIK_META_PATH key when no
 * publisher is listed. tpm_aik_reseal_auth() does each.
 *
 * Return: exit code 0 or 1.
 */
int do_seal_aik_auth(void);

/**
 * do_reprovision_aik() - Replace the userAuth of every attestation key.
 *
 * Walks the keys as do_seal_aik_auth() does; tpm_reprovision_aik() does each,
 * and the output names the certificates a moved key made stale.
 *
 * Return: exit code 0 or 1.
 */
int do_reprovision_aik(void);

/**
 * do_seal_persist_primary() - Persist the seal storage primary.
 *
 * Seal and unseal use it only with seal_persistent_primary set.
 *
 * Return: exit code 0, also when it was already persisted, or 1.
 */
int do_seal_persist_primary(void);

/**
 * do_seal_evict_primary() - Evict the persistent seal storage primary.
 *
 * Sealed blobs still unseal.
 *
 * Return: exit code 0, or 1, also when none was persisted.
 */
int do_seal_evict_primary(void);

#endif /* LOTA_SELFTEST_H */
