/* SPDX-License-Identifier: MIT */
/*
 * LOTA - initramfs PCR14 lock helper
 *
 * Purpose
 *   TPM 2.0 PC Client Platform TPM Profile p3.3 keeps PCR14
 *   OS-writable from Locality 0 with no AuthValue or policy
 *   mechanism that could gate the extend. Without intervention any
 *   userspace caller with /dev/tpmrm0 access can extend PCR14
 *   between cold boot and the lota-agent self_measure() call,
 *   wedging the boot-commitment baseline.
 *
 *   This helper runs inside the initramfs, before pivot_root, before
 *   systemd-udev applies any rule. At that point only the kernel
 *   and components packaged inside the initramfs image have touched
 *   the TPM; if the boot chain itself is trusted (verified by
 *   measured boot / dm-verity) then nothing untrusted has reached
 *   /dev/tpmrm0 yet. The helper extends PCR14 with the
 *   domain-separated digest
 *
 *     SHA256("LOTA-PCR14-INITRAMFS-LOCK-v1" || resetCount_be ||
 *             restartCount_be)
 *
 *   The TPM2_Quote that lota-agent ships later reflects the
 *   resulting "locked" PCR14 value, and the verifier rederives the
 *   same chain. Once locked, any further extension by an untrusted
 *   userspace process produces a value the verifier cannot match,
 *   so the attestation fails closed.
 *
 * Idempotency
 *   The helper is safe to run multiple times within a single boot
 *   session. It reads PCR14 first and exits with code 0 when the
 *   value already matches the expected post-extend digest (which is
 *   the normal "I already ran this boot" outcome on a kexec or
 *   late-stage systemd-tpm2 hook). Only when PCR14 is exactly
 *   0^32 does the helper actually extend.
 *
 * Failure mode
 *   Any TPM error, PCR mismatch (PCR14 already non-zero but not the
 *   expected lock value, e.g. the boot loader extended it with a
 *   different scheme), or unsupported TSS2 layer surfaces as a
 *   non-zero exit. The initramfs systemd unit that wraps this helper
 *   is ordered before sysroot.mount / initrd-root-fs.target so a
 *   non-zero exit aborts the transition to the real root.
 *
 * No-cleanup model
 *   The helper has no persistent per-run state and releases all
 *   TSS2/OpenSSL allocations before exit. ENV variable
 *   LOTA_INITRAMFS_LOCK_TCTI overrides the default /dev/tpmrm0
 *   device path (used by the test harness).
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>

#include <tss2/tss2_esys.h>
#include <tss2/tss2_tcti.h>
#include <tss2/tss2_tcti_device.h>

#define INITRAMFS_LOCK_TAG "LOTA-PCR14-INITRAMFS-LOCK-v1"
#define INITRAMFS_LOCK_PCR 14
#define PCR14_HASH_ALG TPM2_ALG_SHA256
#define HASH_SIZE 32

#ifndef LOTA_INITRAMFS_LOCK_NO_MAIN
static const char *device_path(void)
{
	const char *env = getenv("LOTA_INITRAMFS_LOCK_TCTI");
	if (env && env[0])
		return env;
	return "/dev/tpmrm0";
}
#endif

int lota_initramfs_lock_commit(uint32_t reset_count, uint32_t restart_count,
			       uint8_t out_digest[HASH_SIZE]);

/*
 * lota_initramfs_lock_commit - reproduce the domain-separated digest
 *
 * Exposed with normal C linkage so unit tests can call into the same
 * byte-for-byte derivation used by the standalone helper without
 * re-marshalling the inputs. resetCount and restartCount are encoded
 * big-endian to match the boot-commitment derivation in
 * src/agent/tpm.c::tpm_boot_commitment_digest().
 *
 * Returns: 0 on success, negative errno on failure.
 */
int lota_initramfs_lock_commit(uint32_t reset_count, uint32_t restart_count,
			       uint8_t out_digest[HASH_SIZE])
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
		 EVP_DigestUpdate(md, INITRAMFS_LOCK_TAG,
				  sizeof(INITRAMFS_LOCK_TAG) - 1) == 1 &&
		 EVP_DigestUpdate(md, reset_be, sizeof(reset_be)) == 1 &&
		 EVP_DigestUpdate(md, restart_be, sizeof(restart_be)) == 1 &&
		 EVP_DigestFinal_ex(md, out_digest, NULL) == 1;
	EVP_MD_CTX_free(md);

	return ok ? 0 : -EIO;
}

#ifndef LOTA_INITRAMFS_LOCK_NO_MAIN
/*
 * expected_post_extend - SHA256(0^32 || commit). PCR14 starts at
 * 0^32 on cold boot, and the kernel does not extend it before
 * userspace runs, so SHA256(0^32 || commit) is the only acceptable
 * post-extend value on an honest path.
 */
static int expected_post_extend(const uint8_t commit[HASH_SIZE],
				uint8_t out[HASH_SIZE])
{
	uint8_t zero[HASH_SIZE] = {0};
	EVP_MD_CTX *md = EVP_MD_CTX_new();
	if (!md)
		return -ENOMEM;
	int ok = EVP_DigestInit_ex(md, EVP_sha256(), NULL) == 1 &&
		 EVP_DigestUpdate(md, zero, sizeof(zero)) == 1 &&
		 EVP_DigestUpdate(md, commit, HASH_SIZE) == 1 &&
		 EVP_DigestFinal_ex(md, out, NULL) == 1;
	EVP_MD_CTX_free(md);
	return ok ? 0 : -EIO;
}

static int read_pcr14(ESYS_CONTEXT *esys, uint8_t out[HASH_SIZE])
{
	TPML_PCR_SELECTION sel;
	memset(&sel, 0, sizeof(sel));
	sel.count = 1;
	sel.pcrSelections[0].hash = PCR14_HASH_ALG;
	sel.pcrSelections[0].sizeofSelect = 3;
	sel.pcrSelections[0].pcrSelect[INITRAMFS_LOCK_PCR / 8] =
	    (uint8_t)(1U << (INITRAMFS_LOCK_PCR % 8));

	uint32_t update_counter = 0;
	TPML_PCR_SELECTION *sel_out = NULL;
	TPML_DIGEST *values = NULL;
	TSS2_RC rc =
	    Esys_PCR_Read(esys, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &sel,
			  &update_counter, &sel_out, &values);
	if (rc != TSS2_RC_SUCCESS) {
		fprintf(stderr,
			"lota-pcr14-lock: Esys_PCR_Read failed: 0x%08x\n", rc);
		return -EIO;
	}
	if (!values || values->count == 0 ||
	    values->digests[0].size != HASH_SIZE) {
		Esys_Free(values);
		Esys_Free(sel_out);
		return -ENODATA;
	}
	memcpy(out, values->digests[0].buffer, HASH_SIZE);
	Esys_Free(values);
	Esys_Free(sel_out);
	return 0;
}

static int extend_pcr14(ESYS_CONTEXT *esys, const uint8_t digest[HASH_SIZE])
{
	TPML_DIGEST_VALUES digests;
	ESYS_TR pcr_handle = ESYS_TR_PCR0 + INITRAMFS_LOCK_PCR;

	memset(&digests, 0, sizeof(digests));
	digests.count = 1;
	digests.digests[0].hashAlg = PCR14_HASH_ALG;
	memcpy(digests.digests[0].digest.sha256, digest, HASH_SIZE);

	TSS2_RC rc = Esys_PCR_Extend(esys, pcr_handle, ESYS_TR_PASSWORD,
				     ESYS_TR_NONE, ESYS_TR_NONE, &digests);
	if (rc != TSS2_RC_SUCCESS) {
		fprintf(stderr,
			"lota-pcr14-lock: Esys_PCR_Extend failed: 0x%08x\n",
			rc);
		return -EIO;
	}
	return 0;
}

int main(int argc, char **argv)
{
	(void)argc;
	(void)argv;

	TSS2_TCTI_CONTEXT *tcti = NULL;
	ESYS_CONTEXT *esys = NULL;
	size_t tcti_size = 0;
	const char *dev = device_path();

	TSS2_RC rc = Tss2_Tcti_Device_Init(NULL, &tcti_size, dev);
	if (rc != TSS2_RC_SUCCESS) {
		fprintf(
		    stderr,
		    "lota-pcr14-lock: Tss2_Tcti_Device_Init sizing: 0x%08x\n",
		    rc);
		return 2;
	}
	tcti = calloc(1, tcti_size);
	if (!tcti) {
		fprintf(stderr,
			"lota-pcr14-lock: out of memory for TCTI context\n");
		return 3;
	}
	rc = Tss2_Tcti_Device_Init(tcti, &tcti_size, dev);
	if (rc != TSS2_RC_SUCCESS) {
		fprintf(stderr,
			"lota-pcr14-lock: Tss2_Tcti_Device_Init(%s) failed: "
			"0x%08x\n",
			dev, rc);
		free(tcti);
		return 4;
	}

	rc = Esys_Initialize(&esys, tcti, NULL);
	if (rc != TSS2_RC_SUCCESS) {
		fprintf(stderr,
			"lota-pcr14-lock: Esys_Initialize failed: 0x%08x\n",
			rc);
		Tss2_Tcti_Finalize(tcti);
		free(tcti);
		return 5;
	}

	TPMS_TIME_INFO *time_info = NULL;
	rc = Esys_ReadClock(esys, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
			    &time_info);
	if (rc != TSS2_RC_SUCCESS) {
		fprintf(stderr,
			"lota-pcr14-lock: Esys_ReadClock failed: 0x%08x\n", rc);
		Esys_Finalize(&esys);
		Tss2_Tcti_Finalize(tcti);
		free(tcti);
		return 6;
	}
	uint32_t reset_count = time_info->clockInfo.resetCount;
	uint32_t restart_count = time_info->clockInfo.restartCount;
	Esys_Free(time_info);

	uint8_t commit[HASH_SIZE];
	int crc =
	    lota_initramfs_lock_commit(reset_count, restart_count, commit);
	if (crc < 0) {
		fprintf(
		    stderr,
		    "lota-pcr14-lock: digest derivation failed (errno %d)\n",
		    -crc);
		Esys_Finalize(&esys);
		Tss2_Tcti_Finalize(tcti);
		free(tcti);
		return 7;
	}

	uint8_t expected[HASH_SIZE];
	crc = expected_post_extend(commit, expected);
	if (crc < 0) {
		fprintf(stderr,
			"lota-pcr14-lock: expected-value derivation failed "
			"(errno %d)\n",
			-crc);
		Esys_Finalize(&esys);
		Tss2_Tcti_Finalize(tcti);
		free(tcti);
		return 8;
	}

	uint8_t current[HASH_SIZE];
	crc = read_pcr14(esys, current);
	if (crc < 0) {
		fprintf(stderr,
			"lota-pcr14-lock: PCR14 read failed (errno %d)\n",
			-crc);
		Esys_Finalize(&esys);
		Tss2_Tcti_Finalize(tcti);
		free(tcti);
		return 9;
	}

	uint8_t zero[HASH_SIZE] = {0};
	int exit_code = 0;

	if (memcmp(current, zero, HASH_SIZE) == 0) {
		/* Fresh boot, PCR14 untouched: extend. */
		crc = extend_pcr14(esys, commit);
		if (crc < 0) {
			fprintf(stderr,
				"lota-pcr14-lock: PCR14 extend failed\n");
			exit_code = 10;
		} else {
			fprintf(stderr,
				"lota-pcr14-lock: PCR14 locked (resetCount=%u "
				"restartCount=%u)\n",
				(unsigned)reset_count, (unsigned)restart_count);
		}
	} else if (memcmp(current, expected, HASH_SIZE) == 0) {
		/* helper already ran this boot session: no-op, exit success */
		fprintf(
		    stderr,
		    "lota-pcr14-lock: PCR14 already locked, skipping extend\n");
	} else {
		/*
		 * PCR14 holds something else - boot loader or a non-LOTA
		 * component extended it before this helper ran. agent will
		 * refuse to attest with an explicit -EBADMSG anyway, so report
		 * the mismatch here and fail loud
		 */
		fprintf(stderr, "lota-pcr14-lock: PCR14 holds unexpected value "
				"before lock; "
				"refusing to extend\n");
		exit_code = 11;
	}

	Esys_Finalize(&esys);
	Tss2_Tcti_Finalize(tcti);
	free(tcti);
	return exit_code;
}
#endif
