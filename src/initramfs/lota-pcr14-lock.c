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
 *     SHA256("LOTA-PCR14-INITRAMFS-LOCK-v1")
 *
 *   The lock deliberately does not bind resetCount/restartCount. Those
 *   counters are included by the later lota-agent boot commitment, after
 *   userspace is up and close to the quote. Keeping the initramfs step
 *   counter-stable avoids false failures when restartCount moves between
 *   initramfs and attestation. Once locked, any further extension by an
 *   untrusted userspace process produces a value the verifier cannot
 *   match, so the attestation fails closed.
 *
 * Baseline
 *   PCR14 is not pristine on every platform. On UEFI Secure Boot shim
 *   measures the MOK state (MokList, SbatLevel, MokListRT) into PCR14
 *   before the initramfs runs, so PCR14 is already non-zero.
 *   The helper therefore extends its commitment on top of whatever PCR14
 *   holds (the baseline) instead of requiring 0^32, and records that baseline
 *   at BASELINE_PATH on /run.
 *   lota-agent reads it to anchor its derivations, and the verifier
 *   independently reconstructs it from the signed event log, so forged handoff
 *   cannot move trust - it only fails closed.
 *   On a legacy/BIOS host the baseline is 0^32 and behaviour is unchanged.
 *
 * Idempotency
 *   The helper is safe to run multiple times within a single boot session.
 *   First run records the baseline. Later runs (kexec, a late systemd-tpm2 hook)
 *   recompute SHA256(baseline || commit) from the recorded baseline and exit 0
 *   when PCR14 already matches it.
 *
 * Failure mode
 *   TPM error, unsupported TSS2 layer, failure to persist the baseline, or PCR14
 *   mutating away from the recorded baseline after the first run, all surface as
 *   non-zero exit.
 *   initramfs systemd unit that wraps this helper is ordered before sysroot.mount /
 *   initrd-root-fs.target so non-zero exit aborts the transition to the real root.
 *
 * Cleanup model
 *   Helper records the baseline at BASELINE_PATH on the /run tmpfs and otherwise
 *   releases all TSS2/OpenSSL allocations before exit.
 *   ENV variable LOTA_INITRAMFS_LOCK_TCTI overrides the default /dev/tpmrm0 device
 *   path (used by the test harness)
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <openssl/evp.h>

#include <tss2/tss2_esys.h>
#include <tss2/tss2_tcti.h>
#include <tss2/tss2_tcti_device.h>

#define INITRAMFS_LOCK_TAG "LOTA-PCR14-INITRAMFS-LOCK-v1"
#define INITRAMFS_LOCK_PCR 14
#define PCR14_HASH_ALG TPM2_ALG_SHA256
#define HASH_SIZE 32

/*
 * Baseline handoff.
 * Helper records the PCR14 value it observed before its own extend
 * (0^32 on legacy/BIOS, the firmware/shim MOK measurement on UEFI Secure Boot)
 * here, on the /run tmpfs that persists across the initramfs -> rootfs switch.
 * lota-agent reads it (LOTA_PCR14_BASELINE_PATH in src/agent/tpm.h) so its
 * boot-commitment derivations anchor on the same baseline, and re-runs of this
 * helper use it for idempotency.
 */
#define BASELINE_DIR "/run/lota"
#define BASELINE_PATH "/run/lota/pcr14_baseline"

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
 * re-marshalling the inputs. resetCount and restartCount are accepted for
 * API compatibility with the agent helper, but they are intentionally not
 * part of the initramfs lock digest. Freshness is bound later by the agent
 * boot-commitment derivation in src/agent/tpm.c.
 *
 * Returns: 0 on success, negative errno on failure.
 */
int lota_initramfs_lock_commit(uint32_t reset_count, uint32_t restart_count,
			       uint8_t out_digest[HASH_SIZE])
{
	if (!out_digest)
		return -EINVAL;

	(void)reset_count;
	(void)restart_count;

	EVP_MD_CTX *md = EVP_MD_CTX_new();
	if (!md)
		return -ENOMEM;

	int ok = EVP_DigestInit_ex(md, EVP_sha256(), NULL) == 1 &&
		 EVP_DigestUpdate(md, INITRAMFS_LOCK_TAG,
				  sizeof(INITRAMFS_LOCK_TAG) - 1) == 1 &&
		 EVP_DigestFinal_ex(md, out_digest, NULL) == 1;
	EVP_MD_CTX_free(md);

	return ok ? 0 : -EIO;
}

#ifndef LOTA_INITRAMFS_LOCK_NO_MAIN
/*
 * extend_over - SHA256(base || commit), the PCR14 value after extending
 * commit on top of base.
 * base is the pre-extend PCR14 content: 0^32 on a legacy/BIOS host,
 * or the firmware/shim MOK measurement on UEFI Secure Boot.
 * PCR14 is not pristine on Secure Boot, so the lock cannot assume zero base;
 * it folds whatever the firmware left into the chain.
 */
static int extend_over(const uint8_t base[HASH_SIZE],
		       const uint8_t commit[HASH_SIZE], uint8_t out[HASH_SIZE])
{
	EVP_MD_CTX *md = EVP_MD_CTX_new();
	if (!md)
		return -ENOMEM;
	int ok = EVP_DigestInit_ex(md, EVP_sha256(), NULL) == 1 &&
		 EVP_DigestUpdate(md, base, HASH_SIZE) == 1 &&
		 EVP_DigestUpdate(md, commit, HASH_SIZE) == 1 &&
		 EVP_DigestFinal_ex(md, out, NULL) == 1;
	EVP_MD_CTX_free(md);
	return ok ? 0 : -EIO;
}

/*
 * read_saved_baseline - load a baseline this helper persisted earlier in
 * the same boot session.
 * Returns 1 and fills out on success, 0 when no file exists yet
 * (the normal first-run case), negative errno on error.
 */
static int read_saved_baseline(uint8_t out[HASH_SIZE])
{
	FILE *f = fopen(BASELINE_PATH, "rb");
	if (!f)
		return errno == ENOENT ? 0 : -errno;
	size_t n = fread(out, 1, HASH_SIZE, f);
	int err = ferror(f);
	fclose(f);
	if (err)
		return -EIO;
	return n == HASH_SIZE ? 1 : 0;
}

/*
 * write_baseline - persist the observed pre-extend PCR14 for lota-agent
 * and for idempotent re-runs of this helper.
 * Written before the extend so crash between write and extend still lets
 * the agent attribute PCR14.
 */
static int write_baseline(const uint8_t base[HASH_SIZE])
{
	if (mkdir(BASELINE_DIR, 0755) != 0 && errno != EEXIST)
		return -errno;
	int fd = open(BASELINE_PATH, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW,
		      0600);
	if (fd < 0)
		return -errno;
	FILE *f = fdopen(fd, "wb");
	if (!f) {
		int err = -errno;
		close(fd);
		return err;
	}
	size_t n = fwrite(base, 1, HASH_SIZE, f);
	int ok = (n == HASH_SIZE) && (fflush(f) == 0);
	if (fclose(f) != 0)
		ok = 0;
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
	TSS2_RC rc = Esys_PCR_Read(esys, ESYS_TR_NONE, ESYS_TR_NONE,
				   ESYS_TR_NONE, &sel, &update_counter,
				   &sel_out, &values);
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
		fprintf(stderr,
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
		fprintf(stderr,
			"lota-pcr14-lock: digest derivation failed (errno %d)\n",
			-crc);
		Esys_Finalize(&esys);
		Tss2_Tcti_Finalize(tcti);
		free(tcti);
		return 7;
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

	uint8_t saved[HASH_SIZE];
	int have_saved = read_saved_baseline(saved);
	if (have_saved < 0) {
		fprintf(stderr,
			"lota-pcr14-lock: baseline read failed (errno %d)\n",
			-have_saved);
		Esys_Finalize(&esys);
		Tss2_Tcti_Finalize(tcti);
		free(tcti);
		return 8;
	}

	int exit_code = 0;

	if (have_saved) {
		/*
		 * Helper already recorded a baseline this boot session.
		 * Re-entry (kexec, a late systemd-tpm2 hook):
		 * act idempotently against the recorded baseline
		 */
		uint8_t locked[HASH_SIZE];
		crc = extend_over(saved, commit, locked);
		if (crc < 0) {
			fprintf(stderr,
				"lota-pcr14-lock: derivation failed (errno %d)\n",
				-crc);
			exit_code = 8;
		} else if (memcmp(current, locked, HASH_SIZE) == 0) {
			fprintf(stderr,
				"lota-pcr14-lock: PCR14 already locked, skipping extend\n");
		} else if (memcmp(current, saved, HASH_SIZE) == 0) {
			/* baseline persisted but the extend did not land
			 * (crash between write and extend): finish it */
			crc = extend_pcr14(esys, commit);
			if (crc < 0) {
				fprintf(stderr,
					"lota-pcr14-lock: PCR14 extend failed\n");
				exit_code = 10;
			} else {
				fprintf(stderr,
					"lota-pcr14-lock: PCR14 locked over recorded baseline\n");
			}
		} else {
			/*
			 * PCR14 is neither the recorded baseline nor our locked value:
			 * non-LOTA writer touched it after recorded the baseline this boot.
			 * Fail loud; the verifier rejects the resulting quote regardless.
			 */
			fprintf(stderr,
				"lota-pcr14-lock: PCR14 mutated after the baseline was "
				"recorded this boot; refusing to extend\n");
			exit_code = 11;
		}
	} else {
		/*
		 * First run this boot.
		 * Whatever PCR14 holds now is the pre-LOTA baseline:
		 * 0^32 on a legacy/BIOS host, or the firmware/shim MOK measurement
		 * on UEFI Secure Boot.
		 * Persist it for lota-agent and for idempotent re-runs, then extend
		 * the lock commitment on top.
		 */
		crc = write_baseline(current);
		if (crc < 0) {
			fprintf(stderr,
				"lota-pcr14-lock: baseline persist to %s failed "
				"(errno %d)\n",
				BASELINE_PATH, -crc);
			exit_code = 12;
		} else {
			crc = extend_pcr14(esys, commit);
			if (crc < 0) {
				fprintf(stderr,
					"lota-pcr14-lock: PCR14 extend failed\n");
				exit_code = 10;
			} else {
				fprintf(stderr,
					"lota-pcr14-lock: PCR14 locked over baseline "
					"(observed resetCount=%u restartCount=%u)\n",
					(unsigned)reset_count,
					(unsigned)restart_count);
			}
		}
	}

	Esys_Finalize(&esys);
	Tss2_Tcti_Finalize(tcti);
	free(tcti);
	return exit_code;
}
#endif
