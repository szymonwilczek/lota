/* SPDX-License-Identifier: MIT */
/*
 * lota-pcr14-lock - extend PCR14 with SHA256(INITRAMFS_LOCK_TAG) on top of
 * whatever it holds, and record the pre-extend value at BASELINE_PATH.
 *
 * A re-run in the same boot exits 0 when PCR14 already holds the locked
 * value, finishes the extend when it still holds the recorded value, and
 * exits 11 on any other value. A host without UEFI_FIRMWARE_PATH exits 13.
 * LOTA_INITRAMFS_LOCK_TCTI replaces the /dev/tpmrm0 device path.
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

/* lota-agent reads it as LOTA_PCR14_BASELINE_PATH */
#define BASELINE_DIR "/run/lota"
#define BASELINE_PATH "/run/lota/pcr14_baseline"

/* absent on a legacy BIOS/CSM boot */
#define UEFI_FIRMWARE_PATH "/sys/firmware/efi"

#ifndef LOTA_INITRAMFS_LOCK_NO_MAIN
static const char *device_path(void)
{
	const char *env = getenv("LOTA_INITRAMFS_LOCK_TCTI");
	if (env && env[0])
		return env;
	return "/dev/tpmrm0";
}
#endif

int lota_initramfs_lock_commit(uint8_t out_digest[HASH_SIZE]);

/*
 * lota_initramfs_lock_commit - SHA256(INITRAMFS_LOCK_TAG) into out_digest
 *
 * Not static: tests/test_initramfs_lock.c calls it.
 *
 * Return: 0, -EINVAL for a NULL out_digest, -ENOMEM or -EIO.
 */
int lota_initramfs_lock_commit(uint8_t out_digest[HASH_SIZE])
{
	if (!out_digest)
		return -EINVAL;

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

int lota_initramfs_lock_read_baseline(const char *path, uint8_t out[HASH_SIZE]);

/*
 * lota_initramfs_lock_read_baseline - load a baseline file into out
 *
 * Not static: tests/test_initramfs_lock.c calls it.
 *
 * Return: 1 when it holds exactly HASH_SIZE bytes, 0 when it is missing or
 * any other length, negative errno otherwise.
 */
int lota_initramfs_lock_read_baseline(const char *path, uint8_t out[HASH_SIZE])
{
	uint8_t buf[HASH_SIZE + 1];
	int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
	if (fd < 0)
		return errno == ENOENT ? 0 : -errno;
	FILE *f = fdopen(fd, "rb");
	if (!f) {
		int err = -errno;
		close(fd);
		return err;
	}
	size_t n = fread(buf, 1, sizeof(buf), f);
	int err = ferror(f);
	fclose(f);
	if (err)
		return -EIO;
	if (n != HASH_SIZE)
		return 0;
	memcpy(out, buf, HASH_SIZE);
	return 1;
}

#ifndef LOTA_INITRAMFS_LOCK_NO_MAIN
/* extend_over - SHA256(base || commit), PCR14 after extending commit on base */
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
 * write_baseline - store base at BASELINE_PATH
 *
 * Called before the extend, so a re-run can finish an extend that did not
 * land.
 */
static int write_baseline(const uint8_t base[HASH_SIZE])
{
	/* lota-agent sets 0750 root:lota; the initramfs has no group lota */
	if (mkdir(BASELINE_DIR, 0711) != 0 && errno != EEXIST)
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

	if (access(UEFI_FIRMWARE_PATH, F_OK) != 0) {
		fprintf(stderr,
			"lota-pcr14-lock: this host did not boot via UEFI (%s "
			"absent); LOTA requires UEFI measured boot and refuses "
			"to lock PCR14 on legacy BIOS/CSM\n",
			UEFI_FIRMWARE_PATH);
		return 13;
	}

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

	uint8_t commit[HASH_SIZE];
	int crc = lota_initramfs_lock_commit(commit);
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
	int have_saved =
		lota_initramfs_lock_read_baseline(BASELINE_PATH, saved);
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
			/* recorded, but the extend did not land */
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
			fprintf(stderr,
				"lota-pcr14-lock: PCR14 mutated after the baseline was "
				"recorded this boot; refusing to extend\n");
			exit_code = 11;
		}
	} else {
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
					"lota-pcr14-lock: PCR14 locked over baseline\n");
			}
		}
	}

	Esys_Finalize(&esys);
	Tss2_Tcti_Finalize(tcti);
	free(tcti);
	return exit_code;
}
#endif
