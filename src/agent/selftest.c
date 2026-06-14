/* SPDX-License-Identifier: MIT */
/*
 * LOTA Agent - Self-test commands
 * TPM and IOMMU diagnostic test subcommands
 */

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/random.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <tss2/tss2_tpm2_types.h>

#include "../../include/lota.h"
#include "../../include/lota_envelope.h"
#include "../../include/lota_seal.h"
#include "agent.h"
#include "iommu.h"
#include "quote.h"
#include "selftest.h"
#include "tpm.h"
#include "iommu_types.h"

void print_hex(const char *label, const uint8_t *data, size_t len)
{
	size_t i;
	printf("%s: ", label);
	for (i = 0; i < len && i < 32; i++)
		printf("%02x", data[i]);
	if (len > 32)
		printf("...");
	printf("\n");
}

int test_tpm(void)
{
	int ret;
	uint8_t pcr_value[LOTA_HASH_SIZE];
	uint8_t kernel_hash[LOTA_HASH_SIZE];
	char kernel_path[256];
	char exe_path[LOTA_MAX_PATH_LEN];
	uint8_t self_hash[LOTA_HASH_SIZE];
	ssize_t len;

	printf("=== TPM Test ===\n\n");

	printf("Initializing TPM context...\n");
	ret = tpm_init(&g_agent.tpm_ctx);
	if (ret < 0) {
		fprintf(stderr, "Failed to initialize TPM: %s\n",
			strerror(-ret));
		return ret;
	}
	printf("TPM initialized successfully\n\n");

	printf("Running TPM self-test...\n");
	ret = tpm_self_test(&g_agent.tpm_ctx);
	if (ret < 0) {
		fprintf(stderr, "TPM self-test failed: %s\n", strerror(-ret));
	} else {
		printf("TPM self-test passed\n");
	}
	printf("\n");

	printf("Reading PCR 0 (SRTM)...\n");
	ret = tpm_read_pcr(&g_agent.tpm_ctx, 0, TPM2_ALG_SHA256, pcr_value);
	if (ret < 0) {
		fprintf(stderr, "Failed to read PCR 0: %s\n", strerror(-ret));
	} else {
		print_hex("PCR 0", pcr_value, LOTA_HASH_SIZE);
	}

	printf("\nReading PCR 1 (BIOS config/IOMMU)...\n");
	ret = tpm_read_pcr(&g_agent.tpm_ctx, 1, TPM2_ALG_SHA256, pcr_value);
	if (ret < 0) {
		fprintf(stderr, "Failed to read PCR 1: %s\n", strerror(-ret));
	} else {
		print_hex("PCR 1", pcr_value, LOTA_HASH_SIZE);
	}

	printf("\nReading PCR 10 (IMA)...\n");
	ret = tpm_read_pcr(&g_agent.tpm_ctx, 10, TPM2_ALG_SHA256, pcr_value);
	if (ret < 0) {
		fprintf(stderr, "Failed to read PCR 10: %s\n", strerror(-ret));
	} else {
		print_hex("PCR 10", pcr_value, LOTA_HASH_SIZE);
	}

	/* hash kernel image */
	printf("\nFinding current kernel...\n");
	{
		int k_err = tpm_get_current_kernel_path(
		    &g_agent.tpm_ctx, kernel_path, sizeof(kernel_path));
		if (k_err < 0) {
			fprintf(stderr, "Failed to find kernel: %s\n",
				strerror(-k_err));
		} else {
			printf("Kernel: %s\n", kernel_path);
			printf("Hashing kernel image...\n");
			k_err = tpm_hash_file(kernel_path, kernel_hash);
			if (k_err < 0) {
				fprintf(stderr, "Failed to hash kernel: %s\n",
					strerror(-k_err));
			} else {
				print_hex("Kernel SHA-256", kernel_hash,
					  LOTA_HASH_SIZE);
			}
		}
	}

	/* self-measurement test */
	printf("\n=== Self-Measurement Test ===\n\n");

	len = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
	if (len < 0) {
		fprintf(stderr, "Failed to read /proc/self/exe: %s\n",
			strerror(errno));
	} else {
		int s_err;
		exe_path[len] = '\0';
		printf("Agent binary: %s\n", exe_path);

		s_err = tpm_hash_file(exe_path, self_hash);
		if (s_err < 0) {
			fprintf(stderr, "Failed to hash agent: %s\n",
				strerror(-s_err));
		} else {
			print_hex("Agent SHA-256", self_hash, LOTA_HASH_SIZE);
		}
	}

	printf("\nReading PCR %d before extend...\n", LOTA_PCR_SELF);
	ret = tpm_read_pcr(&g_agent.tpm_ctx, LOTA_PCR_SELF, TPM2_ALG_SHA256,
			   pcr_value);
	if (ret < 0) {
		fprintf(stderr, "Failed to read PCR %d: %s\n", LOTA_PCR_SELF,
			strerror(-ret));
	} else {
		print_hex("PCR 14 (before)", pcr_value, LOTA_HASH_SIZE);
	}

	printf("\nExtending self-hash into PCR %d...\n", LOTA_PCR_SELF);
	ret = self_measure(&g_agent.tpm_ctx);
	if (ret < 0) {
		fprintf(stderr, "Self-measurement failed: %s\n",
			strerror(-ret));
	} else {
		printf("Self-measurement successful\n");
	}

	printf("\nReading PCR %d after extend...\n", LOTA_PCR_SELF);
	ret = tpm_read_pcr(&g_agent.tpm_ctx, LOTA_PCR_SELF, TPM2_ALG_SHA256,
			   pcr_value);
	if (ret < 0) {
		fprintf(stderr, "Failed to read PCR %d: %s\n", LOTA_PCR_SELF,
			strerror(-ret));
	} else {
		print_hex("PCR 14 (after)", pcr_value, LOTA_HASH_SIZE);
	}

	/* AIK provisioning test */
	printf("\n=== AIK Provisioning Test ===\n\n");

	printf("Checking/provisioning AIK at handle 0x%08X...\n",
	       g_agent.tpm_ctx.aik_handle);
	ret = tpm_provision_aik(&g_agent.tpm_ctx);
	if (ret < 0) {
		fprintf(stderr, "AIK provisioning failed: %s\n",
			strerror(-ret));
		fprintf(stderr,
			"Note: May require owner hierarchy authorization\n");
	} else {
		printf("AIK ready\n");
	}

	/* TPM Quote test */
	printf("\n=== TPM Quote Test ===\n\n");

	if (ret == 0) {
		struct tpm_quote_response quote_resp;
		uint8_t test_nonce[LOTA_NONCE_SIZE];
		uint32_t quote_pcr_mask;

		/* Generate random test nonce (production path uses server
		 * challenge) */
		printf("Generating test nonce...\n");
		if (getrandom(test_nonce, LOTA_NONCE_SIZE, 0) !=
		    LOTA_NONCE_SIZE) {
			fprintf(stderr, "getrandom failed: %s\n",
				strerror(errno));
			tpm_cleanup(&g_agent.tpm_ctx);
			return -1;
		}
		print_hex("Nonce", test_nonce, LOTA_NONCE_SIZE);

		/* quote pcrs: 0,1,14 */
		quote_pcr_mask = (1U << 0) | (1U << 1) | (1U << LOTA_PCR_SELF);
		printf("\nRequesting quote for PCRs 0, 1, %d...\n",
		       LOTA_PCR_SELF);

		ret = tpm_quote(&g_agent.tpm_ctx, test_nonce, quote_pcr_mask,
				&quote_resp);
		if (ret < 0) {
			fprintf(stderr, "TPM Quote failed: %s\n",
				strerror(-ret));
		} else {
			printf("Quote generated successfully!\n\n");
			printf("Attestation data size: %u bytes\n",
			       quote_resp.attest_size);
			printf("Signature algorithm: 0x%04X\n",
			       quote_resp.sig_alg);
			printf("Signature size: %u bytes\n",
			       quote_resp.signature_size);
			print_hex("Signature", quote_resp.signature,
				  quote_resp.signature_size);
			printf("\nPCR values in quote:\n");
			print_hex("  PCR 0", quote_resp.pcr_values[0],
				  LOTA_HASH_SIZE);
			print_hex("  PCR 1", quote_resp.pcr_values[1],
				  LOTA_HASH_SIZE);
			print_hex("  PCR 14",
				  quote_resp.pcr_values[LOTA_PCR_SELF],
				  LOTA_HASH_SIZE);
		}
	}

	tpm_cleanup(&g_agent.tpm_ctx);
	printf("\nTPM test complete\n");
	return 0;
}

int test_iommu(void)
{
	struct iommu_status status;
	char buf[1024];
	bool ok;

	printf("=== IOMMU Test ===\n\n");

	ok = iommu_verify_full(&status);

	iommu_status_to_string(&status, buf, sizeof(buf));
	printf("%s\n", buf);

	if (ok) {
		printf("IOMMU verification: PASSED\n");
		return 0;
	} else {
		printf("IOMMU verification: FAILED\n");
		printf("\nRecommendations:\n");
		if (!(status.flags & IOMMU_FLAG_SYSFS_PRESENT)) {
			printf("  - Enable VT-d/AMD-Vi in BIOS\n");
		}
		if (!(status.flags & IOMMU_FLAG_CMDLINE_SET)) {
			printf("  - Add 'intel_iommu=on' or 'amd_iommu=force' "
			       "to kernel cmdline\n");
		}
		if (!(status.flags & IOMMU_FLAG_DMA_REMAP)) {
			printf("  - Check dmesg for IOMMU initialization "
			       "errors\n");
		}
		return 1;
	}
}

/*
 * Read all of stdin into buf (capacity cap). Returns the byte count via
 * *out_len, -E2BIG if the input exceeds cap, or a negative errno. Reading
 * the secret / blob from stdin keeps it out of argv and the environment.
 */
static int read_all_stdin(uint8_t *buf, size_t cap, size_t *out_len)
{
	size_t total = 0;

	for (;;) {
		if (total == cap) {
			/* probe for a trailing byte to detect overflow */
			uint8_t extra;
			ssize_t n = read(STDIN_FILENO, &extra, 1);
			if (n > 0)
				return -E2BIG;
			if (n == 0)
				break;
			if (errno == EINTR)
				continue;
			return -errno;
		}
		ssize_t n = read(STDIN_FILENO, buf + total, cap - total);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -errno;
		}
		if (n == 0)
			break;
		total += (size_t)n;
	}
	*out_len = total;
	return 0;
}

static int write_all_stdout(const uint8_t *buf, size_t len)
{
	size_t off = 0;

	while (off < len) {
		ssize_t n = write(STDOUT_FILENO, buf + off, len - off);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -errno;
		}
		off += (size_t)n;
	}
	return 0;
}

static int parse_seal_mask(const char *str, uint32_t *out_mask)
{
	char *end = NULL;
	unsigned long v;

	if (!str) {
		*out_mask = 0; /* 0 -> tpm_seal_secret picks the default */
		return 0;
	}
	errno = 0;
	v = strtoul(str, &end, 0);
	if (errno != 0 || end == str || *end != '\0' || v > 0xFFFFFFFFul)
		return -EINVAL;
	if (lota_seal_validate_pcr_mask((uint32_t)v) != 0)
		return -EINVAL;
	*out_mask = (uint32_t)v;
	return 0;
}

/*
 * do_seal - read a secret from stdin, seal it to the PCR state, write the
 * sealed blob to stdout. Operator/root tool; never exposed over IPC.
 */
int do_seal(const char *pcr_str)
{
	uint8_t *secret = NULL;
	uint8_t *blob = NULL;
	size_t secret_len = 0, blob_len = 0;
	uint32_t pcr_mask = 0;
	int ret;
	int rc = 1;

	if (parse_seal_mask(pcr_str, &pcr_mask) < 0) {
		fprintf(stderr, "Invalid --seal-pcrs value\n");
		return 1;
	}

	/*
	 * Heap buffers: an envelope payload reaches LOTA_ENVELOPE_MAX_PAYLOAD
	 * (64 KiB), too large for the stack.
	 */
	secret = malloc(LOTA_ENVELOPE_MAX_PAYLOAD);
	blob = malloc(LOTA_ENVELOPE_MAX_BLOB);
	if (!secret || !blob) {
		fprintf(stderr, "Out of memory\n");
		goto out;
	}

	ret = read_all_stdin(secret, LOTA_ENVELOPE_MAX_PAYLOAD, &secret_len);
	if (ret < 0) {
		fprintf(stderr, "Failed to read secret from stdin: %s\n",
			ret == -E2BIG ? "too large (max 65536 bytes)"
				      : strerror(-ret));
		goto out;
	}
	if (secret_len == 0) {
		fprintf(stderr, "Refusing to seal an empty secret\n");
		goto out;
	}

	/*
	 * Silence the TSS library's own WARNING/ERROR spam: seal/unseal print
	 * their own clear diagnostics via tpm_strerror().
	 * overwrite=0 leaves an operator-set TSS2_LOG untouched for debugging.
	 */
	setenv("TSS2_LOG", "all+none", 0);

	ret = tpm_init(&g_agent.tpm_ctx);
	if (ret < 0) {
		fprintf(stderr, "Failed to initialize TPM: %s\n",
			tpm_strerror(ret));
		goto out;
	}

	/*
	 * Direct TPM2_Seal up to its sensitive-data cap; beyond that an
	 * envelope (TPM-sealed KEK + AES-256-GCM payload) carries the bulk.
	 */
	if (secret_len <= LOTA_SEAL_MAX_SECRET)
		ret = tpm_seal_secret(&g_agent.tpm_ctx, secret, secret_len,
				      pcr_mask, blob, LOTA_ENVELOPE_MAX_BLOB,
				      &blob_len);
	else
		ret = tpm_seal_secret_envelope(
		    &g_agent.tpm_ctx, secret, secret_len, pcr_mask, blob,
		    LOTA_ENVELOPE_MAX_BLOB, &blob_len);
	tpm_cleanup(&g_agent.tpm_ctx);
	if (ret < 0) {
		fprintf(stderr, "Seal failed: %s\n", tpm_strerror(ret));
		goto out;
	}

	if (write_all_stdout(blob, blob_len) < 0) {
		fprintf(stderr, "Failed to write sealed blob to stdout\n");
		goto out;
	}
	fprintf(stderr, "Sealed %zu-byte secret to a %zu-byte blob%s.\n",
		secret_len, blob_len,
		secret_len > LOTA_SEAL_MAX_SECRET ? " (envelope)" : "");
	rc = 0;

out:
	if (secret) {
		explicit_bzero(secret, LOTA_ENVELOPE_MAX_PAYLOAD);
		free(secret);
	}
	free(blob);
	return rc;
}

/*
 * do_unseal - read a sealed blob from stdin, unseal it, write the secret
 * to stdout. Fails closed when the host is not in the sealed PCR state.
 */
int do_unseal(void)
{
	uint8_t *blob = NULL;
	uint8_t *secret = NULL;
	size_t blob_len = 0, secret_len = 0;
	bool envelope = false;
	int ret;
	int rc = 1;

	blob = malloc(LOTA_ENVELOPE_MAX_BLOB);
	secret = malloc(LOTA_ENVELOPE_MAX_PAYLOAD);
	if (!blob || !secret) {
		fprintf(stderr, "Out of memory\n");
		goto out;
	}

	ret = read_all_stdin(blob, LOTA_ENVELOPE_MAX_BLOB, &blob_len);
	if (ret < 0) {
		fprintf(stderr, "Failed to read blob from stdin: %s\n",
			ret == -E2BIG ? "too large" : strerror(-ret));
		goto out;
	}
	if (blob_len == 0) {
		fprintf(stderr, "No sealed blob on stdin\n");
		goto out;
	}

	/* leading magic selects the decoder: envelope vs direct seal */
	envelope = lota_envelope_is_envelope(blob, blob_len) != 0;

	/* PCR-policy mismatch is the expected unseal failure.
	 * Keep its report clean by silencing the TSS library's own error
	 * logging (overwrite=0 respects an operator-set TSS2_LOG). */
	setenv("TSS2_LOG", "all+none", 0);

	ret = tpm_init(&g_agent.tpm_ctx);
	if (ret < 0) {
		fprintf(stderr, "Failed to initialize TPM: %s\n",
			tpm_strerror(ret));
		goto out;
	}

	if (envelope)
		ret = tpm_unseal_secret_envelope(
		    &g_agent.tpm_ctx, blob, blob_len, secret,
		    LOTA_ENVELOPE_MAX_PAYLOAD, &secret_len);
	else
		ret =
		    tpm_unseal_secret(&g_agent.tpm_ctx, blob, blob_len, secret,
				      LOTA_ENVELOPE_MAX_PAYLOAD, &secret_len);
	tpm_cleanup(&g_agent.tpm_ctx);
	if (ret < 0) {
		fprintf(stderr, "Unseal failed: %s\n", tpm_strerror(ret));
		/* -EBADMSG is an envelope tamper, not a boot-state mismatch */
		if (ret != -LOTA_ERR_TPM_POLICY_FAIL && ret != -EBADMSG)
			fprintf(stderr,
				"(the host may not be in the sealed boot "
				"state)\n");
		goto out;
	}

	if (write_all_stdout(secret, secret_len) < 0) {
		fprintf(stderr, "Failed to write secret to stdout\n");
		goto out;
	}
	fprintf(stderr, "Unsealed %zu-byte secret%s.\n", secret_len,
		envelope ? " (envelope)" : "");
	rc = 0;

out:
	if (secret) {
		explicit_bzero(secret, LOTA_ENVELOPE_MAX_PAYLOAD);
		free(secret);
	}
	free(blob);
	return rc;
}

/*
 * do_seal_aik_auth - adopt at-rest sealing of the AIK userAuth on an
 * already-enrolled host, without re-enrolling. Seals the current auth to
 * the current PCR state (and, with seal_aik_auth_strict in lota.conf, drops
 * the plaintext sidecar).
 */
int do_seal_aik_auth(void)
{
	int ret;

	setenv("TSS2_LOG", "all+none", 0);

	ret = tpm_init(&g_agent.tpm_ctx);
	if (ret < 0) {
		fprintf(stderr, "Failed to initialize TPM: %s\n",
			tpm_strerror(ret));
		return 1;
	}

	ret = tpm_aik_reseal_auth(&g_agent.tpm_ctx);
	tpm_cleanup(&g_agent.tpm_ctx);
	if (ret < 0) {
		fprintf(stderr, "Could not seal AIK auth: %s\n",
			tpm_strerror(ret));
		return 1;
	}

	if (g_agent.tpm_ctx.seal_aik_auth_strict)
		fprintf(stderr,
			"AIK auth sealed to the current boot state; plaintext "
			"sidecar removed (strict).\n");
	else
		fprintf(
		    stderr,
		    "AIK auth sealed to the current boot state (plaintext "
		    "sidecar kept; set seal_aik_auth_strict to drop it).\n");
	return 0;
}

/*
 * do_reprovision_aik - explicit recovery for strict at-rest sealing. When a
 * firmware/kernel/agent change made the sealed AIK auth unrecoverable,
 * rotate the AIK + auth and re-seal to the current state.
 */
int do_reprovision_aik(void)
{
	int ret;

	setenv("TSS2_LOG", "all+none", 0);

	ret = tpm_init(&g_agent.tpm_ctx);
	if (ret < 0) {
		fprintf(stderr, "Failed to initialize TPM: %s\n",
			tpm_strerror(ret));
		return 1;
	}

	ret = tpm_reprovision_aik(&g_agent.tpm_ctx);
	tpm_cleanup(&g_agent.tpm_ctx);
	if (ret < 0) {
		fprintf(stderr, "AIK re-provisioning failed: %s\n",
			tpm_strerror(ret));
		return 1;
	}

	fprintf(stderr,
		"AIK rotated and its auth re-sealed to the current boot "
		"state.\n"
		"The previous AIK certificate is now stale -- re-enroll:\n"
		"  lota-agent --enroll --ca-server <host> ...\n");
	return 0;
}

/*
 * do_seal_persist_primary - persist the seal storage primary at its
 * persistent handle so subsequent seal/unseal skip the per-op CreatePrimary.
 * Idempotent. Requires seal_persistent_primary=true in lota.conf for the
 * seal/unseal path to actually reuse it.
 */
int do_seal_persist_primary(void)
{
	bool already = false;
	int ret;

	setenv("TSS2_LOG", "all+none", 0);

	ret = tpm_init(&g_agent.tpm_ctx);
	if (ret < 0) {
		fprintf(stderr, "Failed to initialize TPM: %s\n",
			tpm_strerror(ret));
		return 1;
	}

	ret = tpm_seal_persist_primary(&g_agent.tpm_ctx, &already);
	tpm_cleanup(&g_agent.tpm_ctx);
	if (ret < 0) {
		fprintf(stderr, "Could not persist the seal primary: %s\n",
			tpm_strerror(ret));
		return 1;
	}

	if (already)
		fprintf(stderr, "Seal storage primary already persisted.\n");
	else
		fprintf(stderr, "Seal storage primary persisted.\n");
	if (!g_agent.tpm_ctx.seal_persistent_primary)
		fprintf(stderr,
			"Set seal_persistent_primary=true in lota.conf for "
			"seal/unseal to reuse it.\n");
	return 0;
}

/*
 * do_seal_evict_primary - remove the persistent seal storage primary. Sealed
 * blobs remain valid: the per-op derived primary is byte-identical.
 */
int do_seal_evict_primary(void)
{
	int ret;

	setenv("TSS2_LOG", "all+none", 0);

	ret = tpm_init(&g_agent.tpm_ctx);
	if (ret < 0) {
		fprintf(stderr, "Failed to initialize TPM: %s\n",
			tpm_strerror(ret));
		return 1;
	}

	ret = tpm_seal_evict_primary(&g_agent.tpm_ctx);
	tpm_cleanup(&g_agent.tpm_ctx);
	if (ret == -ENOENT) {
		fprintf(stderr,
			"No persistent seal storage primary to evict.\n");
		return 1;
	}
	if (ret < 0) {
		fprintf(stderr, "Could not evict the seal primary: %s\n",
			tpm_strerror(ret));
		return 1;
	}

	fprintf(stderr, "Seal storage primary evicted (sealed blobs stay "
			"valid).\n");
	return 0;
}
