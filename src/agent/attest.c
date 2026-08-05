/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * LOTA Agent - Remote attestation and policy export
 *
 * Handles remote attestation flow (challenge-response), continuous
 * attestation loop, and policy YAML export from live system state.
 */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <time.h>
#include <unistd.h>
#include <openssl/types.h>
#include <sys/types.h>
#include <tss2/tss2_tpm2_types.h>

#include "../../include/attestation.h"
#include "../../include/lota.h"
#include "../../include/lota_ipc.h"
#include "agent.h"
#include "aik_cert.h"
#include "attest.h"
#include "attest_targets.h"
#include "bpf_loader.h"
#include "dbus.h"
#include "enroll.h"
#include "esrt.h"
#include "hardening.h"
#include "iommu.h"
#include "io_utils.h"
#include "ipc.h"
#include "journal.h"
#include "net.h"
#include "policy.h"
#include "quote.h"
#include "sdnotify.h"
#include "selftest.h"
#include "tpm.h"
#include "iommu_types.h"

/*
 * Select a boot measurement PCR that best represents the booted kernel path.
 * Priority reflects common Linux boot flows:
 *   - PCR 11: UKI / systemd-stub
 *   - PCR 9:  initrd + kernel-related GRUB measurements
 *   - PCR 8:  GRUB command line / boot config flow
 *   - PCR 4:  boot manager/loader stage
 */
static int read_kernel_measurement_digest(struct tpm_context *ctx,
					  uint8_t out_hash[LOTA_HASH_SIZE],
					  int *selected_pcr)
{
	static const int candidates[] = { 11, 9, 8, 4 };

	if (!ctx || !out_hash)
		return -EINVAL;

	for (size_t i = 0; i < sizeof(candidates) / sizeof(candidates[0]);
	     i++) {
		int ret = tpm_read_pcr(ctx, candidates[i], TPM2_ALG_SHA256,
				       out_hash);
		if (ret == 0) {
			if (selected_pcr)
				*selected_pcr = candidates[i];
			return 0;
		}
	}

	if (selected_pcr)
		*selected_pcr = -1;
	return -ENOENT;
}

static uint32_t rand_u32_best_effort(void)
{
	uint32_t v = 0;
	ssize_t n = getrandom(&v, sizeof(v), GRND_NONBLOCK);
	if (n == (ssize_t)sizeof(v))
		return v;

	/* fallback: not cryptographic, but sufficient to decorrelate retry
	 * timing */
	v = (uint32_t)time(NULL);
	v ^= (uint32_t)getpid();
	v ^= (uint32_t)(uintptr_t)&v;
	return v;
}

static void collect_kernel_security_features(bool *module_sig, bool *secureboot,
					     bool *lockdown)
{
	if (module_sig)
		*module_sig = bpf_loader_kernel_module_sig_enforced() == 0;
	if (secureboot)
		*secureboot = bpf_loader_secure_boot_enabled() == 0;
	if (lockdown)
		*lockdown = bpf_loader_kernel_lockdown_restrictive() == 0;
}

/*
 * Export a complete YAML policy from the current system state.
 *
 * Collects PCR values, binary hashes, and security feature flags,
 * then emits a verifier-ready YAML document via policy_emit().
 *
 * The output can be piped directly to a file:
 *   sudo lota-agent --export-policy > my-policy.yaml
 *   lota-verifier --policy my-policy.yaml
 *
 * Exported PCRs:
 *   PCR 0:  Firmware/SRTM measurement
 *   PCR 1:  BIOS configuration
 *   PCR 7:  Secure Boot state
 *   PCR 14: LOTA self-measurement
 */
int export_policy(int mode)
{
	struct policy_snapshot snap;
	int ret;
	ssize_t len;
	time_t now;
	struct tm tm_buf;

	size_t pcr_export_count;
	const int *pcrs_to_export = policy_export_pcrs(&pcr_export_count);

	memset(&snap, 0, sizeof(snap));

	if (gethostname(snap.hostname, sizeof(snap.hostname) - 1) != 0)
		snprintf(snap.hostname, sizeof(snap.hostname), "unknown");

	now = time(NULL);
	if (gmtime_r(&now, &tm_buf))
		strftime(snap.timestamp, sizeof(snap.timestamp),
			 "%Y-%m-%dT%H:%M:%SZ", &tm_buf);

	{
		size_t hlen = strlen(snap.hostname);
		if (hlen + sizeof("-baseline") <= sizeof(snap.name))
			snprintf(snap.name, sizeof(snap.name), "%s-baseline",
				 snap.hostname);
		else
			snprintf(snap.name, sizeof(snap.name), "%.54s-baseline",
				 snap.hostname);
	}
	snprintf(snap.description, sizeof(snap.description),
		 "Auto-generated policy from %s", snap.hostname);

	fprintf(stderr, "Initializing TPM...\n");
	ret = tpm_init(&g_agent.tpm_ctx);
	if (ret < 0) {
		fprintf(stderr, "Failed to initialize TPM: %s\n",
			strerror(-ret));
		return ret;
	}

	fprintf(stderr, "Performing self-measurement...\n");
	ret = self_measure(&g_agent.tpm_ctx);
	if (ret < 0) {
		fprintf(stderr, "Warning: Self-measurement failed: %s\n",
			strerror(-ret));
		fprintf(stderr, "PCR 14 may not contain agent measurement.\n");
	}

	/* PCR values */
	snap.pcr_count = (int)pcr_export_count;
	for (int i = 0; i < snap.pcr_count; i++) {
		snap.pcrs[i].index = pcrs_to_export[i];
		ret = tpm_read_pcr(&g_agent.tpm_ctx, pcrs_to_export[i],
				   TPM2_ALG_SHA256, snap.pcrs[i].value);
		if (ret == 0) {
			snap.pcrs[i].valid = true;
		} else {
			fprintf(stderr, "Warning: Failed to read PCR %d: %s\n",
				pcrs_to_export[i], tpm_strerror(ret));
		}
	}

	/* Boot-chain measurement digest (kernel-relevant PCR selection) */
	ret = tpm_get_current_kernel_path(&g_agent.tpm_ctx, snap.kernel_path,
					  sizeof(snap.kernel_path));
	if (ret < 0) {
		fprintf(stderr,
			"Warning: Failed to find kernel path metadata: %s\n",
			tpm_strerror(ret));
	}

	{
		int selected_pcr = -1;
		ret = read_kernel_measurement_digest(
			&g_agent.tpm_ctx, snap.kernel_hash, &selected_pcr);
		if (ret == 0) {
			snap.kernel_hash_valid = true;
			fprintf(stderr,
				"Kernel measurement digest source: PCR %d "
				"(measured boot)\n",
				selected_pcr);
		} else {
			fprintf(stderr,
				"Warning: Failed to read kernel-relevant "
				"measured boot PCR "
				"(tried 11/9/8/4): %s\n",
				tpm_strerror(ret));
		}
	}

	/* Agent binary hash */
	len = readlink("/proc/self/exe", snap.agent_path,
		       sizeof(snap.agent_path) - 1);
	if (len > 0)
		snap.agent_path[len] = '\0';
	else
		fprintf(stderr, "Warning: Failed to read agent path.\n");

	{
		int self_fd = open("/proc/self/exe", O_RDONLY | O_CLOEXEC);
		if (self_fd < 0) {
			fprintf(stderr,
				"Warning: Failed to open /proc/self/exe: %s\n",
				strerror(errno));
		} else {
			ret = tpm_hash_fd(self_fd, snap.agent_hash);
			close(self_fd);
			if (ret == 0) {
				snap.agent_hash_valid = true;
			} else {
				fprintf(stderr,
					"Warning: Failed to hash agent: %s\n",
					tpm_strerror(ret));
			}
		}
	}

	/* Security feature detection */
	{
		struct iommu_status iommu_status;

		snap.iommu_enabled = iommu_verify_full(&iommu_status);
		snap.enforce_mode = (mode == LOTA_MODE_ENFORCE);
		collect_kernel_security_features(
			&snap.module_sig, &snap.secureboot, &snap.lockdown);
	}

	tpm_cleanup(&g_agent.tpm_ctx);

	ret = policy_emit(&snap, stdout);
	if (ret < 0) {
		fprintf(stderr, "Failed to write policy: %s\n", strerror(-ret));
		return ret;
	}

	fprintf(stderr, "\nPolicy export complete.\n");
	return 0;
}

/*
 * @aik_cert_path: the enrolling profile's certificate, or NULL when no CA
 *                 trust anchor is configured and the host therefore has no
 *                 profile to read one from.
 */
static int build_attestation_report(const struct verifier_challenge *challenge,
				    struct lota_attestation_report *report,
				    const char *aik_cert_path)
{
	struct tpm_quote_response quote_resp;
	struct iommu_status iommu_status;
	char kernel_path[LOTA_MAX_PATH_LEN];
	uint8_t binding_nonce[LOTA_NONCE_SIZE] = { 0 };
	int ret;

	memset(&quote_resp, 0, sizeof(quote_resp));
	memset(report, 0, sizeof(*report));

	report->header.magic = LOTA_MAGIC;
	report->header.version = LOTA_VERSION;
	report->header.report_size = sizeof(*report);

	/* nonce from challenge */
	memcpy(report->tpm.nonce, challenge->nonce, LOTA_NONCE_SIZE);
	report->tpm.pcr_mask = challenge->pcr_mask;

	/*
	 * report LSM enforcement mode
	 * this flag is part of nonce binding (signed by TPM quote extraData)
	 */
	if (g_agent.mode == LOTA_MODE_ENFORCE)
		report->header.flags |= LOTA_REPORT_FLAG_ENFORCE;

	/*
	 * report BPF LSM status
	 * this flag is part of nonce binding (signed by TPM quote extraData)
	 */
	if (g_agent.bpf_ctx.loaded)
		report->header.flags |= LOTA_REPORT_FLAG_BPF_ACTIVE;

	/*
	 * Report kernel security features before nonce binding so the TPM quote
	 * signs the exact flags the verifier evaluates.
	 */
	{
		bool module_sig = false;
		bool secureboot = false;
		bool lockdown = false;

		collect_kernel_security_features(&module_sig, &secureboot,
						 &lockdown);
		if (module_sig)
			report->header.flags |= LOTA_REPORT_FLAG_MODULE_SIG;
		if (secureboot)
			report->header.flags |= LOTA_REPORT_FLAG_SECUREBOOT;
		if (lockdown)
			report->header.flags |= LOTA_REPORT_FLAG_LOCKDOWN;
	}

	/*
	 * Get hardware identity (SHA-256 of EK public key).
	 * This provides a unique, immutable identifier for this TPM.
	 * Used by verifier to detect unauthorized hardware changes.
	 */
	ret = tpm_get_hardware_id(&g_agent.tpm_ctx, report->tpm.hardware_id);
	if (ret < 0) {
		fprintf(stderr, "Warning: Failed to get hardware ID: %s\n",
			tpm_strerror(ret));
		/* continue with zero hardware ID - verifier may reject */
		memset(report->tpm.hardware_id, 0,
		       sizeof(report->tpm.hardware_id));
	} else {
		lota_dbg("Hardware ID derived from %s",
			 ret == 1 ? "AIK (EK not available)" : "EK");
	}

	/* system info: kernel path metadata + measured-boot digest */
	ret = tpm_get_current_kernel_path(&g_agent.tpm_ctx, kernel_path,
					  sizeof(kernel_path));
	if (ret == 0) {
		size_t kpath_len = strlen(kernel_path);
		if (kpath_len >= sizeof(report->system.kernel_path))
			kpath_len = sizeof(report->system.kernel_path) - 1;
		memcpy(report->system.kernel_path, kernel_path, kpath_len);
		report->system.kernel_path[kpath_len] = '\0';
	}

	{
		int selected_pcr = -1;
		ret = read_kernel_measurement_digest(&g_agent.tpm_ctx,
						     report->system.kernel_hash,
						     &selected_pcr);
		if (ret == 0) {
			report->header.flags |= LOTA_REPORT_FLAG_KERNEL_HASH_OK;
			lota_dbg(
				"Kernel measurement digest captured from PCR %d",
				selected_pcr);
		} else {
			fprintf(stderr, "Warning: Failed to read "
					"kernel-relevant measured boot PCR "
					"(tried 11/9/8/4)\n");
		}
	}

	/*
	 * Agent self-hash is captured once by self_measure() at startup and
	 * cached on tpm_context. Re-reading /proc/self/exe here would race
	 * package upgrades that swap the on-disk inode while the process
	 * keeps running, splitting the bytes folded into PCR14 from the
	 * bytes carried by the report. The verifier rederives expected
	 * PCR14 from report.system.agent_hash, so the two MUST be identical.
	 */
	{
		char agent_path[PATH_MAX];
		ssize_t len = readlink("/proc/self/exe", agent_path,
				       sizeof(agent_path) - 1);

		ret = tpm_get_self_hash(&g_agent.tpm_ctx,
					report->system.agent_hash);
		if (ret < 0) {
			fprintf(stderr,
				"Self-measurement has not run; agent_hash "
				"unavailable: %s\n",
				tpm_strerror(ret));
			goto cleanup;
		}
		if (len > 0) {
			agent_path[len] = '\0';
			lota_dbg("Agent binary: %s (hash pinned at boot)",
				 agent_path);
		}
	}

	if (iommu_verify_full(&iommu_status))
		report->header.flags |= LOTA_REPORT_FLAG_IOMMU_OK;
	memcpy(&report->system.iommu, &iommu_status,
	       sizeof(report->system.iommu));

	/*
	 * Name the PCR14 derivation before computing the quote binding nonce.
	 * Verifier recomputes extraData from report.Header.Flags with only
	 * TPM_QUOTE_OK masked out, so every derivation flag that affects PCR14
	 * semantics must be part of signed_flags.
	 * Setting these after tpm_quote() would make honest reports
	 * self-inconsistent and would also leave downgrade room for a peer that
	 * tampers with the flag field.
	 *
	 * initramfs lock is not optional: without it PCR14 would be OS-writable
	 * between the kernel handoff and the agent's first extend, so the verifier
	 * has no derivation for the value and refuses the report.
	 * Fail here instead, where the host can name the missing dracut module.
	 */
	if (!g_agent.tpm_ctx.boot_commitment_locked) {
		fprintf(stderr, "PCR14 was not locked by the initramfs helper; "
				"install the 90lota dracut module, rebuild the "
				"initramfs and cold reboot before attesting\n");
		ret = -EPROTO;
		goto cleanup;
	}
	report->header.flags |= LOTA_REPORT_FLAG_BOOT_COMMITMENT_V1 |
				LOTA_REPORT_FLAG_INITRAMFS_LOCK_V1;

	/*
	 * Compute remote-attestation binding nonce = SHA-256(
	 *   challenge_nonce || hardware_id || signed_flags ||
	 *   kernel_hash || agent_hash || iommu_status
	 * ).
	 *
	 * NOTE: This is intentionally different from the token quote nonce used
	 * by the local IPC token path and server-side token verification.
	 */
	{
		EVP_MD_CTX *md = EVP_MD_CTX_new();
		unsigned int md_len;
		uint32_t signed_flags = report->header.flags &
					~LOTA_REPORT_FLAG_TPM_QUOTE_OK;
		uint8_t flags_le[sizeof(signed_flags)];

		flags_le[0] = (uint8_t)(signed_flags);
		flags_le[1] = (uint8_t)(signed_flags >> 8);
		flags_le[2] = (uint8_t)(signed_flags >> 16);
		flags_le[3] = (uint8_t)(signed_flags >> 24);

		if (!md) {
			fprintf(stderr, "Failed to allocate EVP_MD_CTX\n");
			ret = -ENOMEM;
			goto cleanup;
		}
		if (EVP_DigestInit_ex(md, EVP_sha256(), NULL) != 1 ||
		    EVP_DigestUpdate(md, challenge->nonce, LOTA_NONCE_SIZE) !=
			    1 ||
		    EVP_DigestUpdate(md, report->tpm.hardware_id,
				     LOTA_HARDWARE_ID_SIZE) != 1 ||
		    EVP_DigestUpdate(md, flags_le, sizeof(flags_le)) != 1 ||
		    EVP_DigestUpdate(md, report->system.kernel_hash,
				     sizeof(report->system.kernel_hash)) != 1 ||
		    EVP_DigestUpdate(md, report->system.agent_hash,
				     sizeof(report->system.agent_hash)) != 1 ||
		    EVP_DigestUpdate(md, &report->system.iommu,
				     sizeof(report->system.iommu)) != 1 ||
		    EVP_DigestFinal_ex(md, binding_nonce, &md_len) != 1) {
			EVP_MD_CTX_free(md);
			fprintf(stderr, "Failed to compute binding nonce\n");
			ret = -EIO;
			goto cleanup;
		}
		EVP_MD_CTX_free(md);
	}

	ret = tpm_quote(&g_agent.tpm_ctx, binding_nonce, challenge->pcr_mask,
			&quote_resp);
	if (ret < 0) {
		fprintf(stderr, "TPM Quote failed: %s\n", tpm_strerror(ret));
		goto cleanup;
	}
	lota_dbg("TPM quote generated (sig: %u bytes, attest: %u bytes)",
		 quote_resp.signature_size, quote_resp.attest_size);

	/* copy TPM evidence */
	memcpy(report->tpm.pcr_values, quote_resp.pcr_values,
	       sizeof(report->tpm.pcr_values));
	report->tpm.quote_sig_size = quote_resp.signature_size;
	if (quote_resp.signature_size > LOTA_MAX_SIG_SIZE) {
		fprintf(stderr, "TPM signature too large: %u > %u\n",
			quote_resp.signature_size, LOTA_MAX_SIG_SIZE);
		ret = -EOVERFLOW;
		goto cleanup;
	}
	memcpy(report->tpm.quote_signature, quote_resp.signature,
	       quote_resp.signature_size);

	report->tpm.quote_sig_alg = quote_resp.sig_alg;
	report->tpm.quote_sig_hash_alg = quote_resp.hash_alg;

	/*
	 * Copy raw TPMS_ATTEST blob for signature verification.
	 * Verifier will: 1) verify signature over this data
	 *                2) parse extraData to extract nonce
	 *                3) compare with challenge nonce
	 */
	report->tpm.attest_size = quote_resp.attest_size;
	if (quote_resp.attest_size > LOTA_MAX_ATTEST_SIZE) {
		fprintf(stderr, "TPMS_ATTEST too large: %u > %u\n",
			quote_resp.attest_size, LOTA_MAX_ATTEST_SIZE);
		ret = -EOVERFLOW;
		goto cleanup;
	}
	memcpy(report->tpm.attest_data, quote_resp.attest_data,
	       quote_resp.attest_size);

	/*
	 * Export AIK public key for cert-backed registration.
	 * The verifier binds this key to the host hardware id derived
	 * from SHA-256(EK modulus) at first registration and reuses it
	 * to verify quote signatures on subsequent attestations.
	 */
	{
		size_t aik_size = 0;
		ret = tpm_get_aik_public(&g_agent.tpm_ctx,
					 report->tpm.aik_public,
					 LOTA_MAX_AIK_PUB_SIZE, &aik_size);
		if (ret == 0) {
			report->tpm.aik_public_size = (uint16_t)aik_size;
			lota_dbg(
				"AIK public key exported (%zu bytes, DER SPKI)",
				aik_size);
		} else {
			fprintf(stderr,
				"Warning: Failed to export AIK public key: %s\n",
				tpm_strerror(ret));
			report->tpm.aik_public_size = 0;
		}
	}

	/*
	 * The EK certificate is intentionally not sent in attestation
	 * reports. Under the Privacy CA model the verifier authenticates the
	 * AIK through its CA-issued certificate alone and never sees the EK,
	 * so attestations stay unlinkable to the hardware. The EK certificate
	 * is presented only to the attestation CA during --enroll.
	 */
	report->tpm.ek_cert_size = 0;

	/*
	 * Include the CA-issued AIK certificate from the last --enroll against
	 * this profile.
	 * Verifier chains it to the attestation CA root to authenticate the AIK;
	 * unenrolled host carries no certificate and is rejected under
	 * the production require-cert default
	 */
	if (!aik_cert_path) {
		report->tpm.aik_cert_size = 0;
		lota_dbg("No CA trust anchor configured, so no profile to read "
			 "an AIK certificate from");
	} else {
		size_t aik_cert_size = 0;
		int aret = lota_read_file_bounded(aik_cert_path,
						  report->tpm.aik_certificate,
						  LOTA_MAX_AIK_CERT_SIZE,
						  &aik_cert_size);
		if (aret < 0) {
			fprintf(stderr,
				"Warning: Failed to read AIK certificate: %s\n",
				strerror(-aret));
			report->tpm.aik_cert_size = 0;
		} else if (aik_cert_size > 0) {
			report->tpm.aik_cert_size = (uint16_t)aik_cert_size;
			lota_dbg(
				"AIK certificate included (%zu bytes, DER X.509)",
				aik_cert_size);
		} else {
			report->tpm.aik_cert_size = 0;
			lota_dbg("No AIK certificate on disk; run --enroll for "
				 "cert-backed attestation");
		}
	}

	/* AIK rotation metadata */
	if (g_agent.tpm_ctx.aik_meta_loaded) {
		report->tpm.aik_generation =
			g_agent.tpm_ctx.aik_meta.generation;

		if (tpm_aik_in_grace_period(&g_agent.tpm_ctx)) {
			size_t prev_size = 0;
			ret = tpm_aik_get_prev_public(
				&g_agent.tpm_ctx, report->tpm.prev_aik_public,
				LOTA_MAX_AIK_PUB_SIZE, &prev_size);
			if (ret == 0) {
				report->tpm.prev_aik_public_size =
					(uint16_t)prev_size;
				lota_dbg("Previous AIK included (grace period, "
					 "%zu bytes)",
					 prev_size);
			}
		}
	}

	report->header.flags |= LOTA_REPORT_FLAG_TPM_QUOTE_OK;

	ret = 0;

cleanup:
	OPENSSL_cleanse(binding_nonce, sizeof(binding_nonce));
	OPENSSL_cleanse(&quote_resp, sizeof(quote_resp));
	return ret;
}

/*
 * Perform single attestation round.
 * TPM and network must be initialized before calling.
 * Returns: 0 on success, negative errno on failure
 */
static int attest_once(const char *server, int port, const char *ca_cert,
		       int skip_verify, const uint8_t *pin_sha256,
		       const struct profile_paths *paths, int verbose)
{
	struct net_context net_ctx;
	int net_ctx_inited = 0;
	struct verifier_challenge challenge;
	struct verifier_result result;
	struct lota_attestation_report report;
	uint8_t *event_log = NULL;
	size_t event_log_size = 0;
	uint8_t *wire_buf = NULL;
	size_t wire_buf_size = 0;
	ssize_t wire_size = 0;
	int ret;

	memset(&net_ctx, 0, sizeof(net_ctx));
	memset(&challenge, 0, sizeof(challenge));
	memset(&result, 0, sizeof(result));
	memset(&report, 0, sizeof(report));

	if (verbose)
		printf("Connecting to verifier at %s:%d...\n", server, port);

	ret = net_context_init(&net_ctx, server, port, ca_cert, skip_verify,
			       pin_sha256);
	if (ret < 0) {
		if (verbose)
			fprintf(stderr, "Failed to initialize connection: %s\n",
				strerror(-ret));
		goto cleanup;
	}
	net_ctx_inited = 1;

	ret = net_connect(&net_ctx);
	if (ret < 0) {
		if (verbose)
			fprintf(stderr, "Failed to connect to verifier: %s\n",
				strerror(-ret));
		goto cleanup;
	}

	if (verbose)
		printf("Connected, waiting for challenge...\n");

	ret = net_recv_challenge(&net_ctx, &challenge);
	if (ret < 0) {
		if (verbose)
			fprintf(stderr, "Failed to receive challenge: %s\n",
				strerror(-ret));
		goto cleanup;
	}

	if (verbose) {
		printf("Challenge received (PCR mask: 0x%08X)\n",
		       challenge.pcr_mask);
		print_hex("  Nonce", challenge.nonce, LOTA_NONCE_SIZE);
	}

	ret = build_attestation_report(&challenge, &report,
				       paths ? paths->aik_cert : NULL);
	if (ret < 0) {
		if (verbose)
			fprintf(stderr, "Failed to build report: %s\n",
				strerror(-ret));
		goto cleanup;
	}

	/* read TPM event log for verifier PCR reconstruction */
	event_log = malloc(TPM_MAX_EVENT_LOG_SIZE);
	if (event_log) {
		ret = tpm_read_event_log(event_log, TPM_MAX_EVENT_LOG_SIZE,
					 &event_log_size);
		if (ret < 0) {
			if (verbose)
				fprintf(stderr,
					"Warning: Failed to read TPM event "
					"log: %s\n",
					strerror(-ret));
			event_log_size = 0;
		} else if (verbose) {
			printf("TPM event log read (%zu bytes)\n",
			       event_log_size);
		}
	}

	/* serialize report with variable-length sections */
	{
		struct lota_esrt esrt;
		size_t total;

		/* ESRT System Firmware version (anti-rollback signal for the
		 * verifier's re-anchor)
		 * Always sent, present=0 when absent */
		esrt_read_system_firmware(&esrt);

		total = calculate_report_size(0, (uint32_t)event_log_size, 1);
		wire_buf_size = total;
		wire_buf = malloc(total);
		if (!wire_buf) {
			fprintf(stderr,
				"Failed to allocate serialization buffer\n");
			ret = -ENOMEM;
			goto cleanup;
		}

		report.header.report_size = (uint32_t)total;
		wire_size = serialize_report(&report, NULL, 0, event_log,
					     (uint32_t)event_log_size, &esrt,
					     wire_buf, total);
		if (wire_size < 0) {
			fprintf(stderr, "Failed to serialize report: %s\n",
				strerror((int)-wire_size));
			ret = (int)wire_size;
			goto cleanup;
		}
	}

	if (verbose)
		printf("Sending report (%zd bytes, event_log: %zu)...\n",
		       wire_size, event_log_size);

	ret = net_send_report(&net_ctx, wire_buf, (size_t)wire_size);
	if (ret < 0) {
		if (verbose)
			fprintf(stderr, "Failed to send report: %s\n",
				strerror(-ret));
		goto cleanup;
	}

	ret = net_recv_result(&net_ctx, &result);
	if (ret < 0) {
		if (verbose)
			fprintf(stderr, "Failed to receive result: %s\n",
				strerror(-ret));
		goto cleanup;
	}

	if (verbose) {
		printf("Result: %s\n", net_result_str(result.result));
		if (result.result == VERIFY_OK) {
			printf("Valid until: %lu\n",
			       (unsigned long)result.valid_until);
		}
	}

	ret = (result.result == VERIFY_OK) ? 0 : 1;

cleanup:
	OPENSSL_cleanse(&challenge, sizeof(challenge));
	OPENSSL_cleanse(&result, sizeof(result));
	OPENSSL_cleanse(&report, sizeof(report));
	if (wire_buf)
		OPENSSL_cleanse(wire_buf, wire_buf_size);
	if (event_log)
		OPENSSL_cleanse(event_log, event_log_size);
	free(wire_buf);
	free(event_log);
	if (net_ctx_inited)
		net_context_cleanup(&net_ctx);
	OPENSSL_cleanse(&net_ctx, sizeof(net_ctx));
	return ret;
}

/*
 * Resolve the publisher profile the CA trust anchor names, into storage
 * the caller owns for the lifetime of the attestation.
 *
 * Host attesting without an anchor has no profile, so it has no enrolled
 * certificate to present and verifier refuses it under the production
 * require-cert default.
 *
 * Say that here, where the anchor is missing, rather than leaving operator
 * to read it off a rejection.
 */
static const struct profile_paths *
resolve_attest_profile(const char *ca_cert, struct profile_paths *storage)
{
	int ret;

	if (!ca_cert) {
		lota_warn("No CA trust anchor configured: attesting without a "
			  "publisher profile, so no CA-issued AIK certificate "
			  "is presented");
		return NULL;
	}

	ret = profile_paths_from_anchor(ca_cert, storage);
	if (ret < 0) {
		lota_warn("Cannot read the CA trust anchor %s (%s): attesting "
			  "without a publisher profile",
			  ca_cert, strerror(-ret));
		return NULL;
	}

	lota_dbg("Publisher profile %s", storage->id);
	return storage;
}

int do_attest(const char *server, int port, const char *ca_cert,
	      int skip_verify, const uint8_t *pin_sha256)
{
	struct profile_paths storage;
	const struct profile_paths *paths;
	int ret;

	printf("=== Remote Attestation ===\n\n");

	paths = resolve_attest_profile(ca_cert, &storage);

	/*
	 * Long-running attestation path: install tracer refusal and the
	 * seccomp blocklist before any TPM/IPC work. Diagnostic CLI paths
	 * already skipped this in main() so admins keep strace access.
	 */
	ret = hardening_apply_daemon();
	if (ret < 0) {
		fprintf(stderr, "Failed to apply daemon hardening: %s\n",
			strerror(-ret));
		return 1;
	}

	ret = net_init();
	if (ret < 0) {
		fprintf(stderr, "Failed to initialize network: %s\n",
			strerror(-ret));
		return 1;
	}

	printf("Initializing TPM...\n");
	ret = tpm_init(&g_agent.tpm_ctx);
	if (ret < 0) {
		fprintf(stderr, "Failed to initialize TPM: %s\n",
			tpm_strerror(ret));
		net_cleanup();
		return 1;
	}

	if (paths) {
		ret = tpm_bind_profile(&g_agent.tpm_ctx, paths);
		if (ret < 0) {
			fprintf(stderr,
				"Failed to bind the publisher profile: %s\n",
				strerror(-ret));
			tpm_cleanup(&g_agent.tpm_ctx);
			net_cleanup();
			return 1;
		}
	}

	printf("Checking AIK...\n");
	ret = tpm_provision_aik(&g_agent.tpm_ctx);
	if (ret < 0) {
		fprintf(stderr, "Failed to provision AIK: %s\n",
			tpm_strerror(ret));
		tpm_cleanup(&g_agent.tpm_ctx);
		net_cleanup();
		return 1;
	}

	/*
	 * Self-measurement extends PCR14 with clockInfo captured through
	 * the AIK signing path (see tpm_read_signed_clockinfo). AIK must
	 * therefore be provisioned before this call or the agent will fall
	 * back to Esys_ReadClock and produce a PCR14 value the verifier
	 * cannot rederive on simulators that diverge between ReadClock and
	 * Quote.clockInfo.
	 */
	printf("Performing self-measurement...\n");
	ret = self_measure(&g_agent.tpm_ctx);
	if (ret < 0) {
		fprintf(stderr, "Self-measurement failed: %s\n",
			tpm_strerror(ret));
		tpm_cleanup(&g_agent.tpm_ctx);
		net_cleanup();
		return 1;
	}

	ret = tpm_aik_load_metadata(&g_agent.tpm_ctx);
	if (ret < 0) {
		fprintf(stderr, "Failed to load AIK metadata: %s\n",
			tpm_strerror(ret));
		tpm_cleanup(&g_agent.tpm_ctx);
		net_cleanup();
		return 1;
	}

	ret = attest_once(server, port, ca_cert, skip_verify, pin_sha256, paths,
			  1);

	printf("\n=== Attestation %s ===\n",
	       ret == 0 ? "Successful" : "Failed");

	tpm_cleanup(&g_agent.tpm_ctx);
	net_cleanup();
	return ret == 0 ? 0 : 1;
}

/*
 * Reconcile LOTA_STATUS_TPM_LOCKOUT against the TPM context.
 *
 * The TPM module owns the sticky lockout flag; the IPC status bitmap is
 * recomputed before every ipc_update_status() call so the bit reflects
 * the most recent observation. Transitions are logged at notice/error
 * severity so operators can correlate against TPM resource exhaustion.
 *
 * Edge-trigger state lives on struct agent_globals (not as a
 * function-static) so unit tests can drive deterministic
 * cleared->locked->cleared sequences and a future second writer
 * (e.g. an out-of-loop reconciliation path) would observe the same
 * value rather than its own private copy. That hypothetical writer
 * still needs a real lock: today reconcile_tpm_lockout() and
 * handle_get_token() both reach the same tpm_context (directly as
 * g_agent.tpm_ctx here, and through ipc_context.tpm in IPC) only
 * because the production daemon runs them on the same epoll thread.
 */
static uint32_t reconcile_tpm_lockout(uint32_t flags)
{
	bool now = tpm_is_locked_out(&g_agent.tpm_ctx);

	if (now && !g_agent.tpm_lockout_last_known) {
		lota_err("TPM DA lockout detected: TPM2_RC_LOCKOUT observed "
			 "(events=%u, first_seen=%lld)",
			 g_agent.tpm_ctx.lockout_event_count,
			 (long long)g_agent.tpm_ctx.lockout_first_seen);
	} else if (!now && g_agent.tpm_lockout_last_known) {
		lota_notice(
			"TPM DA lockout cleared after successful TPM operation");
	}
	agent_globals_lock(&g_agent);
	g_agent.tpm_lockout_last_known = now;
	agent_globals_unlock(&g_agent);

	if (now)
		return flags | LOTA_STATUS_TPM_LOCKOUT;
	return flags & ~LOTA_STATUS_TPM_LOCKOUT;
}

/*
 * Publish the current AIK rotation state over IPC / D-Bus: generation,
 * creation time, the next-rotation deadline, any open grace window, and
 * whether the issued certificate has been outdated by a local rotation
 * (the enrolled generation no longer matching the live one), which an
 * operator clears with a guided lota-agent --reenroll.
 *
 * paths names the profile whose enrollment is compared against the live AIK;
 * NULL when no CA trust anchor is configured, in which case there is no enrollment
 * to compare and the flag stays clear.
 */
void publish_rotation_state(uint32_t aik_ttl, const struct profile_paths *paths)
{
	struct tpm_context *tpm = &g_agent.tpm_ctx;
	struct enroll_state st;
	uint64_t deadline = 0;
	bool reenroll_required = false;
	uint32_t ttl;

	if (!tpm->aik_meta_loaded)
		return;

	ttl = aik_ttl ? aik_ttl : TPM_AIK_DEFAULT_TTL_SEC;
	if (tpm->aik_meta.provisioned_at > 0)
		deadline = (uint64_t)tpm->aik_meta.provisioned_at + ttl;

	/*
	 * Recorded enrollment whose generation trails the live AIK means a
	 * rotation has outdated the stored certificate.
	 * With no record there is no way to tell, so do not raise the flag
	 */
	if (paths && enroll_state_load_path(paths->enroll_state, &st) == 0)
		reenroll_required = st.aik_generation !=
				    tpm->aik_meta.generation;

	ipc_update_rotation(&g_agent.ipc_ctx, tpm->aik_meta.generation,
			    (uint64_t)tpm->aik_meta.provisioned_at,
			    (uint64_t)tpm->aik_meta.last_rotated_at, deadline,
			    (uint64_t)tpm->grace_deadline, reenroll_required);
}

static uint64_t monotonic_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

/*
 * Point the TPM at a target's publisher and reload nothing else:
 * the metadata and the userAuth are dropped by the bind and read back on demand
 * for the key that is now selected.
 */
static int bind_target(struct attest_target *t)
{
	int ret;

	if (!t->has_profile)
		return 0;

	ret = tpm_bind_profile(&g_agent.tpm_ctx, &t->paths);
	if (ret < 0) {
		lota_err("Cannot bind the publisher profile for %s:%d: %s",
			 t->server, t->port, strerror(-ret));
		return ret;
	}

	ret = tpm_provision_aik(&g_agent.tpm_ctx);
	if (ret < 0) {
		lota_err("AIK unavailable for %s:%d: %s", t->server, t->port,
			 tpm_strerror(ret));
		return ret;
	}

	ret = tpm_aik_load_metadata(&g_agent.tpm_ctx);
	if (ret < 0) {
		lota_err("Cannot load AIK metadata for %s:%d: %s", t->server,
			 t->port, tpm_strerror(ret));
		return ret;
	}
	return 0;
}

/*
 * Has this publisher ever enrolled?
 *
 * Record is written by the enrollment ceremony, whether that ran as -enroll
 * at install time or on demand here, so its absence is what "never enrolled" means.
 */
static bool target_is_enrolled(const struct attest_target *t)
{
	struct enroll_state st;
	bool ok;

	if (!t->has_profile)
		return false;

	ok = enroll_state_load_path(t->paths.enroll_state, &st) == 0;
	OPENSSL_cleanse(&st, sizeof(st));
	return ok;
}

/*
 * Enroll a publisher this host has never enrolled with.
 *
 * This is the install step player cannot perform:
 * at install time there is no publisher yet, and the CA belongs to whoever they
 * buy a title from.
 * Profile carries the CA endpoint and its anchor, so the first time the loop
 * reaches an unenrolled publisher -- or a title asks for one -- the ceremony runs
 * here instead.
 *
 * Failure backs off: CA that is down must not be hammered once per round,
 * and the host keeps working for every other publisher meanwhile.
 */
static bool enroll_target_if_needed(struct attest_target *t)
{
	uint64_t now_ms = monotonic_ms();
	int ret;

	if (!t->has_profile || target_is_enrolled(t))
		return true;

	t->enroll_pending = false;

	{
		time_t agreed = 0;
		int cret = profile_consent_time(&t->paths, &agreed);

		if (cret == -ENOENT) {
			lota_warn("%s:%d has no enrollment and nobody has "
				  "agreed to answer to publisher %s; run "
				  "--allow-publisher %s to record that",
				  t->server, t->port, t->paths.id, t->paths.id);
			return false;
		}
		if (cret < 0) {
			lota_warn("Consent record for publisher %s is "
				  "unreadable (%s); refusing to enroll",
				  t->paths.id, strerror(-cret));
			return false;
		}
	}

	if (t->ca[0] == '\0') {
		lota_warn("%s:%d has no enrollment and its profile names no "
			  "attestation CA; run --enroll for it",
			  t->server, t->port);
		return false;
	}
	if (now_ms < t->next_enroll_ms)
		return false;

	lota_info("Enrolling with %s:%d for publisher %s (first time this "
		  "host has attested for them)",
		  t->ca, t->ca_port, t->paths.id);

	ret = bind_target(t);
	if (ret == 0)
		ret = enroll_profile_now(&g_agent.tpm_ctx, &t->paths, t->ca,
					 t->ca_port, t->ca_cert);
	if (ret == 0) {
		t->enroll_backoff = 0;
		lota_info("Enrolled with %s:%d", t->ca, t->ca_port);
		return true;
	}

	{
		int shift = t->enroll_backoff;
		int delay;

		if (shift > 5)
			shift = 5;
		t->enroll_backoff++;
		delay = ATTEST_BACKOFF_BASE_SEC * (1 << shift);
		if (delay > MAX_BACKOFF_SECONDS)
			delay = MAX_BACKOFF_SECONDS;
		t->next_enroll_ms = now_ms + (uint64_t)delay * 1000;
		lota_warn("Enrollment with %s:%d failed (%s); retry in %ds",
			  t->ca, t->ca_port, strerror(-ret), delay);
	}
	return false;
}

/* Rotate the bound AIK when its TTL has elapsed */
static void rotate_bound_aik_if_due(const struct attest_target *t,
				    uint32_t aik_ttl)
{
	int ret;

	if (!g_agent.tpm_ctx.aik_meta_loaded)
		return;
	if (tpm_aik_needs_rotation(&g_agent.tpm_ctx, aik_ttl) != 1)
		return;

	lota_info("AIK rotation due (gen %lu, age %ld s)",
		  (unsigned long)g_agent.tpm_ctx.aik_meta.generation,
		  (long)tpm_aik_age(&g_agent.tpm_ctx));

	ret = tpm_rotate_aik(&g_agent.tpm_ctx);
	if (ret < 0)
		lota_err("AIK rotation failed: %s", tpm_strerror(ret));
	else
		lota_info("AIK rotated -> generation %lu",
			  (unsigned long)g_agent.tpm_ctx.aik_meta.generation);

	/*
	 * Republish so the rotation, its grace window, and re-enrollment surface
	 * over D-Bus immediately
	 */
	publish_rotation_state(aik_ttl, t->has_profile ? &t->paths : NULL);
}

/* Renew this target's CA-issued AIK certificate before it lapses */
static void renew_target_cert_if_due(struct attest_target *t, uint32_t aik_ttl)
{
	int64_t remaining = 0, total = 0;
	uint64_t mono_ms = monotonic_ms();
	int ret;

	if (!t->auto_renew || mono_ms < t->next_renew_ms)
		return;
	if (aik_cert_lifetime_path(t->paths.aik_cert, &remaining, &total) != 0)
		return;
	if (!aik_cert_renew_due(remaining, total))
		return;

	lota_info("AIK certificate renewal due for %s:%d (%lld s left of "
		  "%lld s)",
		  t->server, t->port, (long long)remaining, (long long)total);

	ret = enroll_renew_cert(&g_agent.tpm_ctx, &t->paths);
	if (ret == 0) {
		t->renew_backoff = 0;
		lota_info("AIK certificate renewed for %s:%d", t->server,
			  t->port);
		publish_rotation_state(aik_ttl, &t->paths);
		return;
	}

	{
		int shift = t->renew_backoff;
		int delay;

		if (shift > 5)
			shift = 5;
		t->renew_backoff++;
		delay = ATTEST_BACKOFF_BASE_SEC * (1 << shift);
		if (delay > MAX_BACKOFF_SECONDS)
			delay = MAX_BACKOFF_SECONDS;
		t->next_renew_ms = mono_ms + (uint64_t)delay * 1000;
		lota_warn("AIK certificate renewal failed for %s:%d (%s); "
			  "retry in %ds, cert expires in %lld s",
			  t->server, t->port, strerror(-ret), delay,
			  (long long)remaining);
		sdnotify_status("AIK cert renewal failing for %s, expires in "
				"%lld s",
				t->server, (long long)remaining);
	}
}

/*
 * Is this publisher owed a report right now?
 *
 * Session-gated target reports only while a title of that publisher's is running.
 * When the last one exits, reporting stops and the verdict is dropped:
 * claiming machine is attested for publisher nobody is reporting to would be
 * asserting something no longer being checked.
 */
static bool target_reporting_now(struct attest_target *t)
{
	if (!t->session_gated || t->sessions > 0)
		return true;

	if (t->attested) {
		lota_info("No session left for %s:%d; reporting stops until a "
			  "title of theirs runs again",
			  t->server, t->port);
		t->attested = false;
		t->valid_until = 0;
	}
	return false;
}

/*
 * One round against one target: how long to wait before the next one.
 * Failure backs this target off; the other publishers keep their cadence.
 */
static int attest_target_round(struct attest_target *t, int skip_verify,
			       const uint8_t *pin_sha256, uint32_t aik_ttl)
{
	time_t now = time(NULL);
	int ret;

	if (!target_reporting_now(t))
		return t->interval;

	if (!enroll_target_if_needed(t)) {
		/* Nothing to report with:
		 * no certificate, so every verifier refuses.
		 * Wait for the enrollment backoff instead of sending evidence
		 * nobody can chain. */
		t->attested = false;
		t->valid_until = 0;
		return t->interval;
	}

	ret = bind_target(t);
	if (ret == 0) {
		rotate_bound_aik_if_due(t, aik_ttl);
		renew_target_cert_if_due(t, aik_ttl);

		lota_dbg("Attestation round starting for %s:%d", t->server,
			 t->port);
		ret = attest_once(t->server, t->port,
				  t->ca_cert[0] ? t->ca_cert : NULL,
				  skip_verify, pin_sha256,
				  t->has_profile ? &t->paths : NULL, 0);
	}

	if (ret == 0) {
		lota_info("Attestation successful (%s:%d)", t->server, t->port);
		t->consecutive_failures = 0;
		t->backoff_sec = 0;
		t->last_success = now;
		t->attested = true;
		t->valid_until = (uint64_t)(now + t->interval +
					    ATTEST_TOKEN_VALIDITY_SLACK_SEC);
		ipc_record_attestation(&g_agent.ipc_ctx, true);
		return t->interval;
	}

	t->consecutive_failures++;
	{
		int shift = t->consecutive_failures - 1;

		if (shift > 5)
			shift = 5; /* 10 * 2^5 = 320 > MAX_BACKOFF_SECONDS */
		t->backoff_sec = ATTEST_BACKOFF_BASE_SEC * (1 << shift);
	}
	if (t->backoff_sec > MAX_BACKOFF_SECONDS)
		t->backoff_sec = MAX_BACKOFF_SECONDS;

	lota_err("Attestation FAILED for %s:%d (attempt %d, backoff %ds)",
		 t->server, t->port, t->consecutive_failures, t->backoff_sec);
	if (t->last_success > 0)
		lota_warn("Last success for %s:%d: %ld seconds ago", t->server,
			  t->port, (long)(now - t->last_success));

	/* one round may be a blip; three in a row is a host nobody trusts */
	if (t->consecutive_failures >= 3) {
		t->attested = false;
		t->valid_until = 0;
	}
	ipc_record_attestation(&g_agent.ipc_ctx, false);

	{
		/* jitter so a fleet does not retry in lockstep */
		int jitter_max = t->backoff_sec / 2;
		int sleep_time;
		int jitter;

		if (jitter_max < 1)
			jitter_max = 1;
		jitter = (int)(rand_u32_best_effort() %
			       (uint32_t)(jitter_max + 1));
		sleep_time = t->backoff_sec + jitter;
		if (sleep_time > MAX_BACKOFF_SECONDS)
			sleep_time = MAX_BACKOFF_SECONDS;
		return sleep_time;
	}
}

/*
 * Host's single answer to "is this machine attested".
 *
 * Every configured publisher has to be satisfied, and the window closes at
 * the earliest of theirs.
 */
static void publish_aggregate_status(const struct attest_target *targets,
				     size_t count, uint32_t *status_flags)
{
	uint64_t valid_until = 0;
	size_t considered = 0;
	bool all = true;

	for (size_t i = 0; i < count; i++) {
		/*
		 * Publisher nobody is playing for is not reporting, so it has
		 * no verdict to contribute.
		 * Counting its silence as failure would leave a consumer host
		 * permanently unattested; counting it as success would assert
		 * something nothing is checking
		 */
		if (targets[i].session_gated && targets[i].sessions == 0)
			continue;

		considered++;
		if (!targets[i].attested) {
			all = false;
			break;
		}
		if (valid_until == 0 || targets[i].valid_until < valid_until)
			valid_until = targets[i].valid_until;
	}

	/* nobody is reporting, so there is no live verdict to report either */
	if (considered == 0)
		all = false;

	if (all)
		*status_flags |= LOTA_STATUS_ATTESTED;
	else
		*status_flags &= ~LOTA_STATUS_ATTESTED;

	ipc_update_status(&g_agent.ipc_ctx,
			  reconcile_tpm_lockout(*status_flags),
			  all ? valid_until : 0);

	if (all)
		sdnotify_status("Attested (%zu publisher%s), valid until %lu",
				considered, considered == 1 ? "" : "s",
				(unsigned long)valid_until);
	else if (considered == 0)
		sdnotify_status("Idle: no title running, nothing reported");
	else
		sdnotify_status("Attestation incomplete");
}

/*
 * Continuous attestation loop.
 * Re-attests every target on its own interval, with exponential backoff on failure.
 */
int do_continuous_attest(const struct lota_config *cfg, const char *server,
			 int port, const char *ca_cert, int skip_verify,
			 const uint8_t *pin_sha256, int interval_sec,
			 uint32_t aik_ttl)
{
	struct attest_target targets[LOTA_CONFIG_MAX_PROFILES];
	size_t target_count = 0;
	uint32_t status_flags = 0;
	uint64_t wd_usec = 0;
	bool wd_enabled;
	int ret;

	lota_info("Continuous attestation starting");

	ret = attest_targets_build(cfg, server, port, ca_cert, interval_sec,
				   targets,
				   sizeof(targets) / sizeof(targets[0]),
				   &target_count);
	if (ret < 0) {
		lota_err("Cannot build the attestation target list: %s",
			 strerror(-ret));
		return 1;
	}

	for (size_t i = 0; i < target_count; i++) {
		lota_info("Target %zu: %s:%d every %d seconds%s", i + 1,
			  targets[i].server, targets[i].port,
			  targets[i].interval,
			  targets[i].session_gated ?
				  ", while a title of theirs runs" :
				  "");
		if (targets[i].profile_error)
			lota_warn("Cannot read the CA trust anchor %s (%s): "
				  "attesting to %s:%d without a publisher "
				  "profile, so no CA-issued AIK certificate is "
				  "presented",
				  targets[i].ca_cert,
				  strerror(-targets[i].profile_error),
				  targets[i].server, targets[i].port);
		else if (!targets[i].has_profile)
			lota_warn("No CA trust anchor for %s:%d: attesting "
				  "without a publisher profile, so no "
				  "CA-issued AIK certificate is presented",
				  targets[i].server, targets[i].port);
	}

	/*
	 * Title that names its publisher gets that publisher's AIK
	 * and that publisher's verdict.
	 * One that names none gets the first profile's token and the host-wide
	 * verdict, which is every publisher agreeing.
	 */
	if (target_count > 1)
		lota_info("A title that does not select a publisher is "
			  "answered for %s:%d and with the host-wide verdict",
			  targets[0].server, targets[0].port);

	/*
	 * Long-running attestation loop: install tracer refusal and the
	 * seccomp blocklist before any TPM/IPC/BPF work. Diagnostic CLI
	 * paths already skipped this in main() so admins keep strace
	 * access on --shutdown, --test-tpm, and similar one-shots.
	 */
	ret = hardening_apply_daemon();
	if (ret < 0) {
		lota_err("Failed to apply daemon hardening: %s",
			 strerror(-ret));
		return 1;
	}

	wd_enabled = sdnotify_watchdog_enabled(&wd_usec);

	lota_info("Starting IPC server");
	ret = ipc_init_or_activate(&g_agent.ipc_ctx);
	if (ret < 0) {
		lota_warn("IPC init failed: %s", strerror(-ret));
		lota_warn("Gaming clients will not be able to query status");
	} else {
		setup_container_listener(&g_agent.ipc_ctx, NULL);
		setup_dbus(&g_agent.ipc_ctx);
	}

	ret = net_init();
	if (ret < 0) {
		lota_err("Failed to initialize network: %s", strerror(-ret));
		dbus_cleanup(g_agent.dbus_ctx);
		ipc_cleanup(&g_agent.ipc_ctx);
		return 1;
	}

	lota_info("Initializing TPM");
	ret = tpm_init(&g_agent.tpm_ctx);
	if (ret < 0) {
		lota_err("Failed to initialize TPM: %s", tpm_strerror(ret));
		net_cleanup();
		dbus_cleanup(g_agent.dbus_ctx);
		ipc_cleanup(&g_agent.ipc_ctx);
		return 1;
	}
	status_flags |= LOTA_STATUS_TPM_OK;

	if (targets[0].has_profile) {
		ret = tpm_bind_profile(&g_agent.tpm_ctx, &targets[0].paths);
		if (ret < 0) {
			lota_err("Failed to bind the publisher profile: %s",
				 strerror(-ret));
			tpm_cleanup(&g_agent.tpm_ctx);
			net_cleanup();
			dbus_cleanup(g_agent.dbus_ctx);
			ipc_cleanup(&g_agent.ipc_ctx);
			return 1;
		}
	}

	lota_info("Checking AIK");
	ret = tpm_provision_aik(&g_agent.tpm_ctx);
	if (ret < 0) {
		lota_err("Failed to provision AIK: %s", tpm_strerror(ret));
		tpm_cleanup(&g_agent.tpm_ctx);
		net_cleanup();
		dbus_cleanup(g_agent.dbus_ctx);
		ipc_cleanup(&g_agent.ipc_ctx);
		return 1;
	}

	/*
	 * Self-measurement extends PCR14 using clockInfo captured through
	 * the AIK signing path (tpm_read_signed_clockinfo). Provision AIK
	 * first so the signed-clock path is available; without it the
	 * fallback to Esys_ReadClock can produce a PCR14 value the
	 * verifier cannot rederive on simulators whose ReadClock and
	 * Quote.clockInfo disagree.
	 */
	lota_info("Performing self-measurement");
	ret = self_measure(&g_agent.tpm_ctx);
	if (ret < 0) {
		/*
		 * Continuing here would let the agent quote PCR14 values that
		 * the verifier cannot rederive (self_hash unpinned, or PCR14
		 * already bound to a different agent binary), so every
		 * subsequent attestation would be rejected as
		 * integrity_mismatch. Fail closed instead so systemd surfaces
		 * the startup failure and the operator addresses the root cause
		 * (typically a cold reboot after a live binary upgrade) before
		 * traffic resumes.
		 */
		lota_err("Self-measurement failed: %s", tpm_strerror(ret));
		tpm_cleanup(&g_agent.tpm_ctx);
		net_cleanup();
		dbus_cleanup(g_agent.dbus_ctx);
		ipc_cleanup(&g_agent.ipc_ctx);
		return 1;
	}

	ipc_set_tpm(&g_agent.ipc_ctx, &g_agent.tpm_ctx,
		    LOTA_TOKEN_QUOTE_PCR_MASK);

	/*
	 * Hand the publishers to the IPC layer so title can name the one
	 * it plays for.
	 * The list outlives every connection: it is on this stack frame,
	 * and ipc_cleanup() runs before this function returns.
	 */
	ipc_set_profiles(&g_agent.ipc_ctx, targets, target_count);

	ret = tpm_aik_load_metadata(&g_agent.tpm_ctx);
	if (ret < 0) {
		lota_err("Failed to load AIK metadata: %s", tpm_strerror(ret));
		tpm_cleanup(&g_agent.tpm_ctx);
		net_cleanup();
		dbus_cleanup(g_agent.dbus_ctx);
		ipc_cleanup(&g_agent.ipc_ctx);
		return 1;
	} else {
		int64_t age = tpm_aik_age(&g_agent.tpm_ctx);
		lota_info("AIK generation: %lu, age: %ld seconds",
			  (unsigned long)g_agent.tpm_ctx.aik_meta.generation,
			  (long)age);
	}

	ipc_update_status(&g_agent.ipc_ctx, reconcile_tpm_lockout(status_flags),
			  0);
	publish_rotation_state(
		aik_ttl, targets[0].has_profile ? &targets[0].paths : NULL);

	/*
	 * Auto-renew the CA-issued AIK certificate:
	 * it is short-lived (24h by default) and would otherwise lapse a day
	 * after install.
	 * Enabled per publisher, whenever that profile recorded CA endpoint
	 * at enroll time.
	 * Manual --reenroll stays the fallback when no endpoint is on disk.
	 */
	for (size_t i = 0; i < target_count; i++) {
		struct enroll_state est;

		targets[i].auto_renew =
			targets[i].has_profile &&
			enroll_state_load_path(targets[i].paths.enroll_state,
					       &est) == 0;
		if (targets[i].auto_renew)
			lota_info("AIK certificate auto-renewal enabled for "
				  "%s:%d",
				  targets[i].server, targets[i].port);
		else
			lota_info("AIK certificate auto-renewal off for %s:%d: "
				  "no recorded CA endpoint (run --enroll to "
				  "record one)",
				  targets[i].server, targets[i].port);
	}

	sdnotify_ready();
	lota_info("Starting attestation loop");

	while (g_agent.running) {
		uint64_t now_ms = monotonic_ms();
		uint64_t wake_ms = 0;

		/*
		 * Every target that has come due, then the earliest deadline left.
		 * Rounds are serialized on purpose: they share one TPM and one
		 * binding, and a quote is short.
		 */
		for (size_t i = 0; i < target_count && g_agent.running; i++) {
			int wait_sec;

			if (now_ms < targets[i].next_due_ms)
				continue;

			wait_sec = attest_target_round(&targets[i], skip_verify,
						       pin_sha256, aik_ttl);
			targets[i].next_due_ms =
				monotonic_ms() + (uint64_t)wait_sec * 1000;
		}

		publish_aggregate_status(targets, target_count, &status_flags);

		/*
		 * Leave the TPM on the first publisher between rounds:
		 * it is the AIK a GET_TOKEN is answered with, and token must not
		 * depend on which target happened to attest last
		 */
		if (target_count > 1 && targets[0].has_profile) {
			ret = bind_target(&targets[0]);
			if (ret < 0)
				lota_warn("Tokens will keep the previous "
					  "publisher's AIK until the next "
					  "round");
		}

		for (size_t i = 0; i < target_count; i++) {
			if (wake_ms == 0 || targets[i].next_due_ms < wake_ms)
				wake_ms = targets[i].next_due_ms;
		}
		lota_dbg("Next attestation round in %llu ms",
			 (unsigned long long)(wake_ms > monotonic_ms() ?
						      wake_ms - monotonic_ms() :
						      0));

		while (g_agent.running) {
			uint64_t current_ms = monotonic_ms();
			bool asked = false;
			int timeout_ms;

			if (current_ms >= wake_ms)
				break;

			/*
			 * title selected a publisher this host has never
			 * enrolled with, or session opened or closed.
			 * Both are moments this loop exists to serve,
			 * so stop sleeping through them:
			 * title that just launched wants its first report now,
			 * not one interval from now
			 */
			for (size_t i = 0; i < target_count; i++) {
				if (targets[i].enroll_pending ||
				    targets[i].session_changed) {
					targets[i].session_changed = false;
					targets[i].next_due_ms = current_ms;
					asked = true;
				}
			}
			if (asked)
				break;

			timeout_ms = (int)(wake_ms - current_ms);

			if (wd_enabled && wd_usec > 0) {
				int wd_timeout_ms = (int)(wd_usec / 2000);

				if (timeout_ms > wd_timeout_ms)
					timeout_ms = wd_timeout_ms;
			}

			ipc_process(&g_agent.ipc_ctx, timeout_ms);
			if (wd_enabled)
				sdnotify_watchdog_ping();
		}
	}

	lota_info("Shutting down continuous attestation");
	sdnotify_stopping();
	tpm_cleanup(&g_agent.tpm_ctx);
	net_cleanup();
	dbus_cleanup(g_agent.dbus_ctx);
	ipc_cleanup(&g_agent.ipc_ctx);
	return 0;
}
