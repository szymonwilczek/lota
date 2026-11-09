/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/* LOTA Agent - Remote attestation and policy export */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
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
#include <sys/utsname.h>
#include <tss2/tss2_tpm2_types.h>

#include "../../include/attestation.h"
#include "../../include/lota.h"
#include "../../include/lota_ipc.h"
#include "agent.h"
#include "aik_cert.h"
#include "attest.h"
#include "attest_aggregate.h"
#include "attest_peer.h"
#include "attest_targets.h"
#include "bpf_loader.h"
#include "daemon.h"
#include "enroll.h"
#include "esrt.h"
#include "moklist.h"
#include "exit_status.h"
#include "hardening.h"
#include "iommu.h"
#include "io_utils.h"
#include "ipc.h"
#include "journal.h"
#include "kernel_measure.h"
#include "net.h"
#include "policy.h"
#include "quote.h"
#include "report_flags.h"
#include "sdnotify.h"
#include "selftest.h"
#include "tpm.h"
#include "watchdog_pace.h"
#include "iommu_types.h"

static int read_pcr_for_kernel_measurement(void *ctx, int pcr,
					   uint8_t out[LOTA_HASH_SIZE])
{
	return tpm_read_pcr((struct tpm_context *)ctx, pcr, TPM2_ALG_SHA256,
			    out);
}

static int read_kernel_measurement_digest(struct tpm_context *ctx,
					  uint8_t out_hash[LOTA_HASH_SIZE],
					  int *selected_pcr)
{
	if (!ctx)
		return -EINVAL;

	return kernel_measurement_select(read_pcr_for_kernel_measurement, ctx,
					 out_hash, selected_pcr);
}

void attest_warn_cert_orphaned(const struct profile_paths *paths,
			       const char *label, int key_present)
{
	uint8_t spki[LOTA_MAX_AIK_PUB_SIZE];
	size_t spki_len = 0;
	int cert_match = 0;

	if (!paths || !profile_aik_cert_stored(paths))
		return;

	if (tpm_get_aik_public(&g_agent.tpm_ctx, spki, sizeof(spki),
			       &spki_len) < 0)
		return;

	cert_match = aik_cert_matches_key(paths->aik_cert, spki, spki_len);

	if (!tpm_aik_provisioning_orphans_cert(key_present, true, cert_match))
		return;

	lota_err("This TPM no longer holds the attestation key that was "
		 "enrolled, and a new one takes its place. The certificate "
		 "stored for this publisher names the key that is gone, so "
		 "every round will be refused until they issue one for the key "
		 "that is here now: lota-agent --reenroll --ca-cert <their "
		 "anchor>. A TPM clear does this. Publisher: %s",
		 label ? label : "unnamed");
}

static uint32_t rand_u32_best_effort(void)
{
	uint32_t v = 0;
	ssize_t n = getrandom(&v, sizeof(v), GRND_NONBLOCK);
	if (n == (ssize_t)sizeof(v))
		return v;

	/* not cryptographic: only decorrelates retry timing */
	v = (uint32_t)time(NULL);
	v ^= (uint32_t)getpid();
	v ^= (uint32_t)(uintptr_t)&v;
	return v;
}

static void collect_kernel_security_features(bool *module_sig, bool *secureboot,
					     bool *lockdown, bool *appraisal)
{
	if (appraisal)
		*appraisal = bpf_loader_kernel_appraises_exec() == 0;
	if (module_sig)
		*module_sig = bpf_loader_kernel_module_sig_enforced(
				      LOTA_MODULE_SIG_ENFORCE_PATH) == 0;
	if (secureboot)
		*secureboot = bpf_loader_secure_boot_enabled() == 0;
	if (lockdown)
		*lockdown = bpf_loader_kernel_lockdown_restrictive(
				    LOTA_KERNEL_LOCKDOWN_PATH) == 0;
}

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
			attest_failure_reason(ret));
		return ret;
	}

	fprintf(stderr, "Performing self-measurement...\n");
	ret = self_measure(&g_agent.tpm_ctx);
	if (ret < 0) {
		fprintf(stderr, "Warning: Self-measurement failed: %s\n",
			attest_failure_reason(ret));
		fprintf(stderr, "PCR 14 may not contain agent measurement.\n");
	}

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

	{
		struct utsname uts;

		if (uname(&uts) == 0)
			snprintf(snap.kernel_release,
				 sizeof(snap.kernel_release), "%s",
				 uts.release);
		else
			fprintf(stderr,
				"Warning: Failed to read the running kernel release: %s\n",
				strerror(errno));
	}

	if (tpm_kernel_path_is_overridden(&g_agent.tpm_ctx)) {
		fprintf(stderr,
			"Note: kernel_path does not affect this policy. The "
			"kernel digest below is the bootloader's measurement "
			"of the image it loaded, not a hash of any file this "
			"agent read.\n");
	}

	{
		uint8_t *event_log = malloc(TPM_MAX_EVENT_LOG_SIZE);
		size_t event_log_size = 0;
		struct kernel_image image;

		/*
		 * The kernel_hashes gate compares the image digest. PCR 9
		 * answers for a whole boot, so a pin on it refuses this host.
		 */
		if (!event_log) {
			snap.kernel_hash_error = -ENOMEM;
		} else {
			ret = tpm_read_event_log(event_log,
						 TPM_MAX_EVENT_LOG_SIZE,
						 &event_log_size);
			if (ret < 0)
				snap.kernel_hash_error = ret;
			else
				snap.kernel_hash_error =
					kernel_image_from_event_log(
						event_log, event_log_size,
						&image);
		}

		if (snap.kernel_hash_error == 0) {
			memcpy(snap.kernel_hash, image.digest, LOTA_HASH_SIZE);
			snprintf(snap.kernel_image_path,
				 sizeof(snap.kernel_image_path), "%s",
				 image.path);
			snap.kernel_hash_valid = true;
			fprintf(stderr,
				"Kernel measurement: the image the bootloader "
				"loaded, %s\n",
				snap.kernel_image_path);
		} else {
			fprintf(stderr,
				"Warning: no kernel digest to export: %s\n",
				policy_kernel_hash_reason(
					snap.kernel_hash_error));
			fprintf(stderr,
				"The policy is written with an empty "
				"kernel_hashes list; the other gates are "
				"unaffected.\n");
		}

		free(event_log);
	}

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

	{
		struct iommu_status iommu_status;

		snap.iommu_enabled = iommu_verify_full(&iommu_status);
		snap.enforce_mode = (mode == LOTA_MODE_ENFORCE);
		collect_kernel_security_features(&snap.module_sig,
						 &snap.secureboot,
						 &snap.lockdown,
						 &snap.ima_appraisal);
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

/* Say when the daemon stops or starts answering, not at every report */
static void note_daemon_view(int ret)
{
	static int last = 1;

	if (ret < 0 && last >= 0)
		lota_warn(
			"The enforcement daemon on %s does not answer (%s): "
			"reports carry no ENFORCE or BPF_ACTIVE until it does",
			LOTA_IPC_SOCKET_PATH, strerror(-ret));
	else if (ret == 0 && last < 0)
		lota_info("The enforcement daemon answers again; reports "
			  "carry its mode");
	last = ret < 0 ? ret : 0;
}

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
	report->header.version = LOTA_REPORT_VERSION;
	report->header.report_size = sizeof(*report);

	memcpy(report->tpm.nonce, challenge->nonce, LOTA_NONCE_SIZE);
	report->tpm.pcr_mask = challenge->pcr_mask;

	/* Flags go in before the binding nonce: the quote signs them */
	{
		struct enforcement_view view;

		note_daemon_view(attest_daemon_view(&view));
		report->header.flags |= report_enforcement_flags(&view);
	}

	{
		bool module_sig = false;
		bool secureboot = false;
		bool lockdown = false;
		bool appraisal = false;

		collect_kernel_security_features(&module_sig, &secureboot,
						 &lockdown, &appraisal);
		if (module_sig)
			report->header.flags |= LOTA_REPORT_FLAG_MODULE_SIG;
		if (secureboot)
			report->header.flags |= LOTA_REPORT_FLAG_SECUREBOOT;
		if (lockdown)
			report->header.flags |= LOTA_REPORT_FLAG_LOCKDOWN;
		if (appraisal)
			report->header.flags |= LOTA_REPORT_FLAG_IMA_APPRAISAL;
	}

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
	 * The hash self_measure() cached at startup: the verifier rederives
	 * PCR14 from this field.
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
	 * The verifier rederives PCR14 only with both flags set and refuses a
	 * report without them. Fail here, where the host can name the missing
	 * dracut module.
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
	 * ComputeAttestationBindingNonce() in the verifier recomputes this.
	 * The token path has a quote nonce of its own.
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

	report->tpm.attest_size = quote_resp.attest_size;
	if (quote_resp.attest_size > LOTA_MAX_ATTEST_SIZE) {
		fprintf(stderr, "TPMS_ATTEST too large: %u > %u\n",
			quote_resp.attest_size, LOTA_MAX_ATTEST_SIZE);
		ret = -EOVERFLOW;
		goto cleanup;
	}
	memcpy(report->tpm.attest_data, quote_resp.attest_data,
	       quote_resp.attest_size);

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
 * One round; TPM and network must be initialized. Returns 0 on success,
 * 1 on a refused verdict, negative on any other failure.
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
	uint8_t *mok_list = NULL;
	size_t wire_buf_size = 0;
	ssize_t wire_size = 0;
	enum attest_stage stage = ATTEST_STAGE_COUNT;
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
		stage = ATTEST_STAGE_TLS_SETUP;
		goto cleanup;
	}
	net_ctx_inited = 1;

	ret = net_connect(&net_ctx);
	if (ret < 0) {
		stage = ATTEST_STAGE_CONNECT;
		goto cleanup;
	}

	if (verbose)
		printf("Connected, waiting for challenge...\n");

	ret = net_recv_challenge(&net_ctx, &challenge);
	if (ret < 0) {
		stage = ATTEST_STAGE_CHALLENGE;
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
		stage = ATTEST_STAGE_BUILD_REPORT;
		goto cleanup;
	}

	event_log = malloc(TPM_MAX_EVENT_LOG_SIZE);
	if (event_log) {
		ret = tpm_read_event_log(event_log, TPM_MAX_EVENT_LOG_SIZE,
					 &event_log_size);
		if (ret < 0) {
			if (verbose)
				fprintf(stderr,
					"Warning: Failed to read TPM event "
					"log: %s\n",
					attest_failure_reason(ret));
			event_log_size = 0;
		} else if (verbose) {
			printf("TPM event log read (%zu bytes)\n",
			       event_log_size);
		}
	}

	{
		struct lota_esrt esrt;
		uint32_t mok_list_size = 0;
		size_t total;

		esrt_read_system_firmware(&esrt);

		/* Verifier checks this against the log's MokList event */
		mok_list = malloc(MOK_LIST_MAX);
		if (!mok_list) {
			ret = -ENOMEM;
			stage = ATTEST_STAGE_SERIALIZE;
			goto cleanup;
		}
		if (mok_list_read(mok_list, MOK_LIST_MAX, &mok_list_size) < 0 &&
		    verbose)
			printf("MOK list not sent\n");

		total = calculate_report_size((uint32_t)event_log_size,
					      mok_list_size);
		wire_buf_size = total;
		wire_buf = malloc(total);
		if (!wire_buf) {
			ret = -ENOMEM;
			stage = ATTEST_STAGE_SERIALIZE;
			goto cleanup;
		}

		report.header.report_size = (uint32_t)total;
		wire_size = serialize_report(&report, event_log,
					     (uint32_t)event_log_size, &esrt,
					     mok_list, mok_list_size, wire_buf,
					     total);
		if (wire_size < 0) {
			ret = (int)wire_size;
			stage = ATTEST_STAGE_SERIALIZE;
			goto cleanup;
		}
	}

	if (verbose)
		printf("Sending report (%zd bytes, event_log: %zu)...\n",
		       wire_size, event_log_size);

	ret = net_send_report(&net_ctx, wire_buf, (size_t)wire_size);
	if (ret < 0) {
		stage = ATTEST_STAGE_SEND;
		goto cleanup;
	}

	ret = net_recv_result(&net_ctx, &result);
	if (ret < 0) {
		stage = ATTEST_STAGE_RESULT;
		goto cleanup;
	}

	if (verbose) {
		printf("Result: %s\n",
		       net_verdict_str(result.result, report.header.flags));
		if (result.result == VERIFY_OK) {
			printf("Valid until: %lu\n",
			       (unsigned long)result.valid_until);
		}
	}

	if (result.result != VERIFY_OK) {
		lota_err("Attestation round failed at %s: %s",
			 attest_stage_str(ATTEST_STAGE_VERDICT),
			 net_verdict_str(result.result, report.header.flags));
		ret = 1;
		goto cleanup;
	}
	ret = 0;

cleanup:
	/* Whatever verbose says: the loop passes 0 */
	if (ret < 0 && stage != ATTEST_STAGE_COUNT)
		lota_err("Attestation round failed at %s: %s",
			 attest_stage_str(stage), attest_failure_reason(ret));
	OPENSSL_cleanse(&challenge, sizeof(challenge));
	OPENSSL_cleanse(&result, sizeof(result));
	OPENSSL_cleanse(&report, sizeof(report));
	if (wire_buf)
		OPENSSL_cleanse(wire_buf, wire_buf_size);
	if (event_log)
		OPENSSL_cleanse(event_log, event_log_size);
	free(wire_buf);
	free(event_log);
	free(mok_list);
	if (net_ctx_inited)
		net_context_cleanup(&net_ctx);
	OPENSSL_cleanse(&net_ctx, sizeof(net_ctx));
	return ret;
}

/*
 * Resolve the publisher profile the CA trust anchor names, into @storage.
 * NULL with no readable anchor: no certificate is presented.
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

/* A bind can drop the AIK record, which provisioning reads for a shared key */
static int provision_bound_aik(void)
{
	int ret = tpm_aik_load_metadata(&g_agent.tpm_ctx);

	if (ret < 0)
		return ret;

	return tpm_provision_aik(&g_agent.tpm_ctx);
}

/*
 * Exit status for a refused self-measurement: LOTA_EXIT_OPERATOR_ACTION
 * when lota_daemon_exit_status() says a restart cannot clear it, else 1.
 */
static int self_measure_exit_status(int ret)
{
	int status = lota_daemon_exit_status(
		ret, g_agent.tpm_ctx.boot_commitment_state);

	if (status != LOTA_EXIT_OPERATOR_ACTION)
		return 1;

	lota_err(
		"Starting the loop again cannot clear this: PCR 14 is written once per boot, so the register refuses this build for as long as the host stays up. The unit stops here and stays failed; the recovery is the reboot named above.");

	return LOTA_EXIT_OPERATOR_ACTION;
}

int do_attest(const char *server, int port, const char *ca_cert,
	      int skip_verify, const uint8_t *pin_sha256)
{
	struct profile_paths storage;
	const struct profile_paths *paths;
	int key_present;
	int ret;

	printf("=== Remote Attestation ===\n\n");

	/* reads a path, not the chip: refuse before the TPM is opened */
	if (tpm_firmware_refuses_attestation(&g_agent.tpm_ctx))
		return 1;

	paths = resolve_attest_profile(ca_cert, &storage);

	ret = hardening_apply_daemon();
	if (ret < 0) {
		fprintf(stderr, "Failed to apply daemon hardening: %s\n",
			strerror(-ret));
		return 1;
	}

	ret = net_init();
	if (ret < 0) {
		fprintf(stderr, "Failed to initialize network: %s\n",
			net_strerror(ret));
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
				tpm_strerror(ret));
			tpm_cleanup(&g_agent.tpm_ctx);
			net_cleanup();
			return 1;
		}
	}

	printf("Checking AIK...\n");
	key_present = tpm_aik_key_present(&g_agent.tpm_ctx);
	ret = provision_bound_aik();
	if (ret < 0) {
		fprintf(stderr, "Failed to provision AIK: %s\n",
			tpm_strerror(ret));
		tpm_cleanup(&g_agent.tpm_ctx);
		net_cleanup();
		return 1;
	}
	attest_warn_cert_orphaned(paths, paths ? paths->id : NULL, key_present);

	printf("Performing self-measurement...\n");
	ret = self_measure(&g_agent.tpm_ctx);
	if (ret < 0) {
		int status;

		fprintf(stderr, "Self-measurement failed: %s\n",
			tpm_strerror(ret));
		status = self_measure_exit_status(ret);
		tpm_cleanup(&g_agent.tpm_ctx);
		net_cleanup();
		return status;
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

	/* With no record there is nothing to compare: the flag stays clear */
	if (paths && enroll_state_load_path(paths->enroll_state, &st) == 0)
		reenroll_required = st.aik_generation !=
				    tpm->aik_meta.generation;

	ipc_update_rotation(&g_agent.ipc_ctx, tpm->aik_meta.generation,
			    (uint64_t)tpm->aik_meta.provisioned_at,
			    (uint64_t)tpm->aik_meta.last_rotated_at, deadline,
			    (uint64_t)tpm->grace_deadline, reenroll_required);
}

/* The loop's attestation tallies, sent to the socket owner with each sync */
static struct attest_peer_counters g_attest_counters;

static uint64_t monotonic_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

/*
 * Is the key now at this profile's handle the key its certificate names?
 * Reading the public area needs no authorization.
 */
static int target_key_matches_cert(struct attest_target *t)
{
	uint8_t spki[LOTA_MAX_AIK_PUB_SIZE];
	size_t spki_len = 0;
	int ret;

	if (!profile_aik_cert_stored(&t->paths))
		return 0;

	ret = tpm_get_aik_public(&g_agent.tpm_ctx, spki, sizeof(spki),
				 &spki_len);
	if (ret < 0) {
		/* unreadable: the later steps report it */
		return 0;
	}

	ret = aik_cert_matches_key(t->paths.aik_cert, spki, spki_len);
	if (ret == -EKEYREJECTED) {
		if (!t->key_mismatch_announced) {
			lota_err("The attestation key at this publisher's "
				 "handle is not the key their certificate was "
				 "issued over, so every quote would be refused "
				 "by the TPM and each refusal spends a "
				 "dictionary-attack attempt. No round is "
				 "attempted until they issue a certificate for "
				 "the key that is here now: lota-agent "
				 "--reenroll --ca-cert <their anchor>. "
				 "Publisher: %s",
				 t->label);
			t->key_mismatch_announced = true;
		}
		return ret;
	}

	if (t->key_mismatch_announced) {
		lota_info("The attestation key at this publisher's handle "
			  "matches their certificate again; rounds resume. "
			  "Publisher: %s",
			  t->label);
		t->key_mismatch_announced = false;
	}

	return 0;
}

static int bind_target(struct attest_target *t)
{
	int ret;

	if (!t->has_profile)
		return 0;

	ret = tpm_bind_profile(&g_agent.tpm_ctx, &t->paths);
	if (ret < 0) {
		lota_err("Cannot bind the publisher profile for %s: %s",
			 t->label, tpm_strerror(ret));
		return ret;
	}

	ret = provision_bound_aik();
	if (ret < 0) {
		/*
		 * Replacing a shared key would orphan its certificate,
		 * so it stays refused; say so once.
		 */
		if (ret == -ENOTSUP &&
		    tpm_aik_key_is_shared(&g_agent.tpm_ctx)) {
			if (!t->shared_key_announced) {
				lota_err("%s No round is attempted for this "
					 "publisher until their record names a "
					 "key of its own. Publisher: %s",
					 TPM_AIK_SHARED_KEY_ADVICE, t->label);
				t->shared_key_announced = true;
			}
			return ret;
		}
		lota_err("AIK unavailable for %s: %s", t->label,
			 tpm_strerror(ret));
		return ret;
	}

	if (t->shared_key_announced) {
		lota_info("This publisher's record now names an attestation "
			  "key of its own; rounds resume. Publisher: %s",
			  t->label);
		t->shared_key_announced = false;
	}

	ret = tpm_aik_load_metadata(&g_agent.tpm_ctx);
	if (ret < 0) {
		lota_err("Cannot load AIK metadata for %s: %s", t->label,
			 tpm_strerror(ret));
		return ret;
	}

	ret = target_key_matches_cert(t);
	if (ret < 0)
		return ret;

	/* Only known after the key read above */
	if (tpm_aik_object_replaced(&g_agent.tpm_ctx))
		lota_warn("The attestation key for %s is not the one bound "
			  "earlier: another object stands at its persistent "
			  "handle now. Nothing cached for the old key is kept, "
			  "and this agent needs no restart to use the new one.",
			  t->label);

	return 0;
}

/* enroll_state_load_path() result; -ENOENT without a profile */
static int target_enrollment_rc(const struct attest_target *t)
{
	struct enroll_state st;
	int rc;

	if (!t->has_profile)
		return -ENOENT;

	rc = enroll_state_load_path(t->paths.enroll_state, &st);
	OPENSSL_cleanse(&st, sizeof(st));
	return rc;
}

/*
 * Enroll a publisher this host has never enrolled with: at install time there
 * is no publisher yet, and the profile carries the CA endpoint and its anchor.
 * Failure backs off.
 */
static bool enroll_target_if_needed(struct attest_target *t)
{
	uint64_t now_ms = monotonic_ms();
	int enroll_rc;
	int ret;

	if (!t->has_profile)
		return true;

	enroll_rc = target_enrollment_rc(t);
	if (enroll_rc == 0)
		return true;

	/* enrolling over it would reissue the cert and lose its endpoint */
	if (enroll_state_record_present(enroll_rc)) {
		lota_warn("Enrollment record for publisher %s is unreadable "
			  "(%s); refusing to enroll over it. Restore %s, or "
			  "re-enroll deliberately with --reenroll",
			  t->paths.id, strerror(-enroll_rc),
			  t->paths.enroll_state);
		return false;
	}

	t->enroll_pending = false;

	{
		time_t agreed = 0;
		int cret = profile_consent_time(&t->paths, &agreed);

		if (cret == -ENOENT) {
			lota_warn("%s has no enrollment and nobody has "
				  "agreed to answer to publisher %s; run "
				  "--allow-publisher %s to record that",
				  t->label, t->paths.id, t->paths.id);
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
		lota_warn("%s has no enrollment and its profile names no "
			  "attestation CA; run --enroll for it",
			  t->label);
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

static void rotate_bound_aik_if_due(uint32_t aik_ttl)
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
}

/*
 * Enable unattended AIK certificate renewal for @t when its enrollment record
 * holds a CA endpoint. Re-reads the record on every call.
 */
static void resolve_target_renew(struct attest_target *t)
{
	char at[LOTA_RENEW_AT_LEN];
	struct enroll_state est;
	enum attest_renew_say say;
	bool enrolled;
	int load_rc = -ENOENT;

	memset(&est, 0, sizeof(est));
	if (t->has_profile)
		load_rc = enroll_state_load_path(t->paths.enroll_state, &est);
	enrolled = load_rc == 0;

	say = attest_target_resolve_renew(t, enrolled ? est.ca_server : NULL,
					  enrolled ? est.ca_port : 0);
	OPENSSL_cleanse(&est, sizeof(est));

	/* off either way; but the endpoint exists, inside the refused record */
	if (say == ATTEST_RENEW_OFF && enroll_state_record_present(load_rc)) {
		lota_info("AIK certificate auto-renewal off for %s: its "
			  "enrollment record could not be read (%s); the "
			  "recorded endpoint is inside it",
			  t->label, strerror(-load_rc));
		return;
	}

	switch (say) {
	case ATTEST_RENEW_ENABLED:
		lota_info("AIK certificate auto-renewal enabled for %s%s",
			  t->label, attest_target_renew_at(t, at, sizeof(at)));
		break;
	case ATTEST_RENEW_OFF:
		lota_info("AIK certificate auto-renewal off for %s: no "
			  "recorded CA endpoint (run --enroll to record one)",
			  t->label);
		break;
	case ATTEST_RENEW_SILENT:
		break;
	}

	if (attest_target_should_announce_renew_move(t))
		lota_warn("%s: the enrollment records %s:%d, which is where "
			  "renewal dials, not the CA this profile is "
			  "configured with; run --enroll --ca-server %s "
			  "--ca-port %d --ca-cert %s to move it",
			  t->label, t->renew_ca, t->renew_ca_port, t->ca,
			  t->ca_port, t->ca_cert);
}

static void renew_target_cert_if_due(struct attest_target *t)
{
	char at[LOTA_RENEW_AT_LEN];
	int64_t remaining = 0, total = 0;
	uint64_t mono_ms = monotonic_ms();
	int ret;

	/* every pass: the loop may have just enrolled this publisher */
	resolve_target_renew(t);

	if (!t->auto_renew || mono_ms < t->next_renew_ms)
		return;
	if (aik_cert_lifetime_path(t->paths.aik_cert, &remaining, &total) != 0)
		return;
	if (!aik_cert_renew_due(remaining, total))
		return;

	lota_info("AIK certificate renewal due for %s%s (%lld s left of "
		  "%lld s)",
		  t->label, attest_target_renew_at(t, at, sizeof(at)),
		  (long long)remaining, (long long)total);

	ret = enroll_renew_cert(&g_agent.tpm_ctx, &t->paths,
				t->ca_cert[0] ? t->ca_cert : NULL);
	if (ret == 0) {
		t->renew_backoff = 0;
		lota_info("AIK certificate renewed for %s%s", t->label,
			  attest_target_renew_at(t, at, sizeof(at)));
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
		lota_warn("AIK certificate renewal failed for %s%s (%s); "
			  "retry in %ds, cert expires in %lld s",
			  t->label, attest_target_renew_at(t, at, sizeof(at)),
			  strerror(-ret), delay, (long long)remaining);
		sdnotify_status("AIK cert renewal failing for %s, expires in "
				"%lld s",
				t->label, (long long)remaining);
	}
}

/*
 * Is this publisher owed a report right now? A session-gated target stops
 * reporting and drops its verdict when its last session ends.
 */
static bool target_reporting_now(struct attest_target *t)
{
	if (attest_target_reports(t))
		return true;

	/* publisher who runs no verifier holds no verdict to lose */
	if (t->token_only)
		return false;

	if (attest_target_should_announce_wait(t))
		lota_info("Nothing is reported to %s until a title of theirs "
			  "runs; enrollment, key rotation and certificate "
			  "renewal continue meanwhile",
			  t->label);

	if (t->attested) {
		lota_info("No session left for %s; reporting stops until a "
			  "title of theirs runs again",
			  t->label);
		t->attested = false;
		t->valid_until = 0;
	}
	return false;
}

/* One round against one target: seconds to wait before its next one */
static int attest_target_round(struct attest_target *t, int skip_verify,
			       const uint8_t *pin_sha256, uint32_t aik_ttl)
{
	time_t now = time(NULL);
	int ret;

	/*
	 * Ahead of both gates below: a token-only publisher's tokens are
	 * signed with this key, and a title selecting a publisher with no
	 * session yet reads not attested until enrollment completes.
	 */
	if (!enroll_target_if_needed(t)) {
		t->attested = false;
		t->valid_until = 0;
		return t->interval;
	}

	ret = bind_target(t);
	if (ret == 0) {
		rotate_bound_aik_if_due(aik_ttl);
		renew_target_cert_if_due(t);
	}

	/*
	 * A key the certificate does not name stays wrong on retry: no backoff,
	 * the ordinary interval until the profile is re-enrolled.
	 */
	if (ret == -EKEYREJECTED) {
		t->attested = false;
		t->valid_until = 0;
		return t->interval;
	}

	/* Likewise a shared key, until the profile is re-enrolled */
	if (ret == -ENOTSUP && t->shared_key_announced) {
		t->attested = false;
		t->valid_until = 0;
		return t->interval;
	}

	if (!target_reporting_now(t))
		return t->interval;

	if (ret == 0) {
		const uint8_t *pin = t->has_pin ? t->pin_sha256 : pin_sha256;

		lota_dbg("Attestation round starting for %s", t->label);
		ret = attest_once(t->server, t->port,
				  t->ca_cert[0] ? t->ca_cert : NULL,
				  skip_verify, pin,
				  t->has_profile ? &t->paths : NULL, 0);
	}

	if (ret == 0) {
		lota_info("Attestation successful (%s)", t->label);
		t->consecutive_failures = 0;
		t->backoff_sec = 0;
		t->auth_fail_announced = false;
		t->last_success = now;
		t->attested = true;
		t->valid_until = (uint64_t)(now + t->interval +
					    ATTEST_TOKEN_VALIDITY_SLACK_SEC);
		g_attest_counters.attest_count++;
		g_attest_counters.last_attest_time = (uint64_t)now;
		return t->interval;
	}

	/* A refused quote authorization stays refused on retry: no backoff */
	if (ret == -LOTA_ERR_TPM_AUTH_FAIL) {
		if (!t->auth_fail_announced) {
			lota_err("The TPM refused to authorize a quote for "
				 "%s. The attestation key or its stored "
				 "authorization is not the one this publisher "
				 "enrolled, so no round is attempted until "
				 "this publisher is "
				 "re-enrolled: lota-agent --reenroll "
				 "--ca-cert <their anchor>.",
				 t->label);
			t->auth_fail_announced = true;
		}
		t->attested = false;
		t->valid_until = 0;
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

	lota_err("Attestation FAILED for %s (attempt %d, backoff %ds)",
		 t->label, t->consecutive_failures, t->backoff_sec);
	if (t->last_success > 0)
		lota_warn("Last success for %s: %ld seconds ago", t->label,
			  (long)(now - t->last_success));

	/* up to two failed rounds keep the verdict */
	if (t->consecutive_failures >= 3) {
		t->attested = false;
		t->valid_until = 0;
	}
	g_attest_counters.fail_count++;

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

static void publish_aggregate_status(const struct attest_target *targets,
				     size_t count, uint32_t *status_flags)
{
	struct attest_aggregate agg;
	uint32_t flags;

	attest_aggregate_compute(targets, count, &agg);

	if (agg.attested)
		*status_flags |= LOTA_STATUS_ATTESTED;
	else
		*status_flags &= ~LOTA_STATUS_ATTESTED;

	flags = reconcile_tpm_lockout(*status_flags);

	g_attest_counters.host_flags = flags & LOTA_IPC_SYNC_HOST_FLAGS;

	ipc_update_status(&g_agent.ipc_ctx, flags, agg.valid_until);

	if (agg.attested)
		sdnotify_status("Attested (%zu publisher%s), valid until %lu",
				agg.considered, agg.considered == 1 ? "" : "s",
				(unsigned long)agg.valid_until);
	else if (count == 0)
		sdnotify_status("Idle: no publisher configured");
	else if (agg.considered == 0)
		sdnotify_status("Idle: no title running, nothing reported");
	else
		sdnotify_status("Attestation incomplete");
}

static void watchdog_keepalive(struct watchdog_pace *pace)
{
	uint64_t now = monotonic_ms();

	if (!watchdog_pace_due(pace, now))
		return;

	sdnotify_watchdog_ping();
	watchdog_pace_mark(pace, now);
}

static void announce_targets(const struct attest_target *targets, size_t count)
{
	if (count == 0)
		lota_info("No publisher and no verifier configured: nothing "
			  "is reported until a reload names one");
	for (size_t i = 0; i < count; i++) {
		if (targets[i].token_only)
			lota_info("Target %zu: %s -- nothing is reported to "
				  "them; their backend verifies the tokens "
				  "titles fetch. Checked every %d seconds for "
				  "enrollment, AIK rotation and certificate "
				  "renewal",
				  i + 1, targets[i].label, targets[i].interval);
		else
			lota_info("Target %zu: %s every %d seconds%s", i + 1,
				  targets[i].label, targets[i].interval,
				  targets[i].session_gated ?
					  ", while a title of theirs runs" :
					  "");
		if (targets[i].profile_error)
			lota_warn("Cannot read the CA trust anchor %s (%s): "
				  "attesting to %s without a publisher "
				  "profile, so no CA-issued AIK certificate is "
				  "presented",
				  targets[i].ca_cert,
				  strerror(-targets[i].profile_error),
				  targets[i].label);
		else if (!targets[i].has_profile)
			lota_warn("No CA trust anchor for %s: attesting "
				  "without a publisher profile, so no "
				  "CA-issued AIK certificate is presented",
				  targets[i].label);
	}

	if (count > 1)
		lota_info("A title that does not select a publisher is "
			  "answered for %s:%d and with the host-wide verdict, "
			  "but opens no session for them -- on a session-gated "
			  "publisher it reads not-attested until a title that "
			  "names one is running",
			  targets[0].server, targets[0].port);
}

static void resolve_auto_renew(struct attest_target *targets, size_t count)
{
	for (size_t i = 0; i < count; i++)
		resolve_target_renew(&targets[i]);
}

/* Bind the first target's publisher and provision its AIK */
static int aik_ready_for(const struct attest_target *first)
{
	int key_present;
	int ret;

	if (first->has_profile) {
		ret = tpm_bind_profile(&g_agent.tpm_ctx, &first->paths);
		if (ret < 0) {
			lota_err("Failed to bind the publisher profile: %s",
				 tpm_strerror(ret));
			return ret;
		}
	}

	lota_info("Checking AIK");
	key_present = tpm_aik_key_present(&g_agent.tpm_ctx);
	ret = provision_bound_aik();
	if (ret < 0) {
		lota_err("Failed to provision AIK: %s", tpm_strerror(ret));
		return ret;
	}
	if (first->has_profile)
		attest_warn_cert_orphaned(&first->paths, first->label,
					  key_present);

	ret = tpm_aik_load_metadata(&g_agent.tpm_ctx);
	if (ret < 0) {
		lota_err("Failed to load AIK metadata: %s", tpm_strerror(ret));
		return ret;
	}
	lota_info("AIK generation: %lu, age: %ld seconds",
		  (unsigned long)g_agent.tpm_ctx.aik_meta.generation,
		  (long)tpm_aik_age(&g_agent.tpm_ctx));
	return 0;
}

/* @targets is the caller's array, LOTA_CONFIG_MAX_PROFILES long */
static int continuous_attest_run(const struct lota_config *cfg,
				 const char *config_path, const char *server,
				 int port, const char *ca_cert, int skip_verify,
				 const uint8_t *pin_sha256, int interval_sec,
				 uint32_t aik_ttl,
				 struct attest_target *targets)
{
	struct attest_peer peer;
	size_t target_count = 0;
	uint32_t status_flags = 0;
	struct watchdog_pace pace;
	uint64_t wd_usec = 0;
	int ret;

	lota_info("Continuous attestation starting");

	/* reads a path, not the chip: refuse before the TPM is opened */
	if (tpm_firmware_refuses_attestation(&g_agent.tpm_ctx)) {
		lota_err("This host cannot attest: it did not boot via UEFI.");
		return 1;
	}

	attest_peer_init(&peer);

	ret = attest_targets_build(cfg, server, port, ca_cert, interval_sec,
				   targets, LOTA_CONFIG_MAX_PROFILES,
				   &target_count);
	/*
	 * Naming nothing is a host before its first publisher, not a failure:
	 * exiting would leave the unit stopped when one is added.
	 */
	if (ret == -EINVAL) {
		target_count = 0;
	} else if (ret < 0) {
		lota_err("Cannot build the attestation target list: %s",
			 strerror(-ret));
		return 1;
	}

	announce_targets(targets, target_count);

	ret = hardening_apply_daemon();
	if (ret < 0) {
		lota_err("Failed to apply daemon hardening: %s",
			 strerror(-ret));
		return 1;
	}

	/* 0 when systemd is not watching */
	if (!sdnotify_watchdog_enabled(&wd_usec))
		wd_usec = 0;
	watchdog_pace_init(&pace, wd_usec / 1000, monotonic_ms());

	/* LOTA_IPC_SOCKET_PATH is the enforcement daemon's: this is a client */
	ret = net_init();
	if (ret < 0) {
		lota_err("Failed to initialize network: %s", net_strerror(ret));
		return 1;
	}

	lota_info("Initializing TPM");
	ret = tpm_init(&g_agent.tpm_ctx);
	if (ret < 0) {
		lota_err("Failed to initialize TPM: %s", tpm_strerror(ret));
		net_cleanup();
		return 1;
	}
	status_flags |= LOTA_STATUS_TPM_OK;

	/* no key is made for a host that names nobody to quote for */
	if (target_count > 0 && aik_ready_for(&targets[0]) < 0) {
		tpm_cleanup(&g_agent.tpm_ctx);
		net_cleanup();
		return 1;
	}

	lota_info("Performing self-measurement");
	ret = self_measure(&g_agent.tpm_ctx);
	if (ret < 0) {
		int status;

		lota_err("Self-measurement failed: %s", tpm_strerror(ret));
		status = self_measure_exit_status(ret);
		tpm_cleanup(&g_agent.tpm_ctx);
		net_cleanup();
		return status;
	}

	/*
	 * Before the first round: a title may already be playing for a
	 * publisher, and this reads back which.
	 */
	attest_peer_sync(&peer, targets, target_count, &g_attest_counters);

	resolve_auto_renew(targets, target_count);

	sdnotify_ready();
	lota_info("Starting attestation loop");

	while (g_agent.running) {
		uint64_t now_ms = monotonic_ms();
		uint64_t wake_ms = 0;

		/* before the round: nothing pings inside it */
		watchdog_keepalive(&pace);

		if (daemon_reload_taken()) {
			size_t before = target_count;
			int rret = attest_targets_reload(
				config_path, server, port, ca_cert,
				interval_sec, targets, LOTA_CONFIG_MAX_PROFILES,
				&target_count);

			if (rret < 0) {
				lota_warn("Reload failed (%s); still reporting "
					  "to the %zu publisher(s) this loop "
					  "started with",
					  strerror(-rret), before);
			} else {
				lota_info("Publisher list reloaded: %zu "
					  "target(s)",
					  target_count);
				announce_targets(targets, target_count);
				resolve_auto_renew(targets, target_count);
				if (before == 0 && target_count > 0) {
					if (aik_ready_for(&targets[0]) < 0)
						lota_warn("The first round "
							  "retries the AIK");
				} else if (target_count > 0 &&
					   targets[0].has_profile &&
					   bind_target(&targets[0]) < 0)
					lota_warn("Tokens will keep the "
						  "previous publisher's AIK "
						  "until the next round");
			}
			now_ms = monotonic_ms();
		}

		/* Serialized: rounds share one TPM and one binding */
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

		/* After the rounds: a title reads this round's answer */
		attest_peer_sync(&peer, targets, target_count,
				 &g_attest_counters);

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
		/* nothing due: wait for a reload, keeping the peer in sync */
		if (target_count == 0)
			wake_ms =
				monotonic_ms() + (uint64_t)interval_sec * 1000;
		lota_dbg("Next attestation round in %llu ms",
			 (unsigned long long)(wake_ms > monotonic_ms() ?
						      wake_ms - monotonic_ms() :
						      0));

		while (g_agent.running) {
			uint64_t current_ms;
			bool asked = false;
			int timeout_ms;

			watchdog_keepalive(&pace);
			current_ms = monotonic_ms();

			if (current_ms >= wake_ms)
				break;

			if (daemon_reload_pending())
				break;

			/* a launched title wants its first report now */
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

			timeout_ms = (int)watchdog_pace_sleep_ms(
				&pace, current_ms, wake_ms - current_ms);

			/*
			 * On the socket owner's connection a session opening
			 * wakes this sleep. With no connection the next sync
			 * retries the link.
			 */
			{
				int peer_fd = attest_peer_fd(&peer);

				if (peer_fd >= 0) {
					struct pollfd pfd = {
						.fd = peer_fd,
						.events = POLLIN,
					};

					if (poll(&pfd, 1, timeout_ms) > 0 &&
					    attest_peer_drain(&peer))
						break;
				} else {
					struct timespec req = {
						.tv_sec = timeout_ms / 1000,
						.tv_nsec = (long)(timeout_ms %
								  1000) *
							   1000000L,
					};

					nanosleep(&req, NULL);
				}
			}
		}
	}

	lota_info("Shutting down continuous attestation");
	sdnotify_stopping();
	attest_peer_close(&peer);
	tpm_cleanup(&g_agent.tpm_ctx);
	net_cleanup();
	return 0;
}

int do_continuous_attest(const struct lota_config *cfg, const char *config_path,
			 const char *server, int port, const char *ca_cert,
			 int skip_verify, const uint8_t *pin_sha256,
			 int interval_sec, uint32_t aik_ttl)
{
	struct attest_target *targets;
	int ret;

	targets = calloc(LOTA_CONFIG_MAX_PROFILES, sizeof(*targets));
	if (!targets) {
		lota_err("Cannot allocate the attestation target list");
		return 1;
	}

	/* A reload re-reads this file; the packaged unit names none */
	ret = continuous_attest_run(
		cfg, config_path ? config_path : LOTA_CONFIG_DEFAULT_PATH,
		server, port, ca_cert, skip_verify, pin_sha256, interval_sec,
		aik_ttl, targets);
	free(targets);
	return ret;
}
