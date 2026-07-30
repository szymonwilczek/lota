/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * LOTA attestation-CA enrollment client - orchestrator.
 *
 * Runs the agent side of the credential-activation ceremony over TLS:
 * present the EK certificate and AIK template, activate the credential
 * the CA wraps to the TPM, and persist the issued AIK certificate.
 */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <openssl/crypto.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/types.h>

#include "agent.h"
#include "enroll.h"
#include "net.h"
#include "profile.h"
#include "tpm.h"
#include "lota_enroll.h"

/* Outer frame: u32 big-endian body length followed by the body. */
static int send_frame(struct net_context *net, const uint8_t *body, size_t len)
{
	uint8_t hdr[4];
	int ret;

	if (len > LOTA_ENROLL_MAX_FRAME)
		return -EMSGSIZE;
	hdr[0] = (uint8_t)(len >> 24);
	hdr[1] = (uint8_t)(len >> 16);
	hdr[2] = (uint8_t)(len >> 8);
	hdr[3] = (uint8_t)len;

	ret = net_write_all(net, hdr, sizeof(hdr));
	if (ret < 0)
		return ret;
	return net_write_all(net, body, len);
}

static int recv_frame(struct net_context *net, uint8_t *buf, size_t buf_max,
		      size_t *out_len)
{
	uint8_t hdr[4];
	uint32_t n;
	int ret;

	ret = net_read_full(net, hdr, sizeof(hdr));
	if (ret < 0)
		return ret;
	n = (uint32_t)hdr[0] << 24 | (uint32_t)hdr[1] << 16 |
	    (uint32_t)hdr[2] << 8 | (uint32_t)hdr[3];
	if (n > LOTA_ENROLL_MAX_FRAME || n > buf_max)
		return -EMSGSIZE;
	ret = net_read_full(net, buf, n);
	if (ret < 0)
		return ret;
	*out_len = n;
	return 0;
}

/* Write a file atomically: write a temp file, fsync, then rename. */
static int write_file_atomic(const char *path, const void *data, size_t len,
			     mode_t mode)
{
	char tmp[PATH_MAX];
	const uint8_t *p = data;
	size_t off = 0;
	int fd, ret;

	if (snprintf(tmp, sizeof(tmp), "%s.tmp", path) >= (int)sizeof(tmp))
		return -ENAMETOOLONG;

	fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, mode);
	if (fd < 0)
		return -errno;

	while (off < len) {
		ssize_t w = write(fd, p + off, len - off);
		if (w < 0) {
			ret = -errno;
			close(fd);
			unlink(tmp);
			return ret;
		}
		off += (size_t)w;
	}

	if (fsync(fd) < 0) {
		ret = -errno;
		close(fd);
		unlink(tmp);
		return ret;
	}
	if (close(fd) < 0) {
		ret = -errno;
		unlink(tmp);
		return ret;
	}
	if (rename(tmp, path) < 0) {
		ret = -errno;
		unlink(tmp);
		return ret;
	}
	return 0;
}

/* Persist the DER certificate atomically. */
static int store_cert(const char *path, const uint8_t *der, size_t len)
{
	return write_file_atomic(path, der, len, 0644);
}

int enroll_to_ca(struct tpm_context *tpm, const char *server, int port,
		 const char *ca_cert, int skip_verify, const uint8_t *pin,
		 const char *token, const char *out_cert_path)
{
	struct net_context net;
	int net_inited = 0;
	uint8_t ek_cert[LOTA_ENROLL_MAX_EK_CERT];
	size_t ek_len = 0;
	uint8_t aik_pub[LOTA_ENROLL_MAX_AIK_PUBLIC];
	size_t aik_len = 0;
	uint8_t body[LOTA_ENROLL_MAX_FRAME];
	uint8_t rbuf[LOTA_ENROLL_MAX_FRAME];
	uint8_t secret[LOTA_ENROLL_MAX_SECRET];
	size_t secret_len = 0;
	size_t rlen = 0;
	struct enroll_challenge ch;
	struct enroll_result res;
	ssize_t blen;
	int ret;

	if (!tpm || !server || !out_cert_path)
		return -EINVAL;

	memset(secret, 0, sizeof(secret));

	ret = tpm_get_ek_cert(tpm, ek_cert, sizeof(ek_cert), &ek_len);
	if (ret < 0) {
		fprintf(stderr,
			"EK certificate unavailable; the CA cannot anchor "
			"this TPM: %s\n",
			strerror(-ret));
		return ret;
	}
	ret = tpm_get_aik_tpmt_public(tpm, aik_pub, sizeof(aik_pub), &aik_len);
	if (ret < 0) {
		fprintf(stderr, "AIK public area unavailable: %s\n",
			strerror(-ret));
		return ret;
	}

	memset(&net, 0, sizeof(net));
	ret = net_context_init(&net, server, port, ca_cert, skip_verify, pin);
	if (ret < 0) {
		fprintf(stderr,
			"Failed to set up the TLS channel to the CA at %s:%d "
			"(check --ca-cert): %s\n",
			server, port, strerror(-ret));
		goto out;
	}
	net_inited = 1;
	ret = net_connect(&net);
	if (ret < 0) {
		fprintf(stderr,
			"Could not reach the attestation CA at %s:%d: %s. "
			"Confirm lota-attest-ca is running and reachable.\n",
			server, port, strerror(-ret));
		goto out;
	}

	blen = enroll_encode_begin(body, sizeof(body), ek_cert, ek_len, aik_pub,
				   aik_len, (const uint8_t *)token,
				   token ? strlen(token) : 0);
	if (blen < 0) {
		ret = (int)blen;
		fprintf(stderr, "Failed to encode the enrollment request: %s\n",
			strerror(-ret));
		goto out;
	}
	ret = send_frame(&net, body, (size_t)blen);
	if (ret < 0) {
		fprintf(stderr,
			"Failed to send the enrollment request to the CA: %s\n",
			strerror(-ret));
		goto out;
	}

	ret = recv_frame(&net, rbuf, sizeof(rbuf), &rlen);
	if (ret < 0) {
		fprintf(stderr,
			"No challenge received from the CA (connection "
			"dropped?): %s\n",
			strerror(-ret));
		goto out;
	}
	ret = enroll_decode_challenge(rbuf, rlen, &ch);
	if (ret < 0) {
		fprintf(stderr, "Malformed challenge from the CA: %s\n",
			strerror(-ret));
		goto out;
	}
	if (ch.status != LOTA_ENROLL_STATUS_OK) {
		if (ch.status == LOTA_ENROLL_STATUS_TOKEN_REJECTED)
			fprintf(stderr,
				"CA rejected the enrollment token (status "
				"%u). Check the token file against the "
				"CA's configured token set%s.\n",
				ch.status,
				token ? "" :
					"; this CA requires --enroll-token-file");
		else
			fprintf(stderr,
				"CA refused enrollment at challenge (status "
				"%u)\n",
				ch.status);
		ret = -EACCES;
		goto out;
	}

	ret = tpm_activate_credential(tpm, ch.cred_blob, ch.cred_blob_len,
				      ch.enc_secret, ch.enc_secret_len, secret,
				      sizeof(secret), &secret_len);
	if (ret < 0) {
		fprintf(stderr, "Credential activation failed: %s\n",
			strerror(-ret));
		goto out;
	}

	blen = enroll_encode_complete(body, sizeof(body), ch.session_id, secret,
				      secret_len);
	OPENSSL_cleanse(secret, sizeof(secret));
	if (blen < 0) {
		ret = (int)blen;
		fprintf(stderr,
			"Failed to encode the credential response: %s\n",
			strerror(-ret));
		goto out;
	}
	ret = send_frame(&net, body, (size_t)blen);
	if (ret < 0) {
		fprintf(stderr,
			"Failed to send the credential response to the CA: %s\n",
			strerror(-ret));
		goto out;
	}

	ret = recv_frame(&net, rbuf, sizeof(rbuf), &rlen);
	if (ret < 0) {
		fprintf(stderr,
			"No completion response from the CA (connection "
			"dropped?): %s\n",
			strerror(-ret));
		goto out;
	}
	ret = enroll_decode_result(rbuf, rlen, &res);
	if (ret < 0) {
		fprintf(stderr,
			"Malformed completion response from the CA: %s\n",
			strerror(-ret));
		goto out;
	}
	if (res.status != LOTA_ENROLL_STATUS_OK) {
		fprintf(stderr,
			"CA refused enrollment at completion (status %u)\n",
			res.status);
		ret = -EACCES;
		goto out;
	}

	ret = store_cert(out_cert_path, res.aik_cert, res.aik_cert_len);
	if (ret < 0) {
		fprintf(stderr, "Failed to store AIK certificate: %s\n",
			strerror(-ret));
		goto out;
	}

	printf("Enrolled. Device ID: %s\n", res.device_id);
	printf("AIK certificate stored at %s (%zu bytes)\n", out_cert_path,
	       res.aik_cert_len);
	ret = 0;

out:
	OPENSSL_cleanse(secret, sizeof(secret));
	if (net_inited)
		net_context_cleanup(&net);
	return ret;
}

/*
 * Persist the endpoint a successful enrollment used together with the AIK
 * generation the issued certificate is bound to, so --reenroll can reuse
 * the endpoint and the daemon can detect when a local AIK rotation has
 * outdated the certificate. A persistence failure does not fail the
 * enrollment: the certificate is already stored.
 */
static void persist_enroll_state(const struct profile_paths *paths,
				 const char *server, int port,
				 const char *ca_cert, int skip_verify,
				 const uint8_t *pin, const char *token)
{
	struct enroll_state st;

	memset(&st, 0, sizeof(st));
	st.ca_port = port;
	st.no_verify_tls = skip_verify ? 1 : 0;
	if (server)
		snprintf(st.ca_server, sizeof(st.ca_server), "%s", server);
	if (ca_cert)
		snprintf(st.ca_cert, sizeof(st.ca_cert), "%s", ca_cert);
	if (token)
		snprintf(st.enroll_token, sizeof(st.enroll_token), "%s", token);
	if (pin) {
		memcpy(st.pin_sha256, pin, sizeof(st.pin_sha256));
		st.has_pin = 1;
	}
	if (tpm_aik_load_metadata(&g_agent.tpm_ctx) == 0)
		st.aik_generation = g_agent.tpm_ctx.aik_meta.generation;

	if (enroll_state_save_path(paths->enroll_state, &st) < 0)
		fprintf(stderr,
			"Warning: could not record enrollment state at %s; "
			"--reenroll will need the CA endpoint again\n",
			paths->enroll_state);
	OPENSSL_cleanse(&st, sizeof(st));
}

/*
 * Bring up the TPM, provision the AIK, run one enrollment against the CA,
 * store the certificate, and record the endpoint. Returns 0 on success,
 * negative errno on failure.
 *
 * Everything the enrollment writes lands in the profile the CA trust anchor
 * names, so second publisher does not overwrite the first one's identity.
 */
static int run_enrollment(const struct profile_paths *paths, const char *server,
			  int port, const char *ca_cert, int skip_verify,
			  const uint8_t *pin, const char *token)
{
	int ret;

	ret = profile_dir_ensure(paths);
	if (ret < 0) {
		fprintf(stderr, "Failed to create %s: %s\n", paths->dir,
			strerror(-ret));
		return ret;
	}

	ret = net_init();
	if (ret < 0) {
		fprintf(stderr, "Failed to initialize network: %s\n",
			strerror(-ret));
		return ret;
	}

	printf("Initializing TPM...\n");
	ret = tpm_init(&g_agent.tpm_ctx);
	if (ret < 0) {
		fprintf(stderr, "Failed to initialize TPM: %s\n",
			tpm_strerror(ret));
		net_cleanup();
		return ret;
	}

	printf("Checking AIK...\n");
	ret = tpm_provision_aik(&g_agent.tpm_ctx);
	if (ret < 0) {
		fprintf(stderr, "Failed to provision AIK: %s\n",
			tpm_strerror(ret));
		tpm_cleanup(&g_agent.tpm_ctx);
		net_cleanup();
		return ret;
	}

	ret = enroll_to_ca(&g_agent.tpm_ctx, server, port, ca_cert, skip_verify,
			   pin, token, paths->aik_cert);
	if (ret == 0)
		persist_enroll_state(paths, server, port, ca_cert, skip_verify,
				     pin, token);

	tpm_cleanup(&g_agent.tpm_ctx);
	net_cleanup();
	return ret;
}

/*
 * Resolve the profile a CA trust anchor names.
 *
 * The anchor is mandatory for every enrollment path:
 * it is the only input that tells two publishers apart, and the host keeps
 * separate AIK per publisher so they cannot correlate the same machine across
 * titles.
 * Without it there is nothing to key the enrollment by.
 */
static int resolve_profile(const char *ca_cert, struct profile_paths *paths)
{
	int ret;

	if (!ca_cert) {
		fprintf(stderr,
			"ERROR: --ca-cert PATH is required.\n"
			"The CA trust anchor names the publisher this host "
			"enrolls with; its enrollment is stored under that "
			"name.\n");
		return -EINVAL;
	}

	ret = profile_paths_from_anchor(ca_cert, paths);
	if (ret < 0)
		fprintf(stderr, "Failed to read the CA trust anchor %s: %s\n",
			ca_cert, strerror(-ret));
	return ret;
}

int do_enroll(const char *server, int port, const char *ca_cert,
	      int skip_verify, const uint8_t *pin, const char *token_file)
{
	char token[LOTA_ENROLL_MAX_TOKEN + 1];
	struct profile_paths paths;
	int ret;

	printf("=== Attestation CA Enrollment ===\n\n");

	if (resolve_profile(ca_cert, &paths) < 0) {
		printf("\n=== Enrollment Failed ===\n");
		return 1;
	}
	printf("Publisher profile: %s\n", paths.id);

	token[0] = '\0';
	if (token_file) {
		ret = enroll_token_from_file(token_file, token, sizeof(token));
		if (ret < 0) {
			fprintf(stderr,
				"Could not read the enrollment token from "
				"%s: %s\n",
				token_file, strerror(-ret));
			printf("\n=== Enrollment Failed ===\n");
			return 1;
		}
	}

	/*
	 * --enroll is a one-shot CLI mode. Return a non-negative exit code
	 * (0 success, 1 failure): diagnostics_dispatch() treats any negative
	 * return as "not a diagnostic, fall through to the daemon", so a
	 * failed enrollment must not leak a negative errno upward.
	 */
	ret = run_enrollment(&paths, server, port, ca_cert, skip_verify, pin,
			     token[0] ? token : NULL);
	OPENSSL_cleanse(token, sizeof(token));

	printf("\n=== Enrollment %s ===\n", ret == 0 ? "Successful" : "Failed");
	return ret == 0 ? 0 : 1;
}

int do_reenroll(const char *ca_cert)
{
	struct profile_paths paths;
	struct enroll_state st;
	int ret;

	if (resolve_profile(ca_cert, &paths) < 0)
		return 1;

	ret = enroll_state_load_path(paths.enroll_state, &st);
	if (ret == -ENOENT) {
		fprintf(stderr,
			"No saved enrollment for this CA at %s.\n"
			"Run --enroll once with --ca-server and the same "
			"--ca-cert first; --reenroll then reuses that "
			"endpoint.\n",
			paths.enroll_state);
		return 1;
	}
	if (ret < 0) {
		fprintf(stderr, "Failed to read enrollment state: %s\n",
			strerror(-ret));
		return 1;
	}

	printf("=== Re-enrolling with %s:%d (profile %s) ===\n\n", st.ca_server,
	       st.ca_port, paths.id);

	/*
	 * endpoint comes from the record, the anchor from the caller:
	 * the anchor is what selected this record in the first place,
	 * so stale path in the record cannot send the re-enrollment somewhere else
	 */
	ret = run_enrollment(&paths, st.ca_server, st.ca_port, ca_cert,
			     st.no_verify_tls,
			     st.has_pin ? st.pin_sha256 : NULL,
			     st.enroll_token[0] ? st.enroll_token : NULL);
	OPENSSL_cleanse(&st, sizeof(st));

	printf("\n=== Re-enrollment %s ===\n",
	       ret == 0 ? "Successful" : "Failed");
	return ret == 0 ? 0 : 1;
}

int enroll_renew_cert(struct tpm_context *tpm,
		      const struct profile_paths *paths)
{
	struct enroll_state st;
	int ret;

	if (!tpm || !paths)
		return -EINVAL;

	ret = enroll_state_load_path(paths->enroll_state, &st);
	if (ret < 0)
		return ret; /* -ENOENT: never enrolled, caller disables renew */

	ret = enroll_to_ca(tpm, st.ca_server, st.ca_port,
			   st.ca_cert[0] ? st.ca_cert : NULL, st.no_verify_tls,
			   st.has_pin ? st.pin_sha256 : NULL,
			   st.enroll_token[0] ? st.enroll_token : NULL,
			   paths->aik_cert);
	if (ret == 0)
		persist_enroll_state(
			paths, st.ca_server, st.ca_port,
			st.ca_cert[0] ? st.ca_cert : NULL, st.no_verify_tls,
			st.has_pin ? st.pin_sha256 : NULL,
			st.enroll_token[0] ? st.enroll_token : NULL);
	OPENSSL_cleanse(&st, sizeof(st));
	return ret;
}
