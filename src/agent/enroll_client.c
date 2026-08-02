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
#include "publishers.h"
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

	ret = tpm_bind_profile(&g_agent.tpm_ctx, paths);
	if (ret < 0) {
		fprintf(stderr,
			ret == -ENOSPC ?
				"No TPM persistent handle left for another "
				"publisher: %s\n" :
				"Failed to bind the publisher profile: %s\n",
			strerror(-ret));
		tpm_cleanup(&g_agent.tpm_ctx);
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

	/*
	 * Running --enroll is the consent:
	 * somebody with root named this CA and asked for the key.
	 * Recording it here keeps one rule for the agent to enforce,
	 * rather than one for operators and one for players
	 */
	if (profile_consent_record(&paths, getuid()) < 0)
		fprintf(stderr,
			"Warning: could not record consent for %s; the loop "
			"may refuse to re-enroll later\n",
			paths.id);

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

/*
 * Build the profile paths for a publisher named by its identity.
 * --allow-publisher runs before anything has enrolled, so there is no anchor
 *  on disk to derive the identity from:
 *  the title (or the publisher's own instructions) supplies the hex directly.
 */
static int paths_from_id(const char *profile_id, struct profile_paths *out)
{
	return profile_paths_from_id(LOTA_PROFILE_BASE_DIR, profile_id, out);
}

int do_allow_publisher(const char *profile_id)
{
	struct profile_paths paths;
	time_t agreed = 0;
	int ret;

	ret = paths_from_id(profile_id, &paths);
	if (ret < 0) {
		fprintf(stderr,
			"ERROR: '%s' is not a publisher identity.\n"
			"It is the lowercase hex SHA-256 (64 characters) of "
			"the publisher's CA trust anchor "
			"SubjectPublicKeyInfo.\n",
			profile_id ? profile_id : "");
		return 1;
	}

	if (profile_consent_time(&paths, &agreed) == 0) {
		printf("Publisher %s was already agreed to.\n", paths.id);
		return 0;
	}

	ret = profile_consent_record(&paths, getuid());
	if (ret < 0) {
		fprintf(stderr, "Failed to record consent for %s: %s\n",
			paths.id, strerror(-ret));
		return 1;
	}

	printf("Publisher %s may now enroll with this machine.\n", paths.id);
	printf("They will hold one attestation key here, unlinkable to the "
	       "one any other publisher holds.\n");
	return 0;
}

/*
 * Register a publisher in lota.conf so a title of theirs can name it.
 *
 * This is the step that used to be a text editor.
 * Game's installer runs it with the publisher's CA endpoint, the trust anchor it
 * ships, and where that publisher's verifier lives; the agent picks the change
 * up on its next start or reload.
 *
 * It records no consent.
 * That stays a separate act by the person at the machine, because installer must
 * not be able to agree on their behalf to publisher holding an attestation key
 * on their hardware -- the whole point of the consent gate.
 * The message says so, and names the command.
 */
int do_add_publisher(const char *config_path, const char *name,
		     const char *ca_server, int ca_port, const char *ca_cert,
		     const char *verifier, int verifier_port, int interval,
		     bool session_gated)
{
	struct profile_paths paths;
	struct lota_profile p;
	int ret;

	if (!ca_server || !ca_server[0] || !ca_cert || !ca_cert[0]) {
		fprintf(stderr,
			"ERROR: --add-publisher needs the CA host and "
			"--ca-cert PATH, the publisher's trust anchor.\n");
		return 1;
	}

	/*
	 * Anchor is the publisher's identity, so it has to be readable
	 * and parseable here rather than at the next start:
	 * installer that wrote a profile naming a file that is not a certificate
	 * would leave a host that refuses to start.
	 */
	ret = profile_paths_from_anchor(ca_cert, &paths);
	if (ret < 0) {
		fprintf(stderr,
			"ERROR: cannot read a publisher identity from %s: "
			"%s\n",
			ca_cert, strerror(-ret));
		return 1;
	}

	/*
	 * Text-level check in the writer compares anchor paths, which misses
	 * the same key reached by a second path -- copied PEM, symlink,
	 * per-title install directory.
	 * The identity is the key, and it is already resolved here, so compare
	 * that against what the file configures before adding anything.
	 */
	{
		struct lota_config existing;
		int i;

		config_init(&existing);
		if (config_load(&existing,
				config_path ? config_path :
					      LOTA_CONFIG_DEFAULT_PATH) == 0) {
			for (i = 0; i < existing.profile_count; i++) {
				struct profile_paths other;

				if (profile_paths_from_anchor(
					    existing.profiles[i].ca_cert,
					    &other) < 0)
					continue;
				if (strcmp(other.id, paths.id) != 0)
					continue;

				printf("Publisher %s is already configured as "
				       "\"%s\"; nothing to do.\n",
				       paths.id, existing.profiles[i].name);
				return 0;
			}
		}
	}

	memset(&p, 0, sizeof(p));
	/* Identity is 64 hex characters and the label field is shorter,
	 * so unnamed publisher is labelled by a readable prefix of it rather
	 * than a silently cut one */
	if (name && name[0])
		snprintf(p.name, sizeof(p.name), "%s", name);
	else
		snprintf(p.name, sizeof(p.name), "publisher-%.16s", paths.id);
	snprintf(p.ca, sizeof(p.ca), "%s", ca_server);
	p.ca_port = ca_port > 0 ? ca_port : LOTA_DEFAULT_CA_PORT;
	snprintf(p.ca_cert, sizeof(p.ca_cert), "%s", ca_cert);
	if (verifier && verifier[0])
		snprintf(p.verifier, sizeof(p.verifier), "%s", verifier);
	p.verifier_port = verifier_port > 0 ? verifier_port :
					      LOTA_DEFAULT_VERIFIER_PORT;
	p.attest_interval = interval;
	p.session_gated = session_gated;

	ret = config_profile_append(
		config_path ? config_path : LOTA_CONFIG_DEFAULT_PATH, &p);
	switch (ret) {
	case 1:
		printf("Publisher %s added to %s as \"%s\".\n", paths.id,
		       config_path ? config_path : LOTA_CONFIG_DEFAULT_PATH,
		       p.name);
		printf("Nothing enrols with them until somebody at this "
		       "machine agrees:\n");
		printf("  lota-agent --allow-publisher %s\n", paths.id);
		printf("A running agent picks the publisher up on reload:\n");
		printf("  systemctl reload lota-agent\n");
		return 0;
	case 0:
		printf("Publisher %s is already configured as \"%s\"; "
		       "nothing to do.\n",
		       paths.id, p.name);
		return 0;
	case -EEXIST:
		fprintf(stderr,
			"ERROR: a different publisher is already configured "
			"as \"%s\". Pass --publisher-name to choose another "
			"label.\n",
			p.name);
		return 1;
	case -E2BIG:
		fprintf(stderr,
			"ERROR: this host already answers to %d publishers, "
			"which is the maximum. Free a slot with "
			"'lota-agent --forget-publisher <id>' and remove its "
			"section from the configuration.\n",
			LOTA_CONFIG_MAX_PROFILES);
		return 1;
	default:
		fprintf(stderr, "ERROR: could not add the publisher: %s\n",
			strerror(-ret));
		return 1;
	}
}

static void print_publisher(const struct publisher_entry *e)
{
	printf("%s\n", e->id);

	if (e->consented) {
		char when[32];
		struct tm tm;

		gmtime_r(&e->consented_at, &tm);
		strftime(when, sizeof(when), "%Y-%m-%d %H:%M:%SZ", &tm);
		printf("  agreed to      %s\n", when);
	} else {
		printf("  agreed to      no (nothing enrolls until it is)\n");
	}

	if (e->enrolled)
		printf("  enrolled with  %s:%d\n", e->ca_server, e->ca_port);
	else
		printf("  enrolled with  not yet\n");

	if (e->has_aik_handle)
		printf("  attestation key at TPM handle 0x%08X\n",
		       e->aik_handle);
	else
		printf("  attestation key none\n");

	if (e->has_cert)
		printf("  certificate    %lld s of validity left\n",
		       (long long)e->cert_remaining_sec);
	else
		printf("  certificate    none stored\n");
}

int do_list_publishers(void)
{
	struct publisher_entry entries[LOTA_PROFILE_MAX_AIK_HANDLES];
	size_t count = 0;
	int ret;

	ret = publishers_list(LOTA_PROFILE_BASE_DIR, entries,
			      sizeof(entries) / sizeof(entries[0]), &count);
	if (ret < 0) {
		fprintf(stderr, "Failed to read %s: %s\n",
			LOTA_PROFILE_BASE_DIR, strerror(-ret));
		return 1;
	}

	if (count == 0) {
		printf("This machine answers to no publisher.\n");
		return 0;
	}

	printf("Publishers this machine answers to:\n\n");
	for (size_t i = 0; i < count; i++) {
		print_publisher(&entries[i]);
		printf("\n");
	}
	printf("Each holds its own attestation key, so none of them can tell "
	       "from the evidence\nthat this is the same machine another one "
	       "sees. What every report contains is\nthe same for all of "
	       "them and is listed in the operator documentation.\n");
	printf("\nTake one back with: lota-agent --forget-publisher <id>\n");
	return 0;
}

int do_forget_publisher(const char *profile_id)
{
	struct profile_paths paths;
	uint32_t handle = 0;
	bool had_key = false;
	int ret;

	ret = paths_from_id(profile_id, &paths);
	if (ret < 0) {
		fprintf(stderr, "ERROR: '%s' is not a publisher identity.\n",
			profile_id ? profile_id : "");
		return 1;
	}

	if (profile_aik_handle_load(&paths, &handle) == 0) {
		ret = tpm_init(&g_agent.tpm_ctx);
		if (ret < 0) {
			fprintf(stderr,
				"Failed to initialize TPM: %s\n"
				"The key stays where it is; nothing was "
				"deleted.\n",
				tpm_strerror(ret));
			return 1;
		}
		ret = tpm_evict_profile_aik(&g_agent.tpm_ctx, handle);
		tpm_cleanup(&g_agent.tpm_ctx);
		if (ret == 0) {
			had_key = true;
		} else if (ret != -ENOENT) {
			fprintf(stderr,
				"Failed to destroy the attestation key at "
				"0x%08X: %s\n"
				"Nothing was deleted: an orphaned key is "
				"worse than a listed one.\n",
				handle, tpm_strerror(ret));
			return 1;
		}
	}

	ret = publishers_forget(&paths);
	if (ret < 0) {
		fprintf(stderr, "Failed to remove %s: %s\n", paths.dir,
			strerror(-ret));
		return 1;
	}

	printf("Publisher %s forgotten.\n", paths.id);
	if (had_key)
		printf("Its attestation key is destroyed; that identity "
		       "cannot be handed back.\n");
	printf("A title of theirs can ask again, and will need consent and a "
	       "new key.\n");
	return 0;
}

int enroll_profile_now(struct tpm_context *tpm,
		       const struct profile_paths *paths, const char *ca_server,
		       int ca_port, const char *ca_cert)
{
	int ret;

	if (!tpm || !paths || !ca_server || !ca_cert)
		return -EINVAL;

	ret = profile_dir_ensure(paths);
	if (ret < 0)
		return ret;

	/*
	 * No enrollment token:
	 * publisher admitting players cannot hand each of them a secret in advance,
	 * so the CA admits on the EK's chain to a pinned root instead.
	 * Operator fleet that does use tokens enrolls with --enroll before
	 * the loop ever reaches this path.
	 */
	ret = enroll_to_ca(tpm, ca_server, ca_port, ca_cert, 0, NULL, NULL,
			   paths->aik_cert);
	if (ret < 0)
		return ret;

	persist_enroll_state(paths, ca_server, ca_port, ca_cert, 0, NULL, NULL);
	return 0;
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
