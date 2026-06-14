/* SPDX-License-Identifier: MIT */
/*
 * LOTA attestation-CA enrollment client.
 *
 * Drives the agent side of the credential-activation ceremony: send the
 * EK certificate and AIK template, activate the returned credential in
 * the TPM, and persist the issued AIK certificate.
 */

#ifndef LOTA_AGENT_ENROLL_H
#define LOTA_AGENT_ENROLL_H

#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "../../include/lota_enroll.h"
#include "net.h"

struct tpm_context;

/* On-disk location of the CA-issued AIK certificate (DER). */
#define LOTA_AIK_CERT_PATH "/var/lib/lota/aik_cert.der"

/* On-disk record of the endpoint a host last enrolled against. */
#define LOTA_ENROLL_STATE_PATH "/var/lib/lota/enroll_state.dat"
#define LOTA_ENROLL_STATE_MAGIC 0x4C455354 /* "LEST" */
#define LOTA_ENROLL_STATE_VERSION 1

/*
 * Enrollment state: the CA endpoint a successful enrollment used plus the
 * AIK generation the issued certificate is bound to. Same-host state, so it
 * is stored in native byte order behind a magic/version guard. It lets
 * --reenroll reuse the endpoint with no re-typed CA arguments, and lets the
 * daemon tell when a local AIK rotation has outdated the stored certificate.
 */
struct enroll_state {
	uint32_t magic;
	uint32_t version;
	uint64_t aik_generation; /* AIK generation the stored cert was issued for */
	int32_t ca_port;
	int32_t no_verify_tls;
	int32_t has_pin;
	uint8_t pin_sha256[NET_PIN_SHA256_LEN];
	char ca_server[256];
	char ca_cert[PATH_MAX];
	uint8_t _reserved[64];
} __attribute__((packed));

int enroll_state_save(const struct enroll_state *st);
int enroll_state_load(struct enroll_state *out); /* -ENOENT if never enrolled */

/* Path-parameterized variants behind the fixed-path wrappers above. */
int enroll_state_save_path(const char *path, const struct enroll_state *st);
int enroll_state_load_path(const char *path, struct enroll_state *out);

struct enroll_challenge {
	uint16_t status;
	char session_id[LOTA_ENROLL_MAX_SESSION_ID + 1];
	uint8_t cred_blob[LOTA_ENROLL_MAX_CRED_BLOB];
	size_t cred_blob_len;
	uint8_t enc_secret[LOTA_ENROLL_MAX_ENC_SECRET];
	size_t enc_secret_len;
};

struct enroll_result {
	uint16_t status;
	uint8_t aik_cert[LOTA_ENROLL_MAX_AIK_CERT];
	size_t aik_cert_len;
	char device_id[LOTA_ENROLL_MAX_DEVICE_ID + 1];
};

/*
 * Wire codec. Encoders return the body length written or negative errno;
 * decoders return 0 or negative errno. The encoded body excludes the
 * outer u32 frame length, which the transport adds.
 */
ssize_t enroll_encode_begin(uint8_t *out, size_t out_max,
			    const uint8_t *ek_cert, size_t ek_cert_len,
			    const uint8_t *aik_public, size_t aik_public_len);
ssize_t enroll_encode_complete(uint8_t *out, size_t out_max,
			       const char *session_id, const uint8_t *secret,
			       size_t secret_len);
int enroll_decode_challenge(const uint8_t *body, size_t len,
			    struct enroll_challenge *out);
int enroll_decode_result(const uint8_t *body, size_t len,
			 struct enroll_result *out);

/*
 * Run one enrollment against the CA at server:port and write the issued
 * AIK certificate to out_cert_path. The TPM context must already have a
 * provisioned AIK. Returns 0 on success, negative errno on failure.
 */
int enroll_to_ca(struct tpm_context *tpm, const char *server, int port,
		 const char *ca_cert, int skip_verify, const uint8_t *pin,
		 const char *out_cert_path);

/*
 * Top-level --enroll handler: bring up the TPM, provision the AIK, run
 * one enrollment against the CA, and store the issued certificate at
 * LOTA_AIK_CERT_PATH. Returns 0 on success, negative errno on failure.
 */
int do_enroll(const char *server, int port, const char *ca_cert,
	      int skip_verify, const uint8_t *pin);

/*
 * Guided re-enrollment: reuse the endpoint recorded by the last successful
 * --enroll, run a fresh credential activation, and refresh the certificate
 * and recorded state. Needs no CA arguments and no manual CA steps.
 * Returns 0 on success, 1 on failure.
 */
int do_reenroll(void);

/*
 * Daemon-side certificate renewal: reuse the recorded CA endpoint and run a
 * fresh credential activation against the CA using the already-provisioned
 * AIK in tpm, refreshing LOTA_AIK_CERT_PATH and the recorded generation.
 * Caller owns TPM and network initialization (unlike do_reenroll, this does
 * not bring up the TPM or the global net layer).
 * Returns 0 on success, or a negative errno on failure:
 * -ENOENT when no endpoint was recorded, so the caller can disable
 * auto-renewal.
 */
int enroll_renew_cert(struct tpm_context *tpm);

#endif /* LOTA_AGENT_ENROLL_H */
