/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
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
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "../../include/lota_enroll.h"
#include "net.h"
#include "profile.h"

struct tpm_context;

/*
 * AIK certificate and the enrollment record live inside the publisher profile
 * the CA trust anchor names -- see profile.h
 * Host that enrolls with two publishers keeps two of each and one AIK per
 * publisher, so the two cannot correlate the machine between them.
 */
#define LOTA_ENROLL_STATE_MAGIC 0x4C455354 /* "LEST" */
#define LOTA_ENROLL_STATE_VERSION 2

/*
 * Enrollment state: the CA endpoint a successful enrollment used plus the
 * AIK generation the issued certificate is bound to. Same-host state, so it
 * is stored in native byte order behind a magic/version guard. It lets
 * --reenroll reuse the endpoint with no re-typed CA arguments, and lets the
 * daemon tell when a local AIK rotation has outdated the stored certificate.
 *
 * Version 2 appends the enrollment token so --reenroll and automatic certificate
 * renewal keep presenting it.
 * Loader requires the current record: short or older one is refused and the host re-enrolls.
 * Record is root-only 0600: the token is tenant-admission secret.
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
	char enroll_token[LOTA_ENROLL_MAX_TOKEN + 1];
} __attribute__((packed));

/* -ENOENT from the load when this profile has never enrolled */
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
 * One certificate inside a chain the platform hands over:
 * a view into the caller's buffer, so a chain costs no second allocation
 */
struct enroll_cert_ref {
	const uint8_t *der;
	size_t len;
};

/*
 * Split a concatenated DER certificate blob into its elements.
 *
 * TPM stores its manufacturer intermediates as one NV blob with the certificates
 * laid end to end and no framing of its own, so the elements are found by walking
 * the ASN.1 SEQUENCE headers.
 *
 * The blob is vendor data the host does not control, so the walk is lenient:
 * it ends at the first bytes that do not begin a certificate this wire can carry,
 * which is what turns trailing NV padding into the end of the list instead of
 * a failed read. A blob that yields nothing is not an error -- the enrollment
 * proceeds on the leaf alone.
 *
 * Returns 0 and the element count, or -EINVAL on a NULL argument.
 */
int enroll_split_cert_chain(const uint8_t *blob, size_t len,
			    struct enroll_cert_ref *out, size_t out_max,
			    size_t *out_count);

/*
 * Wire codec. Encoders return the body length written or negative errno;
 * decoders return 0 or negative errno. The encoded body excludes the
 * outer u32 frame length, which the transport adds.
 *
 * Token names the device's tenant at the CA (the gaming path);
 * NULL or empty means none.
 * Token-less begin is version-1 frame an old CA accepts;
 * Token upgrades the frame to version 2.
 *
 * ek_chain carries the manufacturer intermediates between the leaf and a root
 * the CA pins, for a platform that stores them on the chip; it upgrades the frame
 * to version 3 and is what lets a leaf several levels below its root be verified
 * at all.
 * NULL or empty leaves the frame at the version the token selects,
 * so a host with nothing to present speaks to a CA that predates the field.
 */
ssize_t enroll_encode_begin(uint8_t *out, size_t out_max,
			    const uint8_t *ek_cert, size_t ek_cert_len,
			    const uint8_t *aik_public, size_t aik_public_len,
			    const uint8_t *token, size_t token_len,
			    const struct enroll_cert_ref *ek_chain,
			    size_t ek_chain_len);

/*
 * Read an enrollment token from a file into out (NUL-terminated).
 * out_size must be at least LOTA_ENROLL_MAX_TOKEN + 1.
 * Trailing whitespace is trimmed; the rest must be 1..LOTA_ENROLL_MAX_TOKEN
 * printable, non-whitespace ASCII characters so the secret survives
 * trailing-newline write and a shell round-trip unchanged.
 * Returns 0 or negative errno (-EMSGSIZE oversized, -EINVAL empty or malformed).
 */
int enroll_token_from_file(const char *path, char *out, size_t out_size);
ssize_t enroll_encode_complete(uint8_t *out, size_t out_max,
			       const char *session_id, const uint8_t *secret,
			       size_t secret_len);
int enroll_decode_challenge(const uint8_t *body, size_t len,
			    struct enroll_challenge *out);
int enroll_decode_result(const uint8_t *body, size_t len,
			 struct enroll_result *out);

/*
 * Run one enrollment against the CA at server:port and write the issued
 * AIK certificate to out_cert_path.
 * token is the optional per-tenant enrollment token presented with the begin
 * request (NULL = none).
 * TPM context must already have a provisioned AIK.
 * Returns 0 on success, negative errno on failure.
 */
int enroll_to_ca(struct tpm_context *tpm, const char *server, int port,
		 const char *ca_cert, int skip_verify, const uint8_t *pin,
		 const char *token, const char *out_cert_path);

/*
 * Top-level --enroll handler: bring up the TPM, provision the AIK, run
 * one enrollment against the CA, and store the issued certificate in the profile
 * ca_cert names.
 * ca_cert is required -- it is the profile's identity, not only verification input.
 * token_file optionally names file holding the enrollment token to present
 * (--enroll-token-file).
 * Returns 0 on success, negative errno on failure.
 */
int do_enroll(const char *server, int port, const char *ca_cert,
	      int skip_verify, const uint8_t *pin, const char *token_file);

/*
 * Guided re-enrollment:
 * Reuse the endpoint recorded by the last successful -enroll against the same
 * CA trust anchor, run fresh credential activation, and refresh the certificate
 * and recorded state.
 *
 * Needs no other CA arguments and no manual CA steps.
 * Returns 0 on success, 1 on failure.
 */
int do_reenroll(const char *ca_cert);

/*
 * Daemon-side certificate renewal:
 * Reuse the endpoint recorded in the given profile and run fresh credential
 * activation against the CA using the already-provisioned AIK in tpm,
 * refreshing the profile's certificate and recorded generation.
 *
 * Caller owns TPM and network initialization (unlike do_reenroll, this does not
 * bring up the TPM or the global net layer).
 * Returns 0 on success, or negative errno on failure:
 * -ENOENT when the profile has no recorded endpoint, so the caller can disable
 * auto-renewal.
 */
int enroll_renew_cert(struct tpm_context *tpm,
		      const struct profile_paths *paths,
		      const char *configured_ca_cert);

/*
 * Which CA trust anchor a renewal presents.
 *
 * configured is the anchor this profile is configured with and recorded is
 * the one stored when it enrolled.  Both name the same publisher, since the
 * profile is derived from the anchor, so the choice is about which path is
 * still openable: the daemon's sandbox gives it its own /tmp and /var/tmp,
 * and an enrollment driven from a staging directory records a path that is
 * not there for it.
 *
 * Returns 0 and points *out at the anchor to use, or -ENOENT when neither is
 * set, or -EINVAL for a NULL out.
 *
 * *out points into one of the arguments and lives as long as it does.
 */
int enroll_renew_anchor(const char *configured, const char *recorded,
			const char **out);

/*
 * Record that somebody on this machine agreed to answer to a publisher,
 * named by the hex SHA-256 of its CA trust anchor's SubjectPublicKeyInfo.
 *
 * Nothing enrolls without this: AIK is stable handle a publisher can recognise
 * the machine by, so the decision to hand one out is the player's (or the operator's)
 * and is recorded before the key exists.
 * Whatever shows the player what publisher would learn calls this when they accept.
 *
 * Returns 0 on success, 1 on failure (one-shot CLI mode).
 */
int do_allow_publisher(const char *profile_id);

/*
 * Write a publisher's [profile] section into lota.conf.
 * Records no consent -- that stays a separate act by the person at the machine.
 *
 * @verifier NULL or empty writes the publisher who runs none, so the caller
 * has to pass what was named rather than a default standing in for it.
 */
int do_add_publisher(const char *config_path, const char *name,
		     const char *ca_server, int ca_port, const char *ca_cert,
		     const char *verifier, int verifier_port, int interval,
		     bool session_gated);

/*
 * Show every publisher this host stores anything for, and what it stores.
 * Returns 0 on success, 1 on failure (one-shot CLI mode).
 */
int do_list_publishers(void);

/*
 * Take publisher back: destroy the AIK they can recognise this machine by,
 * delete their enrollment, certificate and consent, and leave nothing that
 * could hand them the same identity again.
 *
 * A profile still configured in lota.conf will enroll again
 * -- with a *new* key -- the next time a title of theirs runs and somebody
 * agrees to it, which is the point: forgetting is about the identity,
 * not about refusing the publisher forever.
 *
 * Returns 0 on success, 1 on failure (one-shot CLI mode).
 */
int do_forget_publisher(const char *profile_id);

/*
 * First enrollment for a publisher, from inside a running agent.
 *
 * Same ceremony as --enroll, minus the process-level bring-up:
 * the caller already holds an initialised TPM with the profile bound
 * and initialised net layer, which is what makes this callable from attestation
 * loop when a title asks for a publisher this host has never enrolled with.
 *
 * Creates the profile directory, stores the issued certificate in it
 * and records the endpoint, so later renewal needs no arguments.
 *
 * Returns 0 on success, or a negative errno.
 */
int enroll_profile_now(struct tpm_context *tpm,
		       const struct profile_paths *paths, const char *ca_server,
		       int ca_port, const char *ca_cert);

#endif /* LOTA_AGENT_ENROLL_H */
