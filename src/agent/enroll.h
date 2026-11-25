/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * LOTA attestation-CA enrollment client.
 *
 * Sends the EK certificate and the AIK public area, activates the credential
 * the CA returns, and stores the issued AIK certificate.
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
#include "pin.h"
#include "profile.h"

struct tpm_context;

#define LOTA_ENROLL_STATE_MAGIC 0x4C455354 /* "LEST" */
#define LOTA_ENROLL_STATE_VERSION 1

/**
 * struct enroll_state - What the last successful enrollment of a profile used.
 * @magic: LOTA_ENROLL_STATE_MAGIC.
 * @version: LOTA_ENROLL_STATE_VERSION.
 * @aik_generation: AIK generation the certificate was issued for; the daemon
 *	reports re-enrollment required when the AIK's differs.
 * @ca_port: CA port.
 * @no_verify_tls: TLS verification was skipped.
 * @has_pin: @pin_sha256 is set.
 * @pin_sha256: The pin net_context_init() takes.
 * @ca_server: CA host.
 * @ca_cert: CA trust anchor path.
 * @_reserved: Zero.
 * @enroll_token: Enrollment token, presented again by --reenroll and renewal.
 *
 * Written in native byte order, mode 0600: the token is a secret.
 */
struct enroll_state {
	uint32_t magic;
	uint32_t version;
	uint64_t aik_generation;
	int32_t ca_port;
	int32_t no_verify_tls;
	int32_t has_pin;
	uint8_t pin_sha256[LOTA_PIN_SHA256_LEN];
	char ca_server[256];
	char ca_cert[PATH_MAX];
	uint8_t _reserved[64];
	char enroll_token[LOTA_ENROLL_MAX_TOKEN + 1];
} __attribute__((packed));

/**
 * enroll_state_save_path() - Write @st to @path through a fsynced temp file.
 * @path: Record path.
 * @st: Record; magic and version are set on the copy written.
 *
 * Return: 0 or a negative errno.
 */
int enroll_state_save_path(const char *path, const struct enroll_state *st);

/**
 * enroll_state_load_path() - Read the record at @path.
 * @path: Record path.
 * @out: Record, with its strings NUL-terminated.
 *
 * Return: 0, -ENOENT when there is no file, -EINVAL for a foreign magic
 * or a NULL argument, -ENOTSUP for another version, -EIO for a short record,
 * or the open() or read() errno.
 */
int enroll_state_load_path(const char *path, struct enroll_state *out);

/**
 * enroll_state_record_present() - Whether a record is on disk.
 * @load_rc: enroll_state_load_path() result.
 *
 * A record that does not load still holds an endpoint; enrolling over it
 * loses that.
 *
 * Return: 0 for -ENOENT, 1 otherwise.
 */
int enroll_state_record_present(int load_rc);

/**
 * enroll_state_peek() - Read the magic and version of a refused record.
 * @path: Record path.
 * @out_magic: First word.
 * @out_version: Second word.
 *
 * Return: 0, -EIO when both cannot be read, -EINVAL, or the open() errno.
 */
int enroll_state_peek(const char *path, uint32_t *out_magic,
		      uint32_t *out_version);

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

/**
 * struct enroll_cert_ref - One DER certificate inside a caller's buffer.
 * @der: First byte.
 * @len: Length.
 */
struct enroll_cert_ref {
	const uint8_t *der;
	size_t len;
};

/**
 * enroll_split_cert_chain() - Split certificates laid end to end.
 * @blob: The certificates, as tpm_get_ek_cert_chain() reads them.
 * @len: Length of @blob.
 * @out: One entry per certificate, pointing into @blob.
 * @out_max: Entries in @out.
 * @out_count: Entries filled.
 *
 * The walk stops without error at the first bytes that are not a
 * definite-length SEQUENCE within LOTA_ENROLL_MAX_EK_CERT, or past
 * LOTA_ENROLL_MAX_EK_CHAIN_BYTES, so padding after the last one ends the list;
 * it also stops when @out is full.
 *
 * Return: 0, or -EINVAL for a NULL argument.
 */
int enroll_split_cert_chain(const uint8_t *blob, size_t len,
			    struct enroll_cert_ref *out, size_t out_max,
			    size_t *out_count);

/**
 * enroll_encode_begin() - Encode the begin request.
 * @out: Body buffer; the frame length is added by the sender.
 * @out_max: Size of @out.
 * @ek_cert: EK certificate.
 * @ek_cert_len: Length of @ek_cert.
 * @aik_public: AIK TPMT_PUBLIC.
 * @aik_public_len: Length of @aik_public.
 * @token: Enrollment token, or NULL.
 * @token_len: Length of @token; 0 writes an empty field.
 * @ek_chain: Manufacturer intermediates, or NULL.
 * @ek_chain_len: Entries in @ek_chain; 0 writes a count of zero.
 *
 * Return: Body length, -EINVAL, -EMSGSIZE for a field over its limit,
 * or -ENOSPC when @out is too small.
 */
ssize_t enroll_encode_begin(uint8_t *out, size_t out_max,
			    const uint8_t *ek_cert, size_t ek_cert_len,
			    const uint8_t *aik_public, size_t aik_public_len,
			    const uint8_t *token, size_t token_len,
			    const struct enroll_cert_ref *ek_chain,
			    size_t ek_chain_len);

/**
 * enroll_token_from_file() - Read an enrollment token.
 * @path: Token file.
 * @out: The token, NUL-terminated.
 * @out_size: At least LOTA_ENROLL_MAX_TOKEN + 1.
 *
 * Trailing spaces, tabs, CR and LF are trimmed; what remains must be 1 to
 * LOTA_ENROLL_MAX_TOKEN printable ASCII characters other than space.
 *
 * Return: 0, -EMSGSIZE when longer, -EINVAL when empty, malformed or for a bad
 * argument, or the open() or read() errno.
 */
int enroll_token_from_file(const char *path, char *out, size_t out_size);

/**
 * enroll_encode_complete() - Encode the complete request.
 * @out: Body buffer.
 * @out_max: Size of @out.
 * @session_id: Session from the challenge.
 * @secret: Activated credential secret.
 * @secret_len: Length of @secret.
 *
 * Return: Body length, -EINVAL, -EMSGSIZE or -ENOSPC.
 */
ssize_t enroll_encode_complete(uint8_t *out, size_t out_max,
			       const char *session_id, const uint8_t *secret,
			       size_t secret_len);

/**
 * enroll_decode_challenge() - Decode the challenge reply.
 * @body: Frame body.
 * @len: Length of @body.
 * @out: Reply; zeroed first.
 *
 * Return: 0, -EPROTO for a foreign magic, -EPROTONOSUPPORT for another
 * version, -EMSGSIZE for a field over its limit, -EBADMSG for a short body
 * or trailing bytes, or -EINVAL.
 */
int enroll_decode_challenge(const uint8_t *body, size_t len,
			    struct enroll_challenge *out);

/**
 * enroll_decode_result() - Decode the result reply.
 * @body: Frame body.
 * @len: Length of @body.
 * @out: Reply; zeroed first.
 *
 * Return: As enroll_decode_challenge().
 */
int enroll_decode_result(const uint8_t *body, size_t len,
			 struct enroll_result *out);

/**
 * lota_enroll_status_text() - Explain a refusal the CA sent.
 * @status: Status of the challenge or the result reply.
 *
 * Return: What was refused and what to do, or NULL for
 * LOTA_ENROLL_STATUS_OK and for a status this build does not know.
 */
const char *lota_enroll_status_text(unsigned int status);

/**
 * enroll_to_ca() - Run one enrollment and store the issued AIK certificate.
 * @tpm: TPM holding the AIK to certify.
 * @server: CA host.
 * @port: CA port.
 * @ca_cert: CA trust anchor.
 * @skip_verify: Skip TLS verification.
 * @pin: Pin for net_context_init(), or NULL.
 * @token: Enrollment token, or NULL.
 * @out_cert_path: Where the certificate is written.
 *
 * Return: 0, -EACCES when the CA refuses, or another negative errno.
 */
int enroll_to_ca(struct tpm_context *tpm, const char *server, int port,
		 const char *ca_cert, int skip_verify, const uint8_t *pin,
		 const char *token, const char *out_cert_path);

/**
 * do_enroll() - Enroll: --enroll.
 * @server: CA host.
 * @port: CA port.
 * @ca_cert: CA trust anchor; required, it names the profile.
 * @skip_verify: Skip TLS verification.
 * @pin: Pin for net_context_init(), or NULL.
 * @token_file: --enroll-token-file, or NULL.
 *
 * Records consent, provisions the profile's AIK, enrolls, and records the
 * endpoint for --reenroll and renewal.
 *
 * Return: exit code 0 or 1.
 */
int do_enroll(const char *server, int port, const char *ca_cert,
	      int skip_verify, const uint8_t *pin, const char *token_file);

/**
 * enum enroll_endpoint_source - Where the endpoint --reenroll dials comes from.
 * @ENROLL_ENDPOINT_FROM_RECORD: nothing named on the command line.
 * @ENROLL_ENDPOINT_FROM_COMMAND_LINE: a host, a port or both named.
 */
enum enroll_endpoint_source {
	ENROLL_ENDPOINT_FROM_RECORD,
	ENROLL_ENDPOINT_FROM_COMMAND_LINE,
};

/**
 * enroll_endpoint_source() - Where the endpoint comes from.
 * @given_server: --ca-server, or NULL.
 * @given_port: --ca-port, or 0.
 *
 * Return: ENROLL_ENDPOINT_FROM_COMMAND_LINE when either is given.
 */
static inline enum enroll_endpoint_source
enroll_endpoint_source(const char *given_server, int given_port)
{
	return (given_server && given_server[0]) || given_port > 0 ?
		       ENROLL_ENDPOINT_FROM_COMMAND_LINE :
		       ENROLL_ENDPOINT_FROM_RECORD;
}

/**
 * enroll_endpoint_server() - CA host to dial.
 * @recorded_server: Host in the record.
 * @given_server: --ca-server, or NULL.
 *
 * Return: @given_server when set, else @recorded_server.
 */
static inline const char *enroll_endpoint_server(const char *recorded_server,
						 const char *given_server)
{
	return given_server && given_server[0] ? given_server : recorded_server;
}

/**
 * enroll_endpoint_port() - CA port to dial.
 * @recorded_port: Port in the record.
 * @given_port: --ca-port, or 0.
 *
 * Return: @given_port when positive, else @recorded_port.
 */
static inline int enroll_endpoint_port(int recorded_port, int given_port)
{
	return given_port > 0 ? given_port : recorded_port;
}

/**
 * do_reenroll() - Enroll again with the recorded endpoint: --reenroll.
 * @ca_cert: CA trust anchor; it selects the record.
 * @ca_server: Host overriding the record, or NULL.
 * @ca_port: Port overriding the record, or 0.
 *
 * TLS, pin and token come from the record. A record that does not load is
 * refused, not enrolled over.
 *
 * Return: exit code 0 or 1.
 */
int do_reenroll(const char *ca_cert, const char *ca_server, int ca_port);

/**
 * enroll_renew_cert() - Renew a profile's certificate from inside the daemon.
 * @tpm: Initialised TPM holding the profile's AIK.
 * @paths: Profile.
 * @configured_ca_cert: Anchor the configuration names, or NULL.
 *
 * Enrolls with the recorded endpoint and the anchor enroll_renew_anchor()
 * picks. The caller has initialised the net layer.
 *
 * Return: 0, -EINVAL for a NULL argument, an enroll_state_load_path() error
 * (-ENOENT: never enrolled), -ENOENT when no anchor is configured or
 * recorded, or an enroll_to_ca() error.
 */
int enroll_renew_cert(struct tpm_context *tpm,
		      const struct profile_paths *paths,
		      const char *configured_ca_cert);

/**
 * enroll_renew_anchor() - Pick the anchor a renewal presents.
 * @configured: Anchor the configuration names, or NULL.
 * @recorded: Anchor in the record, or NULL.
 * @out: One of the two.
 *
 * Both name the profile's publisher; @recorded may be a path the daemon's
 * private /tmp hides, so @configured wins.
 *
 * Return: 0, -ENOENT when both are empty, or -EINVAL for a NULL @out.
 */
int enroll_renew_anchor(const char *configured, const char *recorded,
			const char **out);

/**
 * do_allow_publisher() - Record consent to a publisher: --allow-publisher.
 * @profile_id: Hex SHA-256 of the publisher's anchor SubjectPublicKeyInfo.
 *
 * The daemon does not enroll a profile without it.
 *
 * Return: exit code 0, also when already recorded, or 1.
 */
int do_allow_publisher(const char *profile_id);

/**
 * do_add_publisher() - Append a [profile] section: --add-publisher.
 * @config_path: Configuration file, or NULL for LOTA_CONFIG_DEFAULT_PATH.
 * @name: Label, or NULL for one from the identity.
 * @ca_server: CA host.
 * @ca_port: CA port, or 0 for LOTA_DEFAULT_CA_PORT.
 * @ca_cert: CA trust anchor.
 * @verifier: Verifier host; NULL or empty writes a token-only publisher.
 * @verifier_port: Verifier port, or 0 for LOTA_DEFAULT_VERIFIER_PORT.
 * @interval: Attestation interval.
 * @session_gated: Attest only while a title holds a session.
 *
 * Records no consent.
 *
 * Return: exit code 0, also when the publisher is already configured, or 1.
 */
int do_add_publisher(const char *config_path, const char *name,
		     const char *ca_server, int ca_port, const char *ca_cert,
		     const char *verifier, int verifier_port, int interval,
		     bool session_gated);

/**
 * do_list_publishers() - List every profile on disk: --list-publishers.
 *
 * Return: exit code 0 or 1.
 */
int do_list_publishers(void);

/**
 * do_forget_publisher() - Remove a profile: --forget-publisher.
 * @profile_id: Hex identity, as do_allow_publisher() takes.
 *
 * Evicts the profile's AIK unless another object holds its handle, then
 * removes the profile directory. A configured profile enrolls again only with
 * new consent and a new key.
 *
 * Return: exit code 0 or 1; nothing is removed when the key cannot be checked
 * or evicted.
 */
int do_forget_publisher(const char *profile_id);

/**
 * enroll_profile_now() - First enrollment from inside the daemon.
 * @tpm: Initialised TPM with the profile bound.
 * @paths: Profile; its directory is created.
 * @ca_server: CA host.
 * @ca_port: CA port.
 * @ca_cert: CA trust anchor.
 *
 * Enrolls with TLS verified, no pin and no token, and records the endpoint.
 * The caller has initialised the net layer.
 *
 * Return: 0 or a negative errno.
 */
int enroll_profile_now(struct tpm_context *tpm,
		       const struct profile_paths *paths, const char *ca_server,
		       int ca_port, const char *ca_cert);

#endif /* LOTA_AGENT_ENROLL_H */
