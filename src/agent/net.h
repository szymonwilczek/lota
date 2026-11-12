/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
#ifndef LOTA_NET_H
#define LOTA_NET_H

#include <limits.h>
#include <stddef.h>
#include <stdint.h>

#include "pin.h"

typedef struct ssl_st SSL;
typedef struct ssl_ctx_st SSL_CTX;

/**
 * struct net_context - One TLS client connection.
 * @ssl_ctx: Context net_context_init() configured.
 * @ssl: The connection; NULL until net_connect().
 * @socket_fd: Its socket, or -1.
 * @connected: Nonzero after net_connect() succeeded.
 * @server_addr: Host to resolve, also the name checked on the certificate.
 * @server_port: Port.
 * @skip_verify: Certificate and hostname checks are off.
 * @pin_sha256: SHA-256 of the DER certificate the peer must present.
 * @has_pin: Nonzero when @pin_sha256 is set.
 * @anchor: The trust anchor file, empty for the system trust store.
 */
struct net_context {
	SSL_CTX *ssl_ctx;
	SSL *ssl;
	int socket_fd;
	int connected;
	char server_addr[256];
	int server_port;
	int skip_verify;
	uint8_t pin_sha256[LOTA_PIN_SHA256_LEN];
	int has_pin;
	char anchor[PATH_MAX];
};

/**
 * struct verifier_challenge - The verifier's challenge, 48 bytes on the wire.
 * @magic: LOTA_MAGIC.
 * @version: Protocol version.
 * @nonce: Nonce to quote over.
 * @pcr_mask: PCRs to quote.
 * @flags: LOTA_CHALLENGE_FLAG_* bits.
 */
struct verifier_challenge {
	uint32_t magic;
	uint32_t version;
	uint8_t nonce[32];
	uint32_t pcr_mask;
	uint32_t flags;
};

/**
 * struct verifier_result - The verifier's verdict, 24 bytes on the wire.
 * @magic: LOTA_MAGIC.
 * @version: Protocol version.
 * @result: VERIFY_* code.
 * @flags: Result flags.
 * @valid_until: When the verdict expires.
 */
struct verifier_result {
	uint32_t magic;
	uint32_t version;
	uint32_t result;
	uint32_t flags;
	uint64_t valid_until;
};

/*
 * Verdict codes, the same list as src/verifier/types/report.go;
 * verify_codes_test.go compares the two.
 * A code missing here reaches the host as "Unknown error".
 */
#define VERIFY_OK 0
#define VERIFY_NONCE_FAIL 1
#define VERIFY_SIG_FAIL 2
#define VERIFY_PCR_FAIL 3
#define VERIFY_IOMMU_FAIL 4
#define VERIFY_OLD_VERSION 5
#define VERIFY_INTEGRITY_MISMATCH 6
#define VERIFY_REVOKED 7
#define VERIFY_BANNED 8
#define VERIFY_INTERNAL_ERROR 9
#define VERIFY_IDENTITY_FAIL 10
#define VERIFY_POLICY_REQUIREMENT 11
#define VERIFY_CERTIFICATE_VALIDITY 12
#define VERIFY_CERTIFICATE_MISSING 13
#define VERIFY_SECUREBOOT_REQUIRED 14
#define VERIFY_LOCKDOWN_REQUIRED 15
#define VERIFY_MODULE_SIG_REQUIRED 16
#define VERIFY_ENFORCE_REQUIRED 17
#define VERIFY_IMA_APPRAISAL_REQUIRED 18
#define VERIFY_KERNEL_IMAGE_REQUIRED 19
#define VERIFY_CMDLINE_REQUIRED 20
#define VERIFY_REPORT_MALFORMED 21

/*
 * Transport errors no errno names, above the errno range and apart from the
 * TPM codes at 4097; net_strerror() renders them. A socket errno, when there
 * is one, is what gets returned.
 */
#define LOTA_ERR_NET_PEER_CLOSED 4353 /* TLS shutdown mid-exchange */
#define LOTA_ERR_NET_PEER_GONE 4354 /* EOF with no shutdown and no errno */
#define LOTA_ERR_NET_TLS 4355 /* TLS refused a record on a live connection */
#define LOTA_ERR_NET_TLS_HANDSHAKE 4356 /* handshake did not complete */
#define LOTA_ERR_NET_TLS_CERT 4357 /* peer certificate failed verification */
#define LOTA_ERR_NET_TLS_PIN 4358 /* peer certificate is not the pinned one */

/**
 * net_err_name() - Describe a LOTA_ERR_NET_* code.
 * @err: The code, of either sign.
 *
 * Return: the sentence, or NULL for any other code.
 */
const char *net_err_name(int err);

/**
 * net_err_is_tls() - Whether the failure came from TLS.
 * @err: The code, of either sign.
 *
 * Return: nonzero for the LOTA_ERR_NET_TLS* codes.
 */
int net_err_is_tls(int err);

/**
 * net_strerror() - net_err_name(), falling back to strerror().
 * @err: The code, of either sign.
 *
 * Return: the sentence.
 */
const char *net_strerror(int err);

/**
 * net_transport_error() - Map a TLS read or write that moved no bytes.
 * @ssl_err: SSL_get_error().
 * @sock_errno: errno after the call.
 *
 * Return: -ETIMEDOUT for a socket timeout, the negative @sock_errno,
 * a negative LOTA_ERR_NET_* code, or -EIO.
 */
int net_transport_error(int ssl_err, int sock_errno);

/**
 * net_connect_refusal_hint() - Name the SELinux rule that refused a connect.
 * @err: connect(2) errno.
 * @port: Port connected to.
 * @selinux_root: selinuxfs mount, or NULL for the system one.
 * @buf: Receives the sentence.
 * @cap: Size of @buf.
 *
 * Only EACCES while SELinux enforces. Two rules answer it: a port without
 * lota_port_t, and lota_network_attest off. The sentence names the one the
 * boolean points at, or both when the boolean cannot be read.
 *
 * Return: @buf, or NULL when there is no hint or it did not fit.
 */
const char *net_connect_refusal_hint(int err, int port,
				     const char *selinux_root, char *buf,
				     size_t cap);

/**
 * net_init() - Ignore SIGPIPE, so a write to a closed peer fails with EPIPE.
 *
 * A second call does nothing.
 *
 * Return: 0, or a negative errno.
 */
int net_init(void);

/**
 * net_cleanup() - Let net_init() run again.
 */
void net_cleanup(void);

/**
 * net_context_init() - Configure a TLS 1.3 client.
 * @ctx: Context to fill.
 * @server: Host name or address.
 * @port: Port.
 * @ca_cert_path: Anchor, a CA or the listener's own certificate; NULL for
 *                the system store.
 * @skip_verify: Nonzero turns off certificate and hostname checks.
 * @pin_sha256: SHA-256 of the DER certificate the peer must present, or
 *              NULL; checked also with @skip_verify.
 *
 * Return: 0, -EINVAL when @ca_cert_path does not load, -ENOENT when the
 * system store does not, or another negative errno.
 */
int net_context_init(struct net_context *ctx, const char *server, int port,
		     const char *ca_cert_path, int skip_verify,
		     const uint8_t *pin_sha256);

/**
 * net_context_cleanup() - Disconnect and free the TLS context.
 * @ctx: Context, or NULL.
 */
void net_context_cleanup(struct net_context *ctx);

/**
 * net_connect() - Connect, complete the handshake and check the peer.
 * @ctx: Context from net_context_init().
 *
 * Return: 0, also when already connected; -EHOSTUNREACH when the name does
 * not resolve; the connect(2) errno; -LOTA_ERR_NET_TLS_HANDSHAKE,
 * -LOTA_ERR_NET_TLS_CERT or -LOTA_ERR_NET_TLS_PIN; or another negative
 * errno.
 */
int net_connect(struct net_context *ctx);

/**
 * net_disconnect() - Shut down the TLS session and close the socket.
 * @ctx: Context, or NULL.
 */
void net_disconnect(struct net_context *ctx);

/**
 * net_write_all() - Write exactly @len bytes.
 * @ctx: Connected context.
 * @buf: Bytes.
 * @len: Length of @buf.
 *
 * Return: 0, or a negative errno or LOTA_ERR_NET_* code.
 */
int net_write_all(struct net_context *ctx, const void *buf, size_t len);

/**
 * net_read_full() - Read exactly @len bytes.
 * @ctx: Connected context.
 * @buf: Receives the bytes.
 * @len: Length of @buf.
 *
 * Return: 0, or a negative errno or LOTA_ERR_NET_* code.
 */
int net_read_full(struct net_context *ctx, void *buf, size_t len);

/**
 * net_recv_challenge() - Read the verifier's challenge.
 * @ctx: Connected context.
 * @challenge: Receives it in host byte order.
 *
 * Return: 0, -EPROTO when the magic is wrong, or a negative errno or
 * LOTA_ERR_NET_* code.
 */
int net_recv_challenge(struct net_context *ctx,
		       struct verifier_challenge *challenge);

/**
 * net_send_report() - Send an attestation report.
 * @ctx: Connected context.
 * @report: Packed struct lota_attestation_report.
 * @report_size: Size of @report.
 *
 * Return: 0, or a negative errno or LOTA_ERR_NET_* code.
 */
int net_send_report(struct net_context *ctx, const void *report,
		    size_t report_size);

/**
 * net_recv_result() - Read the verifier's verdict.
 * @ctx: Connected context.
 * @result: Receives it in host byte order.
 *
 * Return: 0, -EPROTO when the magic is wrong, or a negative errno or
 * LOTA_ERR_NET_* code.
 */
int net_recv_result(struct net_context *ctx, struct verifier_result *result);

/**
 * net_result_str() - The sentence for a verdict code.
 * @result: VERIFY_* code.
 *
 * Return: the sentence; "FAIL - Unknown error" for a code not listed.
 */
const char *net_result_str(uint32_t result);

/**
 * net_verdict_str() - The sentence for a verdict on a report.
 * @result: VERIFY_* code.
 * @report_flags: Flags of the report the verdict answers.
 *
 * VERIFY_ENFORCE_REQUIRED has two causes on the host; the
 * LOTA_REPORT_FLAG_BPF_ACTIVE bit tells them apart.
 *
 * Return: the sentence.
 */
const char *net_verdict_str(uint32_t result, uint32_t report_flags);

#endif /* LOTA_NET_H */
