/* SPDX-License-Identifier: MIT */
/*
 * LOTA Agent - Network/TLS client interface
 *
 * Handles communication with remote verifier over TLS.
 */

#ifndef LOTA_NET_H
#define LOTA_NET_H

#include <stddef.h>
#include <stdint.h>

struct tpm_quote_response;

/* SHA-256 digest size for certificate fingerprint pinning */
#define NET_PIN_SHA256_LEN 32

/*
 * Network context - holds TLS connection state
 */
struct net_context {
  void *ssl_ctx;
  void *ssl;
  int socket_fd;
  int connected;
  char server_addr[256];
  int server_port;
  int skip_verify;
  uint8_t pin_sha256[NET_PIN_SHA256_LEN];
  int has_pin; /* nonzero if pin_sha256 is set */
};

/*
 * Challenge received from verifier
 */
struct verifier_challenge {
  uint32_t magic;
  uint32_t version;
  uint8_t nonce[32];
  uint32_t pcr_mask;
  uint32_t flags;
};

/*
 * Result from verifier
 */
struct verifier_result {
  uint32_t magic;
  uint32_t version;
  uint32_t result;
  uint32_t flags;
  uint64_t valid_until;
  uint8_t session_token[32];
};

/* Result codes */
#define VERIFY_OK 0
#define VERIFY_NONCE_FAIL 1
#define VERIFY_SIG_FAIL 2
#define VERIFY_PCR_FAIL 3
#define VERIFY_IOMMU_FAIL 4
#define VERIFY_OLD_VERSION 5
#define VERIFY_INTEGRITY_MISMATCH 6

/*
 * Initialize network subsystem.
 * Must be called once at startup.
 *
 * Returns: 0 on success, negative errno on failure
 */
int net_init(void);

/*
 * Cleanup network subsystem.
 */
void net_cleanup(void);

/*
 * Initialize network context for connection.
 *
 * @ctx: Context to initialize
 * @server: Server hostname or IP
 * @port: Server port
 * @ca_cert_path: Path to CA certificate for verification (NULL for system CAs)
 * @skip_verify: If nonzero, disable TLS certificate verification (INSECURE)
 * @pin_sha256: SHA-256 fingerprint of expected server certificate (NULL to
 * skip)
 *
 * By default (ca_cert_path=NULL, skip_verify=0), the system CA certificate
 * store is used to verify the verifier's certificate. Provide ca_cert_path
 * to use a custom CA (for example: self-signed verifier cert).
 * Set skip_verify=1 only for development/testing - this disables all TLS
 * security.
 *
 * If pin_sha256 is non-NULL, the 32-byte SHA-256 fingerprint of the server's
 * DER-encoded certificate is compared after the TLS handshake. The connection
 * is aborted on mismatch. Pinning is enforced regardless of skip_verify to
 * catch MITM even in insecure test setups.
 *
 * Returns: 0 on success, negative errno on failure
 */
int net_context_init(struct net_context *ctx, const char *server, int port,
                     const char *ca_cert_path, int skip_verify,
                     const uint8_t *pin_sha256);

/*
 * Parse hex-encoded SHA-256 fingerprint into binary.
 *
 * @hex: 64-character hex string. colons (':') and spaces are silently skipped.
 * @out: Output buffer, must be at least NET_PIN_SHA256_LEN bytes
 *
 * Returns: 0 on success, -EINVAL on bad input
 */
int net_parse_pin_sha256(const char *hex, uint8_t *out);

/*
 * Cleanup network context.
 */
void net_context_cleanup(struct net_context *ctx);

/*
 * Connect to verifier server over TLS.
 *
 * @ctx: Initialized context
 *
 * Returns: 0 on success, negative errno on failure
 */
int net_connect(struct net_context *ctx);

/*
 * Disconnect from server.
 */
void net_disconnect(struct net_context *ctx);

/*
 * Receive challenge from verifier.
 * Call after connect, before sending report.
 *
 * @ctx: Connected context
 * @challenge: Output challenge structure
 *
 * Returns: 0 on success, negative errno on failure
 */
int net_recv_challenge(struct net_context *ctx,
                       struct verifier_challenge *challenge);

/*
 * Send attestation report to verifier.
 *
 * @ctx: Connected context
 * @report: Packed attestation report (lota_attestation_report)
 * @report_size: Size of report in bytes
 *
 * Returns: 0 on success, negative errno on failure
 */
int net_send_report(struct net_context *ctx, const void *report,
                    size_t report_size);

/*
 * Receive verification result.
 *
 * @ctx: Connected context
 * @result: Output result structure
 *
 * Returns: 0 on success, negative errno on failure
 */
int net_recv_result(struct net_context *ctx, struct verifier_result *result);

/*
 * Perform full attestation exchange.
 * Convenience function combining all steps.
 *
 * @ctx: Initialized (not connected) context
 * @build_report: Callback to build report with received nonce
 * @user_data: User data passed to callback
 * @result: Output verification result
 *
 * Returns: 0 on success, negative errno on failure
 */
typedef int (*build_report_fn)(const struct verifier_challenge *challenge,
                               void **report_out, size_t *report_size_out,
                               void *user_data);

int net_attest(struct net_context *ctx, build_report_fn build_report,
               void *user_data, struct verifier_result *result);

/*
 * Get human-readable result string.
 */
const char *net_result_str(uint32_t result);

#endif /* LOTA_NET_H */
