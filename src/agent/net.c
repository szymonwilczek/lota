/* SPDX-License-Identifier: MIT */
/*
 * LOTA Agent - Network/TLS client implementation
 *
 * Uses OpenSSL for TLS 1.3 communication with verifier.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#include "net.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include "../../include/attestation.h"

static int ssl_initialized = 0;

int net_init(void) {
  if (ssl_initialized)
    return 0;

  ssl_initialized = 1;
  return 0;
}

void net_cleanup(void) {
  if (!ssl_initialized)
    return;

  ssl_initialized = 0;
}

int net_context_init(struct net_context *ctx, const char *server, int port,
                     const char *ca_cert_path, int skip_verify,
                     const uint8_t *pin_sha256) {
  SSL_CTX *ssl_ctx;
  const SSL_METHOD *method;

  if (!ctx || !server)
    return -EINVAL;

  memset(ctx, 0, sizeof(*ctx));
  ctx->socket_fd = -1;
  ctx->skip_verify = skip_verify;

  if (pin_sha256) {
    memcpy(ctx->pin_sha256, pin_sha256, NET_PIN_SHA256_LEN);
    ctx->has_pin = 1;
  }

  strncpy(ctx->server_addr, server, sizeof(ctx->server_addr) - 1);
  ctx->server_port = port;

  method = TLS_client_method();
  ssl_ctx = SSL_CTX_new(method);
  if (!ssl_ctx) {
    return -ENOMEM;
  }

  SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_3_VERSION);

  if (skip_verify) {
    /*
     * INSECURE!!!: Skip all certificate verification.
     * This makes the connection vulnerable to MITM attacks.
     * I only use this for development/testing with self-signed certs
     * when the CA certificate is not available.
     */
    fprintf(stderr,
            "WARNING: TLS certificate verification DISABLED (--no-verify-tls)\n"
            "WARNING: Connection is vulnerable to MITM attacks!\n"
            "WARNING: Do NOT use in production.\n");
    SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_NONE, NULL);
  } else if (ca_cert_path) {
    /* custom CA certificate provided */
    if (SSL_CTX_load_verify_locations(ssl_ctx, ca_cert_path, NULL) != 1) {
      fprintf(stderr, "Failed to load CA certificate: %s\n", ca_cert_path);
      SSL_CTX_free(ssl_ctx);
      return -EINVAL;
    }
    SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, NULL);
  } else {
    /*
     * No custom CA - use system default certificate store.
     * This verifies the verifier's certificate against trusted system CAs.
     */
    if (SSL_CTX_set_default_verify_paths(ssl_ctx) != 1) {
      fprintf(stderr, "Failed to load system CA certificates.\n"
                      "Use --ca-cert to specify verifier's CA certificate,\n"
                      "or --no-verify-tls for testing (INSECURE).\n");
      SSL_CTX_free(ssl_ctx);
      return -ENOENT;
    }
    SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, NULL);
  }

  ctx->ssl_ctx = ssl_ctx;
  return 0;
}

void net_context_cleanup(struct net_context *ctx) {
  if (!ctx)
    return;

  net_disconnect(ctx);

  if (ctx->ssl_ctx) {
    SSL_CTX_free((SSL_CTX *)ctx->ssl_ctx);
    ctx->ssl_ctx = NULL;
  }
}

int net_connect(struct net_context *ctx) {
  struct addrinfo hints, *result, *rp;
  char port_str[16];
  SSL *ssl;
  int sock = -1;
  int ret;

  if (!ctx || !ctx->ssl_ctx)
    return -EINVAL;

  if (ctx->connected)
    return 0;

  /* resolve server address */
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;

  snprintf(port_str, sizeof(port_str), "%d", ctx->server_port);

  ret = getaddrinfo(ctx->server_addr, port_str, &hints, &result);
  if (ret != 0) {
    return -EHOSTUNREACH;
  }

  for (rp = result; rp != NULL; rp = rp->ai_next) {
    sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
    if (sock < 0)
      continue;

    if (connect(sock, rp->ai_addr, rp->ai_addrlen) == 0)
      break;

    close(sock);
    sock = -1;
  }

  freeaddrinfo(result);

  if (sock < 0) {
    return -ECONNREFUSED;
  }

  ctx->socket_fd = sock;

  ssl = SSL_new((SSL_CTX *)ctx->ssl_ctx);
  if (!ssl) {
    close(sock);
    ctx->socket_fd = -1;
    return -ENOMEM;
  }

  SSL_set_fd(ssl, sock);
  SSL_set_tlsext_host_name(ssl, ctx->server_addr);

  /*
   * Hostname verification: ensure the certificate CN or SAN matches
   * the server that is intended to connect to.
   */
  if (!ctx->skip_verify) {
    if (SSL_set1_host(ssl, ctx->server_addr) != 1) {
      fprintf(stderr, "Failed to set hostname verification for: %s\n",
              ctx->server_addr);
      SSL_free(ssl);
      close(sock);
      ctx->socket_fd = -1;
      return -EINVAL;
    }
  }

  /* TLS handshake */
  ret = SSL_connect(ssl);
  if (ret != 1) {
    int ssl_err = SSL_get_error(ssl, ret);
    unsigned long err_code = ERR_peek_last_error();

    if (ssl_err == SSL_ERROR_SSL) {
      fprintf(stderr, "TLS handshake failed: %s\n",
              ERR_reason_error_string(err_code));
    } else {
      fprintf(stderr, "TLS handshake failed (SSL_ERROR=%d)\n", ssl_err);
    }

    SSL_free(ssl);
    close(sock);
    ctx->socket_fd = -1;
    return -ECONNABORTED;
  }

  /*
   * Post-handshake certificate verification.
   */
  if (!ctx->skip_verify) {
    long verify_result = SSL_get_verify_result(ssl);
    if (verify_result != X509_V_OK) {
      fprintf(stderr,
              "TLS certificate verification failed: %s (code %ld)\n"
              "Use --ca-cert to specify the verifier's CA certificate,\n"
              "or --no-verify-tls for testing (INSECURE).\n",
              X509_verify_cert_error_string(verify_result), verify_result);
      SSL_shutdown(ssl);
      SSL_free(ssl);
      close(sock);
      ctx->socket_fd = -1;
      return -EACCES;
    }

    /* verify server presented a certificate */
    X509 *peer_cert = SSL_get1_peer_certificate(ssl);
    if (!peer_cert) {
      fprintf(stderr, "Verifier did not present a TLS certificate\n");
      SSL_shutdown(ssl);
      SSL_free(ssl);
      close(sock);
      ctx->socket_fd = -1;
      return -EACCES;
    }
    X509_free(peer_cert);
  }

  /*
   * Certificate pinning: compute SHA-256 fingerprint of the server's
   * DER-encoded certificate and compare against the expected pin.
   */
  if (ctx->has_pin) {
    X509 *peer_cert = SSL_get1_peer_certificate(ssl);
    if (!peer_cert) {
      fprintf(stderr,
              "Certificate pinning failed: server presented no certificate\n");
      SSL_shutdown(ssl);
      SSL_free(ssl);
      close(sock);
      ctx->socket_fd = -1;
      return -EACCES;
    }

    unsigned char digest[NET_PIN_SHA256_LEN];
    unsigned int digest_len = 0;

    if (X509_digest(peer_cert, EVP_sha256(), digest, &digest_len) != 1 ||
        digest_len != NET_PIN_SHA256_LEN) {
      fprintf(stderr, "Certificate pinning failed: unable to compute "
                      "SHA-256 fingerprint\n");
      X509_free(peer_cert);
      SSL_shutdown(ssl);
      SSL_free(ssl);
      close(sock);
      ctx->socket_fd = -1;
      return -EACCES;
    }
    X509_free(peer_cert);

    /*
     * Constant-time comparison to prevent timing side-channels.
     * CRYPTO_memcmp returns 0 on match.
     */
    if (CRYPTO_memcmp(digest, ctx->pin_sha256, NET_PIN_SHA256_LEN) != 0) {
      fprintf(stderr, "SECURITY: Certificate pinning FAILED!\n"
                      "  Expected: ");
      for (int i = 0; i < NET_PIN_SHA256_LEN; i++)
        fprintf(stderr, "%02x", ctx->pin_sha256[i]);
      fprintf(stderr, "\n  Got:      ");
      for (int i = 0; i < NET_PIN_SHA256_LEN; i++)
        fprintf(stderr, "%02x", digest[i]);
      fprintf(stderr, "\n"
                      "  The verifier's certificate does not match the "
                      "pinned fingerprint.\n"
                      "  This may indicate a MITM attack or certificate "
                      "rotation.\n");
      SSL_shutdown(ssl);
      SSL_free(ssl);
      close(sock);
      ctx->socket_fd = -1;
      return -EACCES;
    }
  }

  ctx->ssl = ssl;
  ctx->connected = 1;

  return 0;
}

void net_disconnect(struct net_context *ctx) {
  if (!ctx)
    return;

  if (ctx->ssl) {
    SSL_shutdown((SSL *)ctx->ssl);
    SSL_free((SSL *)ctx->ssl);
    ctx->ssl = NULL;
  }

  if (ctx->socket_fd >= 0) {
    close(ctx->socket_fd);
    ctx->socket_fd = -1;
  }

  ctx->connected = 0;
}

int net_recv_challenge(struct net_context *ctx,
                       struct verifier_challenge *challenge) {
  uint8_t buf[48];
  int ret;
  int total = 0;

  if (!ctx || !ctx->connected || !challenge)
    return -EINVAL;

  while (total < (int)sizeof(buf)) {
    ret = SSL_read((SSL *)ctx->ssl, buf + total, sizeof(buf) - total);
    if (ret <= 0) {
      return -EIO;
    }
    total += ret;
  }

  /* challenge parsing (little-endian) */
  memcpy(&challenge->magic, buf + 0, 4);
  memcpy(&challenge->version, buf + 4, 4);
  memcpy(challenge->nonce, buf + 8, 32);
  memcpy(&challenge->pcr_mask, buf + 40, 4);
  memcpy(&challenge->flags, buf + 44, 4);

  if (challenge->magic != LOTA_MAGIC) {
    return -EPROTO;
  }

  return 0;
}

int net_send_report(struct net_context *ctx, const void *report,
                    size_t report_size) {
  int ret;
  size_t total = 0;

  if (!ctx || !ctx->connected || !report || report_size == 0)
    return -EINVAL;

  while (total < report_size) {
    ret = SSL_write((SSL *)ctx->ssl, (const uint8_t *)report + total,
                    report_size - total);
    if (ret <= 0) {
      return -EIO;
    }
    total += ret;
  }

  return 0;
}

int net_recv_result(struct net_context *ctx, struct verifier_result *result) {
  uint8_t buf[56];
  int ret;
  int total = 0;

  if (!ctx || !ctx->connected || !result)
    return -EINVAL;

  while (total < (int)sizeof(buf)) {
    ret = SSL_read((SSL *)ctx->ssl, buf + total, sizeof(buf) - total);
    if (ret <= 0) {
      return -EIO;
    }
    total += ret;
  }

  /* result parsing (little-endian) */
  memcpy(&result->magic, buf + 0, 4);
  memcpy(&result->version, buf + 4, 4);
  memcpy(&result->result, buf + 8, 4);
  memcpy(&result->flags, buf + 12, 4);
  memcpy(&result->valid_until, buf + 16, 8);
  memcpy(result->session_token, buf + 24, 32);

  if (result->magic != LOTA_MAGIC) {
    return -EPROTO;
  }

  return 0;
}

int net_attest(struct net_context *ctx, build_report_fn build_report,
               void *user_data, struct verifier_result *result) {
  struct verifier_challenge challenge;
  void *report = NULL;
  size_t report_size = 0;
  int ret;

  if (!ctx || !build_report || !result)
    return -EINVAL;

  ret = net_connect(ctx);
  if (ret < 0)
    return ret;

  ret = net_recv_challenge(ctx, &challenge);
  if (ret < 0)
    goto out;

  ret = build_report(&challenge, &report, &report_size, user_data);
  if (ret < 0)
    goto out;

  ret = net_send_report(ctx, report, report_size);
  if (ret < 0)
    goto out;

  ret = net_recv_result(ctx, result);

out:
  if (report)
    free(report);
  net_disconnect(ctx);
  return ret;
}

int net_parse_pin_sha256(const char *hex, uint8_t *out) {
  size_t i = 0;
  size_t out_idx = 0;
  uint8_t byte;
  int high;

  if (!hex || !out)
    return -EINVAL;

  while (hex[i] != '\0' && out_idx < NET_PIN_SHA256_LEN) {
    /* skip colons and spaces */
    if (hex[i] == ':' || hex[i] == ' ') {
      i++;
      continue;
    }

    /* need two hex nibbles */
    if (hex[i + 1] == '\0')
      return -EINVAL;

    high = 0;
    byte = 0;

    for (int n = 0; n < 2; n++) {
      char c = hex[i + n];
      uint8_t nibble;

      if (c >= '0' && c <= '9')
        nibble = (uint8_t)(c - '0');
      else if (c >= 'a' && c <= 'f')
        nibble = (uint8_t)(c - 'a' + 10);
      else if (c >= 'A' && c <= 'F')
        nibble = (uint8_t)(c - 'A' + 10);
      else
        return -EINVAL;

      if (n == 0)
        high = nibble;
      else
        byte = (uint8_t)((high << 4) | nibble);
    }

    out[out_idx++] = byte;
    i += 2;
  }

  while (hex[i] == ':' || hex[i] == ' ')
    i++;

  if (out_idx != NET_PIN_SHA256_LEN || hex[i] != '\0')
    return -EINVAL;

  return 0;
}

const char *net_result_str(uint32_t result) {
  switch (result) {
  case VERIFY_OK:
    return "OK - Attestation successful";
  case VERIFY_NONCE_FAIL:
    return "FAIL - Nonce/freshness verification failed";
  case VERIFY_SIG_FAIL:
    return "FAIL - TPM signature verification failed";
  case VERIFY_PCR_FAIL:
    return "FAIL - PCR values don't match policy";
  case VERIFY_IOMMU_FAIL:
    return "FAIL - IOMMU requirement not met";
  case VERIFY_OLD_VERSION:
    return "FAIL - Protocol version mismatch";
  case VERIFY_INTEGRITY_MISMATCH:
    return "FAIL - Integrity mismatch (agent binary changed!)";
  default:
    return "FAIL - Unknown error";
  }
}
