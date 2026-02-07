/* SPDX-License-Identifier: MIT */
/*
 * LOTA IPC Protocol
 *
 * Binary protocol for local attestation queries.
 */

#ifndef LOTA_IPC_H
#define LOTA_IPC_H

#include <stdint.h>

#define LOTA_IPC_SOCKET_PATH "/run/lota/lota.sock"

/* Protocol constants */
#define LOTA_IPC_MAGIC 0x4C4F5441 /* "LOTA" */
#define LOTA_IPC_VERSION 1
#define LOTA_IPC_MAX_PAYLOAD 4096

/*
 * IPC Commands
 */
enum lota_ipc_cmd {
  LOTA_IPC_CMD_PING = 0x01,       /* Whether agent is alive */
  LOTA_IPC_CMD_GET_STATUS = 0x02, /* Attestation status */
  LOTA_IPC_CMD_GET_TOKEN = 0x03,  /* Signed attestation token */
  LOTA_IPC_CMD_SUBSCRIBE = 0x04,  /* Subscribe to status changes */
};

/*
 * Response codes
 */
enum lota_ipc_result {
  LOTA_IPC_OK = 0x00,
  LOTA_IPC_ERR_UNKNOWN_CMD = 0x01,
  LOTA_IPC_ERR_BAD_REQUEST = 0x02,
  LOTA_IPC_ERR_NOT_ATTESTED = 0x03,
  LOTA_IPC_ERR_TPM_FAILURE = 0x04,
  LOTA_IPC_ERR_INTERNAL = 0x05,
  LOTA_IPC_ERR_RATE_LIMITED = 0x06,
  LOTA_IPC_ERR_ACCESS_DENIED = 0x07,
};

/*
 * Attestation status flags
 */
#define LOTA_STATUS_ATTESTED (1 << 0)    /* Successfully attested */
#define LOTA_STATUS_TPM_OK (1 << 1)      /* TPM initialized */
#define LOTA_STATUS_IOMMU_OK (1 << 2)    /* IOMMU verified */
#define LOTA_STATUS_BPF_LOADED (1 << 3)  /* BPF LSM active */
#define LOTA_STATUS_SECURE_BOOT (1 << 4) /* Secure Boot enabled */

/*
 * Request header
 *
 * All requests start with this header.
 * Payload follows immediately after.
 */
struct lota_ipc_request {
  uint32_t magic;   /* LOTA_IPC_MAGIC */
  uint32_t version; /* LOTA_IPC_VERSION */
  uint32_t cmd;     /* enum lota_ipc_cmd */
  uint32_t payload_len;
} __attribute__((packed));

#define LOTA_IPC_REQUEST_SIZE sizeof(struct lota_ipc_request)

/*
 * Response header
 *
 * All responses start with this header.
 * Payload follows immediately after.
 */
struct lota_ipc_response {
  uint32_t magic;   /* LOTA_IPC_MAGIC */
  uint32_t version; /* LOTA_IPC_VERSION */
  uint32_t result;  /* enum lota_ipc_result */
  uint32_t payload_len;
} __attribute__((packed));

#define LOTA_IPC_RESPONSE_SIZE sizeof(struct lota_ipc_response)

/*
 * PING response payload
 */
struct lota_ipc_ping_response {
  uint64_t uptime_sec; /* Agent uptime in seconds */
  uint32_t pid;        /* Agent PID */
} __attribute__((packed));

/*
 * GET_STATUS response payload
 */
struct lota_ipc_status {
  uint32_t flags;            /* LOTA_STATUS_* bitmask */
  uint64_t last_attest_time; /* Unix timestamp of last attestation */
  uint64_t valid_until;      /* Token valid until (Unix timestamp) */
  uint32_t attest_count;     /* Total successful attestations */
  uint32_t fail_count;       /* Total failed attestations */
  uint8_t mode;              /* Current mode (enum lota_mode) */
  uint8_t reserved[3];
} __attribute__((packed));

/*
 * GET_TOKEN request payload (optional)
 */
struct lota_ipc_token_request {
  uint8_t nonce[32]; /* Client-provided nonce (optional, zeros = none) */
} __attribute__((packed));

/*
 * GET_TOKEN response payload
 *
 * Contains a signed attestation statement using TPM Quote.
 * Verification:
 * - Compute expected_nonce = SHA256(issued_at || valid_until || flags ||
 *                                     client_nonce)
 * - Verify TPM signature over attest_data using AIK public key
 * - Parse attest_data, check extraData == expected_nonce
 * - Check PCR digest in attest_data matches expected policy
 */
struct lota_ipc_token {
  uint64_t issued_at;       /* Unix timestamp */
  uint64_t valid_until;     /* Unix timestamp */
  uint32_t flags;           /* LOTA_STATUS_* at issue time */
  uint8_t client_nonce[32]; /* Echo of client nonce */

  /* TPM Quote data */
  uint16_t attest_size; /* Size of TPMS_ATTEST blob */
  uint16_t sig_size;    /* Size of signature */
  uint16_t sig_alg;     /* TPM2_ALG_RSASSA or TPM2_ALG_RSAPSS */
  uint16_t hash_alg;    /* TPM2_ALG_SHA256 */
  uint32_t pcr_mask;    /* PCRs included in quote */

  /*
   * Variable-length data follows:
   *   - attest_data[attest_size]  (TPMS_ATTEST)
   *   - signature[sig_size]       (RSA signature)
   */
} __attribute__((packed));

#define LOTA_IPC_TOKEN_HEADER_SIZE sizeof(struct lota_ipc_token)
#define LOTA_IPC_TOKEN_MAX_ATTEST 1024
#define LOTA_IPC_TOKEN_MAX_SIG 512
#define LOTA_IPC_TOKEN_MAX_SIZE                                                \
  (LOTA_IPC_TOKEN_HEADER_SIZE + LOTA_IPC_TOKEN_MAX_ATTEST +                    \
   LOTA_IPC_TOKEN_MAX_SIG)

#endif /* LOTA_IPC_H */
