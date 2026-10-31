/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * LOTA attestation-CA enrollment wire protocol.
 *
 * Mirrors src/attestca/wire: four length-prefixed, big-endian messages
 * carry one enrollment over TLS. The agent sends BeginRequest and
 * CompleteRequest and decodes ChallengeReply and ResultReply.
 * Each message has one layout, and every variable field is bounded.
 */

#ifndef LOTA_ENROLL_H
#define LOTA_ENROLL_H

/* "LCAE", matched against the big-endian preamble of every frame. */
#define LOTA_ENROLL_MAGIC 0x4C434145u

/*
 * Protocol version, carried by every frame. One layout per message: the
 * token and the intermediates are a length and a count that may be zero.
 * A layout change takes the next number; the agent sends its newest,
 * the CA answers in the request's, an unknown number is refused.
 */
#define LOTA_ENROLL_VERSION 1u

/* Field bounds, identical to the Go wire caps. */
/* see (src/attestca/wire/wire.go) */
#define LOTA_ENROLL_MAX_EK_CERT 2048u
#define LOTA_ENROLL_MAX_AIK_PUBLIC 1024u
#define LOTA_ENROLL_MAX_CRED_BLOB 1024u
#define LOTA_ENROLL_MAX_ENC_SECRET 512u
#define LOTA_ENROLL_MAX_SECRET 64u
#define LOTA_ENROLL_MAX_SESSION_ID 64u
#define LOTA_ENROLL_MAX_AIK_CERT 4096u
#define LOTA_ENROLL_MAX_DEVICE_ID 128u
#define LOTA_ENROLL_MAX_TOKEN 128u

/*
 * Manufacturer intermediates a device presents with its EK leaf.
 *
 * TPM whose EK certificate sits several levels below its manufacturer root
 * stores the intermediates the CA cannot obtain anywhere else in its own NV,
 * so the device is the only party that can supply them.
 * Both caps are frame budget: eight certificates and 8 KB of them still leave
 * the leaf, the AIK template and the token inside LOTA_ENROLL_MAX_FRAME.
 */
#define LOTA_ENROLL_MAX_EK_CHAIN_CERTS 8u
#define LOTA_ENROLL_MAX_EK_CHAIN_BYTES 8192u

/* Bound on a single decoded frame body. */
#define LOTA_ENROLL_MAX_FRAME (16u * 1024u)

/* Reply status codes. */
enum lota_enroll_status {
	LOTA_ENROLL_STATUS_OK = 0,
	LOTA_ENROLL_STATUS_BAD_REQUEST = 1,
	LOTA_ENROLL_STATUS_EK_REJECTED = 2,
	LOTA_ENROLL_STATUS_AIK_REJECTED = 3,
	LOTA_ENROLL_STATUS_ACTIVATION_FAIL = 4,
	LOTA_ENROLL_STATUS_UNKNOWN_SESSION = 5,
	LOTA_ENROLL_STATUS_INTERNAL_ERROR = 6,
	LOTA_ENROLL_STATUS_RATE_LIMITED = 7,
	LOTA_ENROLL_STATUS_TOKEN_REJECTED = 8,
	LOTA_ENROLL_STATUS_CRL_STALE = 9,
};

#endif /* LOTA_ENROLL_H */
