/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * LOTA attestation-CA enrollment wire protocol.
 *
 * Mirrors src/attestca/wire: four length-prefixed, big-endian messages
 * carry one enrollment over TLS. The agent sends BeginRequest and
 * CompleteRequest and decodes ChallengeReply and ResultReply.
 * Every variable field is bounded.
 */

#ifndef LOTA_ENROLL_H
#define LOTA_ENROLL_H

/* "LCAE", matched against the big-endian preamble of every frame. */
#define LOTA_ENROLL_MAGIC 0x4C434145u
#define LOTA_ENROLL_VERSION 1u

/* Field bounds, identical to the Go wire caps. */
/* see (src/attestcta/wire/wire.go) */
#define LOTA_ENROLL_MAX_EK_CERT 2048u
#define LOTA_ENROLL_MAX_AIK_PUBLIC 1024u
#define LOTA_ENROLL_MAX_CRED_BLOB 1024u
#define LOTA_ENROLL_MAX_ENC_SECRET 512u
#define LOTA_ENROLL_MAX_SECRET 64u
#define LOTA_ENROLL_MAX_SESSION_ID 64u
#define LOTA_ENROLL_MAX_AIK_CERT 4096u
#define LOTA_ENROLL_MAX_DEVICE_ID 128u

/* Bound on a single decoded frame body. */
#define LOTA_ENROLL_MAX_FRAME (16u * 1024u)

/* Reply status codes. */
#define LOTA_ENROLL_STATUS_OK 0u
#define LOTA_ENROLL_STATUS_BAD_REQUEST 1u
#define LOTA_ENROLL_STATUS_EK_REJECTED 2u
#define LOTA_ENROLL_STATUS_AIK_REJECTED 3u
#define LOTA_ENROLL_STATUS_ACTIVATION_FAIL 4u
#define LOTA_ENROLL_STATUS_UNKNOWN_SESSION 5u
#define LOTA_ENROLL_STATUS_INTERNAL_ERROR 6u
#define LOTA_ENROLL_STATUS_RATE_LIMITED 7u

#endif /* LOTA_ENROLL_H */
