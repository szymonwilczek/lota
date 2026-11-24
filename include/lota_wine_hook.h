/* SPDX-License-Identifier: MIT */
/*
 * LOTA Wine/Proton hook.
 *
 * LD_PRELOAD library that connects to the agent through the gaming SDK and
 * keeps a set of files Wine-side code can read through the Z: drive mapping.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#ifndef LOTA_WINE_HOOK_H
#define LOTA_WINE_HOOK_H

#include "lota_snapshot.h"

#ifdef __cplusplus
extern "C" {
#endif

/* "1" or "true" disables the hook. */
#define LOTA_HOOK_ENV_DISABLE "LOTA_HOOK_DISABLE"

/*
 * Comma-separated exe prefixes to hook, replacing the skip lists.
 * lota-proton-hook sets it from the Steam launch unless already set.
 */
#define LOTA_HOOK_ENV_ACTIVATE_PATH "LOTA_HOOK_ACTIVATE_PATH"

/*
 * Title dir relative to a Wine drive; Wine's loader hooks only when its argv[1]
 * lies inside, whatever the pin says.
 * lota-proton-hook sets it from the Steam launch unless already set.
 */
#define LOTA_HOOK_ENV_ACTIVATE_PROGRAM "LOTA_HOOK_ACTIVATE_PROGRAM"

/* Comma-separated exe prefixes to skip, on top of the system paths. */
#define LOTA_HOOK_ENV_SKIP_PATH "LOTA_HOOK_SKIP_PATH"

/* debug | info | warn | error | silent, default warn */
#define LOTA_HOOK_ENV_LOG_LEVEL "LOTA_HOOK_LOG_LEVEL"

/* Agent socket path, default LOTA_IPC_SOCKET_PATH. */
#define LOTA_HOOK_ENV_SOCKET "LOTA_HOOK_SOCKET"

/*
 * Directory of the status and token files, first of:
 *   1. $LOTA_HOOK_TOKEN_DIR
 *   2. $XDG_RUNTIME_DIR/lota-hook
 *   3. /tmp/lota-<uid>
 *
 * A candidate the caller does not own is reported and skipped; one at a mode
 * other than 0700 is tightened and its old mode reported.
 * Never $XDG_RUNTIME_DIR/lota: the daemon owns it.
 */
#define LOTA_HOOK_ENV_TOKEN_DIR "LOTA_HOOK_TOKEN_DIR"

#define LOTA_HOOK_TOKEN_DIR_NAME "lota-hook"

/*
 * Publisher to attest for: hex SHA-256 (either case) of its CA anchor
 * SubjectPublicKeyInfo. Needed for a token on a multi-enrollment host;
 * an invalid value is reported and ignored.
 */
#define LOTA_HOOK_ENV_PUBLISHER "LOTA_HOOK_PUBLISHER"

/* Token refresh interval in seconds. */
#define LOTA_HOOK_ENV_REFRESH_SEC "LOTA_HOOK_REFRESH_SEC"

/*
 * Text status file (key=value, one per line).
 * Fields:
 *   LOTA_ATTESTED      1 | 0
 *   LOTA_OFFLINE       1 | 0
 *   LOTA_FLAGS         0xHEX  (LOTA_FLAG_* bitmask)
 *   LOTA_VALID_UNTIL   UNIX_TIMESTAMP
 *   LOTA_ATTEST_COUNT  unsigned
 *   LOTA_FAIL_COUNT    unsigned
 *   LOTA_UPDATED       UNIX_TIMESTAMP (when file was written)
 *   LOTA_PID           hook process PID
 *   LOTA_PROTECTED     1 | 0  (in the protected set)
 *
 * After a gate refused an object:
 *   LOTA_REFUSED_OBJECT  refused path
 *   LOTA_REFUSED_AT      UNIX_TIMESTAMP
 */
#define LOTA_HOOK_STATUS_FILE "lota-status"

#define LOTA_HOOK_TOKEN_FILE "lota-token.bin"

/*
 * Status flags and token in one atomic file, so a reader avoids the race
 * between reading the two files above.
 */
#define LOTA_HOOK_SNAPSHOT_FILE LOTA_SNAPSHOT_FILE_NAME

/*
 * Boot evidence for the token file, in the format lota_token.h describes.
 * Absent when the agent could not produce it.
 */
#define LOTA_HOOK_BOOT_EVIDENCE_FILE "lota-boot-evidence.bin"

#define LOTA_HOOK_DEFAULT_REFRESH_SEC 60

#define LOTA_HOOK_CONNECT_TIMEOUT_MS 2000

/* A status answer may wait on a measurement; on timeout, ask again. */
#define LOTA_HOOK_REQUEST_TIMEOUT_MS (10 * LOTA_HOOK_CONNECT_TIMEOUT_MS)

/* The hook is built hidden so its SDK copy cannot shadow the game's. */
#define LOTA_HOOK_EXPORT __attribute__((visibility("default")))

/**
 * lota_hook_active() - Check whether the hook is running.
 *
 * Return: 1 if the refresh thread is alive, 0 if disabled or init failed.
 */
LOTA_HOOK_EXPORT int lota_hook_active(void);

/**
 * lota_hook_status_path() - Return the absolute path of the status file.
 *
 * Return: a static buffer, or NULL before the hook has initialised.
 */
LOTA_HOOK_EXPORT const char *lota_hook_status_path(void);

/**
 * lota_hook_token_path() - Return the absolute path of the token file.
 *
 * Return: a static buffer, or NULL before the hook has initialised.
 */
LOTA_HOOK_EXPORT const char *lota_hook_token_path(void);

#ifdef __cplusplus
}
#endif

#endif /* LOTA_WINE_HOOK_H */
