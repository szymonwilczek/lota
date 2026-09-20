/* SPDX-License-Identifier: MIT */
/*
 * LOTA Wine/Proton Hook - Public API and Constants
 *
 * LD_PRELOAD shared library that transparently bridges LOTA
 * attestation into Wine/Proton processes. Connects to the local
 * LOTA agent via the Gaming SDK, then maintains a pair of well-known
 * files (text status + binary token) that Wine-side code can read
 * through the Z: drive mapping.
 *
 * Usage:
 *   LD_PRELOAD=liblota_wine_hook.so wine game.exe
 *
 *   # Steam launch options:
 *   lota-proton-hook %command%
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#ifndef LOTA_WINE_HOOK_H
#define LOTA_WINE_HOOK_H

#include "lota_snapshot.h"

#ifdef __cplusplus
extern "C" {
#endif

/* set to "1" or "true" to disable the hook entirely. */
#define LOTA_HOOK_ENV_DISABLE "LOTA_HOOK_DISABLE"

/*
 * Log level: debug | info | warn | error | silent
 * Default: warn
 */
#define LOTA_HOOK_ENV_LOG_LEVEL "LOTA_HOOK_LOG_LEVEL"

/* custom LOTA agent Unix socket path (default: /run/lota/lota.sock). */
#define LOTA_HOOK_ENV_SOCKET "LOTA_HOOK_SOCKET"

/*
 * Directory where the hook writes status / token files.
 * Default resolution order:
 *   1. $LOTA_HOOK_TOKEN_DIR       (explicit)
 *   2. $XDG_RUNTIME_DIR/lota-hook (standard)
 *   3. /tmp/lota-<uid>            (no runtime directory)
 *
 * A candidate the caller does not own is reported and skipped;
 * one at a mode other than 0700 is tightened and its old mode reported.
 * Never $XDG_RUNTIME_DIR/lota: the daemon owns it (root:lota 0750).
 */
#define LOTA_HOOK_ENV_TOKEN_DIR "LOTA_HOOK_TOKEN_DIR"

/* Directory name appended to $XDG_RUNTIME_DIR for the default above */
#define LOTA_HOOK_TOKEN_DIR_NAME "lota-hook"

/*
 * Publisher to attest for: hex SHA-256 (either case) of its CA anchor
 * SubjectPublicKeyInfo. Needed for a token on a multi-enrollment host;
 * an invalid value is reported and ignored.
 */
#define LOTA_HOOK_ENV_PUBLISHER "LOTA_HOOK_PUBLISHER"

/* token refresh interval in seconds (default: 60). */
#define LOTA_HOOK_ENV_REFRESH_SEC "LOTA_HOOK_REFRESH_SEC"

/*
 * Text status file (key=value, one per line).
 * Fields:
 *   LOTA_ATTESTED      1 | 0
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

/*
 * Binary token file.
 * Can be sent directly to a game server for verification.
 */
#define LOTA_HOOK_TOKEN_FILE "lota-token.bin"

/*
 * Atomic combined snapshot file (header + token wire bytes).
 * Readers should prefer this file in order to avoid TOCTOU races between
 * reading status and token separately.
 */
#define LOTA_HOOK_SNAPSHOT_FILE LOTA_SNAPSHOT_FILE_NAME

/*
 * Seconds from hook init to joining the protected set (default 20; 0 joins
 * on the first connect). Joining earlier refuses Proton its own ntdll.so.
 */
#define LOTA_HOOK_ENV_PROTECT_DELAY "LOTA_HOOK_PROTECT_DELAY"

/* defaults */
#define LOTA_HOOK_DEFAULT_REFRESH_SEC 60
#define LOTA_HOOK_DEFAULT_PROTECT_DELAY_SEC 20

#define LOTA_HOOK_CONNECT_TIMEOUT_MS 2000 /* local socket */

/* a status answer may wait on a measurement; on timeout, ask again */
#define LOTA_HOOK_REQUEST_TIMEOUT_MS (10 * LOTA_HOOK_CONNECT_TIMEOUT_MS)

/* the hook is built hidden so its SDK copy cannot shadow the game's */
#define LOTA_HOOK_EXPORT __attribute__((visibility("default")))

/*
 * lota_hook_active - Check whether the hook is running.
 *
 * Returns 1 if the background refresh thread is alive,
 * 0 otherwise (disabled, init failed, or not loaded).
 */
LOTA_HOOK_EXPORT int lota_hook_active(void);

/*
 * lota_hook_status_path - Return absolute path to the status file.
 *
 * Returns pointer to internal static buffer, or NULL if the hook
 * has not been initialised.
 */
LOTA_HOOK_EXPORT const char *lota_hook_status_path(void);

/*
 * lota_hook_token_path - Return absolute path to the token file.
 *
 * Returns pointer to internal static buffer, or NULL if the hook
 * has not been initialised.
 */
LOTA_HOOK_EXPORT const char *lota_hook_token_path(void);

#ifdef __cplusplus
}
#endif

#endif /* LOTA_WINE_HOOK_H */
