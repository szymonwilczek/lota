/* SPDX-License-Identifier: MIT */
/*
 * LOTA anti-cheat layer: heartbeat packets wrap LOTA tokens with per-session
 * context, and a game server verifies them with lota_ac_verify_heartbeat().
 *
 * Two client modes:
 *   Direct - calls lota_gaming SDK over Unix socket (native games)
 *   File   - reads Wine hook status/token files (Wine/Proton games)
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#ifndef LOTA_ANTICHEAT_H
#define LOTA_ANTICHEAT_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define LOTA_AC_MAGIC 0x4C414348 /* "HCAL" on the wire, little-endian */
#define LOTA_AC_VERSION 1
#define LOTA_AC_HEADER_SIZE 110
#define LOTA_AC_MAX_TOKEN 1608
#define LOTA_AC_MAX_HEARTBEAT (LOTA_AC_HEADER_SIZE + LOTA_AC_MAX_TOKEN)
#define LOTA_AC_MAX_GAME_ID 64
#define LOTA_AC_SESSION_ID_SIZE 16
#define LOTA_AC_GAME_HASH_SIZE 32
#define LOTA_AC_RUNTIME_MEASURE_SIZE 32

/*
 * Each value names a frozen pair of hash domain strings, for the game-binding
 * hash and the heartbeat nonce. The verifier rejects any other value. New
 * strings take the next integer.
 *
 * V1: "lota-ac-game-binding:v1\\0" + "lota-ac-heartbeat:v1\\0"
 */
#define LOTA_AC_DOMAIN_VERSION_V1 1u
#define LOTA_AC_DOMAIN_VERSION_CURRENT LOTA_AC_DOMAIN_VERSION_V1

enum lota_ac_provider {
	LOTA_AC_PROVIDER_EAC = 1,
	LOTA_AC_PROVIDER_BATTLEYE = 2,
};

enum lota_ac_state {
	LOTA_AC_STATE_IDLE = 0, /* not initialised */
	LOTA_AC_STATE_RUNNING = 1, /* internal, replaced before init returns */
	LOTA_AC_STATE_TRUSTED = 2, /* attested, and every required flag set */
	LOTA_AC_STATE_UNTRUSTED = 3, /* not trusted */
	LOTA_AC_STATE_ERROR = 4, /* no verdict to report */
};

/*
 * Error codes, below LOTA_AC_ERR_BASE so none collides with the negative errno
 * the measure helpers return.
 *
 * The verification group says why a server refused a heartbeat. The rest say
 * why a producer-side call failed, and are read with lota_ac_last_error().
 */
#define LOTA_AC_ERR_BASE (-1000)

enum {
	LOTA_AC_ERR_OK = 0,

	/* the verification vocabulary */
	LOTA_AC_ERR_INVALID_ARG = LOTA_AC_ERR_BASE - 1,
	LOTA_AC_ERR_MALFORMED = LOTA_AC_ERR_BASE - 2,
	LOTA_AC_ERR_VERSION = LOTA_AC_ERR_BASE - 3,
	LOTA_AC_ERR_SIG_FAIL = LOTA_AC_ERR_BASE - 4,
	LOTA_AC_ERR_NONCE_FAIL = LOTA_AC_ERR_BASE - 5,
	LOTA_AC_ERR_EXPIRED = LOTA_AC_ERR_BASE - 6,
	LOTA_AC_ERR_CRYPTO = LOTA_AC_ERR_BASE - 7,
	/* agent answered: no attestation-key slot left; no retry helps */
	LOTA_AC_ERR_NO_KEY_SLOT = LOTA_AC_ERR_BASE - 25,
	/* TPM in dictionary-attack lockout until it lapses or is cleared */
	LOTA_AC_ERR_TPM_LOCKOUT = LOTA_AC_ERR_BASE - 26,
	/* not the runtime measurement expected */
	LOTA_AC_ERR_RUNTIME_IMAGE = LOTA_AC_ERR_BASE - 24,

	/* the caller's own configuration */

	/* struct_size unset or too small */
	LOTA_AC_ERR_CONFIG_SIZE = LOTA_AC_ERR_BASE - 8,
	/* game_id missing, empty or too long */
	LOTA_AC_ERR_GAME_ID = LOTA_AC_ERR_BASE - 9,
	/* provider is neither EAC nor BattlEye */
	LOTA_AC_ERR_PROVIDER = LOTA_AC_ERR_BASE - 10,

	/* this library */
	LOTA_AC_ERR_NO_MEMORY = LOTA_AC_ERR_BASE - 11,
	/* session id or game-id hash failed */
	LOTA_AC_ERR_INTERNAL = LOTA_AC_ERR_BASE - 12,

	/* the host: a player acts on these */

	/* no agent answering the socket */
	LOTA_AC_ERR_NO_AGENT = LOTA_AC_ERR_BASE - 13,
	/* nobody has agreed to this publisher */
	LOTA_AC_ERR_CONSENT_REQUIRED = LOTA_AC_ERR_BASE - 14,
	/* not enrolled with that publisher */
	LOTA_AC_ERR_UNKNOWN_PROFILE = LOTA_AC_ERR_BASE - 15,
	LOTA_AC_ERR_ACCESS_DENIED = LOTA_AC_ERR_BASE - 16,
	/* file mode: no hook output directory */
	LOTA_AC_ERR_TOKEN_DIR = LOTA_AC_ERR_BASE - 17,
	LOTA_AC_ERR_NOT_ATTESTED = LOTA_AC_ERR_BASE - 18, /* no verdict yet */
	/* beating faster than the agent issues tokens */
	LOTA_AC_ERR_RATE_LIMITED = LOTA_AC_ERR_BASE - 19,

	/* the beat itself */

	/* the agent would not report its state */
	LOTA_AC_ERR_STATUS = LOTA_AC_ERR_BASE - 20,
	/* the agent would not issue a token */
	LOTA_AC_ERR_TOKEN = LOTA_AC_ERR_BASE - 21,
	/* this process could not be measured */
	LOTA_AC_ERR_MEASURE = LOTA_AC_ERR_BASE - 22,
	/* the token would not serialise */
	LOTA_AC_ERR_SERIALIZE = LOTA_AC_ERR_BASE - 23,

	/* boot evidence */

	/* the agent would not hand it over */
	LOTA_AC_ERR_NO_EVIDENCE = LOTA_AC_ERR_BASE - 27,
	/* not the boot the heartbeat quotes */
	LOTA_AC_ERR_BAD_EVIDENCE = LOTA_AC_ERR_BASE - 28,
};

struct lota_ac_config {
	/* sizeof(struct lota_ac_config), 0 is refused; see lota_connect_opts */
	size_t struct_size;

	enum lota_ac_provider provider;
	const char *game_id; /* NUL-terminated, max LOTA_AC_MAX_GAME_ID */

	/*
	 * Flags a title requires beside LOTA_FLAG_ATTESTED, which TRUSTED
	 * always requires. A status word is non-zero as soon as the agent holds
	 * a TPM.
	 */
	uint32_t required_flags;

	/* 1: lota_gaming SDK (native games), 0: Wine hook files */
	int direct;

	/*
	 * File mode: directory with lota-status and lota-token.bin.
	 * NULL: $LOTA_HOOK_TOKEN_DIR, $XDG_RUNTIME_DIR/lota-hook,
	 * /tmp/lota-<uid>.
	 */
	const char *token_dir;

	/* Direct mode: NULL for /run/lota/lota.sock */
	const char *socket_path;

	/*
	 * Direct mode: the publisher this session attests for, hex
	 * SHA-256 of its attestation-CA SubjectPublicKeyInfo. See struct
	 * lota_connect_opts. NULL on a single-publisher host; one that answers
	 * for several refuses a session that names none.
	 */
	const char *publisher_profile;
};

/* Smallest struct_size accepted. */
#define LOTA_AC_CONFIG_SIZE_MIN                               \
	(offsetof(struct lota_ac_config, publisher_profile) + \
	 sizeof(const char *))

/*
 * heartbeat wire format (little-endian, packed):
 *
 *   offset  size   field
 *   0       4      magic           LOTA_AC_MAGIC
 *   4       1      version         LOTA_AC_VERSION
 *   5       1      provider        EAC=1, BE=2
 *   6       2      total_size      full packet size
 *   8       16     session_id      random per-session
 *   24      4      sequence        monotonic counter (nonce-bound)
 *   28      4      lota_flags      mirror of token flags (integrity-checked
 *                                  against embedded token during verify)
 *   32      8      timestamp       Unix epoch (seconds, nonce-bound)
 *   40      32     game_id_hash    SHA-256(<game-binding domain> ||
 *                                  game_id || SHA-256(executable-bytes))
 *   72      2      token_size      embedded LOTA token length
 *   74      4      domain_version  LOTA_AC_DOMAIN_VERSION_*; selects the
 *                                  game-binding/heartbeat domain pair and
 *                                  is itself bound into the heartbeat nonce
 *   78      32     runtime_measure producer-side re-measurement of the
 *                                  executable image. Computed inside the game
 *                                  process, so forgeable and not a trust
 *                                  signal; nonce-bound for tamper-evidence. The
 *                                  agent's own is in the token's
 *                                  runtime_protect_digest.
 *   110     var    lota_token[]    full LOTA token (wire format)
 */
struct lota_ac_heartbeat_wire {
	uint32_t magic;
	uint8_t version;
	uint8_t provider;
	uint16_t total_size;
	uint8_t session_id[LOTA_AC_SESSION_ID_SIZE];
	uint32_t sequence;
	uint32_t lota_flags;
	uint64_t timestamp;
	uint8_t game_id_hash[LOTA_AC_GAME_HASH_SIZE];
	uint16_t token_size;
	uint32_t domain_version;
	uint8_t runtime_measure[LOTA_AC_RUNTIME_MEASURE_SIZE];
} __attribute__((packed));

struct lota_ac_info {
	enum lota_ac_provider provider;
	enum lota_ac_state state;
	uint8_t session_id[LOTA_AC_SESSION_ID_SIZE];
	uint64_t session_start; /* epoch */
	uint64_t last_heartbeat; /* epoch */
	uint32_t heartbeat_seq; /* current counter */
	/*
	 * Last known LOTA_FLAG_*. LOTA_FLAG_UPDATE_PENDING says a package
	 * update replaced the agent binary, effective on the next boot; it
	 * is not a trust signal.
	 */
	uint32_t lota_flags;
	uint8_t game_id_hash[LOTA_AC_GAME_HASH_SIZE];
	int trusted; /* state == LOTA_AC_STATE_TRUSTED */
	/* the boot PCRs the quote signed, for lota_ac_verify_boot_evidence() */
	uint32_t pcr_mask;
	uint8_t pcr_digest[32];
};

struct lota_ac_session;

/**
 * lota_ac_init() - Create an anti-cheat session.
 *
 * Direct mode connects to the agent, file mode locates the Wine hook directory.
 *
 * A direct-mode session that found no agent never connects later: a host that
 * gets ready takes a new session.
 *
 * Return: The session, in LOTA_AC_STATE_ERROR if it got no verdict. NULL on
 * error. lota_ac_last_error() holds the reason.
 */
struct lota_ac_session *lota_ac_init(const struct lota_ac_config *cfg);

/**
 * lota_ac_last_error() - Why the last call on this thread failed.
 *
 * Set by every call that returns a value to check, LOTA_AC_ERR_OK on success:
 * errno for the measure helpers, LOTA_AC_ERR_* otherwise. The renderers,
 * lota_ac_get_state() and lota_ac_shutdown() leave it alone. Thread-local, as a
 * title and its launcher can share a process.
 */
int lota_ac_last_error(void);

/**
 * lota_ac_strerror() - The error code as a sentence.
 * @err: A LOTA_AC_ERR_* code or a negative errno.
 *
 * Return: Stable English with no trailing punctuation, never NULL.
 */
const char *lota_ac_strerror(int err);

/**
 * lota_ac_shutdown() - Destroy a session; NULL is accepted.
 */
void lota_ac_shutdown(struct lota_ac_session *session);

/**
 * lota_ac_get_state() - Current session state.
 *
 * Local telemetry: client memory can be hooked, so a server trusts only
 * lota_ac_verify_heartbeat().
 *
 * Return: The state, LOTA_AC_STATE_IDLE if @session is NULL.
 */
enum lota_ac_state lota_ac_get_state(const struct lota_ac_session *session);

/**
 * lota_ac_get_info() - Local session telemetry.
 *
 * Not authoritative, as with lota_ac_get_state().
 *
 * Return: 0 on success, -EINVAL if an argument is NULL.
 */
int lota_ac_get_info(const struct lota_ac_session *session,
		     struct lota_ac_info *info);

/**
 * lota_ac_tick() - Refresh session state from the agent or the hook files.
 *
 * Return: 0 on success, negative errno on failure.
 */
int lota_ac_tick(struct lota_ac_session *session);

/**
 * lota_ac_heartbeat() - Generate a heartbeat packet.
 * @written: The packet size, on success.
 *
 * Refreshes the state first. The token nonce binds sequence, timestamp, session
 * and game, which takes a live token, so file mode has no heartbeat.
 *
 * Return: 0 on success, -EINVAL for bad arguments, -ENOTCONN without an agent,
 * -ENODATA if no token is available, -ENOSPC if @buf is too small, -EOPNOTSUPP
 * in file mode, another negative errno on failure.
 */
int lota_ac_heartbeat(struct lota_ac_session *session, uint8_t *buf,
		      size_t buflen, size_t *written);

/**
 * lota_ac_boot_evidence() - Fetch the boot evidence for this session's tokens.
 *
 * Layout in lota_token.h, from the agent in direct mode or the hook's
 * lota-boot-evidence.bin in file mode. Send it with a heartbeat. A buffer of
 * LOTA_BOOT_EVIDENCE_MAX_SIZE holds any.
 *
 * Return: 0 on success, -EINVAL for bad arguments, -ENOTCONN without an agent,
 * -ENODATA if there is none to give, -ENOSPC if @buf is too small, -EIO when
 * the agent refused.
 */
int lota_ac_boot_evidence(struct lota_ac_session *session, uint8_t *buf,
			  size_t buflen, size_t *written);

/**
 * lota_ac_compute_game_binding_hash() - Expected game hash for a server.
 *
 *   SHA-256("lota-ac-game-binding:v1\\0" || game_id ||
 *           SHA-256(executable-bytes))
 *
 * Return: 0 on success, negative errno on failure.
 */
int lota_ac_compute_game_binding_hash(const char *game_id, const char *exe_path,
				      uint8_t out[LOTA_AC_GAME_HASH_SIZE]);

/*
 * Runtime re-measurement of the live loaded image.
 *
 * The game-binding hash pins the on-disk main executable at session start, so
 * it sees neither code patched in memory nor shared libraries. This hashes the
 * executable PT_LOAD segments of every file-backed loaded object as mapped.
 * The vDSO has no backing file, so a verifier could not reproduce it, and is
 * excluded.
 *
 * Per-object digest (content only, position-independent):
 *   SHA-256("lota-ac-runtime-object:v1\\0" || seg_count_LE32 ||
 *           for each executable (PF_X) PT_LOAD segment, ascending
 *           p_vaddr:
 *               p_vaddr_LE64 || p_offset_LE64 || p_filesz_LE64 ||
 *               segment_bytes[p_filesz])
 *
 * Combined image digest, over all objects sorted ascending by soname
 * (the object's file basename), so neither load order nor library search
 * path affects the result:
 *   SHA-256("lota-ac-runtime-measure:v1\\0" || object_count_LE32 ||
 *           for each object:
 *               soname_len_LE32 || soname_bytes || object_digest[32])
 *
 * An x86-64 object without DT_TEXTREL takes no load-time relocations in its
 * executable segments, so each live mapping is byte-identical to its on-disk
 * segment content.
 *
 * The producer measures its own image; the verifier reproduces the digest from
 * the same ELF files, the trusted runtime manifest.
 */

#define LOTA_AC_RUNTIME_PATH_MAX 4096

/**
 * lota_ac_compute_runtime_measure() - Measure the calling process's live image.
 *
 * Return: 0 on success, -EINVAL on a NULL argument, -ENOMEM on allocation
 * failure, -E2BIG with too many objects or segments in one, -EIO on a digest
 * failure, -ENOENT if no file-backed executable object is found, -ENOTSUP if
 * the process was started by running the dynamic loader on the executable.
 */
int lota_ac_compute_runtime_measure(uint8_t out[LOTA_AC_RUNTIME_MEASURE_SIZE]);

/*
 * Called once per file-backed loaded object with its on-disk path. Return 0 to
 * continue, non-zero to stop.
 */
typedef int (*lota_ac_runtime_object_fn)(const char *path, void *user);

/**
 * lota_ac_list_runtime_objects() - Enumerate what the runtime measure covers.
 *
 * Use it to capture the trusted runtime manifest.
 *
 * Return: 0 on success or when @fn stops early, -EINVAL on a NULL @fn, -ENOTSUP
 * if the process was started by running the dynamic loader on the executable,
 * negative errno if the main executable path cannot be resolved.
 */
int lota_ac_list_runtime_objects(lota_ac_runtime_object_fn fn, void *user);

/**
 * lota_ac_compute_expected_runtime_measure_set() - Measure of ELF files.
 *
 * Objects are keyed by file basename and sorted, so the order of @paths does
 * not matter. A file with no executable PT_LOAD segment contributes nothing.
 *
 * Return: 0 on success, -EINVAL on a NULL argument, -ENOENT if the set yields
 * no executable object, -E2BIG if too many objects or segments, negative errno
 * on an I/O or parse failure.
 */
int lota_ac_compute_expected_runtime_measure_set(
	const char *const *paths, size_t count,
	uint8_t out[LOTA_AC_RUNTIME_MEASURE_SIZE]);

/**
 * lota_ac_compute_expected_runtime_measure() - Runtime measure of a single ELF.
 *
 * Same as lota_ac_compute_expected_runtime_measure_set(&exe_path, 1, out).
 */
int lota_ac_compute_expected_runtime_measure(
	const char *exe_path, uint8_t out[LOTA_AC_RUNTIME_MEASURE_SIZE]);

/**
 * lota_ac_verify_heartbeat() - Verify a heartbeat packet.
 * @aik_pub_der: Mandatory; unverified claims are attacker-controlled.
 * @expected_game_id_hash: See lota_ac_compute_game_binding_hash().
 * @expected_runtime_measure: See lota_ac_compute_expected_runtime_measure().
 *                            Also bound into the nonce.
 * @info: Session and attestation details.
 *
 * @info is LOTA_AC_STATE_TRUSTED only if the signed status word carries
 * LOTA_FLAG_ATTESTED. A server wanting more reads info->lota_flags, the same
 * word.
 *
 * Return: 0 on success, a LOTA_AC_ERR_* code on failure.
 */
int lota_ac_verify_heartbeat(
	const uint8_t *data, size_t len, const uint8_t *aik_pub_der,
	size_t aik_pub_len,
	const uint8_t expected_game_id_hash[LOTA_AC_GAME_HASH_SIZE],
	const uint8_t expected_runtime_measure[LOTA_AC_RUNTIME_MEASURE_SIZE],
	struct lota_ac_info *info);

/**
 * lota_ac_verify_boot_evidence() - Read Secure Boot from boot evidence.
 * @info: From lota_ac_verify_heartbeat() on the heartbeat the evidence came
 *        with;
 *        the evidence counts only for the boot that quote signed.
 * @secure_boot: 1 if the firmware measured Secure Boot on before the boot
 *               loader, else 0.
 *
 * Return: 0 on success, LOTA_AC_ERR_BAD_EVIDENCE for evidence malformed or of
 * another boot, another LOTA_AC_ERR_* code on failure.
 */
int lota_ac_verify_boot_evidence(const struct lota_ac_info *info,
				 const uint8_t *evidence, size_t len,
				 int *secure_boot);

const char *lota_ac_state_str(enum lota_ac_state state);
const char *lota_ac_provider_str(enum lota_ac_provider provider);

#ifdef __cplusplus
}
#endif

#endif /* LOTA_ANTICHEAT_H */
