/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * LOTA - Linux Open Trusted Attestation
 * Common definitions shared between user-space and BPF
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#ifndef LOTA_H
#define LOTA_H

/*
 * For BPF programs, types come from vmlinux.h
 * For user-space, include linux/types.h
 * BPF programs should include vmlinux.h before this header!!!
 */
#ifndef __BPF_PROGRAM__
#include <linux/types.h>
#include <stdbool.h>
#endif

/* Protocol version */
#define LOTA_VERSION_MAJOR 1
#define LOTA_VERSION_MINOR 0
#define LOTA_VERSION ((LOTA_VERSION_MAJOR << 16) | LOTA_VERSION_MINOR)

/* Magic number: "LOTA" in little-endian */
#define LOTA_MAGIC 0x41544F4C

/* Cryptographic constants */
#define LOTA_HASH_SIZE 32           /* SHA-256 digest size */
#define LOTA_NONCE_SIZE 32          /* Challenge nonce size */
#define LOTA_MAX_SIG_SIZE 512       /* Max TPM signature size (RSA-4096) */
#define LOTA_MAX_AIK_PUB_SIZE 512   /* Max AIK public key (DER SPKI format) */
#define LOTA_MAX_AIK_CERT_SIZE 2048 /* Max AIK certificate size (DER X.509) */
#define LOTA_MAX_EK_CERT_SIZE 2048  /* Max EK certificate size (DER X.509) */
#define LOTA_HARDWARE_ID_SIZE 32    /* SHA-256 of EK public key */

/* Number of PCRs to include in attestation */
#define LOTA_PCR_COUNT 24

/* Ring buffer constants */
#define LOTA_RINGBUF_SIZE (256 * 1024) /* 256 KB */
#define LOTA_MAX_PATH_LEN 256
#define LOTA_MAX_COMM_LEN 16

/* Event types for ring buffer */
enum lota_event_type {
  LOTA_EVENT_EXEC = 1,          /* Binary execution */
  LOTA_EVENT_EXEC_BLOCKED,      /* Execution blocked by policy */
  LOTA_EVENT_MODULE_LOAD,       /* Kernel module load */
  LOTA_EVENT_MODULE_BLOCKED,    /* Module load blocked by policy */
  LOTA_EVENT_MMAP_EXEC,         /* Executable mmap (library load) */
  LOTA_EVENT_MMAP_BLOCKED,      /* Executable mmap blocked by policy */
  LOTA_EVENT_PTRACE,            /* ptrace access attempt */
  LOTA_EVENT_PTRACE_BLOCKED,    /* ptrace access blocked by policy */
  LOTA_EVENT_SETUID,            /* Privilege escalation (setuid) */
  LOTA_EVENT_ANON_EXEC,         /* Anonymous executable mmap (JIT, shellcode) */
  LOTA_EVENT_ANON_EXEC_BLOCKED, /* Anonymous executable mmap blocked */
};

/*
 * LOTA enforcement modes
 * Controls whether LSM hooks block or just monitor
 */
enum lota_mode {
  LOTA_MODE_MONITOR = 0,     /* Log only, allow everything */
  LOTA_MODE_ENFORCE = 1,     /* Block unauthorized operations */
  LOTA_MODE_MAINTENANCE = 2, /* Temporarily allow all (for updates) */
};

/* Config map keys */
#define LOTA_CFG_MODE 0            /* enum lota_mode */
#define LOTA_CFG_STRICT_MMAP 1     /* 1 = block mmap from untrusted paths */
#define LOTA_CFG_BLOCK_PTRACE 2    /* 1 = block ptrace on protected pids */
#define LOTA_CFG_BLOCK_ANON_EXEC 3 /* 1 = block anonymous mmap(PROT_EXEC) */
#define LOTA_CFG_STRICT_EXEC 4     /* 1 = block exec from untrusted paths */
#define LOTA_CFG_STRICT_MODULES 5  /* 1 = enforce verified modules/firmware */
#define LOTA_CFG_MAX_ENTRIES 8

/*
 * Execution event - sent from eBPF to user-space via ring buffer.
 * Packed to ensure consistent layout across architectures.
 *
 * Fields used per event type:
 *   EXEC:           pid, uid, comm, filename, hash
 *   MODULE_LOAD:    pid, comm, filename
 *   MMAP_EXEC:      pid, uid, comm, filename, target_pid (=0)
 *   PTRACE:         pid, uid, comm, target_pid
 *   SETUID:         pid, uid, comm, target_uid (new uid)
 *   *_BLOCKED:      same as base type
 */
struct lota_exec_event {
  __u64 timestamp_ns; /* ktime_get_ns() */
  __u32 event_type;   /* enum lota_event_type */
  __u32 pid;
  __u32 tgid;
  __u32 uid;
  __u32 gid;
  union {
    __u32 target_pid; /* ptrace: target process PID */
    __u32 target_uid; /* setuid: new UID after transition */
  };
  __u32 _pad0;                      /* alignment */
  __u8 hash[LOTA_HASH_SIZE];        /* inode metadata fingerprint (BPF) */
  char comm[LOTA_MAX_COMM_LEN];     /* Process name */
  char filename[LOTA_MAX_PATH_LEN]; /* Binary path / library path */
} __attribute__((packed));

/*
 * Trusted library path prefixes.
 * Libraries loaded via mmap(PROT_EXEC) from these paths are allowed
 * in ENFORCE mode. All other executable mmaps are blocked.
 * Paths are checked with string prefix matching in BPF.
 */
#define LOTA_TRUSTED_LIB_PREFIX_1 "/usr/lib/"
#define LOTA_TRUSTED_LIB_PREFIX_2 "/usr/lib64/"
#define LOTA_TRUSTED_LIB_PREFIX_3 "/lib/"
#define LOTA_TRUSTED_LIB_PREFIX_4 "/lib64/"

/*
 * Protected PID map maximum entries.
 * Processes can be added to this map to receive extra protection:
 *   - ptrace on these PIDs is blocked in ENFORCE mode
 *   - mmap(PROT_EXEC) by these PIDs is logged with higher priority
 */
#define LOTA_MAX_PROTECTED_PIDS 1024

/*
 * Trusted library whitelist maximum entries.
 * Specific library paths (for example game-specific .so files) that
 * are allowed in ENFORCE mode even if not in standard paths.
 */
#define LOTA_MAX_TRUSTED_LIBS 512

#endif /* LOTA_H */
