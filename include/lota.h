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
 * For user-space, use standard headers
 * BPF programs should include vmlinux.h before this header!!!
 */
#ifdef __BPF_PROGRAM__
typedef __u8 uint8_t;
typedef __u16 uint16_t;
typedef __u32 uint32_t;
typedef __u64 uint64_t;
#else
#include <stdbool.h>
#include <stdint.h>
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

/* PCR indices code care about */
#define LOTA_PCR_BIOS_CODE 0      /* SRTM, firmware code */
#define LOTA_PCR_BIOS_CONFIG 1    /* BIOS config (includes IOMMU settings) */
#define LOTA_PCR_OPTION_ROMS 2    /* Option ROMs */
#define LOTA_PCR_BOOTLOADER 4     /* Boot loader code */
#define LOTA_PCR_BOOTLOADER_CFG 5 /* Boot loader config */
#define LOTA_PCR_SECURE_BOOT 7    /* Secure Boot state */
#define LOTA_PCR_GRUB_CMD 8       /* GRUB commands */
#define LOTA_PCR_KERNEL_CMDLINE 9 /* Kernel command line */
#define LOTA_PCR_IMA 10           /* IMA measurements */

/* Number of PCRs to include in attestation */
#define LOTA_PCR_COUNT 24

/* Ring buffer constants */
#define LOTA_RINGBUF_SIZE (256 * 1024) /* 256 KB */
#define LOTA_MAX_PATH_LEN 256
#define LOTA_MAX_COMM_LEN 16

/* Event types for ring buffer */
enum lota_event_type {
  LOTA_EVENT_EXEC = 1,          /* Binary execution */
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
 *   SETUID:         pid, uid, comm, target_pid (new uid)
 *   *_BLOCKED:      same as base type
 */
struct lota_exec_event {
  uint64_t timestamp_ns; /* ktime_get_ns() */
  uint32_t event_type;   /* enum lota_event_type */
  uint32_t pid;
  uint32_t tgid;
  uint32_t uid;
  uint32_t gid;
  uint32_t target_pid;              /* ptrace target / setuid new_uid */
  uint32_t _pad0;                   /* alignment */
  uint8_t hash[LOTA_HASH_SIZE];     /* inode metadata fingerprint (BPF) */
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
