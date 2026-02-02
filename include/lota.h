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
#define LOTA_HASH_SIZE 32         /* SHA-256 digest size */
#define LOTA_NONCE_SIZE 32        /* Challenge nonce size */
#define LOTA_MAX_SIG_SIZE 512     /* Max TPM signature size (RSA-4096) */
#define LOTA_MAX_AIK_PUB_SIZE 512 /* Max AIK public key (DER SPKI format) */

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
  LOTA_EVENT_EXEC = 1,       /* Binary execution */
  LOTA_EVENT_MODULE_LOAD,    /* Kernel module load */
  LOTA_EVENT_MMAP_EXEC,      /* Executable mmap */
  LOTA_EVENT_MODULE_BLOCKED, /* Module load blocked by policy */
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
#define LOTA_CFG_MODE 0 /* enum lota_mode */
#define LOTA_CFG_MAX_ENTRIES 8

/*
 * Execution event - sent from eBPF to user-space via ring buffer.
 * Packed to ensure consistent layout across architectures.
 */
struct lota_exec_event {
  uint64_t timestamp_ns; /* ktime_get_ns() */
  uint32_t event_type;   /* enum lota_event_type */
  uint32_t pid;
  uint32_t tgid;
  uint32_t uid;
  uint32_t gid;
  uint8_t hash[LOTA_HASH_SIZE];     /* SHA-256 of binary (partial) */
  char comm[LOTA_MAX_COMM_LEN];     /* Process name */
  char filename[LOTA_MAX_PATH_LEN]; /* Binary path */
} __attribute__((packed));

/*
 * Partial hash calculation:
 * Due to eBPF instruction limits, entire files cannot be cached.
 * What is hashedh: first 4KB + file size + inode number.
 * This provides a "fingerprint" that changes if binary is modified.
 */
#define LOTA_HASH_SAMPLE_SIZE 4096

#endif /* LOTA_H */
