/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * lota-bench - the machine a session runs on
 *
 * Only what makes two results comparable is read: the CPU and GPU models,
 * memory size, kernel release, distribution, TPM driver and SELinux mode,
 * and per run the CPU governor, platform profile and power supply. No
 * hostname, serial number, user name or path is ever read; every name is
 * a struct bench_field. Each reader takes a descriptor of the root, so the
 * tests can hand it a tree of their own.
 */

#ifndef LOTA_BENCH_MACHINE_H
#define LOTA_BENCH_MACHINE_H

#include <stdint.h>

#include "field.h"

#define BENCH_MAX_GPUS 4

/* where the GPU names are looked up, under the root */
#define BENCH_PCI_IDS "usr/share/hwdata/pci.ids"

enum bench_selinux {
	BSE_DISABLED = 0,
	BSE_PERMISSIVE,
	BSE_ENFORCING,
	BSE_COUNT,
};

extern const char *const bench_selinux_names[BSE_COUNT];

struct bench_gpu {
	uint32_t vendor_id;
	uint32_t device_id;
	struct bench_field name; /* from pci.ids */
	struct bench_field driver; /* the kernel driver bound to it */
};

struct bench_machine {
	struct bench_field cpu_model;
	uint32_t cpu_threads;
	uint64_t memory_bytes;
	unsigned int ngpus;
	struct bench_gpu gpu[BENCH_MAX_GPUS];
	struct bench_field kernel; /* release */
	struct bench_field distro; /* os-release ID and VERSION_ID */
	struct bench_field tpm; /* driver of tpm0, or "none" */
	enum bench_selinux selinux;
};

void bench_machine_read(int root, struct bench_machine *m);

/*
 * The name of the first thing that differs between @a and @b, or NULL.
 * Memory size is left out: the kernel reserves a little more or less of
 * it from one boot to the next.
 */
const char *bench_machine_diff(const struct bench_machine *a,
			       const struct bench_machine *b);

enum bench_supply {
	BSU_UNKNOWN = 0,
	BSU_AC,
	BSU_BATTERY,
	BSU_COUNT,
};

extern const char *const bench_supply_names[BSU_COUNT];

struct bench_power {
	struct bench_field governor; /* of cpu0 */
	struct bench_field profile; /* ACPI platform profile */
	enum bench_supply supply;
};

void bench_power_read(int root, struct bench_power *p);

#endif /* LOTA_BENCH_MACHINE_H */
