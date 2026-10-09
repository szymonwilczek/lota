/* SPDX-License-Identifier: MIT */
/*
 * The integrity map as an enforcement object built before the agent stopped
 * reading kernel addresses still carries it: two 64-bit symbol addresses
 * where this agent reads two verdict flags.
 *
 * Nothing loads this object. It exists so a test can hand the agent the layout
 * a fleet's older signed object has, which is the pairing that made the kernel
 * copy sixteen bytes into the daemon's eight-byte frame.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct legacy_integrity_data {
	__u64 sig_enforce_addr;
	__u64 lockdown_addr;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct legacy_integrity_data);
} integrity_cfg SEC(".maps");
