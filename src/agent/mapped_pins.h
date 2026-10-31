/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * Write guard pins, each stamped with the last measurement round that reached
 * its inode. A library outlives the first process that maps it, so no process
 * owns a pin: one an older round stamped is released, and the set converges
 * on what the last round measured. Plain arrays, testable in user space.
 */

#ifndef LOTA_MAPPED_PINS_H
#define LOTA_MAPPED_PINS_H

#include <stddef.h>
#include <stdint.h>

struct mapped_exec_pin {
	uint64_t dev; /* the kernel's s_dev, not stat(2)'s st_dev */
	uint64_t ino;
	uint64_t round; /* last round that reached it */
};

/* Index of the pin, or count when the inode is not pinned */
static inline size_t mapped_pins_find(const struct mapped_exec_pin *pins,
				      size_t count, uint64_t dev, uint64_t ino)
{
	size_t i;

	if (!pins)
		return count;

	for (i = 0; i < count; i++) {
		if (pins[i].dev == dev && pins[i].ino == ino)
			return i;
	}

	return count;
}

/*
 * Move the pins this round reached to the front and return their count;
 * the caller unpins the rest and truncates. Unordered: lookups scan it all.
 */
static inline size_t mapped_pins_partition(struct mapped_exec_pin *pins,
					   size_t count, uint64_t round)
{
	struct mapped_exec_pin tmp;
	size_t kept = 0;
	size_t i;

	if (!pins)
		return 0;

	for (i = 0; i < count; i++) {
		if (pins[i].round != round)
			continue;
		if (i != kept) {
			tmp = pins[kept];
			pins[kept] = pins[i];
			pins[i] = tmp;
		}
		kept++;
	}

	return kept;
}

#endif /* LOTA_MAPPED_PINS_H */
