/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * Write guard pins, each stamped with the last measurement round that reached
 * its inode. A library outlives the first process that maps it, so no process
 * owns a pin: the round decides which ones are released.
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

/**
 * mapped_pins_find() - Look up an inode.
 * @pins: The pins.
 * @count: How many.
 * @dev: The kernel's s_dev.
 * @ino: Inode number.
 *
 * Return: index of the pin, or @count when the inode is not pinned.
 */
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

/**
 * mapped_pins_partition() - Move the pins @round reached to the front.
 * @pins: The pins.
 * @count: How many.
 * @round: The round.
 *
 * Return: their count. The caller unpins the rest and truncates.
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
