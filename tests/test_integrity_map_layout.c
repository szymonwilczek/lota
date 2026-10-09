/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * Tests for the enforcement object's integrity map layout.
 *
 * The map's layout belongs to the object the kernel loads; the struct the agent
 * reads it into belongs to the build. bpf_map_lookup_elem() copies the map's
 * value_size into the caller's buffer, so an object whose value is wider than
 * the agent's struct overruns the frame it is read into -- which is what a fleet
 * keeping its own signed object gets after the agent is upgraded.
 *
 * Two objects are used: the one this tree builds, which is the matching case,
 * and a fixture carrying the wider value an older object has.
 *
 * Opening an object needs no privilege and no kernel state, so this runs
 * anywhere the tree builds.
 */

#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

#include "../include/lota.h"
#include "../src/agent/bpf_loader.h"

#ifndef TREE_BPF_OBJ
#define TREE_BPF_OBJ "build/lota_lsm.bpf.o"
#endif

#ifndef LEGACY_BPF_OBJ
#define LEGACY_BPF_OBJ "build/legacy_integrity_map.bpf.o"
#endif

static int tests_run;
static int tests_passed;

#define TEST(name)                                         \
	do {                                               \
		tests_run++;                               \
		printf("  [%2d] %-58s ", tests_run, name); \
	} while (0)

#define PASS()                    \
	do {                      \
		tests_passed++;   \
		printf("PASS\n"); \
	} while (0)

#define FAIL(msg)                          \
	do {                               \
		printf("FAIL: %s\n", msg); \
	} while (0)

/* The object this tree builds is the one the agent was compiled against. */
static void test_the_trees_object_matches_this_build(void)
{
	uint32_t key_size = 0;
	uint32_t value_size = 0;
	int ret;

	TEST("the object this tree builds carries this agent's layout");
	ret = bpf_loader_object_integrity_layout(TREE_BPF_OBJ, &key_size,
						 &value_size);
	if (ret < 0)
		FAIL("the tree's own object could not be read");
	else if (value_size != sizeof(struct integrity_data))
		FAIL("the tree's object does not carry the struct it is built with");
	else if (key_size != sizeof(uint32_t))
		FAIL("the tree's object does not key the map on a u32");
	else
		PASS();
}

/* The wider value is what makes the read overrun the agent's struct. */
static void test_a_wider_value_is_seen_for_what_it_is(void)
{
	uint32_t key_size = 0;
	uint32_t value_size = 0;
	int ret;

	TEST("an object with a wider value reports that width");
	ret = bpf_loader_object_integrity_layout(LEGACY_BPF_OBJ, &key_size,
						 &value_size);
	if (ret < 0)
		FAIL("the fixture object could not be read");
	else if (value_size <= sizeof(struct integrity_data))
		FAIL("the fixture does not carry the wider value it exists for");
	else
		PASS();
}

/*
 * The refusal is what keeps the kernel from writing past the struct,
 * so it has to happen before the object is loaded, not at the read.
 */
static void test_a_wider_value_is_refused(void)
{
	TEST("an object whose map does not match this agent is refused");
	if (bpf_loader_check_object_integrity_layout(LEGACY_BPF_OBJ) >= 0)
		FAIL("an object that overruns the agent's struct was accepted");
	else
		PASS();
}

static void test_a_matching_object_is_accepted(void)
{
	TEST("an object whose map matches this agent is accepted");
	if (bpf_loader_check_object_integrity_layout(TREE_BPF_OBJ) < 0)
		FAIL("the object this agent was built with was refused");
	else
		PASS();
}

/*
 * An object with no integrity map at all cannot feed the module gate,
 * and saying so beats letting the loader discover it later.
 */
static void test_an_absent_map_is_refused(void)
{
	TEST("an object carrying no integrity map is refused");
	if (bpf_loader_check_object_integrity_layout("/dev/null") >= 0)
		FAIL("an object with no integrity map was accepted");
	else
		PASS();
}

int main(void)
{
	printf("=== enforcement object integrity map layout tests ===\n\n");

	test_the_trees_object_matches_this_build();
	test_a_wider_value_is_seen_for_what_it_is();
	test_a_wider_value_is_refused();
	test_a_matching_object_is_accepted();
	test_an_absent_map_is_refused();

	printf("\n=== %d/%d passed ===\n", tests_passed, tests_run);
	return tests_passed == tests_run ? 0 : 1;
}
