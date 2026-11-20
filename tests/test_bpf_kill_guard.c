/* SPDX-License-Identifier: MIT */
/*
 * cgroup.kill SIGKILLs past every signal hook, so the file layer refuses it.
 * Reads the built object: no root, no load.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#include <stdio.h>
#include <string.h>

#include <linux/bpf.h>

#include <bpf/libbpf.h>

#include "test.h"

#ifndef BPF_OBJ_PATH
#define BPF_OBJ_PATH "build/lota_lsm.bpf.o"
#endif

#define BPF_FUNC_RINGBUF_RESERVE 131 /* bpf_ringbuf_reserve() helper id */

/* a hook that never reserves ring-buffer space cannot report */
static int reserves_ringbuf(struct bpf_object *obj, const char *prog_name)
{
	const struct bpf_insn *insns;
	struct bpf_program *prog;
	size_t count;

	prog = bpf_object__find_program_by_name(obj, prog_name);
	if (!prog)
		return 0;

	insns = bpf_program__insns(prog);
	count = bpf_program__insn_cnt(prog);
	if (!insns)
		return 0;

	for (size_t i = 0; i < count; i++) {
		if (insns[i].code == (BPF_JMP | BPF_CALL) &&
		    insns[i].src_reg == 0 &&
		    insns[i].imm == BPF_FUNC_RINGBUF_RESERVE)
			return 1;
	}

	return 0;
}

/*
 * Whether the program reads the u64 at @off of its context while r1 still
 * holds it: BPF_PROG() argument n sits at n * 8.
 */
static int reads_ctx_slot(struct bpf_object *obj, const char *prog_name,
			  int off)
{
	const struct bpf_insn *insns;
	struct bpf_program *prog;
	size_t count;

	prog = bpf_object__find_program_by_name(obj, prog_name);
	if (!prog)
		return 0;

	insns = bpf_program__insns(prog);
	count = bpf_program__insn_cnt(prog);
	if (!insns)
		return 0;

	for (size_t i = 0; i < count; i++) {
		unsigned char cls = BPF_CLASS(insns[i].code);

		if (insns[i].code == (BPF_LDX | BPF_MEM | BPF_DW) &&
		    insns[i].src_reg == BPF_REG_1 && insns[i].off == off)
			return 1;
		if (cls == BPF_JMP && BPF_OP(insns[i].code) == BPF_CALL)
			return 0;
		if ((cls == BPF_ALU || cls == BPF_ALU64 || cls == BPF_LD ||
		     cls == BPF_LDX) &&
		    insns[i].dst_reg == BPF_REG_1)
			return 0;
	}

	return 0;
}

static struct bpf_map *find_map(struct bpf_object *obj, const char *map_name)
{
	struct bpf_map *map;

	bpf_object__for_each_map(map, obj) {
		const char *name = bpf_map__name(map);

		if (name && strcmp(name, map_name) == 0)
			return map;
	}

	return NULL;
}

int main(void)
{
	struct bpf_object *obj;
	struct bpf_map *guarded;
	const char *path = BPF_OBJ_PATH;

	test_begin("bpf kill guard");

	libbpf_set_print(NULL);
	obj = bpf_object__open_file(path, NULL);
	if (!obj) {
		FAIL("cannot open %s", path);
		return 1;
	}

	guarded = find_map(obj, "guarded_files");
	TEST("the object carries the files a write must not open");
	if (guarded == NULL)
		FAIL("expected: guarded != NULL");

	/* same key as trusted_libs: superblock dev + inode */
	if (guarded) {
		TEST("the guarded set is looked up, not iterated");
		if (bpf_map__type(guarded) != BPF_MAP_TYPE_HASH)
			FAIL("expected: bpf_map__type(guarded) == BPF_MAP_TYPE_HASH");
		TEST("a guarded file is keyed by superblock device and inode");
		if (!(bpf_map__key_size(guarded) == 2 * sizeof(unsigned long)))
			FAIL("expected: bpf_map__key_size(guarded) == 2 * "
			     "sizeof(unsigned long)");
		TEST("the value says which guard the entry carries");
		if (bpf_map__value_size(guarded) != sizeof(unsigned int))
			FAIL("expected: bpf_map__value_size(guarded) == "
			     "sizeof(unsigned int)");
	}

	/* a refused cgroup.kill write must reach the operator */
	TEST("a refused open leaves a record");
	if (!reserves_ringbuf(obj, "lota_file_open"))
		FAIL("expected: reserves_ringbuf(obj, \"lota_file_open\")");

	/* bpf(cmd, attr, size, kernel), then the previous program's verdict */
	TEST("the bpf hook reads the verdict after the kernel argument");
	if (!reads_ctx_slot(obj, "lota_bpf", 4 * 8))
		FAIL("expected: reads_ctx_slot(obj, \"lota_bpf\", 4 * 8)");
	TEST("the bpf hook does not refuse on the kernel argument");
	if (reads_ctx_slot(obj, "lota_bpf", 3 * 8))
		FAIL("expected: !reads_ctx_slot(obj, \"lota_bpf\", 3 * 8)");

	bpf_object__close(obj);

	return test_end();
}
