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

#ifndef BPF_OBJ_PATH
#define BPF_OBJ_PATH "build/lota_lsm.bpf.o"
#endif

static int g_failures;

#define CHECK(cond, msg)                                    \
	do {                                                \
		if (!(cond)) {                              \
			fprintf(stderr, "FAIL: %s\n", msg); \
			g_failures++;                       \
		} else {                                    \
			printf("PASS: %s\n", msg);          \
		}                                           \
	} while (0)

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

	printf("=== cgroup kill-guard coverage in %s ===\n", path);

	libbpf_set_print(NULL);
	obj = bpf_object__open_file(path, NULL);
	if (!obj) {
		fprintf(stderr, "FAIL: cannot open %s\n", path);
		return 1;
	}

	guarded = find_map(obj, "guarded_files");
	CHECK(guarded != NULL,
	      "the object carries the files a write must not open");

	/* same key as trusted_libs: superblock dev + inode */
	if (guarded) {
		CHECK(bpf_map__type(guarded) == BPF_MAP_TYPE_HASH,
		      "the guarded set is looked up, not iterated");
		CHECK(bpf_map__key_size(guarded) == 2 * sizeof(unsigned long),
		      "a guarded file is keyed by superblock device and inode");
		CHECK(bpf_map__value_size(guarded) == sizeof(unsigned int),
		      "the value says which guard the entry carries");
	}

	/* a refused cgroup.kill write must reach the operator */
	CHECK(reserves_ringbuf(obj, "lota_file_open"),
	      "a refused open leaves a record");

	bpf_object__close(obj);

	if (g_failures) {
		fprintf(stderr, "\n%d test(s) failed\n", g_failures);
		return 1;
	}
	printf("\nAll cgroup kill-guard coverage tests passed\n");
	return 0;
}
