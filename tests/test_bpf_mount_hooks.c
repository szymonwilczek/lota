/* SPDX-License-Identifier: MIT */
/*
 * A bind mount over a trusted library can be made through either mount API:
 * mount(2), which reaches security_sb_mount(), or open_tree(2) followed by
 * move_mount(2), which reaches security_move_mount().
 * They take the same privilege and have the same effect, so an enforcement
 * object that watches one of them refuses nothing an attacker cannot simply
 * ask for the other way.
 *
 * These read the built object rather than a live kernel: the question is which
 * hooks the object carries, which is answerable without root and without
 * loading anything.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <gelf.h>
#include <libelf.h>

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

static Elf_Scn *find_section(Elf *elf, const char *section)
{
	size_t shstrndx;
	Elf_Scn *scn = NULL;

	if (elf_getshdrstrndx(elf, &shstrndx) != 0)
		return NULL;

	while ((scn = elf_nextscn(elf, scn)) != NULL) {
		GElf_Shdr shdr;
		const char *name;

		if (!gelf_getshdr(scn, &shdr))
			continue;

		name = elf_strptr(elf, shstrndx, shdr.sh_name);
		if (name && strcmp(name, section) == 0)
			return scn;
	}

	return NULL;
}

static int find_symbol(Elf *elf, const char *sym_name, GElf_Sym *out)
{
	Elf_Scn *scn = NULL;

	while ((scn = elf_nextscn(elf, scn)) != NULL) {
		GElf_Shdr shdr;
		Elf_Data *data;
		size_t count;

		if (!gelf_getshdr(scn, &shdr) || shdr.sh_type != SHT_SYMTAB)
			continue;

		data = elf_getdata(scn, NULL);
		if (!data || shdr.sh_entsize == 0)
			return 0;

		count = shdr.sh_size / shdr.sh_entsize;
		for (size_t i = 0; i < count; i++) {
			GElf_Sym sym;
			const char *name;

			if (!gelf_getsym(data, (int)i, &sym))
				continue;

			name = elf_strptr(elf, shdr.sh_link, sym.st_name);
			if (name && strcmp(name, sym_name) == 0) {
				*out = sym;
				return 1;
			}
		}
	}

	return 0;
}

static int has_section(Elf *elf, const char *section)
{
	return find_section(elf, section) != NULL;
}

static int has_map(Elf *elf, const char *map_name)
{
	Elf_Scn *maps = find_section(elf, ".maps");
	GElf_Sym sym;

	if (!maps || !find_symbol(elf, map_name, &sym))
		return 0;

	return sym.st_shndx == elf_ndxscn(maps);
}

int main(void)
{
	const char *path = BPF_OBJ_PATH;
	Elf *elf;
	int fd;

	printf("=== mount-hook coverage in %s ===\n", path);

	if (elf_version(EV_CURRENT) == EV_NONE) {
		fprintf(stderr, "FAIL: libelf is unusable\n");
		return 1;
	}

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		fprintf(stderr, "FAIL: cannot open %s\n", path);
		return 1;
	}

	elf = elf_begin(fd, ELF_C_READ, NULL);
	if (!elf) {
		fprintf(stderr, "FAIL: %s is not an ELF object\n", path);
		close(fd);
		return 1;
	}

	CHECK(has_section(elf, "lsm/sb_mount"),
	      "the legacy mount(2) path is hooked");
	CHECK(has_section(elf, "lsm/move_mount"),
	      "the open_tree/move_mount path is hooked");

	CHECK(has_map(elf, "trusted_libs"),
	      "the trusted libraries themselves are keyed");

	CHECK(!has_map(elf, "trusted_lib_mnt"),
	      "no ancestor directory of a trusted library is armed");

	elf_end(elf);
	close(fd);

	if (g_failures) {
		fprintf(stderr, "\n%d test(s) failed\n", g_failures);
		return 1;
	}
	printf("\nAll mount-hook coverage tests passed\n");
	return 0;
}
