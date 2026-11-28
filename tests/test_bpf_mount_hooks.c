/* SPDX-License-Identifier: MIT */
/*
 * A bind mount over a trusted library can be made through either mount API:
 * mount(2), which reaches security_sb_mount(), or open_tree(2) followed by
 * move_mount(2), which reaches security_move_mount(). mount(2) with MS_MOVE
 * moves a mount onto it and reaches only security_sb_mount().
 * They take the same privilege and have the same effect, so an enforcement
 * object that watches one of them refuses nothing an attacker cannot simply
 * ask for the other way.
 *
 * With lock_bpf, lsm/bpf_map refuses a descriptor of a map the object declares
 * in .maps. A map name is any process's to pick, so the hook compares
 * addresses.
 *
 * These read the built object rather than a live kernel: the question is which
 * hooks the object carries, which is answerable without root and without
 * loading anything.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mount.h>

#include <linux/bpf.h>

#include <gelf.h>
#include <libelf.h>

#include "test.h"

#ifndef BPF_OBJ_PATH
#define BPF_OBJ_PATH "build/lota_lsm.bpf.o"
#endif

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

/*
 * Whether a program reserves ring-buffer space, read off the instruction stream:
 * a bpf_ringbuf_reserve() is a call to helper 131, and a hook that never makes
 * one cannot report anything it did.
 */
#define BPF_FUNC_RINGBUF_RESERVE 131

static int reserves_ringbuf(Elf *elf, const char *prog_name)
{
	const char *insns;
	struct bpf_insn insn;
	Elf_Data *data;
	GElf_Sym sym;
	size_t count;

	if (!find_symbol(elf, prog_name, &sym) ||
	    GELF_ST_TYPE(sym.st_info) != STT_FUNC)
		return 0;

	data = elf_getdata(elf_getscn(elf, sym.st_shndx), NULL);
	if (!data || !data->d_buf || sym.st_value + sym.st_size > data->d_size)
		return 0;

	insns = (const char *)data->d_buf + sym.st_value;
	count = sym.st_size / sizeof(insn);

	for (size_t i = 0; i < count; i++) {
		memcpy(&insn, insns + i * sizeof(insn), sizeof(insn));
		if (insn.code == (BPF_JMP | BPF_CALL) && insn.src_reg == 0 &&
		    insn.imm == BPF_FUNC_RINGBUF_RESERVE)
			return 1;
	}

	return 0;
}

/*
 * Whether @prog_name masks a register with every bit of @bits:
 * the flag test of a hook that acts on any of them.
 */
static int masks_bits(Elf *elf, const char *prog_name, unsigned int bits)
{
	const char *insns;
	struct bpf_insn insn;
	Elf_Data *data;
	GElf_Sym sym;
	size_t count;

	if (!find_symbol(elf, prog_name, &sym) ||
	    GELF_ST_TYPE(sym.st_info) != STT_FUNC)
		return 0;

	data = elf_getdata(elf_getscn(elf, sym.st_shndx), NULL);
	if (!data || !data->d_buf || sym.st_value + sym.st_size > data->d_size)
		return 0;

	insns = (const char *)data->d_buf + sym.st_value;
	count = sym.st_size / sizeof(insn);

	for (size_t i = 0; i < count; i++) {
		memcpy(&insn, insns + i * sizeof(insn), sizeof(insn));
		if ((insn.code == (BPF_ALU64 | BPF_AND | BPF_K) ||
		     insn.code == (BPF_ALU | BPF_AND | BPF_K)) &&
		    ((unsigned int)insn.imm & bits) == bits)
			return 1;
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

/*
 * Whether the map address loaded at byte @off of @code is compared with
 * another register by the next instruction, the 16-byte ld_imm64 aside.
 */
static int compared_at(const Elf_Data *code, GElf_Addr off)
{
	struct bpf_insn ld, cmp;
	unsigned char op;

	if (!code->d_buf || off + 3 * sizeof(ld) > code->d_size)
		return 0;

	memcpy(&ld, (const char *)code->d_buf + off, sizeof(ld));
	memcpy(&cmp, (const char *)code->d_buf + off + 2 * sizeof(ld),
	       sizeof(cmp));
	op = BPF_OP(cmp.code);

	return ld.code == (BPF_LD | BPF_IMM | BPF_DW) &&
	       BPF_CLASS(cmp.code) == BPF_JMP && BPF_SRC(cmp.code) == BPF_X &&
	       (op == BPF_JEQ || op == BPF_JNE) &&
	       (cmp.dst_reg == ld.dst_reg || cmp.src_reg == ld.dst_reg);
}

/*
 * Whether @section compares a register with the address of every map in
 * .maps: a relocated ld_imm64 of the map followed by a jeq or jne.
 */
static int compares_every_map(Elf *elf, const char *section)
{
	Elf_Scn *maps = find_section(elf, ".maps");
	Elf_Scn *prog = find_section(elf, section);
	Elf_Scn *scn = NULL;
	Elf_Data *code;
	Elf_Data *syms = NULL;
	GElf_Shdr symhdr = { 0 };
	unsigned char *seen;
	size_t nsyms = 0;
	int total = 0;

	if (!maps || !prog)
		return 0;

	code = elf_getdata(prog, NULL);
	if (!code)
		return 0;

	while ((scn = elf_nextscn(elf, scn)) != NULL) {
		GElf_Shdr shdr;

		if (gelf_getshdr(scn, &shdr) && shdr.sh_type == SHT_SYMTAB &&
		    shdr.sh_entsize) {
			syms = elf_getdata(scn, NULL);
			symhdr = shdr;
			nsyms = shdr.sh_size / shdr.sh_entsize;
		}
	}

	if (!syms || !nsyms)
		return 0;

	seen = calloc(nsyms, 1);
	if (!seen)
		return 0;

	while ((scn = elf_nextscn(elf, scn)) != NULL) {
		GElf_Shdr shdr;
		Elf_Data *data;

		if (!gelf_getshdr(scn, &shdr) || shdr.sh_type != SHT_REL ||
		    shdr.sh_info != elf_ndxscn(prog))
			continue;

		data = elf_getdata(scn, NULL);
		for (size_t i = 0; data && shdr.sh_entsize &&
				   i < shdr.sh_size / shdr.sh_entsize;
		     i++) {
			GElf_Rel rel;
			size_t idx;

			if (!gelf_getrel(data, (int)i, &rel))
				continue;
			idx = GELF_R_SYM(rel.r_info);
			if (idx < nsyms && compared_at(code, rel.r_offset))
				seen[idx] = 1;
		}
	}

	for (size_t i = 0; i < nsyms; i++) {
		GElf_Sym sym;

		if (!gelf_getsym(syms, (int)i, &sym) ||
		    sym.st_shndx != elf_ndxscn(maps) ||
		    GELF_ST_TYPE(sym.st_info) != STT_OBJECT)
			continue;
		if (!seen[i]) {
			FAIL("%s compares no %s", section,
			     elf_strptr(elf, symhdr.sh_link, sym.st_name));
			total = 0;
			break;
		}
		total++;
	}

	free(seen);
	return total > 0;
}

int main(void)
{
	const char *path = BPF_OBJ_PATH;
	Elf *elf;
	int fd;

	test_begin("bpf mount hooks");

	if (elf_version(EV_CURRENT) == EV_NONE) {
		FAIL("libelf is unusable");
		return 1;
	}

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		FAIL("cannot open %s", path);
		return 1;
	}

	elf = elf_begin(fd, ELF_C_READ, NULL);
	if (!elf) {
		FAIL("%s is not an ELF object", path);
		close(fd);
		return 1;
	}

	TEST("the legacy mount(2) path is hooked");
	if (!has_section(elf, "lsm/sb_mount"))
		FAIL("expected: has_section(elf, \"lsm/sb_mount\")");
	TEST("the open_tree/move_mount path is hooked");
	if (!has_section(elf, "lsm/move_mount"))
		FAIL("expected: has_section(elf, \"lsm/move_mount\")");

	TEST("mount(2) is checked for MS_BIND and MS_MOVE alike");
	if (!masks_bits(elf, "lota_sb_mount", MS_BIND | MS_MOVE))
		FAIL("expected: masks_bits(elf, \"lota_sb_mount\", MS_BIND | "
		     "MS_MOVE)");

	TEST("the trusted libraries themselves are keyed");
	if (!has_map(elf, "trusted_libs"))
		FAIL("expected: has_map(elf, \"trusted_libs\")");

	TEST("no ancestor directory of a trusted library is armed");
	if (has_map(elf, "trusted_lib_mnt"))
		FAIL("expected: !has_map(elf, \"trusted_lib_mnt\")");

	TEST("a refused mount(2) bind leaves a record");
	if (!reserves_ringbuf(elf, "lota_sb_mount"))
		FAIL("expected: reserves_ringbuf(elf, \"lota_sb_mount\")");
	TEST("a refused move_mount leaves a record");
	if (!reserves_ringbuf(elf, "lota_move_mount"))
		FAIL("expected: reserves_ringbuf(elf, \"lota_move_mount\")");

	TEST("lsm/bpf_map compares the map with each map in .maps");
	if (!compares_every_map(elf, "lsm/bpf_map"))
		FAIL("expected: compares_every_map(elf, \"lsm/bpf_map\")");

	elf_end(elf);
	close(fd);

	return test_end();
}
