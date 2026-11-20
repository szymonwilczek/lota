/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
#include <errno.h>

#include "../src/agent/bpf_loader.h"
#include "test.h"

/*
 * Pin the load/attach split contract. bpf_loader_attach() must refuse
 * to operate before bpf_loader_load() has succeeded, otherwise main.c
 * could call attach in the wrong order and silently land BPF programs
 * in front of a partially configured lota_config map.
 */
static void test_attach_refuses_before_load(void)
{
	struct bpf_loader_ctx ctx;
	int ret;

	TEST("bpf_loader_init leaves the context unloaded");
	ret = bpf_loader_init(&ctx);
	if (ret != 0) {
		FAIL("bpf_loader_init returned %d", ret);
		return;
	}
	if (ctx.loaded)
		FAIL("bpf_loader_init left ctx.loaded = true");
	if (ctx.attached)
		FAIL("bpf_loader_init left ctx.attached = true");

	TEST("bpf_loader_attach refuses an unloaded context");
	ret = bpf_loader_attach(&ctx);
	if (ret != -EINVAL)
		FAIL("returned %d, want -EINVAL", ret);

	TEST("bpf_loader_attach refuses NULL");
	ret = bpf_loader_attach(NULL);
	if (ret != -EINVAL)
		FAIL("returned %d, want -EINVAL", ret);
}

int main(void)
{
	test_begin("loader attach");
	test_attach_refuses_before_load();
	return test_end();
}
