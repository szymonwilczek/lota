#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../src/agent/bpf_loader.h"

#define PASS() printf("PASS\n")
#define FAIL(fmt, ...)                                                         \
  do {                                                                         \
    printf("FAIL: " fmt "\n", ##__VA_ARGS__);                                  \
    exit(1);                                                                   \
  } while (0)

void test_resolve_existing_symbol(void) {
  printf("Testing resolve_kernel_symbol...\n");
  unsigned long addr = resolve_kernel_symbol("_text");
  if (addr == 0) {
    if (access("/proc/kallsyms", R_OK) != 0) {
      printf("SKIP: /proc/kallsyms not readable\n");
      return;
    }
  }

  unsigned long bad = resolve_kernel_symbol("this_symbol_does_not_exist_12345");
  if (bad != 0) {
    FAIL("Resolved non-existent symbol to %lx", bad);
  }

  PASS();
}

/*
 * Pin the load/attach split contract. bpf_loader_attach() must refuse
 * to operate before bpf_loader_load() has succeeded, otherwise main.c
 * could call attach in the wrong order and silently land BPF programs
 * in front of a partially configured lota_config map.
 */
void test_attach_refuses_before_load(void) {
  printf("Testing bpf_loader_attach refuses unloaded context...\n");

  struct bpf_loader_ctx ctx;
  int ret = bpf_loader_init(&ctx);
  if (ret != 0) {
    FAIL("bpf_loader_init returned %d", ret);
  }
  if (ctx.loaded) {
    FAIL("bpf_loader_init left ctx.loaded = true");
  }
  if (ctx.attached) {
    FAIL("bpf_loader_init left ctx.attached = true");
  }

  ret = bpf_loader_attach(&ctx);
  if (ret != -EINVAL) {
    FAIL("bpf_loader_attach on unloaded ctx returned %d, want -EINVAL", ret);
  }

  ret = bpf_loader_attach(NULL);
  if (ret != -EINVAL) {
    FAIL("bpf_loader_attach(NULL) returned %d, want -EINVAL", ret);
  }

  PASS();
}

int main(void) {
  test_resolve_existing_symbol();
  test_attach_refuses_before_load();
  return 0;
}
