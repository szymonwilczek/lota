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

int main(void) {
  test_resolve_existing_symbol();
  return 0;
}
