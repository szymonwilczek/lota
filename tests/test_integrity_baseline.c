/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * Unit tests for the value the BPF module gate reads.
 *
 * In ENFORCE mode the module and firmware branches of lota_kernel_read_file()
 * stand on two kernel properties: module signature enforcement and a lockdown
 * level of integrity or above.
 * The agent's own startup gate reads both out of sysfs and refuses to start
 * without them, so a running agent has already established the baseline.
 *
 * The packaged unit sets ProtectKernelTunables=yes, which bind-mounts an empty
 * regular file over /proc/kallsyms. A read of the masked file succeeds and yields
 * nothing, so a symbol table is a road the daemon does not have, and a value
 * built from it alone reports a baseline no kernel state supports.
 *
 * Every file is written by the test, because the point is the combinations
 * a single machine cannot present.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "../include/lota.h"
#include "../src/agent/bpf_loader.h"

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

static char kallsyms_path[64];
static char sig_enforce_path[64];
static char lockdown_path[64];

static int write_file(const char *path, const char *content)
{
	size_t len = strlen(content);
	int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	int ret = 0;

	if (fd < 0)
		return -errno;
	if (write(fd, content, len) != (ssize_t)len)
		ret = -EIO;
	close(fd);
	return ret;
}

/* Enough of a symbol table to carry the two symbols the gate resolves */
static const char kallsyms_populated[] =
	"ffffffff81000000 T _text\n"
	"ffffffffa5e6acf8 b sig_enforce\n"
	"ffffffffa5f9858c b kernel_locked_down\n";

/* What ProtectKernelTunables=yes puts in front of the daemon */
static const char kallsyms_masked[] = "";

static const char lockdown_integrity[] = "none [integrity] confidentiality\n";
static const char lockdown_none[] = "[none] integrity confidentiality\n";

static void build(struct integrity_data *cfg)
{
	int ret = bpf_loader_build_integrity_config(
		cfg, kallsyms_path, sig_enforce_path, lockdown_path);

	if (ret != 0)
		FAIL("builder refused a complete set of paths");
}

static void test_hardened_kernel_is_satisfied(void)
{
	struct integrity_data cfg;

	TEST("a hardened kernel with a readable symbol table passes");

	write_file(kallsyms_path, kallsyms_populated);
	write_file(sig_enforce_path, "Y\n");
	write_file(lockdown_path, lockdown_integrity);

	build(&cfg);
	if (!bpf_loader_integrity_config_satisfied(&cfg))
		FAIL("a kernel meeting the baseline was refused");
	else
		PASS();
}

/*
 * The packaged unit masks /proc/kallsyms with an empty file, so the daemon
 * resolved both symbols to zero and the module branch refused every load on
 * a host whose kernel meets the baseline and whose operator had switched
 * the module gate off.
 */
static void test_masked_symbol_table_still_passes(void)
{
	struct integrity_data cfg;

	TEST("a hardened kernel behind a masked symbol table passes");

	write_file(kallsyms_path, kallsyms_masked);
	write_file(sig_enforce_path, "Y\n");
	write_file(lockdown_path, lockdown_integrity);

	build(&cfg);
	if (!bpf_loader_integrity_config_satisfied(&cfg))
		FAIL("a kernel meeting the baseline was refused because the "
		     "symbol table was unreadable");
	else
		PASS();
}

static void test_unenforced_module_signatures_are_refused(void)
{
	struct integrity_data cfg;

	TEST("module signatures not enforced is refused");

	write_file(kallsyms_path, kallsyms_populated);
	write_file(sig_enforce_path, "N\n");
	write_file(lockdown_path, lockdown_integrity);

	build(&cfg);
	if (bpf_loader_integrity_config_satisfied(&cfg))
		FAIL("a kernel loading unsigned modules passed the baseline");
	else
		PASS();
}

static void test_lockdown_off_is_refused(void)
{
	struct integrity_data cfg;

	TEST("lockdown below integrity is refused");

	write_file(kallsyms_path, kallsyms_populated);
	write_file(sig_enforce_path, "Y\n");
	write_file(lockdown_path, lockdown_none);

	build(&cfg);
	if (bpf_loader_integrity_config_satisfied(&cfg))
		FAIL("a kernel outside lockdown passed the baseline");
	else
		PASS();
}

/* A property nobody published is not a property that holds */
static void test_unreadable_state_is_refused(void)
{
	struct integrity_data cfg;

	TEST("a kernel that publishes neither property is refused");

	write_file(kallsyms_path, kallsyms_populated);
	unlink(sig_enforce_path);
	unlink(lockdown_path);

	build(&cfg);
	if (bpf_loader_integrity_config_satisfied(&cfg))
		FAIL("an unreadable kernel state passed the baseline");
	else
		PASS();
}

/* The value carries the verdict, so the two roads can be compared */
static void test_value_reports_both_properties(void)
{
	struct integrity_data cfg;

	TEST("the value reports each property the gate read");

	write_file(kallsyms_path, kallsyms_populated);
	write_file(sig_enforce_path, "Y\n");
	write_file(lockdown_path, lockdown_none);

	build(&cfg);
	if (!cfg.sig_enforce)
		FAIL("enforced module signatures were not reported");
	else if (cfg.lockdown)
		FAIL("lockdown was reported on a kernel outside it");
	else
		PASS();
}

int main(void)
{
	printf("=== Kernel integrity baseline tests ===\n\n");

	snprintf(kallsyms_path, sizeof(kallsyms_path), "/tmp/lota-ksym-%d",
		 (int)getpid());
	snprintf(sig_enforce_path, sizeof(sig_enforce_path),
		 "/tmp/lota-sigenf-%d", (int)getpid());
	snprintf(lockdown_path, sizeof(lockdown_path), "/tmp/lota-lockd-%d",
		 (int)getpid());

	test_hardened_kernel_is_satisfied();
	test_masked_symbol_table_still_passes();
	test_unenforced_module_signatures_are_refused();
	test_lockdown_off_is_refused();
	test_unreadable_state_is_refused();
	test_value_reports_both_properties();

	unlink(kallsyms_path);
	unlink(sig_enforce_path);
	unlink(lockdown_path);

	printf("\n=== %d/%d passed ===\n", tests_passed, tests_run);
	return tests_passed == tests_run ? 0 : 1;
}
