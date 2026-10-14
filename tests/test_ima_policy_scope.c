/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * Unit tests for the IMA appraisal gate the agent runs before it starts.
 *
 * The gate has to answer whether an executable on this host is appraised,
 * and that takes both files: ima_appraise= on the cmdline carries the mode,
 * and the loaded policy carries the scope. A mode with an empty scope appraises
 * nothing -- appraisal applies only to the func= rules the policy contains
 * -- so a host booted ima_appraise=fix with no BPRM_CHECK rule blocks on nothing
 * while looking, from the cmdline alone, like the floor is in place.
 *
 * Both files are written by the test, because the point is the combinations
 * a single machine cannot present.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

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

static char cmdline_path[64];
static char policy_path[64];

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

/* The policy Fedora loads by default: measures, appraises no executable */
static const char policy_measure_only[] =
	"measure func=KEXEC_KERNEL_CHECK\n"
	"appraise func=POLICY_CHECK appraise_type=imasig\n"
	"measure func=MODULE_CHECK\n";

/* What the shipped configs/ima/lota-ima-policy adds on top */
static const char policy_appraises_exec[] =
	"dont_appraise fsmagic=0x9fa0\n"
	"measure func=BPRM_CHECK\n"
	"appraise func=BPRM_CHECK appraise_type=imasig\n"
	"appraise func=MMAP_CHECK mask=MAY_EXEC appraise_type=imasig\n";

static void test_mode_off_is_refused(void)
{
	TEST("ima_appraise=off is refused whatever the policy says");

	write_file(cmdline_path, "ro quiet ima=on ima_appraise=off\n");
	write_file(policy_path, policy_appraises_exec);

	if (bpf_loader_ima_appraisal_active(cmdline_path, policy_path) == 0)
		FAIL("a non-blocking mode passed the gate");
	else
		PASS();
}

static void test_mode_absent_is_refused(void)
{
	TEST("no ima_appraise= at all is refused");

	write_file(cmdline_path, "ro quiet\n");
	write_file(policy_path, policy_appraises_exec);

	if (bpf_loader_ima_appraisal_active(cmdline_path, policy_path) == 0)
		FAIL("a kernel booted without the parameter passed");
	else
		PASS();
}

/*
 * ima_appraise=fix with a policy that has no BPRM_CHECK rule appraises
 * no executable, so the gate must refuse it despite the blocking mode.
 */
static void test_blocking_mode_with_empty_scope_is_refused(void)
{
	TEST("a blocking mode over a policy that appraises no exec is refused");

	write_file(cmdline_path, "ro quiet ima=on ima_appraise=fix\n");
	write_file(policy_path, policy_measure_only);

	if (bpf_loader_ima_appraisal_active(cmdline_path, policy_path) == 0)
		FAIL("a policy appraising no executable passed the gate");
	else
		PASS();
}

static void test_blocking_mode_with_exec_scope_passes(void)
{
	TEST("a blocking mode over a policy that appraises exec passes");

	write_file(cmdline_path, "ro quiet ima=on ima_appraise=enforce\n");
	write_file(policy_path, policy_appraises_exec);

	if (bpf_loader_ima_appraisal_active(cmdline_path, policy_path) != 0)
		FAIL("a host with the floor in place was refused");
	else
		PASS();
}

/* A rule naming no hook applies to every hook, exec included */
static void test_appraise_without_func_covers_exec(void)
{
	TEST("an appraise rule naming no func covers exec");

	write_file(cmdline_path, "ro quiet ima_appraise=enforce\n");
	write_file(policy_path, "appraise fowner=0 appraise_type=imasig\n");

	if (bpf_loader_ima_appraisal_active(cmdline_path, policy_path) != 0)
		FAIL("a policy-wide appraise rule was not counted");
	else
		PASS();
}

/* dont_appraise is not appraise, however it reads to a substring match */
static void test_dont_appraise_is_not_appraise(void)
{
	TEST("dont_appraise rules do not count as appraisal");

	write_file(cmdline_path, "ro quiet ima_appraise=enforce\n");
	write_file(policy_path, "dont_appraise func=BPRM_CHECK\n"
				"measure func=BPRM_CHECK\n");

	if (bpf_loader_ima_appraisal_active(cmdline_path, policy_path) == 0)
		FAIL("an exclusion rule was read as appraisal");
	else
		PASS();
}

/*
 * A kernel built without CONFIG_IMA_READ_POLICY cannot answer the scope question
 * at all. That is unknown, not absent: refusing every such host would turn
 * an unreadable file into a boot failure, so the mode still decides and the gate
 * says what it could not check.
 */
static void test_unreadable_policy_falls_back_to_the_mode(void)
{
	TEST("an unreadable policy leaves the mode deciding");

	write_file(cmdline_path, "ro quiet ima_appraise=enforce\n");
	unlink(policy_path);

	if (bpf_loader_ima_appraisal_active(cmdline_path,
					    "/nonexistent/ima/policy") != 0)
		FAIL("a kernel that cannot publish its policy was refused");
	else
		PASS();
}

int main(void)
{
	printf("=== IMA appraisal scope tests ===\n\n");

	snprintf(cmdline_path, sizeof(cmdline_path), "/tmp/lota-ima-cmd-%d",
		 (int)getpid());
	snprintf(policy_path, sizeof(policy_path), "/tmp/lota-ima-pol-%d",
		 (int)getpid());

	test_mode_off_is_refused();
	test_mode_absent_is_refused();
	test_blocking_mode_with_empty_scope_is_refused();
	test_blocking_mode_with_exec_scope_passes();
	test_appraise_without_func_covers_exec();
	test_dont_appraise_is_not_appraise();
	test_unreadable_policy_falls_back_to_the_mode();

	unlink(cmdline_path);
	unlink(policy_path);

	printf("\n=== %d/%d passed ===\n", tests_passed, tests_run);
	return tests_passed == tests_run ? 0 : 1;
}
