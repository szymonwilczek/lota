/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * Unit tests for the IMA appraisal gate the agent runs before it starts.
 *
 * The gate has to answer whether an executable on this host is appraised,
 * and that takes both files: ima_appraise= on the cmdline carries the mode,
 * and the loaded policy carries the scope. A mode with an empty scope appraises
 * nothing -- appraisal applies only to the func= rules the policy contains
 * -- so a host booted ima_appraise=enforce with no BPRM_CHECK rule blocks on
 * nothing while looking, from the cmdline alone, like the floor is in place.
 *
 * Both files are written by the test, because the point is the combinations
 * a single machine cannot present.
 */

#include <bpf/btf.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "test.h"
#include "../include/lota_ima_appraise.h"
#include "../include/lota_ima_policy_scope.h"
#include "../src/agent/bpf_loader.h"

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

	if (bpf_loader_ima_appraisal_active(cmdline_path, policy_path, 0) == 0)
		FAIL("a non-blocking mode passed the gate");
	else
		PASS();
}

/* fix repairs a failing xattr and passes the access */
static void test_mode_fix_is_refused(void)
{
	TEST("ima_appraise=fix is refused whatever the policy says");

	write_file(cmdline_path, "ro quiet ima=on ima_appraise=fix\n");
	write_file(policy_path, policy_appraises_exec);

	if (bpf_loader_ima_appraisal_active(cmdline_path, policy_path, 0) == 0)
		FAIL("ima_appraise=fix passed the gate");
	else
		PASS();
}

static void test_last_mode_decides(void)
{
	TEST("the last ima_appraise= decides the mode");

	write_file(policy_path, policy_appraises_exec);

	write_file(cmdline_path, "ro ima_appraise=enforce ima_appraise=off\n");
	if (bpf_loader_ima_appraisal_active(cmdline_path, policy_path, 0) ==
	    0) {
		FAIL("enforce then off passed the gate");
		return;
	}

	write_file(cmdline_path, "ro ima_appraise=off ima_appraise=enforce\n");
	if (bpf_loader_ima_appraisal_active(cmdline_path, policy_path, 0) != 0)
		FAIL("off then enforce was refused");
	else
		PASS();
}

/* without the parameter the kernel stays in its default, enforce */
static void test_mode_absent_reads_the_scope(void)
{
	TEST("no ima_appraise= at all leaves the policy to decide");

	write_file(cmdline_path, "ro quiet\n");
	write_file(policy_path, policy_appraises_exec);
	if (bpf_loader_ima_appraisal_active(cmdline_path, policy_path, 0) !=
	    0) {
		FAIL("the default mode over an exec rule was refused");
		return;
	}

	write_file(policy_path, policy_measure_only);
	if (bpf_loader_ima_appraisal_active(cmdline_path, policy_path, 0) !=
	    -ENOENT)
		FAIL("the default mode over no exec rule was not -ENOENT");
	else
		PASS();
}

/*
 * ima_appraise=enforce with a policy that has no BPRM_CHECK rule appraises
 * no executable, so the gate must refuse it despite the blocking mode.
 */
static void test_blocking_mode_with_empty_scope_is_refused(void)
{
	TEST("a blocking mode over a policy that appraises no exec is refused");

	write_file(cmdline_path, "ro quiet ima=on ima_appraise=enforce\n");
	write_file(policy_path, policy_measure_only);

	if (bpf_loader_ima_appraisal_active(cmdline_path, policy_path, 0) == 0)
		FAIL("a policy appraising no executable passed the gate");
	else
		PASS();
}

static void test_blocking_mode_with_exec_scope_passes(void)
{
	TEST("a blocking mode over a policy that appraises exec passes");

	write_file(cmdline_path, "ro quiet ima=on ima_appraise=enforce\n");
	write_file(policy_path, policy_appraises_exec);

	if (bpf_loader_ima_appraisal_active(cmdline_path, policy_path, 0) != 0)
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

	if (bpf_loader_ima_appraisal_active(cmdline_path, policy_path, 0) != 0)
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

	if (bpf_loader_ima_appraisal_active(cmdline_path, policy_path, 0) == 0)
		FAIL("an exclusion rule was read as appraisal");
	else
		PASS();
}

/*
 * An unreadable scope is unknown, not satisfied: no CONFIG_IMA_READ_POLICY,
 * or no privilege (the attest loop has an empty bounding set).
 * 0 would set LOTA_STATUS_KERNEL_APPRAISAL; the errno lets the startup gate
 * pass while the bit stays clear.
 */
static void test_unreadable_scope_is_not_appraised(void)
{
	TEST("an unreadable scope is not reported as appraised");

	write_file(cmdline_path, "ro quiet ima_appraise=enforce\n");
	unlink(policy_path);

	if (bpf_loader_ima_appraisal_active(cmdline_path,
					    "/nonexistent/ima/policy", 0) == 0)
		FAIL("a scope nobody could read was answered as appraising");
	else
		PASS();

	TEST("an unreadable scope says it was unreadable");

	if (bpf_loader_ima_appraisal_active(
		    cmdline_path, "/nonexistent/ima/policy", 0) != -EACCES)
		FAIL("an unreadable scope is not distinguishable from an "
		     "empty one");
	else
		PASS();

	TEST("a Secure Boot host does not appraise on an unreadable scope");

	write_file(cmdline_path, "ro quiet\n");

	if (bpf_loader_ima_appraisal_active(
		    cmdline_path, "/nonexistent/ima/policy", 1) != -EACCES)
		FAIL("the host the attest loop runs on was answered as "
		     "appraising");
	else
		PASS();
}

/*
 * The rule itself, without a file around it.
 * The installer stage that has to satisfy this gate decides on the same predicate,
 * so the shapes a loaded policy prints are asserted where both callers can see
 * them: the built-in appraise_tcb rule names no hook, the arch policy's rule
 * names one that is not exec, and the kernel pads what it prints with trailing
 * blanks.
 */
static void test_rule_shapes(void)
{
	static const struct {
		const char *rule;
		int appraises_exec;
		const char *what;
	} cases[] = {
		{ "appraise fowner=0\n", 1,
		  "the built-in appraise_tcb rule covers exec" },
		{ "appraise func=POLICY_CHECK appraise_type=imasig \n", 0,
		  "a rule naming another hook does not cover exec" },
		{ "appraise func=BPRM_CHECK appraise_type=imasig\n", 1,
		  "the rule the gate asks for covers exec" },
		{ "measure func=BPRM_CHECK\n", 0,
		  "measurement is not appraisal" },
		{ "dont_appraise func=BPRM_CHECK\n", 0,
		  "an exclusion is not appraisal" },
		{ "", 0, "an empty line appraises nothing" },
	};
	size_t i;

	for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		TEST(cases[i].what);
		if (lota_ima_policy_rule_appraises_exec(cases[i].rule) !=
		    cases[i].appraises_exec)
			FAIL("the rule was read the other way round");
		else
			PASS();
	}
}

/*
 * The mode half is not on the cmdline at all where LOTA runs. A Secure Boot
 * kernel drops ima_appraise= and keeps its own blocking default, so the gate
 * reads the parameter only on a host whose kernel honours it -- and the scope
 * is then the whole question.
 */
static void test_secureboot_ignores_the_cmdline_mode(void)
{
	TEST("a Secure Boot host appraises whatever the cmdline asked for");

	write_file(cmdline_path, "ro quiet ima_appraise=off\n");
	write_file(policy_path, policy_appraises_exec);

	if (bpf_loader_ima_appraisal_active(cmdline_path, policy_path, 1) != 0)
		FAIL("a host the kernel appraises in enforce was refused");
	else
		PASS();

	TEST("a Secure Boot host still needs the scope");

	write_file(cmdline_path, "ro quiet ima_appraise=enforce\n");
	write_file(policy_path, policy_measure_only);

	if (bpf_loader_ima_appraisal_active(cmdline_path, policy_path, 1) == 0)
		FAIL("a blocking mode over an empty scope passed");
	else
		PASS();
}

/*
 * What an unappraised kernel costs, which is not the same on every host.
 * The agent starts on one that binds its binary in the kernel and says so in
 * the token; on a host where the binary's only claim is a signature nobody
 * appraises, the same policy is fatal.
 */
static void test_secure_boot_judge(void)
{
	static const uint8_t sb_on[5] = { 0x06, 0, 0, 0, 1 };
	static const uint8_t sb_off[5] = { 0x06, 0, 0, 0, 0 };
	static const uint8_t mok_nv[5] = { 0x07, 0, 0, 0, 1 };
	static const uint8_t mok_rt[5] = { 0x06, 0, 0, 0, 1 };
	static const uint8_t mok_rt_zero[5] = { 0x06, 0, 0, 0, 0 };

	TEST("SecureBoot=1 without MokSBStateRT is on");
	if (bpf_loader_secure_boot_judge(sb_on, 5, NULL, -ENOENT) != 0)
		FAIL("a missing shim variable turned it off");
	else
		PASS();

	TEST("a NON_VOLATILE MokSBStateRT=1 is ignored, as by the kernel");
	if (bpf_loader_secure_boot_judge(sb_on, 5, mok_nv, 5) != 0)
		FAIL("a non-volatile variable turned it off");
	else
		PASS();

	TEST("a volatile MokSBStateRT=1 is shim's insecure mode");
	if (bpf_loader_secure_boot_judge(sb_on, 5, mok_rt, 5) != -EPERM)
		FAIL("insecure mode read as on");
	else if (bpf_loader_secure_boot_judge(sb_on, 5, mok_rt_zero, 5) != 0)
		FAIL("MokSBStateRT=0 turned it off");
	else if (bpf_loader_secure_boot_judge(sb_on, 5, mok_rt, 4) != 0)
		FAIL("a short shim variable turned it off");
	else
		PASS();

	TEST("SecureBoot=0, short or unread is not on");
	if (bpf_loader_secure_boot_judge(sb_off, 5, NULL, -ENOENT) != -EPERM ||
	    bpf_loader_secure_boot_judge(sb_on, 4, NULL, -ENOENT) != -EIO ||
	    bpf_loader_secure_boot_judge(sb_on, -ENOENT, NULL, -ENOENT) !=
		    -ENOENT)
		FAIL("the SecureBoot variable was misread");
	else
		PASS();
}

/* a raw BTF holding one int-returning function named @func */
static int write_btf(const char *path, const char *func)
{
	struct btf *btf = btf__new_empty();
	const void *raw;
	__u32 size;
	int proto;
	int ret = -EIO;
	int fd;

	if (!btf)
		return -ENOMEM;
	proto = btf__add_func_proto(btf, btf__add_int(btf, "int", 4,
						      BTF_INT_SIGNED));
	if (proto > 0 && btf__add_func(btf, func, BTF_FUNC_GLOBAL, proto) > 0 &&
	    (raw = btf__raw_data(btf, &size))) {
		fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
		if (fd >= 0) {
			if (write(fd, raw, size) == (ssize_t)size)
				ret = 0;
			close(fd);
		}
	}
	btf__free(btf);
	return ret;
}

static void test_appraise_built_from_btf(void)
{
	char path[64];

	snprintf(path, sizeof(path), "/tmp/lota-ima-btf-%d", (int)getpid());

	TEST("a kernel BTF with ima_appraise_measurement() appraises");
	if (write_btf(path, "ima_appraise_measurement") != 0)
		FAIL("could not write the BTF");
	else if (lota_ima_appraise_built(path) != 1)
		FAIL("the function was not found");
	else
		PASS();

	TEST("a kernel BTF without it, CONFIG_IMA_APPRAISE=n, does not");
	if (write_btf(path, "ima_must_appraise_stub") != 0)
		FAIL("could not write the BTF");
	else if (lota_ima_appraise_built(path) != 0)
		FAIL("a BTF without the function read as appraising");
	else
		PASS();

	TEST("an unparsable kernel BTF is an error");
	if (write_file(path, "not btf") != 0)
		FAIL("could not write the file");
	else if (lota_ima_appraise_built(path) >= 0)
		FAIL("garbage read as a BTF");
	else
		PASS();

	unlink(path);
}

int main(void)
{
	printf("=== IMA appraisal scope tests ===\n\n");

	snprintf(cmdline_path, sizeof(cmdline_path), "/tmp/lota-ima-cmd-%d",
		 (int)getpid());
	snprintf(policy_path, sizeof(policy_path), "/tmp/lota-ima-pol-%d",
		 (int)getpid());

	test_mode_off_is_refused();
	test_mode_fix_is_refused();
	test_last_mode_decides();
	test_mode_absent_reads_the_scope();
	test_blocking_mode_with_empty_scope_is_refused();
	test_blocking_mode_with_exec_scope_passes();
	test_appraise_without_func_covers_exec();
	test_dont_appraise_is_not_appraise();
	test_unreadable_scope_is_not_appraised();
	test_secureboot_ignores_the_cmdline_mode();
	test_rule_shapes();
	test_secure_boot_judge();
	test_appraise_built_from_btf();

	unlink(cmdline_path);
	unlink(policy_path);

	printf("\n=== %d/%d passed ===\n", tests_passed, tests_run);
	return tests_passed == tests_run ? 0 : 1;
}
