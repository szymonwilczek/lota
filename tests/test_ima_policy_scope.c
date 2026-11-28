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
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "test.h"
#include "../include/lota_ima_appraise.h"
#include "../include/lota_ima_policy_scope.h"
#include "../include/lota_secure_boot.h"
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
}

/* fix repairs a failing xattr and passes the access */
static void test_mode_fix_is_refused(void)
{
	TEST("ima_appraise=fix is refused whatever the policy says");

	write_file(cmdline_path, "ro quiet ima=on ima_appraise=fix\n");
	write_file(policy_path, policy_appraises_exec);

	if (bpf_loader_ima_appraisal_active(cmdline_path, policy_path, 0) == 0)
		FAIL("ima_appraise=fix passed the gate");
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
}

static void test_blocking_mode_with_exec_scope_passes(void)
{
	TEST("a blocking mode over a policy that appraises exec passes");

	write_file(cmdline_path, "ro quiet ima=on ima_appraise=enforce\n");
	write_file(policy_path, policy_appraises_exec);

	if (bpf_loader_ima_appraisal_active(cmdline_path, policy_path, 0) != 0)
		FAIL("a host with the floor in place was refused");
}

/* A rule naming no hook applies to every hook, exec included */
static void test_appraise_without_func_covers_exec(void)
{
	TEST("an appraise rule naming no func covers exec");

	write_file(cmdline_path, "ro quiet ima_appraise=enforce\n");
	write_file(policy_path, "appraise fowner=0 appraise_type=imasig\n");

	if (bpf_loader_ima_appraisal_active(cmdline_path, policy_path, 0) != 0)
		FAIL("a policy-wide appraise rule was not counted");
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

	TEST("an unreadable scope says it was unreadable");

	if (bpf_loader_ima_appraisal_active(
		    cmdline_path, "/nonexistent/ima/policy", 0) != -EACCES)
		FAIL("an unreadable scope is not distinguishable from an "
		     "empty one");

	TEST("a Secure Boot host does not appraise on an unreadable scope");

	write_file(cmdline_path, "ro quiet\n");

	if (bpf_loader_ima_appraisal_active(
		    cmdline_path, "/nonexistent/ima/policy", 1) != -EACCES)
		FAIL("the host the attest loop runs on was answered as "
		     "appraising");
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

	TEST("a Secure Boot host still needs the scope");

	write_file(cmdline_path, "ro quiet ima_appraise=enforce\n");
	write_file(policy_path, policy_measure_only);

	if (bpf_loader_ima_appraisal_active(cmdline_path, policy_path, 1) == 0)
		FAIL("a blocking mode over an empty scope passed");
}

/* a volatile efivar holding @value */
static void write_efivar(const char *path, uint8_t value)
{
	const uint8_t var[5] = { 0x06, 0, 0, 0, value };
	int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);

	if (fd < 0)
		return;
	if (write(fd, var, sizeof(var)) != (ssize_t)sizeof(var))
		FAIL("short write to %s", path);
	close(fd);
}

/* each efivar combination as the EFI stub judges it */
static void test_secure_boot_judge(void)
{
	static const uint8_t on[5] = { 0x06, 0, 0, 0, 1 };
	static const uint8_t off[5] = { 0x06, 0, 0, 0, 0 };
	static const uint8_t nv_on[5] = { 0x07, 0, 0, 0, 1 };
	static const struct {
		const uint8_t *sb, *setup, *mok;
		ssize_t sb_len, setup_len, mok_len;
		int want;
	} cases[] = {
		{ on, NULL, NULL, 5, -ENOENT, -ENOENT, LOTA_SECURE_BOOT_ON },
		{ on, off, off, 5, 5, 5, LOTA_SECURE_BOOT_ON },
		{ on, on, NULL, 5, 5, -ENOENT, LOTA_SECURE_BOOT_SETUP_MODE },
		{ on, on, NULL, 5, 4, -ENOENT, LOTA_SECURE_BOOT_ON },
		{ on, off, on, 5, 5, 5, LOTA_SECURE_BOOT_SHIM_INSECURE },
		{ on, off, nv_on, 5, 5, 5, LOTA_SECURE_BOOT_ON },
		{ on, off, on, 5, 5, 4, LOTA_SECURE_BOOT_ON },
		{ on, on, on, 5, 5, 5, LOTA_SECURE_BOOT_SETUP_MODE },
		{ off, on, on, 5, 5, 5, LOTA_SECURE_BOOT_OFF },
		{ on, NULL, NULL, 4, -ENOENT, -ENOENT, -EIO },
		{ NULL, NULL, NULL, -ENOENT, -ENOENT, -ENOENT, -ENOENT },
	};
	char dir[] = "/tmp/lota-efivars-XXXXXX";
	char path[128];
	int bad = -1;

	TEST("SecureBoot, SetupMode and MokSBStateRT read as the stub does");
	for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		if (lota_secure_boot_judge(cases[i].sb, cases[i].sb_len,
					   cases[i].setup, cases[i].setup_len,
					   cases[i].mok,
					   cases[i].mok_len) != cases[i].want) {
			bad = (int)i;
			break;
		}
	}
	if (bad >= 0)
		FAIL("an efivar combination was judged wrong");

	TEST("the state is read from an efivarfs directory");
	if (!mkdtemp(dir)) {
		FAIL("mkdtemp");
		return;
	}
	snprintf(path, sizeof(path), "%s/%s", dir, LOTA_EFIVAR_SECURE_BOOT);
	write_efivar(path, 1);
	if (lota_secure_boot_read(dir) != LOTA_SECURE_BOOT_ON) {
		FAIL("SecureBoot=1 alone was not on");
	} else {
		snprintf(path, sizeof(path), "%s/%s", dir,
			 LOTA_EFIVAR_SETUP_MODE);
		write_efivar(path, 1);
		if (lota_secure_boot_read(dir) != LOTA_SECURE_BOOT_SETUP_MODE)
			FAIL("SetupMode=1 was not read");
		unlink(path);
	}
	snprintf(path, sizeof(path), "%s/%s", dir, LOTA_EFIVAR_SECURE_BOOT);
	unlink(path);
	rmdir(dir);
}

/* each cmdline as the kernel splits and matches it */
static void test_cmdline_mode_as_the_kernel_reads_it(void)
{
	static const struct {
		const char *cmdline;
		int enforce;
	} cases[] = {
		{ "ro quiet\n", 1 },
		{ "ima_appraise=fix\n", 0 },
		{ "ima_appraise=off -- ima_appraise=enforce", 0 },
		{ "ima_appraise=enforce -- ima_appraise=fix", 1 },
		{ "\"--\" ima_appraise=fix", 1 },
		{ "--x ima_appraise=fix", 0 },
		{ "ima_appraise=enforcex", 1 },
		{ "ima_appraise=fixme", 0 },
		{ "ima_appraise=bogus", 1 },
		{ "ima_appraise=", 1 },
		{ "ima-appraise=log", 0 },
		{ "ima_appraise=\"fix\"", 0 },
		{ "\"ima_appraise=off\"", 0 },
		{ "x=\"a ima_appraise=fix b\"", 1 },
		{ "ima_appraise_x=off", 1 },
	};

	TEST("the cmdline mode is read as the kernel reads it");
	for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		if (lota_ima_cmdline_enforce(cases[i].cmdline) !=
		    cases[i].enforce) {
			FAIL("%s", cases[i].cmdline);
			return;
		}
	}

	write_file(policy_path, policy_appraises_exec);
	write_file(cmdline_path,
		   "ro ima_appraise=off -- ima_appraise=enforce\n");
	if (bpf_loader_ima_appraisal_active(cmdline_path, policy_path, 0) !=
	    -EPERM)
		FAIL("an ima_appraise= past -- decided the gate");
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

	TEST("a kernel BTF without it, CONFIG_IMA_APPRAISE=n, does not");
	if (write_btf(path, "ima_must_appraise_stub") != 0)
		FAIL("could not write the BTF");
	else if (lota_ima_appraise_built(path) != 0)
		FAIL("a BTF without the function read as appraising");

	TEST("an unparsable kernel BTF is an error");
	if (write_file(path, "not btf") != 0)
		FAIL("could not write the file");
	else if (lota_ima_appraise_built(path) >= 0)
		FAIL("garbage read as a BTF");

	unlink(path);
}

int main(void)
{
	test_begin("ima policy scope");

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
	test_cmdline_mode_as_the_kernel_reads_it();

	unlink(cmdline_path);
	unlink(policy_path);

	return test_end();
}
