/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * Unit tests for what a refused daemon start tells its supervisor.
 *
 * The packaged unit carries RestartPreventExitStatus=78 and Restart=on-failure
 * with RestartSec=5s, so the exit status decides between a unit that sits failed
 * with the reason in the journal and one that starts again every five seconds
 * until its fifth start.
 *
 * The refusals that matter here are the PCR 14 verdicts. The boot commitment
 * can be spent once per boot and the register is not resettable from userspace,
 * so every verdict that refuses the extend refuses it for the rest of the boot
 * -- and each attempt still opens the TPM, provisions the AIK and lays down
 * the container socket before finding that out.
 *
 * Nothing here needs a TPM: the verdict is an input, exactly as
 * tpm_classify_pcr14() made it.
 */

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "test.h"
#include "../src/agent/exit_status.h"
#include "../src/agent/tpm.h"

/* The verdicts that refuse the extend, all of which -EBADMSG reaches main. */
static const enum tpm_pcr14_state refusing_verdicts[] = {
	TPM_PCR14_LOCK_MISSING,		 TPM_PCR14_SPENT_BY_SHUTDOWN,
	TPM_PCR14_SPENT_BY_ERROR,	 TPM_PCR14_BINARY_CHANGED,
	TPM_PCR14_TAMPERED_BEFORE_START, TPM_PCR14_MUTATED_IN_SESSION,
	TPM_PCR14_HANDOFF_CHANGED,	 TPM_PCR14_UNATTRIBUTABLE,
	TPM_PCR14_STATE_ROLLBACK,
};

static const char *verdict_name(enum tpm_pcr14_state state)
{
	switch (state) {
	case TPM_PCR14_AWAITING_EXTEND:
		return "awaiting extend";
	case TPM_PCR14_ALREADY_COMMITTED:
		return "already committed";
	case TPM_PCR14_LOCK_MISSING:
		return "lock missing";
	case TPM_PCR14_SPENT_BY_SHUTDOWN:
		return "spent by shutdown";
	case TPM_PCR14_SPENT_BY_ERROR:
		return "spent by error";
	case TPM_PCR14_BINARY_CHANGED:
		return "binary changed";
	case TPM_PCR14_TAMPERED_BEFORE_START:
		return "tampered before start";
	case TPM_PCR14_MUTATED_IN_SESSION:
		return "mutated in session";
	case TPM_PCR14_HANDOFF_CHANGED:
		return "handoff changed";
	case TPM_PCR14_UNATTRIBUTABLE:
		return "unattributable";
	case TPM_PCR14_STATE_ROLLBACK:
		return "state rollback";
	}
	return "unnamed";
}

/*
 * An agent paused by a shutdown requested on this host refuses with -EBADMSG
 * for the rest of the boot.
 */
static void test_spent_commitment_needs_an_operator(void)
{
	int rc = lota_daemon_exit_status(-EBADMSG, TPM_PCR14_SPENT_BY_SHUTDOWN);

	TEST("a commitment spent by shutdown exits for an operator");
	if (rc != LOTA_EXIT_OPERATOR_ACTION)
		FAIL("a refusal only a reboot can clear is restartable");
	else
		PASS();
}

/* Every other refusing verdict is the same class: the register is spent. */
static void test_every_refusing_verdict_needs_an_operator(void)
{
	size_t i;

	for (i = 0; i < sizeof(refusing_verdicts) / sizeof(*refusing_verdicts);
	     i++) {
		enum tpm_pcr14_state state = refusing_verdicts[i];
		int rc = lota_daemon_exit_status(-EBADMSG, state);

		TEST(verdict_name(state));
		if (rc != LOTA_EXIT_OPERATOR_ACTION)
			FAIL("restarting into this verdict cannot clear it");
		else
			PASS();
	}
}

/*
 * A failure before the commitment that a restart may clear exits 1,
 * the status Restart=on-failure retries; its errno is in the log.
 */
static void test_a_correctable_refusal_stays_restartable(void)
{
	int rc = lota_daemon_exit_status(-ENOENT, TPM_PCR14_AWAITING_EXTEND);

	TEST("a failure before the commitment exits 1");
	if (rc == LOTA_EXIT_OPERATOR_ACTION)
		FAIL("a correctable refusal was routed to the operator exit");
	else if (rc != 1)
		FAIL("the errno leaked into the exit status");
	else
		PASS();
}

/*
 * The exit status is the low byte: -EKEYREJECTED read as 127,
 * the shell's "command not found", and -EPERM as 255.
 */
static void test_no_errno_reaches_the_exit_status(void)
{
	static const int errnos[] = { EKEYREJECTED, EACCES, EPERM,
				      EBADMSG,	    ENOMEM, EIO };
	size_t i;

	TEST("every errno exits 1");
	for (i = 0; i < sizeof(errnos) / sizeof(*errnos); i++) {
		if (lota_daemon_exit_status(-errnos[i],
					    TPM_PCR14_AWAITING_EXTEND) != 1) {
			FAIL(strerror(errnos[i]));
			return;
		}
	}
	PASS();
}

/*
 * The policy, the object's signature and its layout are refused before
 * the commitment, from files a restart reads again unchanged.
 */
static void test_a_refusal_before_the_commitment_needs_an_operator(void)
{
	int rc = lota_daemon_exit_status(LOTA_EXIT_OPERATOR_ACTION,
					 TPM_PCR14_AWAITING_EXTEND);

	TEST("a refusal of the policy or the object exits for an operator");
	if (rc != LOTA_EXIT_OPERATOR_ACTION)
		FAIL("the status run_daemon() chose did not survive");
	else
		PASS();
}

/* The mapping that was already there, kept honest. */
static void test_refused_host_configuration_needs_an_operator(void)
{
	int rc = lota_daemon_exit_status(-ENOTSUP, TPM_PCR14_AWAITING_EXTEND);

	TEST("a host configuration the agent refuses exits for an operator");
	if (rc != LOTA_EXIT_OPERATOR_ACTION)
		FAIL("-ENOTSUP no longer reaches the operator exit");
	else
		PASS();
}

/*
 * A key in the TPM whose record is missing from disk: a restart reads the
 * same directory and refuses the same key.
 */
static void test_a_key_with_no_record_needs_an_operator(void)
{
	int rc = lota_daemon_exit_status(-EKEYREVOKED,
					 TPM_PCR14_AWAITING_EXTEND);

	TEST("a key with no record exits for an operator");
	if (rc != LOTA_EXIT_OPERATOR_ACTION)
		FAIL("-EKEYREVOKED exits for a restart");
	else
		PASS();
}

/*
 * A startup check that could not read its input exits 1 and is retried;
 * one that refused what it read exits for an operator.
 */
static void test_a_startup_check_that_could_not_read_is_retried(void)
{
	static const int transient[] = { EIO,	 EMFILE, ENFILE, ENOMEM,
					 EAGAIN, EINTR,	 EBUSY };
	static const int refused[] = { EKEYREJECTED, ENOENT, EINVAL,
				       EBADMSG,	     ENOSPC, ENOTSUP,
				       ENODATA,	     EACCES, 4003 };
	size_t i;

	TEST("a startup check that could not read exits 1");
	for (i = 0; i < sizeof(transient) / sizeof(*transient); i++) {
		if (lota_startup_check_exit_status(-transient[i]) != 1) {
			FAIL(strerror(transient[i]));
			return;
		}
	}
	PASS();

	TEST("a startup check that refused what it read exits for an operator");
	for (i = 0; i < sizeof(refused) / sizeof(*refused); i++) {
		if (lota_startup_check_exit_status(-refused[i]) !=
		    LOTA_EXIT_OPERATOR_ACTION) {
			FAIL(strerror(refused[i]));
			return;
		}
	}
	PASS();
}

/*
 * A kernel that refuses the object refuses it again on the restart,
 * which finds PCR 14 already committed and would exit 1.
 */
static void test_a_refused_object_needs_an_operator(void)
{
	static const int refused[] = { EINVAL, EACCES, EPERM,	ESRCH,
				       ENOENT, E2BIG,  ENOTSUP, ENOEXEC };
	static const int transient[] = { EIO,	 EMFILE, ENFILE, ENOMEM,
					 EAGAIN, EINTR,	 EBUSY };
	size_t i;

	TEST("a refused object exits for an operator");
	for (i = 0; i < sizeof(refused) / sizeof(*refused); i++) {
		if (lota_daemon_exit_status(lota_bpf_load_refusal(-refused[i]),
					    TPM_PCR14_ALREADY_COMMITTED) !=
		    LOTA_EXIT_OPERATOR_ACTION) {
			FAIL(strerror(refused[i]));
			return;
		}
	}
	PASS();

	TEST("a load that could not finish exits 1");
	for (i = 0; i < sizeof(transient) / sizeof(*transient); i++) {
		int err = lota_bpf_load_refusal(-transient[i]);

		if (lota_daemon_exit_status(err, TPM_PCR14_ALREADY_COMMITTED) !=
		    1) {
			FAIL(strerror(transient[i]));
			return;
		}
	}
	PASS();
}

/* A daemon that served and stopped carries its own status out. */
static void test_a_served_daemon_carries_its_own_status(void)
{
	int rc = lota_daemon_exit_status(0, TPM_PCR14_ALREADY_COMMITTED);

	TEST("a daemon that served exits 0");
	if (rc != 0)
		FAIL("a clean stop did not exit 0");
	else if (lota_daemon_exit_status(-EBADF, TPM_PCR14_ALREADY_COMMITTED) !=
		 1)
		FAIL("a failed event loop does not exit 1");
	else
		PASS();
}

static FILE *open_unit(const char *unit)
{
	char path[256];
	FILE *fp;

	snprintf(path, sizeof(path), "systemd/%s", unit);
	fp = fopen(path, "re");
	if (!fp) {
		snprintf(path, sizeof(path), "../systemd/%s", unit);
		fp = fopen(path, "re");
	}
	return fp;
}

/* copy the value of @unit's last [Unit] @key= into @out; false when none */
static bool unit_value(const char *unit, const char *key, char *out, size_t cap)
{
	size_t len = strlen(key);
	char line[512];
	bool in_unit = false;
	bool found = false;
	FILE *fp = open_unit(unit);

	if (!fp)
		return false;
	while (fgets(line, sizeof(line), fp)) {
		if (line[0] == '[')
			in_unit = strncmp(line, "[Unit]", 6) == 0;
		if (!in_unit || strncmp(line, key, len) != 0 ||
		    line[len] != '=')
			continue;
		snprintf(out, cap, "%.*s", (int)strcspn(line + len + 1, "\n"),
			 line + len + 1);
		found = true;
	}
	fclose(fp);

	return found;
}

/* whether @unit's RestartPreventExitStatus= lists @status */
static bool unit_prevents_restart_on(const char *unit, int status)
{
	char line[512];
	char wanted[64];
	bool found = false;
	FILE *fp = open_unit(unit);

	if (!fp)
		return false;

	snprintf(wanted, sizeof(wanted), "%d", status);
	while (fgets(line, sizeof(line), fp)) {
		if (strncmp(line, "RestartPreventExitStatus=", 25) != 0)
			continue;
		if (strstr(line + 25, wanted))
			found = true;
	}
	fclose(fp);

	return found;
}

static void test_the_unit_prevents_restarting_on_that_status(void)
{
	TEST("the packaged unit prevents a restart on that status");

	if (!unit_prevents_restart_on("lota-agent.service",
				      LOTA_EXIT_OPERATOR_ACTION))
		FAIL("RestartPreventExitStatus does not list the status");
	else
		PASS();
}

/*
 * A failure a restart does not clear exits 1 on every start. A finite interval
 * misses one whose starts are spaced wider than interval / burst.
 */
static void test_the_unit_stops_a_failure_that_repeats(void)
{
	char interval[64] = "";
	char burst[64] = "";

	TEST("the packaged unit stops restarting a failure that repeats");
	if (!unit_value("lota-agent.service", "StartLimitIntervalSec", interval,
			sizeof(interval)) ||
	    !unit_value("lota-agent.service", "StartLimitBurst", burst,
			sizeof(burst)))
		FAIL("the unit sets no start limit");
	else if (strcmp(interval, "infinity") != 0)
		FAIL("the interval is not infinity");
	else if (strtol(burst, NULL, 10) <= 0)
		FAIL("the burst is not a positive count");
	else
		PASS();
}

/* @unit's first @key= line with its continuations joined; false when none */
static bool unit_logical_line(const char *unit, const char *key, char *out,
			      size_t cap)
{
	size_t len = strlen(key);
	char line[512];
	bool found = false;
	bool more = false;
	FILE *fp = open_unit(unit);

	if (!fp)
		return false;
	out[0] = '\0';
	while (fgets(line, sizeof(line), fp)) {
		size_t n;

		if (!found &&
		    (strncmp(line, key, len) != 0 || line[len] != '='))
			continue;
		if (found && !more)
			break;
		found = true;
		n = strcspn(line, "\n");
		more = n > 0 && line[n - 1] == '\\';
		if (more)
			n--;
		strncat(out, line,
			cap - strlen(out) - 1 < n ? cap - strlen(out) - 1 : n);
	}
	fclose(fp);

	return found;
}

/*
 * A connection queued on lota-agent.socket starts the unit again after
 * a refusal; the unit stops the socket on that status alone.
 */
static void test_the_unit_stops_its_socket_on_that_status(void)
{
	char cmd[1024];
	char status[64];

	snprintf(status, sizeof(status), "\"$$EXIT_STATUS\" = %d",
		 LOTA_EXIT_OPERATOR_ACTION);
	TEST("the packaged unit stops its socket on that status");
	if (!unit_logical_line("lota-agent.service", "ExecStopPost", cmd,
			       sizeof(cmd)))
		FAIL("the unit has no ExecStopPost");
	else if (!strstr(cmd, "\"$$EXIT_CODE\" = exited") ||
		 !strstr(cmd, status))
		FAIL("the stop is not conditioned on exit status 78");
	else if (!strstr(cmd, "systemctl --no-block stop lota-agent.socket"))
		FAIL("the socket is not stopped without blocking");
	else
		PASS();
}

/*
 * The second status the unit has to know about.
 *
 * A start under a running agent -- which is what systemd attempts every time
 * something restarts lota-agent.socket, since it cannot kill the daemon that
 * is already serving -- refuses on the PID file. On the generic failure status
 * the unit retried it every five seconds for the rest of the boot while the
 * real agent went on enforcing, so the number and the unit are held together
 * here the same way.
 */
static void test_the_unit_does_not_retry_a_running_instance(void)
{
	TEST("the packaged unit does not retry under a running agent");

	if (!unit_prevents_restart_on("lota-agent.service",
				      LOTA_EXIT_ALREADY_RUNNING))
		FAIL("RestartPreventExitStatus does not list the status");
	else
		PASS();
}

/*
 * A restart between an agent upgrade and the reboot meets a PCR 14 committed
 * to the old binary; without the status the attest unit retries every 30 s
 * until reboot, stuck in activating.
 */
static void test_the_attest_unit_stops_on_a_spent_commitment(void)
{
	TEST("the attest unit prevents a restart on that status");

	if (!unit_prevents_restart_on("lota-attest.service",
				      LOTA_EXIT_OPERATOR_ACTION))
		FAIL("RestartPreventExitStatus does not list the status");
	else
		PASS();
}

/*
 * The two statuses have to stay distinct: one says an operator has to change
 * the host, the other says nothing is wrong with it.
 */
static void test_the_two_no_retry_statuses_differ(void)
{
	TEST("a busy start and a refused host are told apart");

	if (LOTA_EXIT_ALREADY_RUNNING == LOTA_EXIT_OPERATOR_ACTION)
		FAIL("the two no-retry statuses collapsed into one");
	else
		PASS();
}

int main(void)
{
	printf("=== Daemon exit status tests ===\n\n");

	test_spent_commitment_needs_an_operator();
	test_every_refusing_verdict_needs_an_operator();
	test_a_correctable_refusal_stays_restartable();
	test_no_errno_reaches_the_exit_status();
	test_a_refusal_before_the_commitment_needs_an_operator();
	test_refused_host_configuration_needs_an_operator();
	test_a_key_with_no_record_needs_an_operator();
	test_a_startup_check_that_could_not_read_is_retried();
	test_a_refused_object_needs_an_operator();
	test_a_served_daemon_carries_its_own_status();
	test_the_unit_prevents_restarting_on_that_status();
	test_the_unit_stops_a_failure_that_repeats();
	test_the_unit_stops_its_socket_on_that_status();
	test_the_unit_does_not_retry_a_running_instance();
	test_the_attest_unit_stops_on_a_spent_commitment();
	test_the_two_no_retry_statuses_differ();

	printf("\n=== %d/%d passed ===\n", tests_passed, tests_run);
	return tests_passed == tests_run ? 0 : 1;
}
