/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * Unit tests for what a refused daemon start tells its supervisor.
 *
 * The packaged unit carries RestartPreventExitStatus=78 and Restart=on-failure
 * with RestartSec=5s, so the exit status decides between a unit that sits failed
 * with the reason in the journal and one that starts again every five seconds
 * until the host reboots. StartLimitBurst does not save it: RestartSec spaces
 * the attempts wider than StartLimitIntervalUSec, so the burst counter never
 * fills.
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
#include <string.h>

#include "../src/agent/exit_status.h"
#include "../src/agent/tpm.h"

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

/* The verdicts that refuse the extend, all of which -EBADMSG reaches main. */
static const enum tpm_pcr14_state refusing_verdicts[] = {
	TPM_PCR14_LOCK_MISSING,	      TPM_PCR14_SPENT_BY_SHUTDOWN,
	TPM_PCR14_BINARY_CHANGED,     TPM_PCR14_TAMPERED_BEFORE_START,
	TPM_PCR14_MUTATED_IN_SESSION, TPM_PCR14_UNATTRIBUTABLE,
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
	case TPM_PCR14_BINARY_CHANGED:
		return "binary changed";
	case TPM_PCR14_TAMPERED_BEFORE_START:
		return "tampered before start";
	case TPM_PCR14_MUTATED_IN_SESSION:
		return "mutated in session";
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
 * A configuration the operator can correct without rebooting keeps its errno:
 * the boot commitment was never reached, so the unit is free to try again once
 * the file is fixed.
 */
static void test_a_correctable_refusal_stays_restartable(void)
{
	int rc = lota_daemon_exit_status(-ENOENT, TPM_PCR14_AWAITING_EXTEND);

	TEST("a refusal before the commitment keeps its errno");
	if (rc == LOTA_EXIT_OPERATOR_ACTION)
		FAIL("a correctable refusal was routed to the operator exit");
	else if (rc != -ENOENT)
		FAIL("the errno the daemon returned did not survive");
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

/* A daemon that served and stopped carries its own status out. */
static void test_a_served_daemon_carries_its_own_status(void)
{
	int rc = lota_daemon_exit_status(0, TPM_PCR14_ALREADY_COMMITTED);

	TEST("a daemon that served exits 0");
	if (rc != 0)
		FAIL("a clean stop did not exit 0");
	else
		PASS();
}

/*
 * The unit file's behaviour depends on the number, not on the name,
 * so the two are compared here.
 */
static void test_the_unit_prevents_restarting_on_that_status(void)
{
	char line[512];
	char wanted[64];
	bool found = false;
	FILE *fp = fopen("systemd/lota-agent.service", "re");

	if (!fp)
		fp = fopen("../systemd/lota-agent.service", "re");

	TEST("the packaged unit prevents a restart on that status");
	if (!fp) {
		FAIL("could not open lota-agent.service");
		return;
	}

	snprintf(wanted, sizeof(wanted), "%d", LOTA_EXIT_OPERATOR_ACTION);
	while (fgets(line, sizeof(line), fp)) {
		if (strncmp(line, "RestartPreventExitStatus=", 25) != 0)
			continue;
		if (strstr(line + 25, wanted))
			found = true;
	}
	fclose(fp);

	if (!found)
		FAIL("RestartPreventExitStatus does not list the status");
	else
		PASS();
}

int main(void)
{
	printf("=== Daemon exit status tests ===\n\n");

	test_spent_commitment_needs_an_operator();
	test_every_refusing_verdict_needs_an_operator();
	test_a_correctable_refusal_stays_restartable();
	test_refused_host_configuration_needs_an_operator();
	test_a_served_daemon_carries_its_own_status();
	test_the_unit_prevents_restarting_on_that_status();

	printf("\n=== %d/%d passed ===\n", tests_passed, tests_run);
	return tests_passed == tests_run ? 0 : 1;
}
