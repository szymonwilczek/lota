/* SPDX-License-Identifier: MIT */
/*
 * Unit tests for who may end a protected process.
 *
 * Title that calls lota_protect_self() is unkillable:
 * lota_task_kill passes signal only from the task itself, from the agent,
 * from a task holding LOTA_TASK_AUTH_ADMIN, or from the kernel, and the admin
 * flag lives on the agent's own PID in a frozen map.
 * Nothing else on the machine holds it, root included, so a hung title costs
 * the player a reboot.
 *
 * The way out is the agent delivering the signal on request, which makes
 * the question "on whose request".
 *
 * The rule tested here is the one kill(2) would have applied had the LSM
 * not intervened -- the owner of the process, or root -- so the verb returns
 * what the machine already had rather than granting anything new.
 *
 * Everything past that boundary is what the tests pin: signal that is not
 * termination, a process nobody protected, and the agent itself.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */
#include <signal.h>
#include <stdio.h>

#include "../src/agent/terminate_policy.h"

static int g_failures;

#define CHECK(cond, msg)                                    \
	do {                                                \
		if (!(cond)) {                              \
			fprintf(stderr, "FAIL: %s\n", msg); \
			g_failures++;                       \
		} else {                                    \
			printf("PASS: %s\n", msg);          \
		}                                           \
	} while (0)

/* request that is allowed, which each case below then spoils one field of */
static struct terminate_request base_request(void)
{
	struct terminate_request req = {
		.target_pid = 1200,
		.target_uid = 1000,
		.caller_uid = 1000,
		.caller_pid = 1300,
		.agent_pid = 900,
		.signal = SIGTERM,
		.target_is_protected = true,
	};

	return req;
}

int main(void)
{
	printf("=== protected-process termination policy tests ===\n\n");

	{
		struct terminate_request req = base_request();

		CHECK(terminate_policy_decide(&req) == TERMINATE_ALLOW,
		      "the owner of a protected process may end it");
	}

	{
		struct terminate_request req = base_request();

		req.caller_uid = 0;
		CHECK(terminate_policy_decide(&req) == TERMINATE_ALLOW,
		      "root may end a protected process it does not own");
	}

	{
		struct terminate_request req = base_request();

		req.signal = SIGKILL;
		CHECK(terminate_policy_decide(&req) == TERMINATE_ALLOW,
		      "SIGKILL is a termination");
	}

	/*
	 * verb exists to end a process, not to become a general signal relay:
	 * anything a protected process handles rather than dies from would let
	 * a caller drive it while it stays in the measured set.
	 */
	{
		struct terminate_request req = base_request();

		req.signal = SIGUSR1;
		CHECK(terminate_policy_decide(&req) == TERMINATE_DENY_SIGNAL,
		      "a signal that is not a termination is refused");
		req.signal = 0;
		CHECK(terminate_policy_decide(&req) == TERMINATE_DENY_SIGNAL,
		      "an existence probe is refused: kill(2) already answers it");
		req.signal = SIGSTOP;
		CHECK(terminate_policy_decide(&req) == TERMINATE_DENY_SIGNAL,
		      "stopping a protected process is not ending it");
	}

	{
		struct terminate_request req = base_request();

		req.caller_uid = 1001;
		CHECK(terminate_policy_decide(&req) == TERMINATE_DENY_OWNER,
		      "a stranger to the process is refused, as kill(2) would refuse them");
	}

	/*
	 * unprotected process is reachable with kill(2) by whoever the kernel
	 * allows, so relaying one through the agent would only add a path that
	 * answers with the agent's privilege instead of the caller's.
	 */
	{
		struct terminate_request req = base_request();

		req.target_is_protected = false;
		CHECK(terminate_policy_decide(&req) ==
			      TERMINATE_DENY_NOT_PROTECTED,
		      "a process nobody protected is not this verb's business");
	}

	/*
	 * stopping the agent is --shutdown's job and a reboot is that path's
	 * security contract, because PCR 14 commits for the whole boot.
	 * Ending the agent here would retire enforcement while the machine keeps
	 * running and still reads as attested.
	 */
	{
		struct terminate_request req = base_request();

		req.target_pid = req.agent_pid;
		req.caller_uid = 0;
		CHECK(terminate_policy_decide(&req) == TERMINATE_DENY_AGENT,
		      "the agent is not terminated through the verb it serves");
	}

	{
		struct terminate_request req = base_request();

		req.target_pid = 0;
		CHECK(terminate_policy_decide(&req) == TERMINATE_DENY_TARGET,
		      "PID 0 is a process group, not a process");
		req.target_pid = 1;
		req.caller_uid = 0;
		req.target_uid = 0;
		CHECK(terminate_policy_decide(&req) == TERMINATE_DENY_TARGET,
		      "PID 1 is refused even to root: no title is init");
	}

	CHECK(terminate_policy_decide(NULL) == TERMINATE_DENY_TARGET,
	      "a missing request is refused rather than assumed");

	printf("\n%s\n", g_failures ? "FAILURES" : "All tests passed");
	return g_failures ? 1 : 0;
}
