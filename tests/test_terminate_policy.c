/* SPDX-License-Identifier: MIT */
/*
 * Unit tests for who may end a protected process.
 *
 * The agent delivers SIGTERM or SIGKILL to a protected title on request
 * and journals it, which makes the question "on whose request".
 *
 * The rule tested here is the one kill(2) applies -- the owner of the
 * process, or root -- so the verb grants nothing the caller lacks.
 *
 * Everything past that boundary is what the tests pin: signal that is not
 * termination, a process nobody protected, and the agent itself.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */
#include <signal.h>

#include "../src/agent/terminate_policy.h"

#include "test.h"

/* request that is allowed, which each case below then spoils one field of */
static struct terminate_request base_request(void)
{
	struct terminate_request req = {
		.target_pid = 1200,
		.target_uid = 1000,
		.caller_uid = 1000,
		.agent_pid = 900,
		.signal = SIGTERM,
		.target_is_protected = true,
	};

	return req;
}

int main(void)
{
	test_begin("terminate policy");

	{
		struct terminate_request req = base_request();

		TEST("the owner of a protected process may end it");
		if (terminate_policy_decide(&req) != TERMINATE_ALLOW)
			FAIL("expected: terminate_policy_decide(&req) == "
			     "TERMINATE_ALLOW");
	}

	{
		struct terminate_request req = base_request();

		req.caller_uid = 0;
		TEST("root may end a protected process it does not own");
		if (terminate_policy_decide(&req) != TERMINATE_ALLOW)
			FAIL("expected: terminate_policy_decide(&req) == "
			     "TERMINATE_ALLOW");
	}

	{
		struct terminate_request req = base_request();

		req.signal = SIGKILL;
		TEST("SIGKILL is a termination");
		if (terminate_policy_decide(&req) != TERMINATE_ALLOW)
			FAIL("expected: terminate_policy_decide(&req) == "
			     "TERMINATE_ALLOW");
	}

	/*
	 * verb exists to end a process, not to become a general signal relay:
	 * anything a protected process handles rather than dies from would let
	 * a caller drive it while it stays in the measured set.
	 */
	{
		struct terminate_request req = base_request();

		req.signal = SIGUSR1;
		TEST("a signal that is not a termination is refused");
		if (terminate_policy_decide(&req) != TERMINATE_DENY_SIGNAL)
			FAIL("expected: terminate_policy_decide(&req) == "
			     "TERMINATE_DENY_SIGNAL");
		req.signal = 0;
		TEST("an existence probe is refused: kill(2) already answers it");
		if (terminate_policy_decide(&req) != TERMINATE_DENY_SIGNAL)
			FAIL("expected: terminate_policy_decide(&req) == "
			     "TERMINATE_DENY_SIGNAL");
		req.signal = SIGSTOP;
		TEST("stopping a protected process is not ending it");
		if (terminate_policy_decide(&req) != TERMINATE_DENY_SIGNAL)
			FAIL("expected: terminate_policy_decide(&req) == "
			     "TERMINATE_DENY_SIGNAL");
	}

	{
		struct terminate_request req = base_request();

		req.caller_uid = 1001;
		TEST("a stranger to the process is refused, as by kill(2)");
		if (terminate_policy_decide(&req) != TERMINATE_DENY_OWNER)
			FAIL("expected: terminate_policy_decide(&req) == "
			     "TERMINATE_DENY_OWNER");
	}

	/*
	 * unprotected process is reachable with kill(2) by whoever the kernel
	 * allows, so relaying one through the agent would only add a path that
	 * answers with the agent's privilege instead of the caller's.
	 */
	{
		struct terminate_request req = base_request();

		req.target_is_protected = false;
		TEST("a process nobody protected is not this verb's business");
		if (terminate_policy_decide(&req) !=
		    TERMINATE_DENY_NOT_PROTECTED)
			FAIL("expected: terminate_policy_decide(&req) == "
			     "TERMINATE_DENY_NOT_PROTECTED");
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
		TEST("the agent is not terminated through the verb it serves");
		if (terminate_policy_decide(&req) != TERMINATE_DENY_AGENT)
			FAIL("expected: terminate_policy_decide(&req) == "
			     "TERMINATE_DENY_AGENT");
	}

	{
		struct terminate_request req = base_request();

		req.target_pid = 0;
		TEST("PID 0 is a process group, not a process");
		if (terminate_policy_decide(&req) != TERMINATE_DENY_TARGET)
			FAIL("expected: terminate_policy_decide(&req) == "
			     "TERMINATE_DENY_TARGET");
		req.target_pid = 1;
		req.caller_uid = 0;
		req.target_uid = 0;
		TEST("PID 1 is refused even to root: no title is init");
		if (terminate_policy_decide(&req) != TERMINATE_DENY_TARGET)
			FAIL("expected: terminate_policy_decide(&req) == "
			     "TERMINATE_DENY_TARGET");
	}

	TEST("a missing request is refused rather than assumed");
	if (terminate_policy_decide(NULL) != TERMINATE_DENY_TARGET)
		FAIL("expected: terminate_policy_decide(NULL) == "
		     "TERMINATE_DENY_TARGET");

	/*
	 * Caller sees a wire code, not the sentence, so the code has to separate
	 * the cases a player can act on.
	 * One code for all of them makes a refusal say the wrong thing:
	 * live run had the agent's own PID and PID 1 both reported as
	 * "belongs to another user"
	 */
	TEST("an unprotected target has a code of its own");
	if (terminate_decision_result(TERMINATE_DENY_NOT_PROTECTED) !=
	    LOTA_IPC_ERR_NOT_PROTECTED)
		FAIL("expected: terminate_decision_result(TERMINATE_DENY_NOT_PROTECTED) "
		     "== LOTA_IPC_ERR_NOT_PROTECTED");
	TEST("a target this verb does not speak for has a code of its own");
	if (terminate_decision_result(TERMINATE_DENY_TARGET) !=
	    LOTA_IPC_ERR_TARGET_REFUSED)
		FAIL("expected: terminate_decision_result(TERMINATE_DENY_TARGET) "
		     "== LOTA_IPC_ERR_TARGET_REFUSED");
	TEST("the agent is refused as a target, not as a caller");
	if (terminate_decision_result(TERMINATE_DENY_AGENT) !=
	    LOTA_IPC_ERR_TARGET_REFUSED)
		FAIL("expected: terminate_decision_result(TERMINATE_DENY_AGENT) "
		     "== LOTA_IPC_ERR_TARGET_REFUSED");
	TEST("a caller who does not own the process is denied access");
	if (terminate_decision_result(TERMINATE_DENY_OWNER) !=
	    LOTA_IPC_ERR_ACCESS_DENIED)
		FAIL("expected: terminate_decision_result(TERMINATE_DENY_OWNER) "
		     "== LOTA_IPC_ERR_ACCESS_DENIED");
	TEST("a signal outside the two relayed is denied access");
	if (terminate_decision_result(TERMINATE_DENY_SIGNAL) !=
	    LOTA_IPC_ERR_ACCESS_DENIED)
		FAIL("expected: terminate_decision_result(TERMINATE_DENY_SIGNAL) "
		     "== LOTA_IPC_ERR_ACCESS_DENIED");

	return test_end();
}
