/* SPDX-License-Identifier: MIT */
/*
 * Unit tests for the --terminate-protected report line.
 *
 * The count is what else stays protected and must not include the signalled
 * process, or a player goes looking for a second protected title.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#include <errno.h>
#include <string.h>

#include "test.h"
#include "../src/agent/terminate_report.h"

int main(void)
{
	char buf[256];

	test_begin("terminate report");

	TEST("each refusal maps to its own errno");
	if (!(terminate_result_errno(LOTA_IPC_ERR_NOT_PROTECTED) == -EINVAL &&
	      terminate_result_errno(LOTA_IPC_ERR_TARGET_REFUSED) == -EPERM &&
	      terminate_result_errno(LOTA_IPC_ERR_BAD_REQUEST) == -ESRCH &&
	      terminate_result_errno(LOTA_IPC_ERR_ACCESS_DENIED) == -EACCES))
		FAIL("a refusal is mapped to another one's errno");

	TEST("a signal that failed in the agent is not an ownership refusal");
	if (terminate_result_errno(LOTA_IPC_ERR_INTERNAL) != -EIO)
		FAIL("LOTA_IPC_ERR_INTERNAL is not -EIO");

	TEST("a code the verb does not answer with is a protocol error");
	if (terminate_result_errno(LOTA_IPC_ERR_RATE_LIMITED) != -EPROTO)
		FAIL("an unexpected code is read as a refusal");

	TEST("ending the only protected process claims no other");
	terminate_sent_message(14418, false, 0, buf, sizeof(buf));
	if (!(strstr(buf, "SIGTERM") && strstr(buf, "14418") &&
	      strstr(buf, "no other process in its process tree is protected")))
		FAIL("%s", buf);

	TEST("every count says it is of other processes");
	terminate_sent_message(14418, false, 2, buf, sizeof(buf));
	if (!(strstr(buf, "other") &&
	      !strstr(buf, "2 processes still protected")))
		FAIL("%s", buf);

	TEST("one other protected process is reported as another");
	terminate_sent_message(14418, false, 1, buf, sizeof(buf));
	if (!strstr(buf,
		    "1 other process in its process tree is still protected"))
		FAIL("%s", buf);

	TEST("several others are counted in the plural");
	terminate_sent_message(14418, false, 3, buf, sizeof(buf));
	if (!strstr(buf,
		    "3 other processes in its process tree are still protected"))
		FAIL("%s", buf);

	TEST("the signal that was sent is named");
	terminate_sent_message(2, true, 0, buf, sizeof(buf));
	if (!(strstr(buf, "SIGKILL") && !strstr(buf, "SIGTERM")))
		FAIL("%s", buf);

	TEST("a caller without a buffer is not written to");
	terminate_sent_message(1, false, 0, NULL, 0);

	return test_end();
}
