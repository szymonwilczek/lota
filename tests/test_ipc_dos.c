/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * IPC DoS / Concurrency Test
 *
 * Verifies that the agent can handle more than 64 concurrent connections.
 *
 * Usage:
 *   1. Start agent: sudo ./build/lota-agent --test-ipc
 *   2. Run test: ./build/test_ipc_dos
 */

#include "../include/lota_gaming.h"
#include "test.h"

#define TEST_CONNECTIONS 100

static struct lota_client *clients[TEST_CONNECTIONS];

int main(void)
{
	int i;
	int opened = 0;
	int ret;
	struct lota_status status;

	test_begin("ipc dos");

	TEST("agent accepts 100 concurrent connections");
	for (i = 0; i < TEST_CONNECTIONS; i++) {
		clients[i] = lota_connect();
		if (!clients[i]) {
			FAIL("client %d failed to connect", i);
			break;
		}
		opened++;
	}

	TEST("last connection answers a status query");
	if (opened == 0) {
		SKIP("no connection open");
	} else {
		ret = lota_get_status(clients[opened - 1], &status);
		if (ret != 0)
			FAIL("connection %d: %s", opened - 1,
			     lota_strerror(ret));
	}

	for (i = 0; i < opened; i++) {
		lota_disconnect(clients[i]);
		clients[i] = NULL;
	}
	return test_end();
}
