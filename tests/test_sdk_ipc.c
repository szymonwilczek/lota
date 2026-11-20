/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * LOTA SDK Integration Test
 * Tests SDK functions against running lota-agent IPC server.
 *
 * Usage:
 *   1. Start the agent this build produced: sudo <build>/lota-agent --test-ipc
 *   2. Run test:                            <build>/test_sdk_ipc
 */
#include <string.h>
#include <stdint.h>

#include "../include/lota_gaming.h"
#include "test.h"

#ifndef AGENT_BIN_PATH
#define AGENT_BIN_PATH "build/lota-agent"
#endif

static void check(const char *name, int passed, const char *detail)
{
	TEST(name);
	if (!passed)
		FAIL("%s", detail);
}

/* No-op subscription callback. File scope: clang rejects the nested
 * function definition that GCC accepts as an extension. */
static void dummy_cb(const struct lota_status *s, uint32_t e, void *u)
{
	(void)s;
	(void)e;
	(void)u;
}

/*
 * Needs a running agent: --test-signed for every test, --test-ipc for
 * all but the token (an agent with no TPM refuses GET_TOKEN).
 */
int main(void)
{
	struct lota_client *client;
	struct lota_status status;
	struct lota_token token;
	struct lota_token token2;
	uint8_t client_nonce[32];
	uint64_t uptime = 0;
	const char *ver;
	int ret;

	test_begin("sdk ipc");

	TEST("lota_connect()");
	client = lota_connect();
	if (!client) {
		FAIL("connection failed; start: sudo %s --test-signed",
		     AGENT_BIN_PATH);
		return test_end();
	}

	ret = lota_get_status(client, &status);
	check("lota_get_status()", ret == 0, "status query failed");
	if (ret == 0)
		check("status ATTESTED flag set",
		      (status.flags & LOTA_FLAG_ATTESTED) != 0,
		      "agent should report attested");

	ret = lota_is_attested(client);
	check("lota_is_attested()", ret == 1, "should return 1 for attested");

	for (int i = 0; i < 32; i++)
		client_nonce[i] = (uint8_t)i;

	memset(&token, 0, sizeof(token));
	ret = lota_get_token(client, client_nonce, &token);
	check("lota_get_token()", ret == 0, lota_strerror(ret));

	if (ret == 0) {
		/* nonce should be echoed back */
		check("client nonce echoed",
		      memcmp(token.nonce, client_nonce, 32) == 0,
		      "nonce mismatch");
		check("valid timestamps", token.valid_until > 0,
		      "invalid timestamps");

		/* for --test-signed mode, signature should be present */
		if (token.signature_len > 0) {
			check("TPM signature present",
			      token.signature_len == 256,
			      "expected 256-byte RSA signature");
			check("attest data present", token.attest_size > 100,
			      "expected ~145 byte TPMS_ATTEST");
		}

		lota_token_free(&token);
	}

	memset(&token2, 0, sizeof(token2));
	ret = lota_get_token(client, client_nonce, &token2);
	if (ret == 0) {
		check("token timestamp fresh",
		      token2.valid_until >= token.valid_until,
		      "timestamp not advancing");
		lota_token_free(&token2);
	}

	ret = lota_ping(client, &uptime);
	check("lota_ping()", ret == LOTA_OK, lota_strerror(ret));

	ret = lota_protect_self(client);
	check("lota_protect_self() first call", ret == LOTA_OK,
	      lota_strerror(ret));
	ret = lota_protect_self(client);
	check("lota_protect_self() idempotent", ret == LOTA_OK,
	      lota_strerror(ret));

	lota_disconnect(client);

	client = lota_connect();
	check("reconnect after disconnect", client != NULL, "reconnect failed");

	if (client) {
		ret = lota_get_status(client, &status);
		check("status after reconnect", ret == 0, "status failed");
		lota_disconnect(client);
	}

	ver = lota_sdk_version();
	check("lota_sdk_version()", ver != NULL && strlen(ver) > 0,
	      "no version");

	client = lota_connect();
	TEST("subscription connection");
	if (!client) {
		FAIL("could not connect");
		return test_end();
	}

	ret = lota_subscribe(client, LOTA_EVENT_STATUS, NULL, NULL);
	check("lota_subscribe rejects NULL callback",
	      ret == LOTA_ERR_INVALID_ARG, lota_strerror(ret));

	ret = lota_subscribe(client, LOTA_EVENT_STATUS, dummy_cb, NULL);
	check("lota_subscribe()", ret == 0, lota_strerror(ret));

	if (ret == 0) {
		ret = lota_unsubscribe(client);
		check("lota_unsubscribe()", ret == 0, lota_strerror(ret));
	}
	lota_disconnect(client);

	return test_end();
}
