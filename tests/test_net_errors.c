/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * Unit tests for net_transport_error(): an orderly close, a socket errno
 * and a TLS protocol failure must map to distinct codes, none of them -EIO.
 */

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include <openssl/ssl.h>

#include "../src/agent/attest.h"
#include "../src/agent/net.h"
#include "../src/agent/tpm.h"

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

static void test_outcomes_are_distinct(void)
{
	int closed = net_transport_error(SSL_ERROR_ZERO_RETURN, 0);
	int reset = net_transport_error(SSL_ERROR_SYSCALL, ECONNRESET);
	int eof = net_transport_error(SSL_ERROR_SYSCALL, 0);
	int proto = net_transport_error(SSL_ERROR_SSL, 0);

	CHECK(closed != proto,
	      "a peer that closed and a protocol failure are different codes");
	CHECK(closed != eof,
	      "a peer that closed and one that vanished are different codes");
	CHECK(reset != proto,
	      "a reset connection and a protocol failure are different codes");
	CHECK(closed < 0 && reset < 0 && eof < 0 && proto < 0,
	      "every transport outcome is a negative code");
}

/* SSL_ERROR_SYSCALL failed below TLS: the socket errno is the answer */
static void test_socket_errno_survives(void)
{
	CHECK(net_transport_error(SSL_ERROR_SYSCALL, ECONNRESET) == -ECONNRESET,
	      "a reset connection is reported as the reset it was");
	CHECK(net_transport_error(SSL_ERROR_SYSCALL, ETIMEDOUT) == -ETIMEDOUT,
	      "a timed-out socket is reported as the timeout it was");
}

/* compared with strerror(EIO), not an English string: it is localised */
static void test_nothing_reads_as_a_disk_fault(void)
{
	char eio[128];
	int outcomes[4];
	size_t i;

	snprintf(eio, sizeof(eio), "%s", strerror(EIO));

	outcomes[0] = net_transport_error(SSL_ERROR_ZERO_RETURN, 0);
	outcomes[1] = net_transport_error(SSL_ERROR_SYSCALL, 0);
	outcomes[2] = net_transport_error(SSL_ERROR_SSL, 0);
	outcomes[3] = net_transport_error(SSL_ERROR_SYSCALL, ECONNRESET);

	for (i = 0; i < sizeof(outcomes) / sizeof(outcomes[0]); i++) {
		const char *reason = attest_failure_reason(outcomes[i]);

		CHECK(reason && reason[0],
		      "every transport outcome renders to something");
		CHECK(reason && strcmp(reason, eio) != 0,
		      "no transport outcome renders as the C library's EIO");
	}
}

/* distinct codes must also read differently in the journal */
static void test_renderings_are_distinct(void)
{
	char closed[192], proto[192], eof[192];

	snprintf(closed, sizeof(closed), "%s",
		 attest_failure_reason(
			 net_transport_error(SSL_ERROR_ZERO_RETURN, 0)));
	snprintf(eof, sizeof(eof), "%s",
		 attest_failure_reason(
			 net_transport_error(SSL_ERROR_SYSCALL, 0)));
	snprintf(proto, sizeof(proto), "%s",
		 attest_failure_reason(net_transport_error(SSL_ERROR_SSL, 0)));

	CHECK(strcmp(closed, proto) != 0,
	      "a peer that closed and a protocol failure read differently");
	CHECK(strcmp(closed, eof) != 0,
	      "a peer that closed and one that vanished read differently");
}

/* the transport codes must not shadow the TPM ones */
static void test_tpm_codes_still_render(void)
{
	const char *locked = attest_failure_reason(-LOTA_ERR_TPM_LOCKED);
	const char *eacces = attest_failure_reason(-EACCES);
	char posix[128];

	snprintf(posix, sizeof(posix), "%s", strerror(EACCES));

	CHECK(locked && strstr(locked, "lockout"),
	      "a dictionary-attack lockout is still named");
	CHECK(eacces && strcmp(eacces, posix) == 0,
	      "an ordinary errno still renders as the C library renders it");
}

int main(void)
{
	printf("=== transport failure naming tests ===\n");
	test_outcomes_are_distinct();
	test_socket_errno_survives();
	test_nothing_reads_as_a_disk_fault();
	test_renderings_are_distinct();
	test_tpm_codes_still_render();

	if (g_failures) {
		fprintf(stderr, "\n%d test(s) failed\n", g_failures);
		return 1;
	}
	printf("\nAll transport failure naming tests passed\n");
	return 0;
}
