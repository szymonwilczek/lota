/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * Unit tests for net_transport_error(): an orderly close, a socket errno
 * and a TLS protocol failure must map to distinct codes, none of them -EIO.
 */

#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include <openssl/ssl.h>

#include "../src/agent/attest.h"
#include "../src/agent/net.h"
#include "../src/agent/tpm.h"

#include "test.h"

static void test_outcomes_are_distinct(void)
{
	int closed = net_transport_error(SSL_ERROR_ZERO_RETURN, 0);
	int reset = net_transport_error(SSL_ERROR_SYSCALL, ECONNRESET);
	int eof = net_transport_error(SSL_ERROR_SYSCALL, 0);
	int proto = net_transport_error(SSL_ERROR_SSL, 0);

	TEST("a peer that closed and a protocol failure are different codes");
	if (closed == proto)
		FAIL("expected: closed != proto");
	TEST("a peer that closed and one that vanished are different codes");
	if (closed == eof)
		FAIL("expected: closed != eof");
	TEST("a reset connection and a protocol failure are different codes");
	if (reset == proto)
		FAIL("expected: reset != proto");
	TEST("every transport outcome is a negative code");
	if (!(closed < 0 && reset < 0 && eof < 0 && proto < 0))
		FAIL("expected: closed < 0 && reset < 0 && eof < 0 && proto < "
		     "0");
}

/* SSL_ERROR_SYSCALL failed below TLS: the socket errno is the answer */
static void test_socket_errno_survives(void)
{
	TEST("a reset connection is reported as the reset it was");
	if (net_transport_error(SSL_ERROR_SYSCALL, ECONNRESET) != -ECONNRESET)
		FAIL("expected: net_transport_error(SSL_ERROR_SYSCALL, "
		     "ECONNRESET) == -ECONNRESET");
	TEST("a timed-out socket is reported as the timeout it was");
	if (net_transport_error(SSL_ERROR_SYSCALL, ETIMEDOUT) != -ETIMEDOUT)
		FAIL("expected: net_transport_error(SSL_ERROR_SYSCALL, "
		     "ETIMEDOUT) == -ETIMEDOUT");
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

		TEST("every transport outcome renders to something");
		if (!(reason && reason[0]))
			FAIL("expected: reason && reason[0]");
		TEST("no transport outcome renders as the C library's EIO");
		if (!(reason && strcmp(reason, eio) != 0))
			FAIL("expected: reason && strcmp(reason, eio) != 0");
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

	TEST("a peer that closed and a protocol failure read differently");
	if (strcmp(closed, proto) == 0)
		FAIL("expected: strcmp(closed, proto) != 0");
	TEST("a peer that closed and one that vanished read differently");
	if (strcmp(closed, eof) == 0)
		FAIL("expected: strcmp(closed, eof) != 0");
}

/* the transport codes must not shadow the TPM ones */
static void test_tpm_codes_still_render(void)
{
	const char *locked = attest_failure_reason(-LOTA_ERR_TPM_LOCKED);
	const char *eacces = attest_failure_reason(-EACCES);
	char posix[128];

	snprintf(posix, sizeof(posix), "%s", strerror(EACCES));

	TEST("a dictionary-attack lockout is still named");
	if (!(locked && strstr(locked, "lockout")))
		FAIL("expected: locked && strstr(locked, \"lockout\")");
	TEST("an ordinary errno still renders as the C library renders it");
	if (!(eacces && strcmp(eacces, posix) == 0))
		FAIL("expected: eacces && strcmp(eacces, posix) == 0");
}

/*
 * One-shot verbs (--enroll, --reenroll) skip the daemon's signal setup,
 * so net_init() itself must ignore SIGPIPE or a write to a closed peer kills
 * them.
 */
static void test_bring_up_survives_a_dead_peer(void)
{
	struct sigaction old;

	signal(SIGPIPE, SIG_DFL);
	net_init();
	memset(&old, 0, sizeof(old));
	sigaction(SIGPIPE, NULL, &old);

	TEST("network bring-up leaves a write to a dead peer survivable");
	if (old.sa_handler != SIG_IGN)
		FAIL("expected: old.sa_handler == SIG_IGN");

	/* whatever the answer, the rest of this file does exactly that */
	signal(SIGPIPE, SIG_IGN);
}

/*
 * A loopback port, or -1. With @serve, @pid gets a child that accepts one
 * connection and closes it without TLS; without, nothing listens on the port.
 */
static int loopback_port(int serve, pid_t *pid)
{
	struct sockaddr_in addr;
	socklen_t len = sizeof(addr);
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	int port;

	*pid = -1;
	if (fd < 0)
		return -1;

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	addr.sin_port = 0;

	if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0 ||
	    listen(fd, 1) < 0 ||
	    getsockname(fd, (struct sockaddr *)&addr, &len) < 0) {
		close(fd);
		return -1;
	}
	port = ntohs(addr.sin_port);

	if (!serve) {
		/* the port is known and nothing holds it: connect is refused */
		close(fd);
		return port;
	}

	*pid = fork();
	if (*pid < 0) {
		close(fd);
		return -1;
	}
	if (*pid == 0) {
		int c = accept(fd, NULL, NULL);

		if (c >= 0)
			close(c);
		close(fd);
		_exit(0);
	}
	close(fd);
	return port;
}

static int connect_to(int port)
{
	struct net_context ctx;
	int ret;

	memset(&ctx, 0, sizeof(ctx));
	/* no verification: the peer never presents a certificate */
	if (net_context_init(&ctx, "127.0.0.1", port, NULL, 1, NULL) < 0)
		return -EINVAL;
	ret = net_connect(&ctx);
	net_context_cleanup(&ctx);
	return ret;
}

/* a failed handshake (certificates) is not a refused connect (address/port) */
static void test_handshake_is_not_unreachable(void)
{
	pid_t child = -1;
	int port = loopback_port(1, &child);
	int handshake, refused;

	if (port < 0) {
		FAIL("could not raise a loopback listener");
		return;
	}

	handshake = connect_to(port);
	if (child > 0)
		waitpid(child, NULL, 0);

	TEST("a peer that speaks no TLS fails the connect");
	if (handshake >= 0)
		FAIL("expected: handshake < 0");
	TEST("a failed handshake is named by the transport vocabulary");
	if (net_err_name(handshake) == NULL)
		FAIL("expected: net_err_name(handshake) != NULL");

	port = loopback_port(0, &child);
	refused = connect_to(port);

	TEST("a port nothing listens on is still reported as refused");
	if (refused != -ECONNREFUSED)
		FAIL("expected: refused == -ECONNREFUSED");
	TEST("a failed handshake and a refused connect are different codes");
	if (handshake == refused)
		FAIL("expected: handshake != refused");
}

int main(void)
{
	test_begin("net errors");
	test_outcomes_are_distinct();
	test_socket_errno_survives();
	test_nothing_reads_as_a_disk_fault();
	test_renderings_are_distinct();
	test_tpm_codes_still_render();
	test_bring_up_survives_a_dead_peer();
	test_handshake_is_not_unreachable();

	return test_end();
}
