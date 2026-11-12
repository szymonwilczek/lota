/* SPDX-License-Identifier: MIT */
/*
 * LOTA Agent - Network/TLS client implementation
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#include "net.h"

#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <signal.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/crypto.h>
#include <openssl/prov_ssl.h>
#include <openssl/types.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <stdio.h>
#include <stdlib.h>

#include "attestation.h"
#include "config.h"
#include "journal.h"
#include "lota.h"

#define NET_IO_TIMEOUT_SEC 30

/* read directly: the agent does not link libselinux */
#define NET_SELINUX_ROOT "/sys/fs/selinux"
#define NET_ATTEST_BOOLEAN "lota_network_attest"

_Static_assert(sizeof(struct verifier_challenge) == 48,
	       "verifier_challenge must be 48 bytes on wire");
_Static_assert(sizeof(struct verifier_result) == 24,
	       "verifier_result must be 24 bytes on wire");

static int ssl_initialized = 0;

/* with stdio closed, socket() can hand out 0, 1 or 2 */
static int normalize_socket_fd(int fd)
{
	if (fd < 0)
		return -EINVAL;

	if (fd <= STDERR_FILENO) {
		int dupfd = fcntl(fd, F_DUPFD_CLOEXEC, STDERR_FILENO + 1);
		if (dupfd < 0)
			return -errno;
		close(fd);
		fd = dupfd;
	}

	{
		int fd_flags = fcntl(fd, F_GETFD, 0);
		if (fd_flags < 0)
			return -errno;
		if (fcntl(fd, F_SETFD, fd_flags | FD_CLOEXEC) < 0)
			return -errno;
	}

	return fd;
}

int net_transport_error(int ssl_err, int sock_errno)
{
	switch (ssl_err) {
	case SSL_ERROR_ZERO_RETURN:
		return -LOTA_ERR_NET_PEER_CLOSED;
	case SSL_ERROR_SYSCALL:
		/* SO_RCVTIMEO/SO_SNDTIMEO expiry arrives as EAGAIN */
		if (sock_errno == EAGAIN || sock_errno == EWOULDBLOCK)
			return -ETIMEDOUT;
		if (sock_errno)
			return -sock_errno;
		/* no errno, no close_notify: the peer was killed */
		return -LOTA_ERR_NET_PEER_GONE;
	case SSL_ERROR_SSL:
		return -LOTA_ERR_NET_TLS;
	default:
		return -EIO;
	}
}

static int ssl_wait(SSL *ssl, int event)
{
	int fd = SSL_get_fd(ssl);
	struct pollfd pfd;
	int ret;

	if (fd < 0)
		return -EINVAL;

	pfd.fd = fd;
	pfd.events = 0;
	pfd.revents = 0;

	if (event == SSL_ERROR_WANT_READ)
		pfd.events = POLLIN;
	else if (event == SSL_ERROR_WANT_WRITE)
		pfd.events = POLLOUT;
	else
		return -EINVAL;

	ret = poll(&pfd, 1, NET_IO_TIMEOUT_SEC * 1000);
	if (ret == 0)
		return -ETIMEDOUT;
	if (ret < 0)
		return -errno;

	return 0;
}

int net_init(void)
{
	struct sigaction sa;

	if (ssl_initialized)
		return 0;

	/*
	 * A write to a closed peer must fail with EPIPE, not kill the process;
	 * one-shot verbs never run the daemon's signal setup.
	 */
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = SIG_IGN;
	sigemptyset(&sa.sa_mask);
	if (sigaction(SIGPIPE, &sa, NULL) < 0)
		return -errno;

	ssl_initialized = 1;
	return 0;
}

void net_cleanup(void)
{
	if (!ssl_initialized)
		return;

	ssl_initialized = 0;
}

int net_context_init(struct net_context *ctx, const char *server, int port,
		     const char *ca_cert_path, int skip_verify,
		     const uint8_t *pin_sha256)
{
	SSL_CTX *ssl_ctx;
	const SSL_METHOD *method;

	if (!ctx || !server)
		return -EINVAL;

	memset(ctx, 0, sizeof(*ctx));
	ctx->socket_fd = -1;
	ctx->skip_verify = skip_verify;

	if (pin_sha256) {
		memcpy(ctx->pin_sha256, pin_sha256, LOTA_PIN_SHA256_LEN);
		ctx->has_pin = 1;
	}

	strncpy(ctx->server_addr, server, sizeof(ctx->server_addr) - 1);
	ctx->server_port = port;

	method = TLS_client_method();
	ssl_ctx = SSL_CTX_new(method);
	if (!ssl_ctx) {
		return -ENOMEM;
	}

	SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_3_VERSION);

	if (skip_verify) {
		lota_warn(
			"TLS certificate verification DISABLED (--no-verify-tls)");
		lota_warn("Connection is vulnerable to MITM attacks!");
		lota_warn("Do NOT use in production.");
		SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_NONE, NULL);
	} else if (ca_cert_path) {
		/* pinned anchor: a CA or the listener's own certificate */
		if (SSL_CTX_load_verify_locations(ssl_ctx, ca_cert_path,
						  NULL) != 1) {
			lota_err("Failed to load CA certificate: %s",
				 ca_cert_path);
			SSL_CTX_free(ssl_ctx);
			return -EINVAL;
		}
		/*
		 * Let the chain end at the pinned certificate even when it is
		 * a CA-issued leaf whose issuer is not in the store.
		 */
		X509_VERIFY_PARAM_set_flags(SSL_CTX_get0_param(ssl_ctx),
					    X509_V_FLAG_PARTIAL_CHAIN);
		SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, NULL);
	} else {
		if (SSL_CTX_set_default_verify_paths(ssl_ctx) != 1) {
			lota_err("Failed to load system CA certificates. "
				 "Use --ca-cert to specify verifier's CA "
				 "certificate, "
				 "or --no-verify-tls for testing (INSECURE).");
			SSL_CTX_free(ssl_ctx);
			return -ENOENT;
		}
		SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, NULL);
	}

	ctx->ssl_ctx = ssl_ctx;
	return 0;
}

void net_context_cleanup(struct net_context *ctx)
{
	if (!ctx)
		return;

	net_disconnect(ctx);

	if (ctx->ssl_ctx) {
		SSL_CTX_free(ctx->ssl_ctx);
		ctx->ssl_ctx = NULL;
	}
}

int net_connect(struct net_context *ctx)
{
	struct addrinfo hints, *result, *rp;
	int last_errno = 0;
	char port_str[16];
	SSL *ssl;
	int sock = -1;
	int ret;

	if (!ctx || !ctx->ssl_ctx)
		return -EINVAL;

	if (ctx->connected)
		return 0;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	snprintf(port_str, sizeof(port_str), "%d", ctx->server_port);

	ret = getaddrinfo(ctx->server_addr, port_str, &hints, &result);
	if (ret != 0) {
		return -EHOSTUNREACH;
	}

	for (rp = result; rp != NULL; rp = rp->ai_next) {
		sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (sock < 0) {
			last_errno = errno;
			continue;
		}

		{
			int normalized = normalize_socket_fd(sock);
			if (normalized < 0) {
				close(sock);
				sock = -1;
				continue;
			}
			sock = normalized;
		}

		int flags = fcntl(sock, F_GETFL, 0);
		if (flags < 0) {
			close(sock);
			sock = -1;
			continue;
		}
		fcntl(sock, F_SETFL, flags | O_NONBLOCK);

		ret = connect(sock, rp->ai_addr, rp->ai_addrlen);
		last_errno = errno;
		if (ret == 0) {
			fcntl(sock, F_SETFL, flags);
			break;
		}

		if (errno == EINPROGRESS) {
			int epfd = epoll_create1(EPOLL_CLOEXEC);
			struct epoll_event ev;
			ev.events = EPOLLOUT | EPOLLERR | EPOLLHUP;
			ev.data.fd = sock;

			if (epfd >= 0 &&
			    epoll_ctl(epfd, EPOLL_CTL_ADD, sock, &ev) == 0) {
				int n = epoll_wait(epfd, &ev, 1,
						   10000); /* 10s timeout */
				if (n > 0) {
					int err = 0;
					socklen_t len = sizeof(err);
					if (getsockopt(sock, SOL_SOCKET,
						       SO_ERROR, &err,
						       &len) == 0 &&
					    err != 0)
						last_errno = err;
					if (err == 0) {
						close(epfd);
						fcntl(sock, F_SETFL,
						      flags); /* restore
								 blocking */
						break;
					}
				}
			}
			if (epfd >= 0)
				close(epfd);
		}

		close(sock);
		sock = -1;
	}

	freeaddrinfo(result);

	if (sock < 0) {
		char hint[512];
		const char *cause = net_connect_refusal_hint(
			last_errno, ctx->server_port, NULL, hint, sizeof(hint));

		/* the caller prints only the errno; the port is known here */
		if (cause)
			lota_err("Cannot reach %s:%d. %s", ctx->server_addr,
				 ctx->server_port, cause);
		return last_errno ? -last_errno : -ECONNREFUSED;
	}

	ctx->socket_fd = sock;

	{
		struct timeval tv = { .tv_sec = NET_IO_TIMEOUT_SEC,
				      .tv_usec = 0 };
		setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
		setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
	}

	ssl = SSL_new(ctx->ssl_ctx);
	if (!ssl) {
		close(sock);
		ctx->socket_fd = -1;
		return -ENOMEM;
	}

	SSL_set_fd(ssl, sock);
	SSL_set_tlsext_host_name(ssl, ctx->server_addr);

	if (!ctx->skip_verify) {
		if (SSL_set1_host(ssl, ctx->server_addr) != 1) {
			lota_err("Failed to set hostname verification for: %s",
				 ctx->server_addr);
			SSL_free(ssl);
			close(sock);
			ctx->socket_fd = -1;
			return -EINVAL;
		}
	}

	ret = SSL_connect(ssl);
	if (ret != 1) {
		int ssl_err = SSL_get_error(ssl, ret);
		unsigned long err_code = ERR_peek_last_error();
		long verify_result = ctx->skip_verify ?
					     X509_V_OK :
					     SSL_get_verify_result(ssl);

		if (verify_result != X509_V_OK) {
			lota_err("TLS certificate verification failed: %s "
				 "(code %ld). "
				 "Use --ca-cert or --no-verify-tls for testing",
				 X509_verify_cert_error_string(verify_result),
				 verify_result);
			SSL_free(ssl);
			close(sock);
			ctx->socket_fd = -1;
			return -LOTA_ERR_NET_TLS_CERT;
		}

		if (ssl_err == SSL_ERROR_SSL) {
			lota_err("TLS handshake failed: %s",
				 ERR_reason_error_string(err_code));
		} else {
			lota_err("TLS handshake failed (SSL_ERROR=%d)",
				 ssl_err);
		}

		SSL_free(ssl);
		close(sock);
		ctx->socket_fd = -1;
		/* the socket connected: TLS refused, the host was reachable */
		return -LOTA_ERR_NET_TLS_HANDSHAKE;
	}

	if (ctx->skip_verify) {
		if (ctx->has_pin) {
			lota_err("INSECURE TLS: certificate verification "
				 "DISABLED for %s:%d "
				 "(--no-verify-tls). Pinning is enabled, but "
				 "hostname/CA "
				 "verification is bypassed.",
				 ctx->server_addr, ctx->server_port);
		} else {
			lota_err("INSECURE TLS: certificate verification "
				 "DISABLED for %s:%d "
				 "(--no-verify-tls). Connection is vulnerable "
				 "to MITM.",
				 ctx->server_addr, ctx->server_port);
		}
	}

	if (!ctx->skip_verify) {
		X509 *peer_cert = SSL_get1_peer_certificate(ssl);
		if (!peer_cert) {
			lota_err("Verifier did not present a TLS certificate");
			SSL_shutdown(ssl);
			SSL_free(ssl);
			close(sock);
			ctx->socket_fd = -1;
			return -LOTA_ERR_NET_TLS_CERT;
		}
		X509_free(peer_cert);
	}

	if (ctx->has_pin) {
		X509 *peer_cert = SSL_get1_peer_certificate(ssl);
		if (!peer_cert) {
			lota_err("Certificate pinning failed: server presented "
				 "no certificate");
			SSL_shutdown(ssl);
			SSL_free(ssl);
			close(sock);
			ctx->socket_fd = -1;
			return -LOTA_ERR_NET_TLS_PIN;
		}

		unsigned char digest[LOTA_PIN_SHA256_LEN];
		unsigned int digest_len = 0;

		if (X509_digest(peer_cert, EVP_sha256(), digest, &digest_len) !=
			    1 ||
		    digest_len != LOTA_PIN_SHA256_LEN) {
			lota_err("Certificate pinning failed: unable to "
				 "compute SHA-256 fingerprint");
			X509_free(peer_cert);
			SSL_shutdown(ssl);
			SSL_free(ssl);
			close(sock);
			ctx->socket_fd = -1;
			return -LOTA_ERR_NET_TLS_PIN;
		}
		X509_free(peer_cert);

		if (CRYPTO_memcmp(digest, ctx->pin_sha256,
				  LOTA_PIN_SHA256_LEN) != 0) {
			{
				char expected_hex[LOTA_PIN_SHA256_LEN * 2 + 1];
				char got_hex[LOTA_PIN_SHA256_LEN * 2 + 1];
				for (int i = 0; i < LOTA_PIN_SHA256_LEN; i++) {
					snprintf(expected_hex + i * 2, 3,
						 "%02x", ctx->pin_sha256[i]);
					snprintf(got_hex + i * 2, 3, "%02x",
						 digest[i]);
				}
				lota_err(
					"SECURITY: Certificate pinning FAILED! "
					"Expected: %s Got: %s "
					"This may indicate a MITM attack or "
					"certificate rotation.",
					expected_hex, got_hex);
			}
			SSL_shutdown(ssl);
			SSL_free(ssl);
			close(sock);
			ctx->socket_fd = -1;
			return -LOTA_ERR_NET_TLS_PIN;
		}
	}

	ctx->ssl = ssl;
	ctx->connected = 1;

	return 0;
}

void net_disconnect(struct net_context *ctx)
{
	if (!ctx)
		return;

	if (ctx->ssl) {
		SSL_shutdown(ctx->ssl);
		SSL_free(ctx->ssl);
		ctx->ssl = NULL;
	}

	if (ctx->socket_fd >= 0) {
		close(ctx->socket_fd);
		ctx->socket_fd = -1;
	}

	ctx->connected = 0;
}

int net_recv_challenge(struct net_context *ctx,
		       struct verifier_challenge *challenge)
{
	uint8_t buf[sizeof(struct verifier_challenge)];
	int ret;
	int total = 0;

	if (!ctx || !ctx->connected || !challenge)
		return -EINVAL;

	while (total < (int)sizeof(buf)) {
		ret = SSL_read(ctx->ssl, buf + total, sizeof(buf) - total);
		if (ret <= 0) {
			int ssl_err = SSL_get_error(ctx->ssl, ret);
			if (ssl_err == SSL_ERROR_WANT_READ ||
			    ssl_err == SSL_ERROR_WANT_WRITE) {
				int wait_ret = ssl_wait(ctx->ssl, ssl_err);
				if (wait_ret < 0)
					return wait_ret;
				continue;
			}
			return net_transport_error(ssl_err, errno);
		}
		total += ret;
	}

	memcpy(&challenge->magic, buf + 0, 4);
	memcpy(&challenge->version, buf + 4, 4);
	memcpy(challenge->nonce, buf + 8, 32);
	memcpy(&challenge->pcr_mask, buf + 40, 4);
	memcpy(&challenge->flags, buf + 44, 4);

	challenge->magic = le32toh(challenge->magic);
	challenge->version = le32toh(challenge->version);
	challenge->pcr_mask = le32toh(challenge->pcr_mask);
	challenge->flags = le32toh(challenge->flags);

	if (challenge->magic != LOTA_MAGIC) {
		return -EPROTO;
	}

	return 0;
}

int net_send_report(struct net_context *ctx, const void *report,
		    size_t report_size)
{
	int ret;
	size_t total = 0;

	if (!ctx || !ctx->connected || !report || report_size == 0)
		return -EINVAL;

	while (total < report_size) {
		ret = SSL_write(ctx->ssl, (const uint8_t *)report + total,
				report_size - total);
		if (ret <= 0) {
			int ssl_err = SSL_get_error(ctx->ssl, ret);
			if (ssl_err == SSL_ERROR_WANT_READ ||
			    ssl_err == SSL_ERROR_WANT_WRITE) {
				int wait_ret = ssl_wait(ctx->ssl, ssl_err);
				if (wait_ret < 0)
					return wait_ret;
				continue;
			}
			return net_transport_error(ssl_err, errno);
		}
		total += ret;
	}

	return 0;
}

int net_recv_result(struct net_context *ctx, struct verifier_result *result)
{
	uint8_t buf[sizeof(struct verifier_result)];
	int ret;
	int total = 0;

	if (!ctx || !ctx->connected || !result)
		return -EINVAL;

	while (total < (int)sizeof(buf)) {
		ret = SSL_read(ctx->ssl, buf + total, sizeof(buf) - total);
		if (ret <= 0) {
			int ssl_err = SSL_get_error(ctx->ssl, ret);
			if (ssl_err == SSL_ERROR_WANT_READ ||
			    ssl_err == SSL_ERROR_WANT_WRITE) {
				int wait_ret = ssl_wait(ctx->ssl, ssl_err);
				if (wait_ret < 0)
					return wait_ret;
				continue;
			}
			return net_transport_error(ssl_err, errno);
		}
		total += ret;
	}

	memcpy(&result->magic, buf + 0, 4);
	memcpy(&result->version, buf + 4, 4);
	memcpy(&result->result, buf + 8, 4);
	memcpy(&result->flags, buf + 12, 4);
	memcpy(&result->valid_until, buf + 16, 8);

	result->magic = le32toh(result->magic);
	result->version = le32toh(result->version);
	result->result = le32toh(result->result);
	result->flags = le32toh(result->flags);
	result->valid_until = le64toh(result->valid_until);

	if (result->magic != LOTA_MAGIC) {
		return -EPROTO;
	}

	return 0;
}

int net_write_all(struct net_context *ctx, const void *buf, size_t len)
{
	size_t total = 0;

	if (!ctx || !ctx->connected || !buf)
		return -EINVAL;
	if (len == 0)
		return 0;

	while (total < len) {
		int ret = SSL_write(ctx->ssl, (const uint8_t *)buf + total,
				    (int)(len - total));
		if (ret <= 0) {
			int ssl_err = SSL_get_error(ctx->ssl, ret);
			if (ssl_err == SSL_ERROR_WANT_READ ||
			    ssl_err == SSL_ERROR_WANT_WRITE) {
				int wait_ret = ssl_wait(ctx->ssl, ssl_err);
				if (wait_ret < 0)
					return wait_ret;
				continue;
			}
			return net_transport_error(ssl_err, errno);
		}
		total += (size_t)ret;
	}

	return 0;
}

int net_read_full(struct net_context *ctx, void *buf, size_t len)
{
	size_t total = 0;

	if (!ctx || !ctx->connected || !buf)
		return -EINVAL;
	if (len == 0)
		return 0;

	while (total < len) {
		int ret = SSL_read(ctx->ssl, (uint8_t *)buf + total,
				   (int)(len - total));
		if (ret <= 0) {
			int ssl_err = SSL_get_error(ctx->ssl, ret);
			if (ssl_err == SSL_ERROR_WANT_READ ||
			    ssl_err == SSL_ERROR_WANT_WRITE) {
				int wait_ret = ssl_wait(ctx->ssl, ssl_err);
				if (wait_ret < 0)
					return wait_ret;
				continue;
			}
			return net_transport_error(ssl_err, errno);
		}
		total += (size_t)ret;
	}

	return 0;
}

/* 0 or 1 from the first byte of a selinuxfs node, or -1 */
static int selinux_node_state(const char *root, const char *rel)
{
	char path[256], state[8];
	ssize_t got;
	int fd, n;

	n = snprintf(path, sizeof(path), "%s/%s", root, rel);
	if (n < 0 || (size_t)n >= sizeof(path))
		return -1;
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -1;
	got = read(fd, state, sizeof(state) - 1);
	close(fd);
	if (got <= 0)
		return -1;
	state[got] = '\0';
	if (state[0] != '0' && state[0] != '1')
		return -1;
	return state[0] - '0';
}

const char *net_connect_refusal_hint(int err, int port,
				     const char *selinux_root, char *buf,
				     size_t cap)
{
	const char *root = selinux_root ? selinux_root : NET_SELINUX_ROOT;
	int tunable, n;

	if (err != EACCES || !buf || cap == 0)
		return NULL;
	if (port <= 0 || port > 65535)
		return NULL;

	/* absent or permissive: this EACCES came from somewhere else */
	if (selinux_node_state(root, "enforce") != 1)
		return NULL;

	/* "<active> <pending>"; no node without the module, so either rule */
	tunable = selinux_node_state(root, "booleans/" NET_ATTEST_BOOLEAN);

	if (tunable == 0)
		n = snprintf(buf, cap,
			     "SELinux is enforcing and the " NET_ATTEST_BOOLEAN
			     " boolean is off, which is "
			     "what refuses this connect. Labelling the port "
			     "changes nothing while the boolean is off -- "
			     "semanage would answer 'already defined' and exit "
			     "0. Turn it back on:\n"
			     "  sudo setsebool -P " NET_ATTEST_BOOLEAN " on");
	else if (tunable == 1)
		n = snprintf(buf, cap,
			     "SELinux is enforcing and TCP port %d carries no "
			     "LOTA label, which is what refuses this connect. "
			     "Label the port and the next round goes through:\n"
			     "  sudo semanage port -a -t lota_port_t -p tcp %d",
			     port, port);
	else
		n = snprintf(buf, cap,
			     "SELinux is enforcing and refused this connect. "
			     "Two rules refuse it and this host "
			     "cannot read which one did: TCP port %d carrying "
			     "no LOTA label, and the " NET_ATTEST_BOOLEAN
			     " boolean being off.\n"
			     "  sudo semanage port -a -t lota_port_t -p tcp "
			     "%d\n"
			     "  sudo setsebool -P " NET_ATTEST_BOOLEAN " on",
			     port, port);

	/* half a command is worse than none -- an operator would run it */
	if (n < 0 || (size_t)n >= cap)
		return NULL;

	return buf;
}

const char *net_result_str(uint32_t result)
{
	switch (result) {
	case VERIFY_OK:
		return "OK - Attestation successful";
	case VERIFY_NONCE_FAIL:
		return "FAIL - Nonce/freshness verification failed";
	case VERIFY_SIG_FAIL:
		return "FAIL - TPM signature verification failed";
	case VERIFY_PCR_FAIL:
		return "FAIL - PCR values don't match policy";
	case VERIFY_IOMMU_FAIL:
		return "FAIL - IOMMU requirement not met";
	case VERIFY_OLD_VERSION:
		return "FAIL - Protocol version mismatch: this agent speaks a "
		       "report wire the publisher's verifier does not "
		       "implement. Update the agent to the build the "
		       "publisher runs its fleet on";
	case VERIFY_REPORT_MALFORMED:
		/* a damaged frame, not an old build: no upgrade advice */
		return "FAIL - The publisher's verifier could not read the "
		       "report this host sent: it arrived incomplete or "
		       "altered on the way. Nothing on this machine is in "
		       "question yet. Attest again, and if it keeps "
		       "happening, the network path between this host and "
		       "the verifier is what to look at";
	case VERIFY_INTEGRITY_MISMATCH:
		return "FAIL - Integrity mismatch: a measurement this host is "
		       "pinned to no longer matches. It is the agent binary, "
		       "the PCR 14 boot commitment or the firmware/Secure Boot "
		       "baseline, and the publisher's verifier log names "
		       "which. An updated agent needs its build allowed there; "
		       "a firmware or boot-chain change needs this host "
		       "re-anchored";
	case VERIFY_REVOKED:
		return "FAIL - This host's attestation key was revoked by the "
		       "publisher's administrator, who decides on "
		       "re-enrollment";
	case VERIFY_BANNED:
		return "FAIL - This machine is banned by the publisher's "
		       "administrator; nothing on it changes that answer";
	case VERIFY_INTERNAL_ERROR:
		return "FAIL - Verifier internal error";
	case VERIFY_POLICY_REQUIREMENT:
		return "FAIL - This host does not meet a requirement the "
		       "publisher's policy states about it, and the verdict "
		       "does not say which. The requirements this agent knows "
		       "have a verdict of their own, so this is either one a "
		       "newer verifier states -- update the agent and attest "
		       "again -- or one only the publisher can settle, such "
		       "as a host whose firmware baseline nobody has enrolled";
	case VERIFY_SECUREBOOT_REQUIRED:
		return "FAIL - Secure Boot is not on for this host and the "
		       "publisher's policy requires it. The firmware's own "
		       "measurement is what is read here, so the machine's "
		       "own report cannot substitute for it: turn Secure Boot "
		       "on in firmware setup, boot, then attest again";
	case VERIFY_LOCKDOWN_REQUIRED:
		return "FAIL - This host's kernel is not in lockdown and the "
		       "publisher's policy requires it. Boot with "
		       "lockdown=integrity on the kernel command line (Secure "
		       "Boot turns it on by itself on most distributions)";
	case VERIFY_MODULE_SIG_REQUIRED:
		return "FAIL - This host's kernel loads unsigned modules and "
		       "the publisher's policy requires signature "
		       "enforcement. Boot with module.sig_enforce=1, or a "
		       "kernel built with CONFIG_MODULE_SIG_FORCE";
	case VERIFY_ENFORCE_REQUIRED:
		return "FAIL - The LOTA enforcement daemon is not enforcing "
		       "on this host, and the publisher's policy requires it "
		       "to. Set mode = enforce in " LOTA_CONFIG_DEFAULT_PATH
		       ", keep lota-agent.service enabled, and reboot: "
		       "stopping the agent spends this boot's attestation";
	case VERIFY_IMA_APPRAISAL_REQUIRED:
		return "FAIL - This host could not show that its kernel "
		       "appraises executables (appraisal in enforce mode and "
		       "an appraise rule on BPRM_CHECK or without func=), and "
		       "the publisher's policy requires IMA appraisal. It is "
		       "a boot-time policy and a signed filesystem: see the "
		       "publisher's bring-up instructions before turning it "
		       "on, because a host that appraises what it cannot "
		       "verify does not boot";
	case VERIFY_KERNEL_IMAGE_REQUIRED:
		return "FAIL - This host's kernel is not one the publisher's "
		       "policy allows, or its boot did not measure a kernel "
		       "image the policy could be checked against. Boot a "
		       "kernel the publisher lists, from a bootloader that "
		       "measures it into PCR 9";
	case VERIFY_CMDLINE_REQUIRED:
		return "FAIL - This host's kernel command line carries a "
		       "parameter the publisher's policy denies, or its boot "
		       "did not measure the command line at all. The "
		       "verifier's log names the parameter; the usual ones "
		       "are debug and kernel-integrity switches added by hand";
	case VERIFY_CERTIFICATE_MISSING:
		return "FAIL - This host presented no attestation "
		       "certificate, so the publisher has nothing to identify "
		       "it by. The enrolment did not finish or its "
		       "certificate is not on disk. Run lota-agent --reenroll "
		       "--publisher <their ID>";
	case VERIFY_CERTIFICATE_VALIDITY:
		return "FAIL - This host's attestation certificate is outside "
		       "the window it is valid in. Either it has expired, "
		       "which is what a certificate lifetime running out looks "
		       "like, or this machine's clock is behind the "
		       "publisher's and the certificate is not valid yet. The "
		       "quote itself is not in question. Check the clock, then "
		       "run lota-agent --reenroll --publisher <their ID>";
	case VERIFY_IDENTITY_FAIL:
		return "FAIL - The certificate this host presented does not "
		       "certify the key it signed with, so the publisher "
		       "cannot tell which machine this is. A TPM clear leaves "
		       "exactly this. Run lota-agent --reenroll --publisher "
		       "<their ID>";
	default:
		return "FAIL - Unknown error";
	}
}

const char *net_verdict_str(uint32_t result, uint32_t report_flags)
{
	if (result != VERIFY_ENFORCE_REQUIRED)
		return net_result_str(result);

	/* BPF_ACTIVE is the daemon's answer that its LSM is loaded */
	if (report_flags & LOTA_REPORT_FLAG_BPF_ACTIVE)
		return "FAIL - The LOTA LSM is loaded on this host but is not "
		       "enforcing, and the publisher's policy requires it to "
		       "be. Set mode = enforce in " LOTA_CONFIG_DEFAULT_PATH
		       " and reboot: stopping the agent spends this boot's "
		       "attestation, so a restart does not bring it back";

	return "FAIL - The LOTA enforcement daemon is not running on this "
	       "host, or runs without its LSM, and the publisher's policy "
	       "requires enforcement. Its journal (journalctl -u "
	       "lota-agent) says why. Keep lota-agent.service enabled, set "
	       "mode = enforce in " LOTA_CONFIG_DEFAULT_PATH ", and reboot";
}
