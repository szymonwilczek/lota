/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * LOTA demo anti-cheat heartbeat producer.
 *
 * Runs a direct-mode lota_ac_session against the local agent and
 * POSTs each LACH packet to demo_server.
 * --once exits with the server's verdict.
 */

#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <curl/curl.h>

#include <lota/lota_anticheat.h>
#include <lota/lota_gaming.h>

#define DEMO_DEFAULT_URL "http://127.0.0.1:7443/heartbeat"
#define DEMO_DEFAULT_GAME_ID "trust-pong"
#define DEMO_DEFAULT_INTERVAL_SEC 5
#define DEMO_RESPONSE_MAX (16 * 1024)

enum demo_exit {
	DEMO_EXIT_TRUSTED = 0,
	DEMO_EXIT_UNTRUSTED = 1,
	DEMO_EXIT_REJECT = 2,
	DEMO_EXIT_TRANSPORT = 3,
	DEMO_EXIT_USAGE = 64,
};

struct demo_options {
	const char *server_url;
	const char *game_id;
	const char *socket_path;
	/* see lota_ac_config.publisher_profile */
	const char *publisher_profile;
	const char *tamper_marker;
	const char *ca_cert; /* provisioning CA that signs the server cert */
	const char *client_cert; /* producer mTLS certificate */
	const char *client_key; /* producer mTLS private key */
	enum lota_ac_provider provider;
	unsigned int interval_sec;
	bool once;
	bool print_runtime_objects;
	bool protect_self;
};

struct response_buf {
	char *data;
	size_t len;
};

static volatile sig_atomic_t demo_stop = 0;

static void on_signal(int signo)
{
	(void)signo;
	demo_stop = 1;
}

static void print_usage(const char *argv0)
{
	fprintf(stderr,
		"Usage: %s [--server URL] [--game-id ID] [--socket PATH]\n"
		"          [--publisher HEX]\n"
		"          [--provider eac|battleye] [--interval SEC] [--once]\n"
		"          [--tamper-marker PATH] [--print-runtime-objects]\n"
		"          [--protect-self]\n"
		"          [--ca-cert PATH] [--client-cert PATH] [--client-key "
		"PATH]\n"
		"\n"
		"Opens an lota_ac_session against the local LOTA agent and\n"
		"POSTs heartbeats to the demo server. Exit code in --once mode\n"
		"matches the server verdict: 0=TRUSTED, 1=UNTRUSTED, 2=REJECT,\n"
		"3=transport error, 64=usage error.\n"
		"\n"
		"For a mutual-TLS server (https:// URL) pass --ca-cert to verify\n"
		"the server against the provisioning CA and --client-cert /\n"
		"--client-key to present the producer's certificate."
		"\n"
		"--publisher names the publisher this producer plays for, as\n"
		"the hex SHA-256 of their CA anchor's public key (the id\n"
		"'lota-agent --list-publishers' prints). Naming it opens a\n"
		"session for that publisher; a session-gated host reports only\n"
		"while one is open, so a producer that names nobody is never\n"
		"attested for anybody. A host that answers for several\n"
		"publishers refuses a request that names none.\n"
		"\n"
		"--print-runtime-objects prints, one path per line, the\n"
		"file-backed objects (main binary + shared libraries) this\n"
		"process maps and that the runtime measurement covers,\n"
		"then exits. Redirect it into a file to capture the trusted\n"
		"runtime manifest for 'demo_server --anticheat-runtime-manifest'.\n"
		"\n"
		"--protect-self puts this process in the agent's protected set,\n"
		"so its live code is measured from the kernel side and folded\n"
		"into every token it fetches. That is what an anti-cheat wants\n"
		"and it is opt-in here, because it needs the objects this\n"
		"process maps to carry fs-verity digests (see the README).\n"
		"\n"
		"When --tamper-marker is set (or LOTA_DEMO_TAMPER_MARKER is\n"
		"exported) and the named path exists at heartbeat time, the\n"
		"producer flips one byte inside the signed token before POSTing\n"
		"so the server's signature check fails and the verdict flips to\n"
		"UNTRUSTED. The wire format itself stays well-formed, so this\n"
		"exercises the integrity path rather than the parser.\n",
		argv0);
}

static int print_runtime_object_cb(const char *path, void *user)
{
	(void)user;
	printf("%s\n", path);
	return 0;
}

/*
 * Emit the trusted runtime manifest: the file-backed objects this
 * process maps and that the runtime measurement covers.
 * The operator captures this once and feeds it to
 * 'demo_server --anticheat-runtime-manifest'.
 */
static int print_runtime_objects(void)
{
	int rc = lota_ac_list_runtime_objects(print_runtime_object_cb, NULL);
	if (rc < 0) {
		fprintf(stderr,
			"demo_anticheat: cannot enumerate runtime objects: %s\n",
			strerror(-rc));
		return DEMO_EXIT_TRANSPORT;
	}
	return 0;
}

static int parse_provider(const char *s, enum lota_ac_provider *out)
{
	if (!s || !*s)
		return -EINVAL;
	if (!strcmp(s, "eac")) {
		*out = LOTA_AC_PROVIDER_EAC;
		return 0;
	}
	if (!strcmp(s, "battleye") || !strcmp(s, "be")) {
		*out = LOTA_AC_PROVIDER_BATTLEYE;
		return 0;
	}
	return -EINVAL;
}

static int parse_args(int argc, char **argv, struct demo_options *opt)
{
	opt->server_url = DEMO_DEFAULT_URL;
	opt->game_id = DEMO_DEFAULT_GAME_ID;
	opt->socket_path = NULL;
	opt->publisher_profile = NULL;
	opt->tamper_marker = NULL;
	opt->ca_cert = NULL;
	opt->client_cert = NULL;
	opt->client_key = NULL;
	opt->provider = LOTA_AC_PROVIDER_EAC;
	opt->interval_sec = DEMO_DEFAULT_INTERVAL_SEC;
	opt->once = false;
	opt->print_runtime_objects = false;
	opt->protect_self = false;

	const char *env_interval = getenv("LOTA_DEMO_INTERVAL_SEC");
	if (env_interval && *env_interval) {
		long v = strtol(env_interval, NULL, 10);
		if (v > 0 && v < 3600)
			opt->interval_sec = (unsigned int)v;
	}

	const char *env_marker = getenv("LOTA_DEMO_TAMPER_MARKER");
	if (env_marker && *env_marker)
		opt->tamper_marker = env_marker;

	static const struct option long_opts[] = {
		{ "server", required_argument, NULL, 's' },
		{ "game-id", required_argument, NULL, 'g' },
		{ "socket", required_argument, NULL, 'S' },
		{ "provider", required_argument, NULL, 'p' },
		{ "interval", required_argument, NULL, 'i' },
		{ "once", no_argument, NULL, '1' },
		{ "tamper-marker", required_argument, NULL, 'T' },
		{ "print-runtime-objects", no_argument, NULL, 'O' },
		{ "protect-self", no_argument, NULL, 'P' },
		{ "ca-cert", required_argument, NULL, 'A' },
		{ "client-cert", required_argument, NULL, 'E' },
		{ "publisher", required_argument, NULL, 'u' },
		{ "client-key", required_argument, NULL, 'K' },
		{ "help", no_argument, NULL, 'h' },
		{ NULL, 0, NULL, 0 },
	};

	int c;
	while ((c = getopt_long(argc, argv, "s:g:S:u:p:i:1T:OPA:E:K:h",
				long_opts, NULL)) != -1) {
		switch (c) {
		case 's':
			opt->server_url = optarg;
			break;
		case 'g':
			opt->game_id = optarg;
			break;
		case 'S':
			opt->socket_path = optarg;
			break;
		case 'u':
			opt->publisher_profile = optarg;
			break;
		case 'p':
			if (parse_provider(optarg, &opt->provider) != 0) {
				fprintf(stderr, "bad --provider %s\n", optarg);
				return -EINVAL;
			}
			break;
		case 'i': {
			long v = strtol(optarg, NULL, 10);
			if (v <= 0 || v >= 3600) {
				fprintf(stderr, "bad --interval %s\n", optarg);
				return -EINVAL;
			}
			opt->interval_sec = (unsigned int)v;
			break;
		}
		case '1':
			opt->once = true;
			break;
		case 'P':
			opt->protect_self = true;
			break;
		case 'O':
			opt->print_runtime_objects = true;
			break;
		case 'A':
			opt->ca_cert = optarg;
			break;
		case 'E':
			opt->client_cert = optarg;
			break;
		case 'K':
			opt->client_key = optarg;
			break;
		case 'T':
			if (!optarg || !*optarg) {
				fprintf(stderr,
					"--tamper-marker requires PATH\n");
				return -EINVAL;
			}
			opt->tamper_marker = optarg;
			break;
		case 'h':
			print_usage(argv[0]);
			return 1;
		default:
			return -EINVAL;
		}
	}

	if ((opt->client_cert != NULL) != (opt->client_key != NULL)) {
		fprintf(stderr,
			"--client-cert and --client-key must be set together\n");
		return -EINVAL;
	}
	return 0;
}

/*
 * Peer and host verification apply to an https:// URL; --ca-cert names the
 * provisioning CA and the client pair identifies the producer.
 */
static void configure_tls(CURL *curl, const struct demo_options *opt)
{
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
	if (opt->ca_cert)
		curl_easy_setopt(curl, CURLOPT_CAINFO, opt->ca_cert);
	if (opt->client_cert) {
		curl_easy_setopt(curl, CURLOPT_SSLCERT, opt->client_cert);
		curl_easy_setopt(curl, CURLOPT_SSLKEY, opt->client_key);
	}
}

static size_t response_writer(void *ptr, size_t size, size_t nmemb, void *user)
{
	struct response_buf *buf = user;
	size_t add = size * nmemb;
	if (buf->len + add >= DEMO_RESPONSE_MAX)
		return 0;
	char *next = realloc(buf->data, buf->len + add + 1);
	if (!next)
		return 0;
	buf->data = next;
	memcpy(buf->data + buf->len, ptr, add);
	buf->len += add;
	buf->data[buf->len] = '\0';
	return add;
}

/*
 * Returns the string value of @key in the server's flat JSON reply, or NULL.
 * Escapes are not decoded. The caller frees the result.
 */
static char *extract_string_field(const char *body, const char *key)
{
	if (!body || !key)
		return NULL;
	char needle[64];
	int n = snprintf(needle, sizeof(needle), "\"%s\"", key);
	if (n <= 0 || (size_t)n >= sizeof(needle))
		return NULL;
	const char *p = strstr(body, needle);
	if (!p)
		return NULL;
	p += n;
	while (*p && (isspace((unsigned char)*p) || *p == ':'))
		p++;
	if (*p != '"')
		return NULL;
	p++;
	const char *end = strchr(p, '"');
	if (!end)
		return NULL;
	size_t len = (size_t)(end - p);
	char *out = malloc(len + 1);
	if (!out)
		return NULL;
	memcpy(out, p, len);
	out[len] = '\0';
	return out;
}

static enum demo_exit verdict_to_exit(const char *state)
{
	if (!state)
		return DEMO_EXIT_TRANSPORT;
	if (!strcmp(state, "TRUSTED"))
		return DEMO_EXIT_TRUSTED;
	if (!strcmp(state, "UNTRUSTED"))
		return DEMO_EXIT_UNTRUSTED;
	if (!strcmp(state, "REJECT"))
		return DEMO_EXIT_REJECT;
	return DEMO_EXIT_TRANSPORT;
}

static int post_heartbeat(CURL *curl, const char *url, const uint8_t *body,
			  size_t body_len, struct response_buf *response,
			  long *http_status, double *latency_ms)
{
	response->data = NULL;
	response->len = 0;

	struct curl_slist *headers = NULL;
	headers = curl_slist_append(headers,
				    "Content-Type: application/octet-stream");

	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
	curl_easy_setopt(curl, CURLOPT_POST, 1L);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)body_len);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &response_writer);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, response);
	curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, 5000L);
	curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);

	struct timespec t0, t1;
	clock_gettime(CLOCK_MONOTONIC, &t0);
	CURLcode rc = curl_easy_perform(curl);
	clock_gettime(CLOCK_MONOTONIC, &t1);

	curl_slist_free_all(headers);

	if (rc != CURLE_OK) {
		fprintf(stderr, "demo_anticheat: curl: %s\n",
			curl_easy_strerror(rc));
		return -EIO;
	}
	curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, http_status);
	*latency_ms = (double)(t1.tv_sec - t0.tv_sec) * 1000.0 +
		      (double)(t1.tv_nsec - t0.tv_nsec) / 1e6;
	return 0;
}

/* Checked once per heartbeat */
static bool tamper_marker_armed(const char *path)
{
	if (!path || !*path)
		return false;
	return access(path, F_OK) == 0;
}

static int send_one_heartbeat(struct lota_ac_session *session, CURL *curl,
			      const struct demo_options *opt, uint32_t *out_seq,
			      enum demo_exit *out_verdict)
{
	uint8_t buf[LOTA_AC_MAX_HEARTBEAT];
	size_t written = 0;
	int rc = lota_ac_heartbeat(session, buf, sizeof(buf), &written);
	if (rc != 0) {
		fprintf(stderr, "demo_anticheat: lota_ac_heartbeat: %s (%s)\n",
			lota_ac_strerror(lota_ac_last_error()), strerror(-rc));
		*out_verdict = DEMO_EXIT_TRANSPORT;
		return rc;
	}
	/* LACH sequence: little-endian u32 at offset 24 */
	*out_seq = (uint32_t)buf[24] | ((uint32_t)buf[25] << 8) |
		   ((uint32_t)buf[26] << 16) | ((uint32_t)buf[27] << 24);

	/*
	 * The packet ends with the token signature, so flipping its last byte
	 * keeps the packet parseable and the server answers UNTRUSTED.
	 */
	if (written > LOTA_AC_HEADER_SIZE &&
	    tamper_marker_armed(opt->tamper_marker)) {
		buf[written - 1] ^= 0xFF;
		fprintf(stderr,
			"demo_anticheat: tamper marker %s present, flipped "
			"signature byte at offset %zu\n",
			opt->tamper_marker, written - 1);
	}

	struct response_buf resp = {};
	long http_status = 0;
	double latency_ms = 0.0;
	rc = post_heartbeat(curl, opt->server_url, buf, written, &resp,
			    &http_status, &latency_ms);
	if (rc != 0) {
		free(resp.data);
		*out_verdict = DEMO_EXIT_TRANSPORT;
		return rc;
	}

	char *state = extract_string_field(resp.data, "state");
	char *reason = extract_string_field(resp.data, "reason");
	*out_verdict = verdict_to_exit(state);

	fprintf(stderr,
		"demo_anticheat: seq=%u state=%s latency=%.1fms http=%ld",
		*out_seq, state ? state : "?", latency_ms, http_status);
	if (reason && *reason)
		fprintf(stderr, " reason=\"%s\"", reason);
	fputc('\n', stderr);

	free(state);
	free(reason);
	free(resp.data);
	return 0;
}

int main(int argc, char **argv)
{
	struct demo_options opt;
	int rc = parse_args(argc, argv, &opt);
	if (rc > 0)
		return 0;
	if (rc != 0) {
		print_usage(argv[0]);
		return DEMO_EXIT_USAGE;
	}

	if (opt.print_runtime_objects)
		return print_runtime_objects();

	struct sigaction sa = { .sa_handler = on_signal };
	sigemptyset(&sa.sa_mask);
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);

	if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) {
		fprintf(stderr, "demo_anticheat: curl_global_init failed\n");
		return DEMO_EXIT_TRANSPORT;
	}

	struct lota_ac_config cfg = {
		.struct_size = sizeof(cfg),
		.provider = opt.provider,
		.game_id = opt.game_id,
		.direct = 1,
		.socket_path = opt.socket_path,
		.publisher_profile = opt.publisher_profile,
	};

	/*
	 * The session keeps its own agent connection. Protection
	 * belongs to the process, so a second connection claims it.
	 */
	struct lota_client *protect_client = NULL;

	if (opt.protect_self) {
		struct lota_connect_opts popts = {
			.struct_size = sizeof(popts),
			.timeout_ms = 8000,
			.socket_path = opt.socket_path,
			.publisher_profile = opt.publisher_profile,
		};

		protect_client = lota_connect_opts(&popts);
		if (!protect_client) {
			fprintf(stderr,
				"demo_anticheat: --protect-self: cannot reach the "
				"agent (%d)\n",
				lota_connect_last_error());
			curl_global_cleanup();
			return DEMO_EXIT_TRANSPORT;
		}
		int prc = lota_protect_self(protect_client);
		if (prc != 0) {
			fprintf(stderr,
				"demo_anticheat: --protect-self refused: %s\n",
				lota_strerror(prc));
			lota_disconnect(protect_client);
			curl_global_cleanup();
			return DEMO_EXIT_TRANSPORT;
		}
		fprintf(stderr,
			"demo_anticheat: protected (pid=%d); every token now "
			"folds this process's measured code\n",
			(int)getpid());
	}

	struct lota_ac_session *session = lota_ac_init(&cfg);
	if (!session) {
		fprintf(stderr, "demo_anticheat: lota_ac_init failed: %s\n",
			lota_ac_strerror(lota_ac_last_error()));
		if (protect_client)
			lota_disconnect(protect_client);
		curl_global_cleanup();
		return DEMO_EXIT_TRANSPORT;
	}

	CURL *curl = curl_easy_init();
	if (!curl) {
		fprintf(stderr, "demo_anticheat: curl_easy_init failed\n");
		lota_ac_shutdown(session);
		if (protect_client)
			lota_disconnect(protect_client);
		curl_global_cleanup();
		return DEMO_EXIT_TRANSPORT;
	}
	configure_tls(curl, &opt);

	fprintf(stderr,
		"demo_anticheat: producer up (server=%s game=%s provider=%s "
		"interval=%us once=%s tamper_marker=%s)\n",
		opt.server_url, opt.game_id, lota_ac_provider_str(opt.provider),
		opt.interval_sec, opt.once ? "yes" : "no",
		opt.tamper_marker ? opt.tamper_marker : "(none)");

	enum demo_exit verdict = DEMO_EXIT_TRANSPORT;
	int exit_code = DEMO_EXIT_TRANSPORT;
	for (;;) {
		uint32_t seq = 0;
		rc = send_one_heartbeat(session, curl, &opt, &seq, &verdict);
		if (opt.once) {
			exit_code = (rc == 0) ? (int)verdict :
						DEMO_EXIT_TRANSPORT;
			break;
		}
		exit_code = (rc == 0) ? (int)verdict : DEMO_EXIT_TRANSPORT;

		for (unsigned int waited = 0;
		     waited < opt.interval_sec && !demo_stop; waited++)
			sleep(1);
		if (demo_stop) {
			fprintf(stderr,
				"demo_anticheat: shutdown requested, exiting\n");
			break;
		}
	}

	curl_easy_cleanup(curl);
	lota_ac_shutdown(session);
	if (protect_client)
		lota_disconnect(protect_client);
	curl_global_cleanup();
	return exit_code;
}
