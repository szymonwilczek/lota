/* SPDX-License-Identifier: MIT */
/*
 * LOTA demo anti-cheat heartbeat producer.
 *
 * Drives an lota_ac_session in direct mode against the local LOTA
 * agent and POSTs the resulting LACH packet to the demo server.
 * Designed to be the smallest possible reference for an EAC- or
 * BattlEye-style integrator: open a session, mint a heartbeat,
 * ship it over HTTP, log the verdict, sleep, repeat.
 *
 * --once exits with the server-reported verdict as the process
 * return code so setup.sh can use it as a liveness check.
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

#include "lota_anticheat.h"

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
	enum lota_ac_provider provider;
	unsigned int interval_sec;
	bool once;
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
	fprintf(
	    stderr,
	    "Usage: %s [--server URL] [--game-id ID] [--socket PATH]\n"
	    "          [--provider eac|battleye] [--interval SEC] [--once]\n"
	    "\n"
	    "Opens an lota_ac_session against the local LOTA agent and\n"
	    "POSTs heartbeats to the demo server. Exit code in --once mode\n"
	    "matches the server verdict: 0=TRUSTED, 1=UNTRUSTED, 2=REJECT,\n"
	    "3=transport error, 64=usage error.\n",
	    argv0);
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
	opt->provider = LOTA_AC_PROVIDER_EAC;
	opt->interval_sec = DEMO_DEFAULT_INTERVAL_SEC;
	opt->once = false;

	const char *env_interval = getenv("LOTA_DEMO_INTERVAL_SEC");
	if (env_interval && *env_interval) {
		long v = strtol(env_interval, NULL, 10);
		if (v > 0 && v < 3600)
			opt->interval_sec = (unsigned int)v;
	}

	static const struct option long_opts[] = {
	    {"server", required_argument, NULL, 's'},
	    {"game-id", required_argument, NULL, 'g'},
	    {"socket", required_argument, NULL, 'S'},
	    {"provider", required_argument, NULL, 'p'},
	    {"interval", required_argument, NULL, 'i'},
	    {"once", no_argument, NULL, '1'},
	    {"help", no_argument, NULL, 'h'},
	    {0, 0, 0, 0},
	};

	int c;
	while ((c = getopt_long(argc, argv, "s:g:S:p:i:1h", long_opts, NULL)) !=
	       -1) {
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
		case 'h':
			print_usage(argv[0]);
			return 1;
		default:
			return -EINVAL;
		}
	}
	return 0;
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
 * Extract a quoted value for the given JSON key without pulling in a
 * full JSON parser. Returns a heap-allocated NUL-terminated string the
 * caller frees, or NULL when the key is absent. Good enough for the
 * server's fixed response schema; not safe for arbitrary inputs.
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
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, response_writer);
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

static int send_one_heartbeat(struct lota_ac_session *session, CURL *curl,
			      const struct demo_options *opt, uint32_t *out_seq,
			      enum demo_exit *out_verdict)
{
	uint8_t buf[LOTA_AC_MAX_HEARTBEAT];
	size_t written = 0;
	int rc = lota_ac_heartbeat(session, buf, sizeof(buf), &written);
	if (rc != 0) {
		fprintf(stderr, "demo_anticheat: lota_ac_heartbeat: %s\n",
			strerror(-rc));
		*out_verdict = DEMO_EXIT_TRANSPORT;
		return rc;
	}
	/* sequence lives at offset 24 in the LACH header (LE u32). */
	*out_seq = (uint32_t)buf[24] | ((uint32_t)buf[25] << 8) |
		   ((uint32_t)buf[26] << 16) | ((uint32_t)buf[27] << 24);

	struct response_buf resp = {0};
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

	struct sigaction sa = {.sa_handler = on_signal};
	sigemptyset(&sa.sa_mask);
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);

	if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) {
		fprintf(stderr, "demo_anticheat: curl_global_init failed\n");
		return DEMO_EXIT_TRANSPORT;
	}

	struct lota_ac_config cfg = {
	    .provider = opt.provider,
	    .game_id = opt.game_id,
	    .direct = 1,
	    .socket_path = opt.socket_path,
	};
	struct lota_ac_session *session = lota_ac_init(&cfg);
	if (!session) {
		fprintf(stderr,
			"demo_anticheat: lota_ac_init failed (agent socket "
			"unreachable at %s)\n",
			opt.socket_path ? opt.socket_path
					: "/run/lota/lota.sock");
		curl_global_cleanup();
		return DEMO_EXIT_TRANSPORT;
	}

	CURL *curl = curl_easy_init();
	if (!curl) {
		fprintf(stderr, "demo_anticheat: curl_easy_init failed\n");
		lota_ac_shutdown(session);
		curl_global_cleanup();
		return DEMO_EXIT_TRANSPORT;
	}

	fprintf(stderr,
		"demo_anticheat: producer up (server=%s game=%s provider=%s "
		"interval=%us once=%s)\n",
		opt.server_url, opt.game_id, lota_ac_provider_str(opt.provider),
		opt.interval_sec, opt.once ? "yes" : "no");

	enum demo_exit verdict = DEMO_EXIT_TRANSPORT;
	int exit_code = DEMO_EXIT_TRANSPORT;
	for (;;) {
		uint32_t seq = 0;
		rc = send_one_heartbeat(session, curl, &opt, &seq, &verdict);
		if (opt.once) {
			exit_code =
			    (rc == 0) ? (int)verdict : DEMO_EXIT_TRANSPORT;
			break;
		}
		exit_code = (rc == 0) ? (int)verdict : DEMO_EXIT_TRANSPORT;

		for (unsigned int waited = 0;
		     waited < opt.interval_sec && !demo_stop; waited++)
			sleep(1);
		if (demo_stop) {
			fprintf(
			    stderr,
			    "demo_anticheat: shutdown requested, exiting\n");
			break;
		}
	}

	curl_easy_cleanup(curl);
	lota_ac_shutdown(session);
	curl_global_cleanup();
	return exit_code;
}
