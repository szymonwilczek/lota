/* SPDX-License-Identifier: MIT */
/*
 * LOTA CI attestation step.
 *
 * Pipeline side of the release gate: ask the gate for a challenge, ask the local
 * LOTA agent for a token answering it, present the token, and write out the secret
 * the gate releases. Nothing else.
 *
 * It is written to be dropped into a pipeline as one step, so every outcome is exit
 * code and every failure is fail-closed: the output file is created only after
 * the gate has released, so a step that fails for any reason
 * -- no agent, unattested host, refused release, network error -- leaves the job
 *  without the secret rather than proceeding with a stale one.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#include <curl/curl.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <lota/lota_gaming.h>

/*
 * Exit codes.
 * Pipeline distinguishes "this host is not allowed" from "the gate was unreachable":
 * the first is a policy decision to act on, the second is infrastructure to retry.
 */
#define EXIT_USAGE 2
#define EXIT_NO_AGENT 3
#define EXIT_NO_TOKEN 4
#define EXIT_TRANSPORT 5
#define EXIT_REFUSED 6
#define EXIT_OUTPUT 7

#define MAX_RESPONSE (256 * 1024)

struct buffer {
	char *data;
	size_t len;
};

struct options {
	const char *gate;
	const char *socket_path;
	const char *out_path;
	const char *ca_cert;
	long timeout_sec;
};

static size_t collect(void *chunk, size_t size, size_t nmemb, void *userdata)
{
	struct buffer *buf = userdata;
	size_t bytes = size * nmemb;

	if (bytes == 0 || buf->len > MAX_RESPONSE - bytes)
		return 0;

	char *grown = realloc(buf->data, buf->len + bytes + 1);
	if (!grown)
		return 0;

	buf->data = grown;
	memcpy(buf->data + buf->len, chunk, bytes);
	buf->len += bytes;
	buf->data[buf->len] = '\0';
	return bytes;
}

/*
 * Extracts a JSON string value.
 * Gate's two responses have three string fields between them and no nesting,
 * so a scanner is the honest dependency here
 * -- integrator with a JSON library in the build already uses it.
 */
static char *json_string(const char *json, const char *key)
{
	char pattern[64];
	snprintf(pattern, sizeof(pattern), "\"%s\"", key);

	const char *at = strstr(json, pattern);
	if (!at)
		return NULL;

	at = strchr(at + strlen(pattern), ':');
	if (!at)
		return NULL;
	while (*at == ':' || *at == ' ' || *at == '\t')
		at++;
	if (*at != '"')
		return NULL;
	at++;

	const char *end = strchr(at, '"');
	if (!end)
		return NULL;

	size_t len = (size_t)(end - at);
	char *out = malloc(len + 1);
	if (!out)
		return NULL;
	memcpy(out, at, len);
	out[len] = '\0';
	return out;
}

static int base64_decode(const char *in, uint8_t *out, size_t out_size,
			 size_t *written)
{
	static const char alphabet[] =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	uint32_t acc = 0;
	int bits = 0;
	size_t n = 0;

	for (const char *p = in; *p; p++) {
		if (*p == '=')
			break;
		const char *pos = strchr(alphabet, *p);
		if (!pos)
			return -1;

		acc = (acc << 6) | (uint32_t)(pos - alphabet);
		bits += 6;
		if (bits < 8)
			continue;

		bits -= 8;
		if (n >= out_size)
			return -1;
		out[n++] = (uint8_t)((acc >> bits) & 0xFF);
	}

	*written = n;
	return 0;
}

static char *base64_encode(const uint8_t *in, size_t len)
{
	static const char alphabet[] =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	size_t out_len = ((len + 2) / 3) * 4;
	char *out = malloc(out_len + 1);
	size_t o = 0;

	if (!out)
		return NULL;

	for (size_t i = 0; i < len; i += 3) {
		uint32_t block = (uint32_t)in[i] << 16;
		size_t have = 1;

		if (i + 1 < len) {
			block |= (uint32_t)in[i + 1] << 8;
			have++;
		}
		if (i + 2 < len) {
			block |= in[i + 2];
			have++;
		}

		out[o++] = alphabet[(block >> 18) & 0x3F];
		out[o++] = alphabet[(block >> 12) & 0x3F];
		out[o++] = have > 1 ? alphabet[(block >> 6) & 0x3F] : '=';
		out[o++] = have > 2 ? alphabet[block & 0x3F] : '=';
	}

	out[o] = '\0';
	return out;
}

static CURL *new_handle(const struct options *opts, const char *url,
			struct buffer *resp, long *status)
{
	CURL *curl = curl_easy_init();
	if (!curl)
		return NULL;

	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, collect);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, resp);
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, opts->timeout_sec);
	curl_easy_setopt(curl, CURLOPT_FAILONERROR, 0L);
	curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
	if (opts->ca_cert)
		curl_easy_setopt(curl, CURLOPT_CAINFO, opts->ca_cert);

	(void)status;
	return curl;
}

/* POST /nonce -> the challenge the token must answer */
static int fetch_nonce(const struct options *opts, uint8_t nonce[32],
		       char **nonce_b64)
{
	char url[512];
	struct buffer resp = { 0 };
	long status = 0;
	int rc = -1;

	snprintf(url, sizeof(url), "%s/nonce", opts->gate);

	CURL *curl = new_handle(opts, url, &resp, &status);
	if (!curl)
		return -1;

	curl_easy_setopt(curl, CURLOPT_POST, 1L);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, "");

	CURLcode res = curl_easy_perform(curl);
	curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);

	if (res != CURLE_OK) {
		fprintf(stderr, "ci-attest: gate unreachable: %s\n",
			curl_easy_strerror(res));
		goto out;
	}
	if (status != 200) {
		fprintf(stderr,
			"ci-attest: gate refused a challenge (HTTP %ld)\n",
			status);
		goto out;
	}

	char *value = json_string(resp.data ? resp.data : "", "nonce");
	if (!value) {
		fprintf(stderr, "ci-attest: gate response has no nonce\n");
		goto out;
	}

	size_t written = 0;
	if (base64_decode(value, nonce, 32, &written) != 0 || written != 32) {
		fprintf(stderr, "ci-attest: gate nonce is not 32 bytes\n");
		free(value);
		goto out;
	}

	*nonce_b64 = value;
	rc = 0;

out:
	curl_easy_cleanup(curl);
	free(resp.data);
	return rc;
}

/*
 * POST /release -> the secret, or a reason.
 * The reason is printed as the step's own diagnostic:
 * it is what tells whoever reads the pipeline log whether the host
 * or the pipeline is at fault.
 */
static int present_token(const struct options *opts, const char *nonce_b64,
			 const char *token_b64, char **secret_b64)
{
	char url[512];
	struct buffer resp = { 0 };
	long status = 0;
	int rc = EXIT_TRANSPORT;
	char *body = NULL;

	snprintf(url, sizeof(url), "%s/release", opts->gate);

	size_t body_len = strlen(nonce_b64) + strlen(token_b64) + 32;
	body = malloc(body_len);
	if (!body)
		return EXIT_TRANSPORT;
	snprintf(body, body_len, "{\"nonce\":\"%s\",\"token\":\"%s\"}",
		 nonce_b64, token_b64);

	CURL *curl = new_handle(opts, url, &resp, &status);
	if (!curl) {
		free(body);
		return EXIT_TRANSPORT;
	}

	struct curl_slist *headers =
		curl_slist_append(NULL, "Content-Type: application/json");
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
	curl_easy_setopt(curl, CURLOPT_POST, 1L);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body);

	CURLcode res = curl_easy_perform(curl);
	curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);

	if (res != CURLE_OK) {
		fprintf(stderr, "ci-attest: gate unreachable: %s\n",
			curl_easy_strerror(res));
		goto out;
	}

	if (status != 200) {
		char *reason =
			json_string(resp.data ? resp.data : "", "reason");
		fprintf(stderr, "ci-attest: release refused: %s\n",
			reason ? reason : "no reason given");
		free(reason);
		rc = EXIT_REFUSED;
		goto out;
	}

	char *value = json_string(resp.data ? resp.data : "", "secret");
	if (!value) {
		fprintf(stderr, "ci-attest: gate released no secret\n");
		rc = EXIT_REFUSED;
		goto out;
	}

	*secret_b64 = value;
	rc = 0;

out:
	curl_slist_free_all(headers);
	curl_easy_cleanup(curl);
	free(resp.data);
	free(body);
	return rc;
}

/* Writes the secret 0600 and only on success,
 * so a failed step leaves nothing behind for a later one to pick up. */
static int write_secret(const char *path, const uint8_t *secret, size_t len)
{
	int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, 0600);
	if (fd < 0) {
		fprintf(stderr, "ci-attest: cannot write %s: %s\n", path,
			strerror(errno));
		return -1;
	}

	ssize_t written = write(fd, secret, len);
	if (written < 0 || (size_t)written != len) {
		fprintf(stderr, "ci-attest: short write to %s\n", path);
		close(fd);
		unlink(path);
		return -1;
	}

	if (close(fd) != 0) {
		fprintf(stderr, "ci-attest: cannot close %s: %s\n", path,
			strerror(errno));
		unlink(path);
		return -1;
	}
	return 0;
}

static void usage(const char *argv0)
{
	fprintf(stderr,
		"usage: %s --gate URL --out FILE [--socket PATH]\n"
		"          [--ca-cert FILE] [--timeout SEC]\n\n"
		"Proves this host's attestation state to the release gate and\n"
		"writes the released secret to --out. Exits non-zero, writing\n"
		"nothing, if the host cannot prove it.\n\n"
		"Exit codes: %d usage, %d no agent, %d no token, %d transport,\n"
		"            %d refused, %d output\n",
		argv0, EXIT_USAGE, EXIT_NO_AGENT, EXIT_NO_TOKEN, EXIT_TRANSPORT,
		EXIT_REFUSED, EXIT_OUTPUT);
}

int main(int argc, char **argv)
{
	struct options opts = {
		.gate = NULL,
		.socket_path = NULL,
		.out_path = NULL,
		.ca_cert = NULL,
		.timeout_sec = 15,
	};

	static const struct option longopts[] = {
		{ "gate", required_argument, NULL, 'g' },
		{ "out", required_argument, NULL, 'o' },
		{ "socket", required_argument, NULL, 's' },
		{ "ca-cert", required_argument, NULL, 'c' },
		{ "timeout", required_argument, NULL, 't' },
		{ "help", no_argument, NULL, 'h' },
		{ NULL, 0, NULL, 0 },
	};

	int opt;
	while ((opt = getopt_long(argc, argv, "g:o:s:c:t:h", longopts, NULL)) !=
	       -1) {
		switch (opt) {
		case 'g':
			opts.gate = optarg;
			break;
		case 'o':
			opts.out_path = optarg;
			break;
		case 's':
			opts.socket_path = optarg;
			break;
		case 'c':
			opts.ca_cert = optarg;
			break;
		case 't':
			opts.timeout_sec = strtol(optarg, NULL, 10);
			break;
		case 'h':
			usage(argv[0]);
			return 0;
		default:
			usage(argv[0]);
			return EXIT_USAGE;
		}
	}

	if (!opts.gate || !opts.out_path) {
		usage(argv[0]);
		return EXIT_USAGE;
	}

	/*
	 * The agent is the only thing that can answer a challenge, because the key
	 * that signs the answer never leaves the TPM.
	 * Connect before asking the gate for anything: host with no agent cannot
	 * prove anything, and saying so without a network round trip keeps
	 * the failure legible in a pipeline log.
	 */
	struct lota_connect_opts connect_opts = {
		/* Library refuses a zero struct_size rather than guessing one,
		 * so integrator who omits it gets no client and the step reports
		 * a host with no agent. */
		.struct_size = sizeof(connect_opts),
		.socket_path = opts.socket_path,
		.timeout_ms = 5000,
	};
	struct lota_client *client = lota_connect_opts(&connect_opts);
	if (!client) {
		fprintf(stderr,
			"ci-attest: no LOTA agent on this host; cannot attest\n");
		return EXIT_NO_AGENT;
	}

	curl_global_init(CURL_GLOBAL_DEFAULT);

	uint8_t nonce[32];
	char *nonce_b64 = NULL;
	if (fetch_nonce(&opts, nonce, &nonce_b64) != 0) {
		lota_disconnect(client);
		curl_global_cleanup();
		return EXIT_TRANSPORT;
	}

	struct lota_token token;
	int ret = lota_get_token(client, nonce, &token);
	if (ret != LOTA_OK) {
		fprintf(stderr, "ci-attest: agent issued no token: %s\n",
			lota_strerror(ret));
		lota_disconnect(client);
		free(nonce_b64);
		curl_global_cleanup();
		return EXIT_NO_TOKEN;
	}

	size_t token_size = lota_token_serialized_size(&token);
	size_t token_written = 0;
	uint8_t *token_wire = malloc(token_size);
	if (!token_wire || lota_token_serialize(&token, token_wire, token_size,
						&token_written) != LOTA_OK) {
		fprintf(stderr, "ci-attest: cannot serialize the token\n");
		free(token_wire);
		lota_token_free(&token);
		lota_disconnect(client);
		free(nonce_b64);
		curl_global_cleanup();
		return EXIT_NO_TOKEN;
	}

	lota_token_free(&token);
	lota_disconnect(client);

	char *token_b64 = base64_encode(token_wire, token_written);
	free(token_wire);
	if (!token_b64) {
		free(nonce_b64);
		curl_global_cleanup();
		return EXIT_NO_TOKEN;
	}

	char *secret_b64 = NULL;
	int rc = present_token(&opts, nonce_b64, token_b64, &secret_b64);
	free(nonce_b64);
	free(token_b64);
	curl_global_cleanup();

	if (rc != 0)
		return rc;

	uint8_t *secret = malloc(strlen(secret_b64));
	size_t secret_len = 0;
	if (!secret || base64_decode(secret_b64, secret, strlen(secret_b64),
				     &secret_len) != 0) {
		fprintf(stderr, "ci-attest: released secret is not base64\n");
		free(secret);
		free(secret_b64);
		return EXIT_REFUSED;
	}
	free(secret_b64);

	if (write_secret(opts.out_path, secret, secret_len) != 0) {
		free(secret);
		return EXIT_OUTPUT;
	}
	free(secret);

	fprintf(stderr, "ci-attest: host attested; secret written to %s\n",
		opts.out_path);
	return 0;
}
