/* SPDX-License-Identifier: MIT */
/*
 * trust_pong - LOTA gaming SDK reference demo.
 *
 * Single-window SDL2 game (paddle vs back wall, score on bounce) that
 * exercises the gaming SDK at startup and then mirrors the verdict
 * the demo server publishes for the trust-pong game id. The game
 * deliberately does not produce its own heartbeats: that work lives
 * in demo_anticheat. trust_pong only consumes the server's state so
 * the reviewer sees the end-to-end pipeline without having to read
 * two heartbeat producers.
 *
 * Cold-launch contract: when the agent is missing, the server is
 * down, or the policy is wrong, the game still opens its window and
 * shows the OFFLINE / UNTRUSTED banner. It never segfaults on a
 * failed handshake.
 */

#include <ctype.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <curl/curl.h>
#include <SDL.h>

#include "lota_gaming.h"
#include "ui.h"

#define POLL_INTERVAL_MS 750
#define POLL_TIMEOUT_MS 600
#define DEFAULT_NONCE_URL "http://127.0.0.1:7443/nonce"
#define DEFAULT_STATE_URL "http://127.0.0.1:7443/state"
#define DEFAULT_GAME_ID "trust-pong"
#define DEFAULT_AGENT_SOCKET NULL

struct game_state {
	int paddle_y;
	int ball_x;
	int ball_y;
	int ball_vx;
	int ball_vy;
	int score;
	int hits;
	bool frozen;
	int untrusted_streak;
};

struct verdict_snapshot {
	enum ui_verdict verdict;
	char reason[160];
};

struct cli_opts {
	const char *server_base;
	const char *game_id;
	const char *socket_path;
};

struct response_buf {
	char *data;
	size_t len;
	size_t cap;
};

static atomic_int g_poll_verdict = UI_VERDICT_CHECKING;
static char g_poll_reason[160];
static pthread_mutex_t g_poll_lock = PTHREAD_MUTEX_INITIALIZER;
static atomic_bool g_poll_stop = false;

static int append_buf(struct response_buf *b, const char *data, size_t n)
{
	if (b->len + n + 1 > b->cap) {
		size_t cap = b->cap ? b->cap * 2 : 1024;
		while (cap < b->len + n + 1)
			cap *= 2;
		char *next = realloc(b->data, cap);
		if (!next)
			return -ENOMEM;
		b->data = next;
		b->cap = cap;
	}
	memcpy(b->data + b->len, data, n);
	b->len += n;
	b->data[b->len] = '\0';
	return 0;
}

static size_t curl_writer(void *ptr, size_t size, size_t nmemb, void *user)
{
	struct response_buf *buf = user;
	size_t total = size * nmemb;
	if (append_buf(buf, ptr, total) != 0)
		return 0;
	return total;
}

static char *extract_string(const char *body, const char *key)
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

/*
 * Initial trust handshake: GET nonce + session id from the demo
 * server, ask the agent for a token bound to that nonce, drop the
 * token payload because the heartbeat producer will mint signed
 * heartbeats on its own. The handshake exists to validate that the
 * agent is reachable and that the server is online before the
 * SDL2 window opens. Failure is non-fatal: the game launches with
 * the OFFLINE banner and switches to the live verdict once a
 * heartbeat lands.
 */
static int initial_handshake(const struct cli_opts *opts, CURL *curl)
{
	struct response_buf body = {0};
	struct curl_slist *headers =
	    curl_slist_append(NULL, "Content-Type: application/json");
	char url[256];
	snprintf(url, sizeof(url), "%s/nonce", opts->server_base);
	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
	curl_easy_setopt(curl, CURLOPT_POST, 1L);
	char post_body[64];
	snprintf(post_body, sizeof(post_body), "{\"game_id\":\"%s\"}",
		 opts->game_id);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_body);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_writer);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &body);
	curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, 1500L);
	curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
	CURLcode rc = curl_easy_perform(curl);
	curl_slist_free_all(headers);

	if (rc != CURLE_OK) {
		fprintf(stderr,
			"trust_pong: nonce handshake failed (server "
			"unreachable: %s)\n",
			curl_easy_strerror(rc));
		free(body.data);
		return -EIO;
	}

	char *nonce_b64 = extract_string(body.data, "nonce");
	char *session = extract_string(body.data, "session_id");
	free(body.data);
	if (!nonce_b64 || !session) {
		fprintf(
		    stderr,
		    "trust_pong: nonce handshake returned no session/nonce\n");
		free(nonce_b64);
		free(session);
		return -EIO;
	}
	fprintf(stderr,
		"trust_pong: handshake OK session=%s nonce_b64_len=%zu\n",
		session, strlen(nonce_b64));
	free(nonce_b64);
	free(session);

	/*
	 * Agent reachability check via the gaming SDK. The token itself
	 * is intentionally discarded: trust_pong does not own the
	 * heartbeat channel, demo_anticheat does. We only need to prove
	 * the agent is up before the SDL2 window opens.
	 */
	struct lota_connect_opts copts = {
	    .socket_path = opts->socket_path,
	    .timeout_ms = 1500,
	};
	struct lota_client *client = lota_connect_opts(&copts);
	if (!client) {
		fprintf(stderr,
			"trust_pong: lota_connect failed (agent down)\n");
		return -ENOTCONN;
	}
	int attested = lota_is_attested(client);
	lota_disconnect(client);
	if (attested != 1) {
		fprintf(stderr,
			"trust_pong: agent reachable but not attested "
			"(status=%d)\n",
			attested);
		return -EAGAIN;
	}
	return 0;
}

static enum ui_verdict verdict_from_label(const char *state)
{
	if (!state)
		return UI_VERDICT_OFFLINE;
	if (!strcmp(state, "TRUSTED"))
		return UI_VERDICT_TRUSTED;
	if (!strcmp(state, "UNTRUSTED"))
		return UI_VERDICT_UNTRUSTED;
	if (!strcmp(state, "REJECT"))
		return UI_VERDICT_UNTRUSTED;
	if (!strcmp(state, "PENDING"))
		return UI_VERDICT_CHECKING;
	return UI_VERDICT_OFFLINE;
}

static void publish_verdict(enum ui_verdict v, const char *reason)
{
	atomic_store(&g_poll_verdict, (int)v);
	pthread_mutex_lock(&g_poll_lock);
	if (reason) {
		strncpy(g_poll_reason, reason, sizeof(g_poll_reason) - 1);
		g_poll_reason[sizeof(g_poll_reason) - 1] = '\0';
	} else {
		g_poll_reason[0] = '\0';
	}
	pthread_mutex_unlock(&g_poll_lock);
}

static void snapshot_verdict(struct verdict_snapshot *out)
{
	out->verdict = (enum ui_verdict)atomic_load(&g_poll_verdict);
	pthread_mutex_lock(&g_poll_lock);
	memcpy(out->reason, g_poll_reason, sizeof(out->reason));
	pthread_mutex_unlock(&g_poll_lock);
}

struct poll_args {
	char url[256];
};

static void *poll_thread(void *arg)
{
	struct poll_args *args = arg;
	CURL *curl = curl_easy_init();
	if (!curl) {
		publish_verdict(UI_VERDICT_OFFLINE, "curl_easy_init failed");
		return NULL;
	}
	curl_easy_setopt(curl, CURLOPT_URL, args->url);
	curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, (long)POLL_TIMEOUT_MS);
	curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);

	while (!atomic_load(&g_poll_stop)) {
		struct response_buf body = {0};
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_writer);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, &body);
		CURLcode rc = curl_easy_perform(curl);
		if (rc != CURLE_OK) {
			publish_verdict(UI_VERDICT_OFFLINE,
					curl_easy_strerror(rc));
		} else {
			char *state = extract_string(body.data, "state");
			char *license = extract_string(body.data, "license");
			char reason[160];
			snprintf(reason, sizeof(reason), "%s%s%s",
				 state ? state : "?",
				 license ? " license=" : "",
				 license ? license : "");
			publish_verdict(verdict_from_label(state), reason);
			free(state);
			free(license);
		}
		free(body.data);

		for (int waited = 0;
		     waited < POLL_INTERVAL_MS && !atomic_load(&g_poll_stop);
		     waited += 50)
			SDL_Delay(50);
	}
	curl_easy_cleanup(curl);
	return NULL;
}

static void tick_game(struct game_state *g)
{
	if (g->frozen)
		return;

	g->ball_x += g->ball_vx;
	g->ball_y += g->ball_vy;

	if (g->ball_y < UI_BANNER_H) {
		g->ball_y = UI_BANNER_H;
		g->ball_vy = -g->ball_vy;
	}
	if (g->ball_y + UI_BALL_SIZE > UI_WINDOW_H) {
		g->ball_y = UI_WINDOW_H - UI_BALL_SIZE;
		g->ball_vy = -g->ball_vy;
	}
	if (g->ball_x + UI_BALL_SIZE >= UI_WINDOW_W - 16) {
		g->ball_x = UI_WINDOW_W - 16 - UI_BALL_SIZE;
		g->ball_vx = -g->ball_vx;
		g->hits++;
		g->score += 10;
	}
	if (g->ball_x <= 32 + UI_PADDLE_W) {
		bool paddle_hit = g->ball_y + UI_BALL_SIZE > g->paddle_y &&
				  g->ball_y < g->paddle_y + UI_PADDLE_H;
		if (paddle_hit) {
			g->ball_x = 32 + UI_PADDLE_W;
			g->ball_vx = -g->ball_vx;
			g->hits++;
			g->score += 5;
		} else if (g->ball_x < 0) {
			g->ball_x = UI_WINDOW_W / 2;
			g->ball_y = UI_WINDOW_H / 2;
			g->ball_vx = 5;
			g->ball_vy = 3;
			g->score = (g->score > 5) ? g->score - 5 : 0;
		}
	}
}

static void poll_input(struct game_state *g, const Uint8 *keys, bool *quit)
{
	if (keys[SDL_SCANCODE_ESCAPE] || keys[SDL_SCANCODE_Q])
		*quit = true;
	if (g->frozen)
		return;
	if (keys[SDL_SCANCODE_W] || keys[SDL_SCANCODE_UP])
		g->paddle_y -= 6;
	if (keys[SDL_SCANCODE_S] || keys[SDL_SCANCODE_DOWN])
		g->paddle_y += 6;
	if (g->paddle_y < UI_BANNER_H)
		g->paddle_y = UI_BANNER_H;
	if (g->paddle_y + UI_PADDLE_H > UI_WINDOW_H)
		g->paddle_y = UI_WINDOW_H - UI_PADDLE_H;
}

static int parse_cli(int argc, char **argv, struct cli_opts *opts)
{
	opts->server_base = "http://127.0.0.1:7443";
	opts->game_id = DEFAULT_GAME_ID;
	opts->socket_path = DEFAULT_AGENT_SOCKET;

	for (int i = 1; i < argc; i++) {
		const char *a = argv[i];
		if (!strcmp(a, "--server") && i + 1 < argc) {
			opts->server_base = argv[++i];
		} else if (!strcmp(a, "--game-id") && i + 1 < argc) {
			opts->game_id = argv[++i];
		} else if (!strcmp(a, "--socket") && i + 1 < argc) {
			opts->socket_path = argv[++i];
		} else if (!strcmp(a, "--help") || !strcmp(a, "-h")) {
			fprintf(
			    stderr,
			    "Usage: %s [--server BASE_URL] [--game-id ID] "
			    "[--socket PATH]\n"
			    "Default server base: %s (the demo server's listen "
			    "address, without the /endpoint suffix)\n",
			    argv[0], opts->server_base);
			return 1;
		} else {
			fprintf(stderr, "trust_pong: unknown arg %s\n", a);
			return -EINVAL;
		}
	}
	return 0;
}

int main(int argc, char **argv)
{
	struct cli_opts opts;
	int rc = parse_cli(argc, argv, &opts);
	if (rc > 0)
		return 0;
	if (rc != 0)
		return 64;

	signal(SIGPIPE, SIG_IGN);
	if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) {
		fprintf(stderr, "trust_pong: curl_global_init failed\n");
		return 1;
	}

	CURL *handshake = curl_easy_init();
	if (handshake) {
		if (initial_handshake(&opts, handshake) != 0) {
			publish_verdict(
			    UI_VERDICT_OFFLINE,
			    "handshake failed - check agent + server");
		} else {
			publish_verdict(UI_VERDICT_CHECKING,
					"awaiting first heartbeat verdict");
		}
		curl_easy_cleanup(handshake);
	}

	struct poll_args pargs;
	snprintf(pargs.url, sizeof(pargs.url), "%s/state?game_id=%s",
		 opts.server_base, opts.game_id);
	pthread_t poller;
	int prc = pthread_create(&poller, NULL, poll_thread, &pargs);
	if (prc != 0) {
		fprintf(stderr, "trust_pong: pthread_create: %s\n",
			strerror(prc));
		curl_global_cleanup();
		return 1;
	}

	struct ui_context ui;
	if (ui_init(&ui) != 0) {
		atomic_store(&g_poll_stop, true);
		pthread_join(poller, NULL);
		curl_global_cleanup();
		return 1;
	}

	struct game_state g = {
	    .paddle_y = (UI_WINDOW_H - UI_PADDLE_H) / 2,
	    .ball_x = UI_WINDOW_W / 2,
	    .ball_y = UI_WINDOW_H / 2,
	    .ball_vx = 5,
	    .ball_vy = 3,
	};

	bool quit = false;
	while (!quit) {
		SDL_Event ev;
		while (SDL_PollEvent(&ev)) {
			if (ev.type == SDL_QUIT)
				quit = true;
		}
		const Uint8 *keys = SDL_GetKeyboardState(NULL);
		poll_input(&g, keys, &quit);

		struct verdict_snapshot snap;
		snapshot_verdict(&snap);

		if (snap.verdict == UI_VERDICT_UNTRUSTED) {
			g.untrusted_streak++;
			if (g.untrusted_streak >= 2)
				g.frozen = true;
		} else if (snap.verdict == UI_VERDICT_TRUSTED) {
			g.untrusted_streak = 0;
		}

		tick_game(&g);

		enum ui_verdict draw =
		    g.frozen ? UI_VERDICT_FROZEN : snap.verdict;
		ui_begin_frame(&ui, draw);
		ui_draw_banner(&ui, draw, snap.reason);
		ui_draw_back_wall(&ui);
		ui_draw_paddle(&ui, g.paddle_y);
		ui_draw_ball(&ui, g.ball_x, g.ball_y);
		ui_draw_score(&ui, g.score, g.hits);
		if (g.frozen)
			ui_draw_frozen_overlay(&ui);
		ui_end_frame(&ui);

		SDL_Delay(16);
	}

	atomic_store(&g_poll_stop, true);
	pthread_join(poller, NULL);
	ui_shutdown(&ui);
	curl_global_cleanup();
	return 0;
}
