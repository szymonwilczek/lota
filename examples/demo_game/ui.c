/* SPDX-License-Identifier: MIT */

#include "ui.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>

enum text_role {
	TEXT_SMALL = 0,
	TEXT_STATUS,
	TEXT_OVERLAY,
};

static SDL_Color color_text(void)
{
	return (SDL_Color){0xE8, 0xEC, 0xF1, 0xFF};
}
static SDL_Color color_muted(void)
{
	return (SDL_Color){0xA8, 0xB0, 0xBA, 0xFF};
}
static SDL_Color color_bg(void)
{
	return (SDL_Color){0x0B, 0x0D, 0x10, 0xFF};
}
static SDL_Color color_bar(void)
{
	return (SDL_Color){0x15, 0x18, 0x1D, 0xFF};
}
static SDL_Color color_game(void)
{
	return (SDL_Color){0xC8, 0xD0, 0xDA, 0xFF};
}

static void verdict_palette(enum ui_verdict v, SDL_Color *accent)
{
	switch (v) {
	case UI_VERDICT_TRUSTED:
		*accent = (SDL_Color){0x35, 0xD0, 0x78, 0xFF};
		return;
	case UI_VERDICT_UNTRUSTED:
		*accent = (SDL_Color){0xF0, 0xA0, 0x34, 0xFF};
		return;
	case UI_VERDICT_FROZEN:
		*accent = (SDL_Color){0xF0, 0x4A, 0x55, 0xFF};
		return;
	case UI_VERDICT_OFFLINE:
		*accent = (SDL_Color){0x8A, 0x94, 0xA0, 0xFF};
		return;
	case UI_VERDICT_CHECKING:
	default:
		*accent = (SDL_Color){0xE8, 0xC1, 0x4A, 0xFF};
		return;
	}
}

static const char *verdict_label(enum ui_verdict v)
{
	switch (v) {
	case UI_VERDICT_TRUSTED:
		return "TRUSTED";
	case UI_VERDICT_UNTRUSTED:
		return "UNTRUSTED";
	case UI_VERDICT_FROZEN:
		return "INTEGRITY LOSS";
	case UI_VERDICT_OFFLINE:
		return "OFFLINE";
	case UI_VERDICT_CHECKING:
	default:
		return "CHECKING";
	}
}

static int text_scale(enum text_role role)
{
	switch (role) {
	case TEXT_STATUS:
		return 3;
	case TEXT_OVERLAY:
		return 6;
	case TEXT_SMALL:
	default:
		return 2;
	}
}

static const unsigned char *glyph_rows(char c)
{
	static const unsigned char glyphs[128][7] = {
	    [' '] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
	    ['!'] = {0x04, 0x04, 0x04, 0x04, 0x04, 0x00, 0x04},
	    ['\''] = {0x04, 0x04, 0x08, 0x00, 0x00, 0x00, 0x00},
	    ['('] = {0x02, 0x04, 0x08, 0x08, 0x08, 0x04, 0x02},
	    [')'] = {0x08, 0x04, 0x02, 0x02, 0x02, 0x04, 0x08},
	    ['+'] = {0x00, 0x04, 0x04, 0x1F, 0x04, 0x04, 0x00},
	    [','] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x08},
	    ['-'] = {0x00, 0x00, 0x00, 0x1F, 0x00, 0x00, 0x00},
	    ['.'] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x0C, 0x0C},
	    ['/'] = {0x01, 0x01, 0x02, 0x04, 0x08, 0x10, 0x10},
	    [':'] = {0x00, 0x04, 0x04, 0x00, 0x04, 0x04, 0x00},
	    ['='] = {0x00, 0x00, 0x1F, 0x00, 0x1F, 0x00, 0x00},
	    ['?'] = {0x0E, 0x11, 0x01, 0x02, 0x04, 0x00, 0x04},
	    ['0'] = {0x0E, 0x11, 0x13, 0x15, 0x19, 0x11, 0x0E},
	    ['1'] = {0x04, 0x0C, 0x14, 0x04, 0x04, 0x04, 0x1F},
	    ['2'] = {0x0E, 0x11, 0x01, 0x02, 0x04, 0x08, 0x1F},
	    ['3'] = {0x1E, 0x01, 0x01, 0x0E, 0x01, 0x01, 0x1E},
	    ['4'] = {0x02, 0x06, 0x0A, 0x12, 0x1F, 0x02, 0x02},
	    ['5'] = {0x1F, 0x10, 0x10, 0x1E, 0x01, 0x01, 0x1E},
	    ['6'] = {0x0E, 0x10, 0x10, 0x1E, 0x11, 0x11, 0x0E},
	    ['7'] = {0x1F, 0x01, 0x02, 0x04, 0x08, 0x08, 0x08},
	    ['8'] = {0x0E, 0x11, 0x11, 0x0E, 0x11, 0x11, 0x0E},
	    ['9'] = {0x0E, 0x11, 0x11, 0x0F, 0x01, 0x01, 0x0E},
	    ['A'] = {0x0E, 0x11, 0x11, 0x1F, 0x11, 0x11, 0x11},
	    ['B'] = {0x1E, 0x11, 0x11, 0x1E, 0x11, 0x11, 0x1E},
	    ['C'] = {0x0F, 0x10, 0x10, 0x10, 0x10, 0x10, 0x0F},
	    ['D'] = {0x1E, 0x11, 0x11, 0x11, 0x11, 0x11, 0x1E},
	    ['E'] = {0x1F, 0x10, 0x10, 0x1E, 0x10, 0x10, 0x1F},
	    ['F'] = {0x1F, 0x10, 0x10, 0x1E, 0x10, 0x10, 0x10},
	    ['G'] = {0x0F, 0x10, 0x10, 0x13, 0x11, 0x11, 0x0F},
	    ['H'] = {0x11, 0x11, 0x11, 0x1F, 0x11, 0x11, 0x11},
	    ['I'] = {0x1F, 0x04, 0x04, 0x04, 0x04, 0x04, 0x1F},
	    ['J'] = {0x07, 0x02, 0x02, 0x02, 0x12, 0x12, 0x0C},
	    ['K'] = {0x11, 0x12, 0x14, 0x18, 0x14, 0x12, 0x11},
	    ['L'] = {0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x1F},
	    ['M'] = {0x11, 0x1B, 0x15, 0x15, 0x11, 0x11, 0x11},
	    ['N'] = {0x11, 0x19, 0x15, 0x13, 0x11, 0x11, 0x11},
	    ['O'] = {0x0E, 0x11, 0x11, 0x11, 0x11, 0x11, 0x0E},
	    ['P'] = {0x1E, 0x11, 0x11, 0x1E, 0x10, 0x10, 0x10},
	    ['Q'] = {0x0E, 0x11, 0x11, 0x11, 0x15, 0x12, 0x0D},
	    ['R'] = {0x1E, 0x11, 0x11, 0x1E, 0x14, 0x12, 0x11},
	    ['S'] = {0x0F, 0x10, 0x10, 0x0E, 0x01, 0x01, 0x1E},
	    ['T'] = {0x1F, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04},
	    ['U'] = {0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x0E},
	    ['V'] = {0x11, 0x11, 0x11, 0x11, 0x11, 0x0A, 0x04},
	    ['W'] = {0x11, 0x11, 0x11, 0x15, 0x15, 0x15, 0x0A},
	    ['X'] = {0x11, 0x11, 0x0A, 0x04, 0x0A, 0x11, 0x11},
	    ['Y'] = {0x11, 0x11, 0x0A, 0x04, 0x04, 0x04, 0x04},
	    ['Z'] = {0x1F, 0x01, 0x02, 0x04, 0x08, 0x10, 0x1F},
	};
	static const unsigned char unknown[7] = {0x1F, 0x11, 0x15, 0x15,
						 0x15, 0x11, 0x1F};
	unsigned char uc = (unsigned char)toupper((unsigned char)c);

	if (uc < 128) {
		for (int i = 0; i < 7; i++) {
			if (glyphs[uc][i])
				return glyphs[uc];
		}
		if (uc == ' ')
			return glyphs[uc];
	}
	return unknown;
}

static void text_size(enum text_role role, const char *text, int *w, int *h)
{
	int scale = text_scale(role);

	*w = text ? (int)strlen(text) * 6 * scale : 0;
	*h = 7 * scale;
}

static void draw_text(struct ui_context *ui, enum text_role role,
		      const char *text, SDL_Color color, int x, int y)
{
	int scale = text_scale(role);
	SDL_Rect px = {0, 0, scale, scale};

	SDL_SetRenderDrawColor(ui->renderer, color.r, color.g, color.b,
			       color.a);
	for (const char *p = text; p && *p; p++, x += 6 * scale) {
		const unsigned char *rows = glyph_rows(*p);
		for (int row = 0; row < 7; row++) {
			for (int col = 0; col < 5; col++) {
				if (!(rows[row] & (1U << (4 - col))))
					continue;
				px.x = x + col * scale;
				px.y = y + row * scale;
				SDL_RenderFillRect(ui->renderer, &px);
			}
		}
	}
}

static void fill_rect(struct ui_context *ui, SDL_Rect r, SDL_Color color)
{
	SDL_SetRenderDrawColor(ui->renderer, color.r, color.g, color.b,
			       color.a);
	SDL_RenderFillRect(ui->renderer, &r);
}

static void fit_text(enum text_role role, const char *src, int max_w, char *dst,
		     size_t dst_cap)
{
	int w = 0, h = 0;

	if (!src || !*src || dst_cap == 0) {
		if (dst_cap > 0)
			dst[0] = '\0';
		return;
	}
	snprintf(dst, dst_cap, "%s", src);
	text_size(role, dst, &w, &h);
	if (max_w <= 0 || w <= max_w)
		return;

	size_t len = strlen(dst);
	while (len > 3) {
		dst[len - 3] = '.';
		dst[len - 2] = '.';
		dst[len - 1] = '.';
		dst[len] = '\0';
		text_size(role, dst, &w, &h);
		if (w <= max_w)
			return;
		len--;
		dst[len] = '\0';
	}
	snprintf(dst, dst_cap, "...");
}

static void draw_text_fit(struct ui_context *ui, enum text_role role,
			  const char *text, SDL_Color color, int x, int y,
			  int max_w)
{
	char fitted[256];

	fit_text(role, text, max_w, fitted, sizeof(fitted));
	draw_text(ui, role, fitted, color, x, y);
}

static void draw_text_right(struct ui_context *ui, enum text_role role,
			    const char *text, SDL_Color color, int right_x,
			    int y)
{
	int w = 0, h = 0;

	if (!text || !*text)
		return;
	text_size(role, text, &w, &h);
	draw_text(ui, role, text, color, right_x - w, y);
}

static void draw_text_centered(struct ui_context *ui, enum text_role role,
			       const char *text, SDL_Color color, int cx, int y)
{
	int w = 0, h = 0;

	if (!text || !*text)
		return;
	text_size(role, text, &w, &h);
	draw_text(ui, role, text, color, cx - w / 2, y - h / 2);
}

int ui_init(struct ui_context *ui)
{
	memset(ui, 0, sizeof(*ui));

	if (SDL_Init(SDL_INIT_VIDEO | SDL_INIT_TIMER | SDL_INIT_EVENTS) != 0) {
		fprintf(stderr, "trust_pong: SDL_Init: %s\n", SDL_GetError());
		return -1;
	}

	ui->window = SDL_CreateWindow("LOTA trust_pong", SDL_WINDOWPOS_CENTERED,
				      SDL_WINDOWPOS_CENTERED, UI_WINDOW_W,
				      UI_WINDOW_H, SDL_WINDOW_SHOWN);
	if (!ui->window) {
		fprintf(stderr, "trust_pong: CreateWindow: %s\n",
			SDL_GetError());
		goto fail;
	}
	ui->renderer = SDL_CreateRenderer(ui->window, -1,
					  SDL_RENDERER_ACCELERATED |
					      SDL_RENDERER_PRESENTVSYNC);
	if (!ui->renderer)
		ui->renderer = SDL_CreateRenderer(ui->window, -1, 0);
	if (!ui->renderer) {
		fprintf(stderr, "trust_pong: CreateRenderer: %s\n",
			SDL_GetError());
		goto fail;
	}
	return 0;

fail:
	ui_shutdown(ui);
	return -1;
}

void ui_shutdown(struct ui_context *ui)
{
	if (ui->renderer)
		SDL_DestroyRenderer(ui->renderer);
	if (ui->window)
		SDL_DestroyWindow(ui->window);
	SDL_Quit();
	memset(ui, 0, sizeof(*ui));
}

void ui_begin_frame(struct ui_context *ui, enum ui_verdict verdict)
{
	(void)verdict;
	SDL_Color bg = color_bg();

	SDL_SetRenderDrawColor(ui->renderer, bg.r, bg.g, bg.b, bg.a);
	SDL_RenderClear(ui->renderer);
}

void ui_end_frame(struct ui_context *ui)
{
	SDL_RenderPresent(ui->renderer);
}

void ui_draw_banner(struct ui_context *ui, enum ui_verdict verdict,
		    const char *reason)
{
	SDL_Color accent;
	char reason_line[220];
	const char *label = verdict_label(verdict);

	verdict_palette(verdict, &accent);
	snprintf(reason_line, sizeof(reason_line), "%s", reason ? reason : "");

	SDL_Rect banner = {0, 0, UI_WINDOW_W, UI_BANNER_H};
	fill_rect(ui, banner, color_bar());

	SDL_Rect strip = {0, UI_BANNER_H - 3, UI_WINDOW_W, 3};
	fill_rect(ui, strip, accent);

	draw_text(ui, TEXT_STATUS, label, color_text(), 16, 10);
	draw_text_fit(ui, TEXT_SMALL, reason_line, color_muted(), 16, 42,
		      UI_WINDOW_W - 32);
}

void ui_draw_score(struct ui_context *ui, int score, int hits)
{
	char buf[64];

	snprintf(buf, sizeof(buf), "score %05d  hits %03d", score, hits);
	draw_text_right(ui, TEXT_SMALL, buf, color_muted(), UI_WINDOW_W - 16,
			14);
}

void ui_draw_paddle(struct ui_context *ui, int y)
{
	SDL_SetRenderDrawColor(ui->renderer, 0xC8, 0xD0, 0xDA, 0xFF);
	SDL_Rect p = {32, y, UI_PADDLE_W, UI_PADDLE_H};
	SDL_RenderFillRect(ui->renderer, &p);
}

void ui_draw_ball(struct ui_context *ui, int x, int y)
{
	SDL_SetRenderDrawColor(ui->renderer, 0xC8, 0xD0, 0xDA, 0xFF);
	SDL_Rect b = {x, y, UI_BALL_SIZE, UI_BALL_SIZE};
	SDL_RenderFillRect(ui->renderer, &b);
}

void ui_draw_back_wall(struct ui_context *ui)
{
	SDL_Color c = color_game();
	SDL_SetRenderDrawColor(ui->renderer, c.r, c.g, c.b, c.a);
	SDL_Rect wall = {UI_WINDOW_W - 16, UI_BANNER_H, 16,
			 UI_WINDOW_H - UI_BANNER_H};
	SDL_RenderFillRect(ui->renderer, &wall);
}

void ui_draw_frozen_overlay(struct ui_context *ui)
{
	SDL_SetRenderDrawBlendMode(ui->renderer, SDL_BLENDMODE_BLEND);
	SDL_SetRenderDrawColor(ui->renderer, 0x00, 0x00, 0x00, 0xD8);
	SDL_Rect full = {0, UI_BANNER_H, UI_WINDOW_W,
			 UI_WINDOW_H - UI_BANNER_H};
	SDL_RenderFillRect(ui->renderer, &full);
	SDL_SetRenderDrawBlendMode(ui->renderer, SDL_BLENDMODE_NONE);

	draw_text_centered(ui, TEXT_OVERLAY, "INTEGRITY LOSS", color_text(),
			   UI_WINDOW_W / 2, UI_WINDOW_H / 2 - 24);
	draw_text_centered(
	    ui, TEXT_SMALL, "session terminated after two UNTRUSTED heartbeats",
	    color_muted(), UI_WINDOW_W / 2, UI_WINDOW_H / 2 + 24);
}
