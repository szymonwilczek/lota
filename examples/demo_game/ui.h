/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * trust_pong UI: the SDL2 window, bitmap text, banner, score and game shapes.
 */

#ifndef LOTA_EXAMPLES_DEMO_GAME_UI_H
#define LOTA_EXAMPLES_DEMO_GAME_UI_H

#include <SDL.h>

#define UI_WINDOW_W 800
#define UI_WINDOW_H 600
#define UI_BANNER_H 88
#define UI_PADDLE_W 16
#define UI_PADDLE_H 96
#define UI_BALL_SIZE 16

enum ui_verdict {
	UI_VERDICT_CHECKING = 0,
	UI_VERDICT_TRUSTED,
	UI_VERDICT_UNTRUSTED,
	UI_VERDICT_FROZEN,
	UI_VERDICT_OFFLINE,
};

struct ui_context {
	SDL_Window *window;
	SDL_Renderer *renderer;
};

/* Returns 0, or -1 with @ui zeroed. */
int ui_init(struct ui_context *ui);

void ui_shutdown(struct ui_context *ui);

/* Clears the frame; @verdict is ignored. */
void ui_begin_frame(struct ui_context *ui, enum ui_verdict verdict);

void ui_end_frame(struct ui_context *ui);

/*
 * Colour and title follow @verdict; a non-NULL @reason fills up to two rows
 * under the title.
 */
void ui_draw_banner(struct ui_context *ui, enum ui_verdict verdict,
		    const char *reason);

void ui_draw_score(struct ui_context *ui, int score, int hits);

void ui_draw_paddle(struct ui_context *ui, int y);

void ui_draw_ball(struct ui_context *ui, int x, int y);

void ui_draw_back_wall(struct ui_context *ui);

/* Centre overlay for a frozen game. */
void ui_draw_frozen_overlay(struct ui_context *ui);

#endif /* LOTA_EXAMPLES_DEMO_GAME_UI_H */
