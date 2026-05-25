/* SPDX-License-Identifier: MIT */
/*
 * trust_pong UI helpers.
 *
 * Thin wrapper over SDL2 so trust_pong.c reads as a game loop with
 * declarative draw calls instead of raw SDL setup. Owns the bitmap
 * text renderer, banner, score, and primitive game shapes.
 */

#ifndef LOTA_EXAMPLES_DEMO_GAME_UI_H
#define LOTA_EXAMPLES_DEMO_GAME_UI_H

#include <SDL.h>

#define UI_WINDOW_W 800
#define UI_WINDOW_H 600
#define UI_BANNER_H 68
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

/*
 * Initialise SDL2 and open the window.
 * Returns 0 on success and a negative errno-style code on failure.
 * On failure no resources are leaked and the context is zeroed.
 */
int ui_init(struct ui_context *ui);

void ui_shutdown(struct ui_context *ui);

/*
 * Clear the framebuffer to the background colour for the current
 * verdict. Called once per frame before draw calls.
 */
void ui_begin_frame(struct ui_context *ui, enum ui_verdict verdict);

/*
 * Present the back buffer.
 */
void ui_end_frame(struct ui_context *ui);

/*
 * Banner along the top of the window. Colour and text track the
 * verdict; reason (when non-NULL) is shown on a dedicated second row
 * so the operator sees why the verdict flipped without leaving the
 * game window.
 */
void ui_draw_banner(struct ui_context *ui, enum ui_verdict verdict,
		    const char *reason);

void ui_draw_score(struct ui_context *ui, int score, int hits);

void ui_draw_paddle(struct ui_context *ui, int y);

void ui_draw_ball(struct ui_context *ui, int x, int y);

void ui_draw_back_wall(struct ui_context *ui);

/*
 * Centre-screen overlay for the terminal "integrity loss" message.
 * The caller is responsible for deciding when to call it (after two
 * consecutive UNTRUSTED verdicts in the demo flow).
 */
void ui_draw_frozen_overlay(struct ui_context *ui);

#endif /* LOTA_EXAMPLES_DEMO_GAME_UI_H */
