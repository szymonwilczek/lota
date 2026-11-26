/* SPDX-License-Identifier: MIT
 * Copyright (C) 2026 Szymon Wilczek
 *
 * lota-install - Terminal UI
 *
 * Output goes to the normal scrollback; only the live region (spinner and a
 * tail of child output) is redrawn in place. Without a tty, with --plain or
 * TERM=dumb, output is prefixed log lines; NO_COLOR drops colour.
 */

#ifndef LOTA_INSTALL_UI_H
#define LOTA_INSTALL_UI_H

#include <stddef.h>
#include <time.h>

#define UI_LIVE_TAIL 6 /* child output lines kept under the spinner */
#define UI_LIVE_LINE_CAP 256

enum ui_result {
	UI_OK = 0,
	UI_DONE, /* already satisfied, nothing ran */
	UI_FAIL,
	UI_REBOOT, /* needs a reboot to take effect */
	UI_SKIP, /* not applicable on this host */
	UI_PENDING, /* work or input still needed */
	UI_BLOCKED, /* needs work the installer does not do */
	UI_APPLIED, /* this run applied the stage and it holds */
};

/*
 * When set on a struct ui, ui_* output goes through these callbacks
 * and none to stdout; ui_banner() writes nothing and ui_confirm()
 * answers yes without asking.
 */
struct ui_sink {
	void (*line)(void *ud, const char *text);
	/* a live action started (running=1) or finished (running=0) */
	void (*status)(void *ud, const char *label, int running,
		       enum ui_result r, double secs);
	void (*tick)(void *ud);
	int (*abort)(void *ud); /* nonzero: terminate the running child */
	void *ud;
};

struct ui {
	int tty; /* 0: plain log lines */
	int color;
	const struct ui_sink *sink;

	int live_active;
	int live_rows; /* rows currently drawn for the live region */
	unsigned spin;
	char live_label[UI_LIVE_LINE_CAP];
	char live_tail[UI_LIVE_TAIL][UI_LIVE_LINE_CAP];
	int tail_count;
	char carry[UI_LIVE_LINE_CAP]; /* partial line between feeds */
	size_t carry_len;
	struct timespec live_start;
};

/**
 * ui_init() - Initialise a UI for stdout.
 * @ui:          UI to initialise.
 * @force_plain: use plain log lines even on a tty.
 */
void ui_init(struct ui *ui, int force_plain);

/**
 * ui_term_width() - Terminal width.
 * @ui: the UI.
 *
 * Return: columns of stdout; 80 in plain mode, when the width cannot be
 * read, or below 20 columns.
 */
int ui_term_width(struct ui *ui);

/**
 * ui_disp_len() - Display columns of a UTF-8 string.
 * @s: the string.
 *
 * Every code point counts as one column.
 *
 * Return: the column count.
 */
int ui_disp_len(const char *s);

/**
 * ui_banner() - Print the product banner.
 * @ui:       the UI; nothing is printed with a sink.
 * @title:    product name.
 * @version:  version string.
 * @subtitle: line under the title.
 */
void ui_banner(struct ui *ui, const char *title, const char *version,
	       const char *subtitle);

/**
 * ui_stage_begin() - Print a stage header.
 * @ui:    the UI.
 * @idx:   1-based stage number.
 * @total: number of steps.
 * @title: stage title.
 */
void ui_stage_begin(struct ui *ui, int idx, int total, const char *title);

/**
 * ui_stage_result() - Print a stage outcome.
 * @ui:    the UI.
 * @r:     outcome.
 * @title: stage title.
 * @note:  reason, or NULL.
 */
void ui_stage_result(struct ui *ui, enum ui_result r, const char *title,
		     const char *note);

/**
 * ui_result_word() - Word a plain transcript prints for an outcome.
 * @r: outcome.
 *
 * Return: a static string.
 */
const char *ui_result_word(enum ui_result r);

/**
 * ui_explain() - Print a word-wrapped explanation block.
 * @ui:   the UI.
 * @body: the text.
 */
void ui_explain(struct ui *ui, const char *body);

/**
 * ui_text() - Print a word-wrapped paragraph.
 * @ui:  the UI.
 * @fmt: printf format.
 */
void ui_text(struct ui *ui, const char *fmt, ...)
	__attribute__((format(printf, 2, 3)));

/**
 * ui_error() - Print a word-wrapped error.
 * @ui:  the UI.
 * @fmt: printf format.
 */
void ui_error(struct ui *ui, const char *fmt, ...)
	__attribute__((format(printf, 2, 3)));

/**
 * ui_kv() - Print an aligned key and value.
 * @ui:  the UI.
 * @key: the key.
 * @val: the value.
 */
void ui_kv(struct ui *ui, const char *key, const char *val);

enum ui_default {
	UI_DEFAULT_YES = 0,
	UI_DEFAULT_NO,
};

/**
 * ui_confirm() - Ask a yes/no question on stdin.
 * @ui:         the UI.
 * @prompt:     the question.
 * @assume_yes: answer yes without asking.
 * @def:        answer an empty line takes.
 *
 * y and yes accept; n, no, q and quit decline, in any case.
 *
 * Return: 1 to proceed, also with @assume_yes or a sink set. 0 on a decline,
 * EOF, or three unrecognised answers.
 */
int ui_confirm(struct ui *ui, const char *prompt, int assume_yes,
	       enum ui_default def);

/* live region: ui_live_begin(), then ui_live_feed() and ui_live_tick(), then
 * ui_live_end() */
void ui_live_begin(struct ui *ui, const char *label);
void ui_live_feed(struct ui *ui, const char *chunk, size_t len);
void ui_live_tick(struct ui *ui);
void ui_live_end(struct ui *ui, enum ui_result r);

#endif /* LOTA_INSTALL_UI_H */
