/* SPDX-License-Identifier: MIT
 * Copyright (C) 2026 Szymon Wilczek
 *
 * lota-install - Terminal UI
 *
 * Inline-scrolling renderer:
 *
 * Styled blocks are appended to the normal scrollback (nothing is lost when the
 * run ends) and only the live region - the spinner line plus a tail of child
 * output - is redrawn in place.
 *
 * The terminal width is re-queried on every redraw and on SIGWINCH, so the
 * layout follows resizes without an alternate screen.
 *
 * Without a TTY (or with -plain / NO_COLOR) every element degrades to prefixed
 * log lines.
 */

#ifndef LOTA_INSTALL_UI_H
#define LOTA_INSTALL_UI_H

#include <stddef.h>
#include <time.h>

/* Lines of child output kept visible under the spinner */
#define UI_LIVE_TAIL 6
#define UI_LIVE_LINE_CAP 256

/* Outcome glyph for a finished stage or live action */
enum ui_result {
	UI_OK = 0, /* Green check */
	UI_DONE, /* Dim check: already satisfied, nothing ran */
	UI_FAIL, /* Red cross */
	UI_REBOOT, /* Yellow: needs a reboot to take effect */
	UI_SKIP, /* Dim circle: not applicable on this host */
	UI_PENDING, /* Yellow dot: work or input still needed */
};

/* Output sink:
 * When set on a struct ui, every ui_* call routes through these callbacks
 * instead of writing to stdout.
 * Full-screen TUI installs one so stage applies and the self-check
 * (which talk to the ui_* API) render into its panes instead of corrupting
 * the alternate screen. */
struct ui_sink {
	/* one finished line of output or commentary */
	void (*line)(void *ud, const char *text);
	/* a live action started (running=1) or finished (running=0) */
	void (*status)(void *ud, const char *label, int running,
		       enum ui_result r, double secs);
	/* spinner cadence while a child process runs */
	void (*tick)(void *ud);
	/* nonzero = terminate the running child (user abort) */
	int (*abort)(void *ud);
	void *ud;
};

struct ui {
	int tty; /* 1 = full TUI, 0 = plain log lines */
	int color; /* SGR sequences allowed */

	/* non-NULL = redirect every ui_* call (see struct ui_sink) */
	const struct ui_sink *sink;

	/* Live region state */
	int live_active;
	int live_rows; /* rows currently rendered for the region */
	unsigned spin;
	char live_label[UI_LIVE_LINE_CAP];
	char live_tail[UI_LIVE_TAIL][UI_LIVE_LINE_CAP];
	int tail_count; /* lines stored (<= UI_LIVE_TAIL, rolling) */
	char carry[UI_LIVE_LINE_CAP]; /* partial line between feeds */
	size_t carry_len;
	struct timespec live_start;
};

/* force_plain disables the TUI even on a TTY */
void ui_init(struct ui *ui, int force_plain);

/* current terminal width (re-queried; plain mode returns 80) */
int ui_term_width(struct ui *ui);

/* display columns of a UTF-8 string (every glyph the installer emits
 * is single-width) */
int ui_disp_len(const char *s);

/* product banner: rounded box with title and right-aligned version */
void ui_banner(struct ui *ui, const char *title, const char *version,
	       const char *subtitle);

/* stage header: "Stage idx/total - title" */
void ui_stage_begin(struct ui *ui, int idx, int total, const char *title);

/*
 * Collapsed stage outcome line.
 * Note MAY be NULL!
 */
void ui_stage_result(struct ui *ui, enum ui_result r, const char *title,
		     const char *note);

/* explanation block: dim vertical bar, word-wrapped body */
void ui_explain(struct ui *ui, const char *body);

/* word-wrapped paragraph / warning / error */
void ui_text(struct ui *ui, const char *fmt, ...)
	__attribute__((format(printf, 2, 3)));
void ui_warn(struct ui *ui, const char *fmt, ...)
	__attribute__((format(printf, 2, 3)));
void ui_error(struct ui *ui, const char *fmt, ...)
	__attribute__((format(printf, 2, 3)));

/* aligned "key  value" detail line */
void ui_kv(struct ui *ui, const char *key, const char *val);

/* 1 = proceed, 0 = abort.
 * Reads a line from stdin.
 * assume_yes skips the prompt and proceeds. */
int ui_confirm(struct ui *ui, const char *prompt, int assume_yes);

/* live region: begin -> feed/tick -> end */
void ui_live_begin(struct ui *ui, const char *label);
void ui_live_feed(struct ui *ui, const char *chunk, size_t len);
void ui_live_tick(struct ui *ui);
void ui_live_end(struct ui *ui, enum ui_result r);

#endif /* LOTA_INSTALL_UI_H */
