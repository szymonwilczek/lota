/* SPDX-License-Identifier: MIT
 * Copyright (C) 2026 Szymon Wilczek
 *
 * lota-install - Terminal UI
 */

#include "ui.h"

#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <termios.h>

/*
 * SGR fragments
 * Empty strings in no-color mode
 */
#define SGR_RESET "\033[0m"
#define SGR_BOLD "\033[1m"
#define SGR_DIM "\033[2m"
#define SGR_RED "\033[31m"
#define SGR_GREEN "\033[32m"
#define SGR_YELLOW "\033[33m"
#define SGR_CYAN "\033[36m"

static volatile sig_atomic_t g_winch;

static void winch_handler(int sig)
{
	(void)sig;
	g_winch = 1;
}

static const char *col(const struct ui *ui, const char *sgr)
{
	return ui->color ? sgr : "";
}

void ui_init(struct ui *ui, int force_plain)
{
	struct sigaction sa;
	const char *term = getenv("TERM");

	memset(ui, 0, sizeof(*ui));
	ui->tty = !force_plain && isatty(STDOUT_FILENO) &&
		  (!term || strcmp(term, "dumb") != 0);
	ui->color = ui->tty && !getenv("NO_COLOR");

	if (ui->tty) {
		memset(&sa, 0, sizeof(sa));
		sa.sa_handler = winch_handler;
		sa.sa_flags = SA_RESTART;
		sigaction(SIGWINCH, &sa, NULL);
	}
}

int ui_term_width(struct ui *ui)
{
	struct winsize ws;

	if (!ui->tty)
		return 80;
	if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) != 0 || ws.ws_col < 20)
		return 80;
	return ws.ws_col;
}

/* counting codepoints is exact here:
 * every glyph the installer emits is single-width */
int ui_disp_len(const char *s)
{
	int n = 0;

	for (; *s; s++)
		if (((unsigned char)*s & 0xC0) != 0x80)
			n++;
	return n;
}

/* feeds a possibly multi-line text to the sink, one line per call */
static void sink_emit_lines(struct ui *ui, const char *text)
{
	char line[UI_LIVE_LINE_CAP];

	while (*text) {
		const char *nl = strchr(text, '\n');
		size_t seg = nl ? (size_t)(nl - text) : strlen(text);

		if (seg >= sizeof(line))
			seg = sizeof(line) - 1;
		memcpy(line, text, seg);
		line[seg] = '\0';
		ui->sink->line(ui->sink->ud, line);
		text += seg;
		if (*text == '\n')
			text++;
	}
}

/* Copies at most `cols` display columns, never splitting a UTF-8
 * sequence.
 * `out` must hold UI_LIVE_LINE_CAP bytes. */
static void disp_trunc(char *out, const char *s, int cols)
{
	int used = 0;
	size_t o = 0;

	while (*s && o < UI_LIVE_LINE_CAP - 5) {
		size_t step = 1;

		if (((unsigned char)*s & 0xC0) != 0x80) {
			if (used == cols)
				break;
			used++;
		}
		while (((unsigned char)s[step] & 0xC0) == 0x80)
			step++;
		if (o + step >= UI_LIVE_LINE_CAP - 5)
			break;
		memcpy(out + o, s, step);
		o += step;
		s += step;
	}
	out[o] = '\0';
}

/* Word-wraps `text` to the current width and prints each line as prefix + body.
 * Explicit newlines in the text are honored. */
static void wrap_print(struct ui *ui, const char *prefix, const char *text)
{
	int width = ui_term_width(ui);
	int body = width - ui_disp_len(prefix) - 1;
	const char *p = text;

	if (body < 20)
		body = 20;

	while (*p) {
		const char *nl = strchr(p, '\n');
		size_t seg = nl ? (size_t)(nl - p) : strlen(p);

		while (1) {
			size_t take = seg;
			size_t fit = 0;
			size_t i = 0;
			int used = 0;

			/* widest prefix of the segment that fits */
			while (i < seg && used < body) {
				if (((unsigned char)p[i] & 0xC0) != 0x80)
					used++;
				i++;
			}
			if (i < seg) {
				/* break at the last space inside the fit */
				for (fit = i; fit > 0 && p[fit] != ' '; fit--)
					;
				take = fit > 0 ? fit : i;
			}

			printf("%s%.*s\n", prefix, (int)take, p);
			p += take;
			seg -= take;
			while (seg > 0 && *p == ' ') {
				p++;
				seg--;
			}
			if (seg == 0)
				break;
		}
		if (nl)
			p++;
	}
}

void ui_banner(struct ui *ui, const char *title, const char *version,
	       const char *subtitle)
{
	int width = ui_term_width(ui);
	int inner;
	int pad;
	int i;

	/* full-screen frontend draws its own chrome */
	if (ui->sink)
		return;

	if (!ui->tty) {
		printf("[lota-install] %s %s\n", title, version);
		printf("[lota-install] %s\n", subtitle);
		return;
	}

	if (width > 76)
		width = 76;
	inner = width - 2;

	printf("%s╭", col(ui, SGR_DIM));
	for (i = 0; i < inner; i++)
		printf("─");
	printf("╮%s\n", col(ui, SGR_RESET));

	pad = inner - 2 - ui_disp_len(title) - ui_disp_len(version) - 2;
	if (pad < 1)
		pad = 1;
	printf("%s│%s  %s%s%s%*s%s%s  %s│%s\n", col(ui, SGR_DIM),
	       col(ui, SGR_RESET), col(ui, SGR_BOLD), title, col(ui, SGR_RESET),
	       pad, "", col(ui, SGR_DIM), version, col(ui, SGR_DIM),
	       col(ui, SGR_RESET));

	pad = inner - 2 - ui_disp_len(subtitle);
	if (pad < 0)
		pad = 0;
	printf("%s│%s  %s%s%s%*s%s│%s\n", col(ui, SGR_DIM), col(ui, SGR_RESET),
	       col(ui, SGR_DIM), subtitle, col(ui, SGR_RESET), pad, "",
	       col(ui, SGR_DIM), col(ui, SGR_RESET));

	printf("%s╰", col(ui, SGR_DIM));
	for (i = 0; i < inner; i++)
		printf("─");
	printf("╯%s\n", col(ui, SGR_RESET));
	fflush(stdout);
}

void ui_stage_begin(struct ui *ui, int idx, int total, const char *title)
{
	if (ui->sink) {
		char buf[UI_LIVE_LINE_CAP];

		snprintf(buf, sizeof(buf), "== %s (%d/%d) ==", title, idx,
			 total);
		ui->sink->line(ui->sink->ud, buf);
		return;
	}
	if (!ui->tty) {
		printf("[lota-install] stage %d/%d: %s\n", idx, total, title);
		fflush(stdout);
		return;
	}
	printf("\n%s➜%s %sStage %d/%d — %s%s\n", col(ui, SGR_CYAN),
	       col(ui, SGR_RESET), col(ui, SGR_BOLD), idx, total, title,
	       col(ui, SGR_RESET));
	fflush(stdout);
}

static const char *result_glyph(const struct ui *ui, enum ui_result r,
				const char **sgr)
{
	switch (r) {
	case UI_OK:
		*sgr = col(ui, SGR_GREEN);
		return "✔";
	case UI_DONE:
		*sgr = col(ui, SGR_DIM);
		return "✔";
	case UI_FAIL:
		*sgr = col(ui, SGR_RED);
		return "✖";
	case UI_REBOOT:
		*sgr = col(ui, SGR_YELLOW);
		return "↻";
	case UI_PENDING:
		*sgr = col(ui, SGR_YELLOW);
		return "●";
	case UI_SKIP:
	default:
		*sgr = col(ui, SGR_DIM);
		return "○";
	}
}

static const char *result_word(enum ui_result r)
{
	switch (r) {
	case UI_OK:
		return "ok";
	case UI_DONE:
		return "already satisfied";
	case UI_FAIL:
		return "FAILED";
	case UI_REBOOT:
		return "needs reboot";
	case UI_PENDING:
		return "pending";
	case UI_SKIP:
	default:
		return "skipped";
	}
}

void ui_stage_result(struct ui *ui, enum ui_result r, const char *title,
		     const char *note)
{
	const char *sgr;
	const char *glyph;

	if (ui->sink) {
		char buf[UI_LIVE_LINE_CAP];

		snprintf(buf, sizeof(buf), "%s: %s%s%s", result_word(r), title,
			 note ? " - " : "", note ? note : "");
		ui->sink->line(ui->sink->ud, buf);
		return;
	}
	if (!ui->tty) {
		printf("[lota-install]   %s: %s%s%s\n", result_word(r), title,
		       note ? " - " : "", note ? note : "");
		fflush(stdout);
		return;
	}
	glyph = result_glyph(ui, r, &sgr);
	if (!note)
		note = result_word(r);

	/* short notes ride the title line,
	 * long ones wrap below it */
	if (ui_disp_len(title) + ui_disp_len(note) + 9 <= ui_term_width(ui)) {
		printf("  %s%s%s %s%s — %s%s\n", sgr, glyph, col(ui, SGR_RESET),
		       title, col(ui, SGR_DIM), note, col(ui, SGR_RESET));
	} else {
		printf("  %s%s%s %s %s(%s)%s\n", sgr, glyph, col(ui, SGR_RESET),
		       title, col(ui, SGR_DIM), result_word(r),
		       col(ui, SGR_RESET));
		printf("%s", col(ui, SGR_DIM));
		wrap_print(ui, "    ", note);
		printf("%s", col(ui, SGR_RESET));
	}
	fflush(stdout);
}

void ui_explain(struct ui *ui, const char *body)
{
	char prefix[32];

	if (ui->sink) {
		sink_emit_lines(ui, body);
		return;
	}
	if (!ui->tty) {
		wrap_print(ui, "[lota-install]   ", body);
		fflush(stdout);
		return;
	}
	snprintf(prefix, sizeof(prefix), "  %s│%s ", col(ui, SGR_DIM),
		 col(ui, SGR_RESET));
	printf("\n");
	wrap_print(ui, prefix, body);
	printf("\n");
	fflush(stdout);
}

static void vtext(struct ui *ui, const char *sgr, const char *tag,
		  const char *fmt, va_list ap)
{
	char buf[2048];

	vsnprintf(buf, sizeof(buf), fmt, ap);
	if (ui->sink) {
		if (tag[0]) {
			char tagged[2048];

			snprintf(tagged, sizeof(tagged), "%s%s", tag, buf);
			sink_emit_lines(ui, tagged);
		} else {
			sink_emit_lines(ui, buf);
		}
		return;
	}
	if (!ui->tty) {
		printf("[lota-install] %s%s\n", tag, buf);
		fflush(stdout);
		return;
	}
	printf("%s", sgr);
	wrap_print(ui, "  ", buf);
	printf("%s", col(ui, SGR_RESET));
	fflush(stdout);
}

void ui_text(struct ui *ui, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vtext(ui, "", "", fmt, ap);
	va_end(ap);
}

void ui_warn(struct ui *ui, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vtext(ui, col(ui, SGR_YELLOW), "WARN: ", fmt, ap);
	va_end(ap);
}

void ui_error(struct ui *ui, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vtext(ui, col(ui, SGR_RED), "ERROR: ", fmt, ap);
	va_end(ap);
}

void ui_kv(struct ui *ui, const char *key, const char *val)
{
	if (ui->sink) {
		char buf[UI_LIVE_LINE_CAP];

		snprintf(buf, sizeof(buf), "%-28s %s", key, val);
		ui->sink->line(ui->sink->ud, buf);
		return;
	}
	if (!ui->tty) {
		printf("[lota-install]   %-28s %s\n", key, val);
		fflush(stdout);
		return;
	}
	printf("  %s%-28s%s %s\n", col(ui, SGR_DIM), key, col(ui, SGR_RESET),
	       val);
	fflush(stdout);
}

int ui_confirm(struct ui *ui, const char *prompt, int assume_yes)
{
	char line[64];

	if (assume_yes)
		return 1;
	/* Full-screen frontend confirms through its own modal before
	 * calling into a stage.
	 * Nothing on the ui_* path asks again. */
	if (ui->sink)
		return 1;

	if (ui->tty)
		printf("  %s▸%s %s %s[Enter to continue, q to quit]%s ",
		       col(ui, SGR_CYAN), col(ui, SGR_RESET), prompt,
		       col(ui, SGR_DIM), col(ui, SGR_RESET));
	else
		printf("[lota-install] %s [Enter to continue, q to quit] ",
		       prompt);
	fflush(stdout);

	if (!fgets(line, sizeof(line), stdin))
		return 0;
	if (line[0] == 'q' || line[0] == 'Q')
		return 0;
	return 1;
}

static const char *const spin_frames[] = { "⠋", "⠙", "⠹", "⠸", "⠼",
					   "⠴", "⠦", "⠧", "⠇", "⠏" };

static double live_elapsed(const struct ui *ui)
{
	struct timespec now;

	clock_gettime(CLOCK_MONOTONIC, &now);
	return (double)(now.tv_sec - ui->live_start.tv_sec) +
	       (double)(now.tv_nsec - ui->live_start.tv_nsec) / 1e9;
}

/* Erases the previously rendered region and repaints it at the current width.
 * After a resize the old row count is unreliable (the terminal may have
 * rewrapped), so start fresh below instead of erasing. */
static void live_redraw(struct ui *ui)
{
	int width = ui_term_width(ui);
	char line[UI_LIVE_LINE_CAP];
	int rows = 0;
	int i;

	if (!ui->tty)
		return;

	if (g_winch) {
		g_winch = 0;
		ui->live_rows = 0;
	}
	if (ui->live_rows > 0)
		printf("\r\033[%dA\033[0J", ui->live_rows);

	disp_trunc(line, ui->live_label, width - 6);
	printf("  %s%s%s %s%s(%.0fs)%s\n", col(ui, SGR_CYAN),
	       spin_frames[ui->spin % 10], col(ui, SGR_RESET), line,
	       col(ui, SGR_DIM), live_elapsed(ui), col(ui, SGR_RESET));
	rows++;

	for (i = 0; i < ui->tail_count; i++) {
		disp_trunc(line, ui->live_tail[i], width - 6);
		printf("  %s│ %s%s\n", col(ui, SGR_DIM), line,
		       col(ui, SGR_RESET));
		rows++;
	}

	ui->live_rows = rows;
	fflush(stdout);
}

void ui_live_begin(struct ui *ui, const char *label)
{
	snprintf(ui->live_label, sizeof(ui->live_label), "%s", label);
	ui->live_active = 1;
	ui->live_rows = 0;
	ui->tail_count = 0;
	ui->carry_len = 0;
	ui->spin = 0;
	clock_gettime(CLOCK_MONOTONIC, &ui->live_start);

	if (ui->sink) {
		ui->sink->status(ui->sink->ud, label, 1, UI_OK, 0.0);
		return;
	}
	if (!ui->tty) {
		printf("[lota-install]   run: %s\n", label);
		fflush(stdout);
		return;
	}
	live_redraw(ui);
}

/* Appends one complete output line to the rolling tail. */
static void live_push_line(struct ui *ui, const char *s)
{
	if (ui->sink) {
		ui->sink->line(ui->sink->ud, s);
		return;
	}
	if (!ui->tty) {
		printf("[lota-install]   | %s\n", s);
		fflush(stdout);
		return;
	}
	if (ui->tail_count == UI_LIVE_TAIL) {
		memmove(ui->live_tail[0], ui->live_tail[1],
			sizeof(ui->live_tail) - sizeof(ui->live_tail[0]));
		ui->tail_count--;
	}
	snprintf(ui->live_tail[ui->tail_count], UI_LIVE_LINE_CAP, "%s", s);
	ui->tail_count++;
}

void ui_live_feed(struct ui *ui, const char *chunk, size_t len)
{
	size_t i;

	if (!ui->live_active)
		return;

	for (i = 0; i < len; i++) {
		char c = chunk[i];

		if (c == '\n' || ui->carry_len == sizeof(ui->carry) - 1) {
			ui->carry[ui->carry_len] = '\0';
			if (ui->carry_len > 0)
				live_push_line(ui, ui->carry);
			ui->carry_len = 0;
			if (c != '\n')
				ui->carry[ui->carry_len++] = c;
		} else if (c != '\r') {
			ui->carry[ui->carry_len++] = c;
		}
	}
	if (ui->tty && !ui->sink)
		live_redraw(ui);
}

void ui_live_tick(struct ui *ui)
{
	if (!ui->live_active)
		return;
	ui->spin++;
	if (ui->sink) {
		ui->sink->tick(ui->sink->ud);
		return;
	}
	if (!ui->tty)
		return;
	live_redraw(ui);
}

void ui_live_end(struct ui *ui, enum ui_result r)
{
	const char *sgr;
	const char *glyph;
	double secs;

	if (!ui->live_active)
		return;

	/* flush a trailing partial line */
	if (ui->carry_len > 0) {
		ui->carry[ui->carry_len] = '\0';
		live_push_line(ui, ui->carry);
		ui->carry_len = 0;
	}
	secs = live_elapsed(ui);
	ui->live_active = 0;

	if (ui->sink) {
		ui->sink->status(ui->sink->ud, ui->live_label, 0, r, secs);
		return;
	}
	if (!ui->tty) {
		printf("[lota-install]   %s: %s (%.1fs)\n", result_word(r),
		       ui->live_label, secs);
		fflush(stdout);
		return;
	}

	/* collapse: erase the region, keep failure tails for debugging */
	if (g_winch) {
		g_winch = 0;
		ui->live_rows = 0;
	}
	if (ui->live_rows > 0)
		printf("\r\033[%dA\033[0J", ui->live_rows);
	ui->live_rows = 0;

	glyph = result_glyph(ui, r, &sgr);
	printf("  %s%s%s %s %s(%s, %.1fs)%s\n", sgr, glyph, col(ui, SGR_RESET),
	       ui->live_label, col(ui, SGR_DIM), result_word(r), secs,
	       col(ui, SGR_RESET));

	if (r == UI_FAIL) {
		int i;

		for (i = 0; i < ui->tail_count; i++)
			printf("  %s│ %s%s\n", col(ui, SGR_DIM),
			       ui->live_tail[i], col(ui, SGR_RESET));
	}
	fflush(stdout);
}
