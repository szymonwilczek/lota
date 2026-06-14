/* SPDX-License-Identifier: MIT
 *
 * lota-install - Full-screen Interactive Frontend
 *
 * Takes over the terminal like most of the TUIs:
 * Alternate screen, raw keys, stage list pane, details pane and an output pane,
 * all re-laid-out on every resize.
 *
 * This frontend probes, confirms and applies the same stage table, and the ui
 * sink (ui.h) feeds child output and self-check lines into the output pane
 * instead of stdout.
 *
 * Keys:
 *    - arrows/jk ->	select
 *   - Enter ->		runs the selected stage
 *   - a -> 		runs every pending stage in order
 *   - r ->		re-probes
 *   - PgUp/PgDn, Ctrl-U/Ctrl-D ->	scroll the output
 *   - q -> 		quit
 */

#include "tui.h"

#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>
#include <sys/types.h>

#include "ui.h"

/* cell grid */

/* attr byte: low 3 bits color index, high bits styles */
#define C_DEF 0
#define C_RED 1
#define C_GREEN 2
#define C_YELLOW 3
#define C_CYAN 4
#define C_MAGENTA 5
#define A_BOLD 0x08
#define A_DIM 0x10
#define A_INV 0x20

struct cell {
	char ch[5]; /* one UTF-8 codepoint */
	uint8_t attr;
};

#define TUI_MAX_STAGES 32
#define OUT_LINES 512
#define OUT_CAP 240

enum tui_mode {
	M_NAV = 0,
	M_CONFIRM,
	M_RUNNING,
	M_BARRIER,
	M_DONE,
};

struct tui {
	struct install_ctx *ctx;

	/* terminal */
	int cols, rows;
	struct cell *grid;
	int gcap;     /* cells allocated */
	char *fb;     /* compose buffer for one flush */
	size_t fbcap; /* bytes allocated */
	size_t fblen;

	/* Probed stage states;
	 * index install_stage_count = self-check */
	int n;
	enum stage_state st[TUI_MAX_STAGES];
	char note[TUI_MAX_STAGES][STAGE_NOTE_CAP];
	int selfcheck_done;
	int selfcheck_ok;

	/* interaction */
	enum tui_mode mode;
	int sel;
	int auto_run;
	int quit;
	char flash[OUT_CAP];

	/* Output pane ring buffer;
	 * scroll 0 follows the tail */
	char out[OUT_LINES][OUT_CAP];
	int out_head, out_n;
	int scroll;

	/* Running action */
	int running;
	unsigned spin;
	char run_label[OUT_CAP];
	struct timespec run_start;
	int abort_req;
};

/* terminal mode */

static volatile sig_atomic_t t_winch;
static struct termios t_saved;
static int t_active;

static void tui_winch(int sig)
{
	(void)sig;
	t_winch = 1;
}

static void term_restore(void)
{
	if (!t_active)
		return;
	t_active = 0;
	/* leave the alternate screen, show the cursor, reset attrs */
	(void)!write(STDOUT_FILENO, "\033[0m\033[?25h\033[?1049l", 19);
	tcsetattr(STDIN_FILENO, TCSAFLUSH, &t_saved);
}

static void tui_fatal_signal(int sig)
{
	term_restore();
	_exit(128 + sig);
}

static int term_enter(void)
{
	struct termios raw;
	struct sigaction sa;

	if (tcgetattr(STDIN_FILENO, &t_saved) != 0)
		return -errno;
	raw = t_saved;
	/* raw keys, no echo, no signal generation
	 * (Ctrl-C is a key here: it aborts running command before quitting) */
	raw.c_lflag &= ~(tcflag_t)(ICANON | ECHO | ISIG);
	raw.c_iflag &= ~(tcflag_t)(IXON | ICRNL);
	raw.c_cc[VMIN] = 0;
	raw.c_cc[VTIME] = 0;
	if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw) != 0)
		return -errno;

	t_active = 1;
	atexit(term_restore);
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = tui_fatal_signal;
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGHUP, &sa, NULL);
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = tui_winch;
	sa.sa_flags = SA_RESTART;
	sigaction(SIGWINCH, &sa, NULL);

	(void)!write(STDOUT_FILENO, "\033[?1049h\033[?25l", 14);
	return 0;
}

/* grid primitives */

static void grid_resize(struct tui *t)
{
	struct winsize ws;

	if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) != 0 || ws.ws_col < 2 ||
	    ws.ws_row < 2) {
		t->cols = 80;
		t->rows = 24;
	} else {
		t->cols = ws.ws_col;
		t->rows = ws.ws_row;
	}

	if (t->cols * t->rows > t->gcap) {
		free(t->grid);
		t->gcap = t->cols * t->rows;
		t->grid = calloc((size_t)t->gcap, sizeof(*t->grid));
		if (!t->grid) {
			term_restore();
			fprintf(stderr, "lota-install: Out of memory\n");
			exit(EXIT_INSTALL_FAIL);
		}
	}
}

static void grid_clear(struct tui *t)
{
	int i;

	for (i = 0; i < t->cols * t->rows; i++) {
		t->grid[i].ch[0] = '\0';
		t->grid[i].attr = 0;
	}
}

static struct cell *cell_at(struct tui *t, int x, int y)
{
	if (x < 0 || y < 0 || x >= t->cols || y >= t->rows)
		return NULL;
	return &t->grid[y * t->cols + x];
}

/* writes a UTF-8 string starting at (x,y), clipped to the row */
static void put_text(struct tui *t, int x, int y, uint8_t attr, const char *s)
{
	while (*s) {
		struct cell *c;
		size_t step = 1;

		while (((unsigned char)s[step] & 0xC0) == 0x80)
			step++;
		c = cell_at(t, x, y);
		if (!c)
			break;
		if (step > 4)
			step = 4;
		memcpy(c->ch, s, step);
		c->ch[step] = '\0';
		c->attr = attr;
		s += step;
		x++;
	}
}

/* like put_text but never paints past maxw display columns, so pane
 * content cannot bleed across a pane border */
static void put_clip(struct tui *t, int x, int y, int maxw, uint8_t attr,
		     const char *s)
{
	int used = 0;

	while (*s && used < maxw) {
		struct cell *c;
		size_t step = 1;

		while (((unsigned char)s[step] & 0xC0) == 0x80)
			step++;
		c = cell_at(t, x, y);
		if (!c)
			break;
		if (step > 4)
			step = 4;
		memcpy(c->ch, s, step);
		c->ch[step] = '\0';
		c->attr = attr;
		s += step;
		x++;
		used++;
	}
}

static void put_textf(struct tui *t, int x, int y, uint8_t attr,
		      const char *fmt, ...)
    __attribute__((format(printf, 5, 6)));

static void put_textf(struct tui *t, int x, int y, uint8_t attr,
		      const char *fmt, ...)
{
	char buf[512];
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);
	put_text(t, x, y, attr, buf);
}

/* fills a horizontal run with one glyph */
static void put_run(struct tui *t, int x, int y, int w, uint8_t attr,
		    const char *glyph)
{
	int i;

	for (i = 0; i < w; i++) {
		struct cell *c = cell_at(t, x + i, y);

		if (!c)
			break;
		snprintf(c->ch, sizeof(c->ch), "%s", glyph);
		c->attr = attr;
	}
}

/* rounded box with an embedded title */
static void put_box(struct tui *t, int x, int y, int w, int h, uint8_t attr,
		    const char *title)
{
	int i;

	if (w < 2 || h < 2)
		return;
	put_text(t, x, y, attr, "╭");
	put_run(t, x + 1, y, w - 2, attr, "─");
	put_text(t, x + w - 1, y, attr, "╮");
	for (i = 1; i < h - 1; i++) {
		put_text(t, x, y + i, attr, "│");
		put_text(t, x + w - 1, y + i, attr, "│");
	}
	put_text(t, x, y + h - 1, attr, "╰");
	put_run(t, x + 1, y + h - 1, w - 2, attr, "─");
	put_text(t, x + w - 1, y + h - 1, attr, "╯");
	if (title && title[0])
		put_textf(t, x + 2, y, attr | A_BOLD, " %s ", title);
}

/* Word-wraps text into a rectangle.
 * Returns rows consumed. */
static int draw_wrapped(struct tui *t, int x, int y, int w, int maxl,
			uint8_t attr, const char *text)
{
	const char *p = text;
	int line = 0;

	if (w < 4)
		return 0;

	while (*p && line < maxl) {
		const char *nl = strchr(p, '\n');
		size_t seg = nl ? (size_t)(nl - p) : strlen(p);

		do {
			size_t take = seg;
			size_t i = 0;
			int used = 0;
			char buf[512];

			while (i < seg && used < w) {
				if (((unsigned char)p[i] & 0xC0) != 0x80)
					used++;
				i++;
			}
			if (i < seg) {
				size_t fit;

				for (fit = i; fit > 0 && p[fit] != ' '; fit--)
					;
				take = fit > 0 ? fit : i;
			}
			if (take >= sizeof(buf))
				take = sizeof(buf) - 1;
			memcpy(buf, p, take);
			buf[take] = '\0';
			put_text(t, x, y + line, attr, buf);
			line++;
			p += take;
			seg -= take;
			while (seg > 0 && *p == ' ') {
				p++;
				seg--;
			}
		} while (seg > 0 && line < maxl);
		if (nl && *p == '\n')
			p++;
	}
	return line;
}

/* frame flush */

static void fb_put(struct tui *t, const char *s, size_t len)
{
	if (t->fblen + len + 1 > t->fbcap) {
		size_t want = (t->fblen + len + 1) * 2 + 4096;
		char *nfb = realloc(t->fb, want);

		if (!nfb)
			return;
		t->fb = nfb;
		t->fbcap = want;
	}
	memcpy(t->fb + t->fblen, s, len);
	t->fblen += len;
}

static void attr_sgr(uint8_t attr, char *buf, size_t cap)
{
	static const int fg[] = {0, 31, 32, 33, 36, 35, 0, 0};
	size_t off;

	snprintf(buf, cap, "\033[0");
	off = strlen(buf);
	if (attr & A_BOLD)
		off += (size_t)snprintf(buf + off, cap - off, ";1");
	if (attr & A_DIM)
		off += (size_t)snprintf(buf + off, cap - off, ";2");
	if (attr & A_INV)
		off += (size_t)snprintf(buf + off, cap - off, ";7");
	if (fg[attr & 7])
		off +=
		    (size_t)snprintf(buf + off, cap - off, ";%d", fg[attr & 7]);
	snprintf(buf + off, cap - off, "m");
}

static void flush_grid(struct tui *t)
{
	int last_attr = -1;
	int y;

	if (!t->grid)
		return;

	t->fblen = 0;
	fb_put(t, "\033[H", 3);
	for (y = 0; y < t->rows; y++) {
		char pos[24];
		int x;

		snprintf(pos, sizeof(pos), "\033[%d;1H", y + 1);
		fb_put(t, pos, strlen(pos));
		for (x = 0; x < t->cols; x++) {
			const struct cell *c = &t->grid[y * t->cols + x];

			if (c->attr != last_attr) {
				char sgr[24];

				attr_sgr(c->attr, sgr, sizeof(sgr));
				fb_put(t, sgr, strlen(sgr));
				last_attr = c->attr;
			}
			if (c->ch[0])
				fb_put(t, c->ch, strlen(c->ch));
			else
				fb_put(t, " ", 1);
		}
	}
	fb_put(t, "\033[0m", 4);
	(void)!write(STDOUT_FILENO, t->fb, t->fblen);
}

/* output ring */

static void out_push(struct tui *t, const char *line)
{
	int idx = (t->out_head + t->out_n) % OUT_LINES;

	if (t->out_n == OUT_LINES) {
		t->out_head = (t->out_head + 1) % OUT_LINES;
		t->out_n--;
		idx = (t->out_head + t->out_n) % OUT_LINES;
	}
	snprintf(t->out[idx], OUT_CAP, "%s", line);
	t->out_n++;
	/* new output snaps the view back to the tail */
	t->scroll = 0;
}

/* stage state */

static void probe_stage(struct tui *t, int i)
{
	t->st[i] =
	    install_stages[i].probe(t->ctx, t->note[i], sizeof(t->note[i]));
}

static void probe_all(struct tui *t)
{
	int i;

	for (i = 0; i < t->n; i++)
		probe_stage(t, i);
}

static int barrier_index(void)
{
	int i;

	for (i = 0; i < install_stage_count; i++)
		if (install_stages[i].barrier)
			return i;
	return -1;
}

/* first stage that still needs something (skips DONE/SKIP) */
static int first_unmet(struct tui *t)
{
	int i;

	for (i = 0; i < t->n; i++)
		if (t->st[i] != STAGE_DONE && t->st[i] != STAGE_SKIP)
			return i;
	return -1;
}

static int reboot_pending(struct tui *t)
{
	int b = barrier_index();

	return t->ctx->reboot_needed || (b >= 0 && t->st[b] == STAGE_REBOOT);
}

/* Everything before the barrier is satisfied
 * (REBOOT counts: it is applied and only waits for the boot),
 * and the reboot is due */
static int ready_for_reboot(struct tui *t)
{
	int b = barrier_index();
	int i;

	if (b < 0)
		return 0;
	for (i = 0; i < b; i++)
		if (t->st[i] != STAGE_DONE && t->st[i] != STAGE_SKIP &&
		    t->st[i] != STAGE_REBOOT)
			return 0;
	return reboot_pending(t);
}

/* rendering */

static const char *const spin_frames[] = {"⠋", "⠙", "⠹", "⠸", "⠼",
					  "⠴", "⠦", "⠧", "⠇", "⠏"};

static double elapsed_since(const struct timespec *start)
{
	struct timespec now;

	clock_gettime(CLOCK_MONOTONIC, &now);
	return (double)(now.tv_sec - start->tv_sec) +
	       (double)(now.tv_nsec - start->tv_nsec) / 1e9;
}

static const char *state_glyph(enum stage_state st, uint8_t *attr)
{
	switch (st) {
	case STAGE_DONE:
		*attr = C_GREEN;
		return "✔";
	case STAGE_PENDING:
		*attr = C_YELLOW;
		return "●";
	case STAGE_REBOOT:
		*attr = C_YELLOW;
		return "↻";
	case STAGE_BLOCKED:
		*attr = C_RED;
		return "!";
	case STAGE_SKIP:
		*attr = A_DIM;
		return "○";
	case STAGE_ERROR:
	default:
		*attr = C_RED;
		return "✖";
	}
}

static const char *state_word(enum stage_state st)
{
	switch (st) {
	case STAGE_DONE:
		return "Done";
	case STAGE_PENDING:
		return "Pending - Ready to apply";
	case STAGE_REBOOT:
		return "Waiting for a reboot";
	case STAGE_BLOCKED:
		return "Blocked - NEEDS YOUR INPUT";
	case STAGE_SKIP:
		return "Not applicable";
	case STAGE_ERROR:
	default:
		return "Probe error";
	}
}

static const char barrier_text[] =
    "Reboot is required before the install can continue.\n"
    "\n"
    "PCR 14 - the TPM slot LOTA measures itself into - only resets on "
    "a hardware reset, so this step cannot be skipped or faked in "
    "software.\n"
    "\n"
    "Reboot, run the same lota-install command again, and it resumes "
    "exactly where it left off: every finished stage is detected from "
    "live system state, not from a state file.";

static const char done_text[] =
    "LOTA install complete.\n"
    "\n"
    "The agent now attests this host to the operator's verifier. Games "
    "request tokens through the local socket.\n"
    "\n"
    "Pause any time with 'sudo lota-agent --shutdown'. Resuming "
    "requires a reboot - the agent burns its boot measurement on "
    "shutdown by design.\n"
    "\n"
    "Telemetry summary is in the Output pane (PgUp/PgDn to "
    "scroll).";

static void render_stage_list(struct tui *t, int x, int y, int w, int h)
{
	int i;

	for (i = 0; i <= t->n && i < h; i++) {
		uint8_t gattr = 0;
		uint8_t lattr = (i == t->sel) ? A_INV : 0;
		const char *glyph;
		char label[128];

		if (i == t->n) {
			/* virtual self-check row */
			glyph = t->selfcheck_done ? "✔" : "▸";
			gattr = t->selfcheck_done
				    ? C_GREEN
				    : (first_unmet(t) < 0 ? C_CYAN : A_DIM);
			snprintf(label, sizeof(label), "Self-check & summary");
		} else {
			glyph = state_glyph(t->st[i], &gattr);
			snprintf(label, sizeof(label), "%s",
				 install_stages[i].title);
		}

		if (i == t->sel)
			put_run(t, x, y + i, w, A_INV, " ");
		put_text(t, x + 1, y + i, lattr | gattr, glyph);
		{
			char row[160];

			snprintf(row, sizeof(row), "%2d %s", i + 1, label);
			put_clip(t, x + 3, y + i, w - 3, lattr, row);
		}
	}
}

/* columns the stage list needs so no title ever wraps or clips:
 * border+pad (4) + glyph cell (2) + "NN " (3) + longest title + pad */
static int stage_list_width(struct tui *t)
{
	int max = ui_disp_len("Self-check & summary");
	int i;

	for (i = 0; i < t->n; i++) {
		int l = ui_disp_len(install_stages[i].title);

		if (l > max)
			max = l;
	}
	return max + 10;
}

static void render_details(struct tui *t, int x, int y, int w, int h)
{
	int used = 0;

	switch (t->mode) {
	case M_BARRIER:
		put_text(t, x, y, C_YELLOW | A_BOLD, "Reboot required");
		draw_wrapped(t, x, y + 2, w, h - 2, 0, barrier_text);
		return;
	case M_DONE:
		put_text(t, x, y, C_GREEN | A_BOLD, "Install complete");
		draw_wrapped(t, x, y + 2, w, h - 2, 0, done_text);
		return;
	case M_RUNNING:
		put_textf(t, x, y, C_CYAN | A_BOLD, "%s",
			  spin_frames[t->spin % 10]);
		put_clip(t, x + 2, y, w - 2, A_BOLD, t->run_label);
		put_textf(t, x, y + 1, A_DIM, "%.0fs elapsed",
			  elapsed_since(&t->run_start));
		put_clip(t, x, y + 3, w, A_DIM,
			 "Ctrl-C aborts the running command");
		return;
	default:
		break;
	}

	if (t->sel == t->n) {
		put_clip(t, x, y, w, A_BOLD, "Self-check & summary");
		used = 2;
		if (t->selfcheck_done) {
			draw_wrapped(t, x, y + used, w, h - used, 0,
				     t->selfcheck_ok
					 ? "Self-check passed. See the "
					   "Output pane for the details and "
					   "the telemetry summary."
					 : "Self-check FAILED - see the "
					   "Output pane. Fix the reported "
					   "item and press Enter to run it "
					   "again.");
		} else if (first_unmet(t) < 0) {
			draw_wrapped(t, x, y + used, w, h - used, 0,
				     "All stages are satisfied. Press Enter "
				     "to run the final self-check: kernel "
				     "floor, agent service, certificate and "
				     "an attestation round-trip when a "
				     "verifier was given. It ends with a "
				     "summary of exactly what telemetry "
				     "leaves this machine.");
		} else {
			draw_wrapped(t, x, y + used, w, h - used, A_DIM,
				     "Available once every stage is "
				     "satisfied.");
		}
		return;
	}

	put_clip(t, x, y, w, A_BOLD, install_stages[t->sel].title);
	{
		uint8_t a;

		state_glyph(t->st[t->sel], &a);
		put_clip(t, x, y + 1, w, a, state_word(t->st[t->sel]));
	}
	used = 3;
	used += draw_wrapped(t, x, y + used, w, h - used, 0, t->note[t->sel]);
	used++;

	if (t->st[t->sel] == STAGE_PENDING && install_stages[t->sel].apply &&
	    used < h) {
		used += draw_wrapped(t, x, y + used, w, h - used, A_DIM,
				     install_stages[t->sel].explain);
		used++;
		if (used < h)
			put_clip(t, x, y + used, w, C_CYAN,
				 "[Enter] apply this stage");
	}
}

/* lines `text` needs when wrapped to `w` columns;
 * draws off-grid so the counting loop stays the one draw_wrapped uses */
static int wrap_count(struct tui *t, int w, const char *text)
{
	return draw_wrapped(t, 0, t->rows, w, 9999, 0, text);
}

/* centered confirmation dialog: nothing is applied without an explicit yes,
 * and the consent step cannot be missed in a side pane */
static void render_confirm_modal(struct tui *t)
{
	const struct stage *s = &install_stages[t->sel];
	int w = t->cols - 12;
	int body;
	int mh;
	int x, y, i;

	if (w > 66)
		w = 66;
	if (w < 32)
		w = t->cols - 4;
	body = wrap_count(t, w - 4, s->explain);
	mh = body + 6;
	if (mh > t->rows - 2) {
		mh = t->rows - 2;
		body = mh - 6;
	}
	x = (t->cols - w) / 2;
	y = (t->rows - mh) / 2;

	/* blank the area so panes underneath do not show through */
	for (i = 0; i < mh; i++)
		put_run(t, x, y + i, w, 0, " ");
	put_box(t, x, y, w, mh, C_YELLOW, "Confirm");

	put_clip(t, x + 2, y + 1, w - 4, A_BOLD, s->title);
	draw_wrapped(t, x + 2, y + 3, w - 4, body, 0, s->explain);
	put_clip(t, x + 2, y + mh - 2, w - 4, C_YELLOW | A_BOLD,
		 "[y / Enter] apply      [n / Esc] cancel");
}

static void render_output(struct tui *t, int x, int y, int w, int h)
{
	int total = t->out_n;
	int start;
	int i;

	if (h <= 0)
		return;
	start = total - h - t->scroll;
	if (start < 0)
		start = 0;
	for (i = 0; i < h && start + i < total; i++) {
		const char *line =
		    t->out[(t->out_head + start + i) % OUT_LINES];
		uint8_t attr = A_DIM;

		if (strncmp(line, "==", 2) == 0 ||
		    strncmp(line, "ERROR:", 6) == 0)
			attr = strncmp(line, "ERROR:", 6) == 0 ? C_RED : 0;
		draw_wrapped(t, x, y + i, w, 1, attr, line);
	}
	if (t->scroll > 0)
		put_textf(t, x + w - 12, y + h - 1, C_YELLOW, "[+%d more]",
			  t->scroll);
}

static const char *keybar_text(const struct tui *t)
{
	switch (t->mode) {
	case M_CONFIRM:
		return " y / Enter apply   n / Esc cancel   q quit ";
	case M_RUNNING:
		return " Ctrl-C abort ";
	case M_BARRIER:
		return " q quit (reboot, then re-run lota-install)   Esc "
		       "back ";
	case M_DONE:
		return " q quit ";
	case M_NAV:
	default:
		return " ↑/↓ Select   Enter Run   a Run all   r Re-probe   "
		       "PgUp/PgDn Ctrl-U/D Output   q Quit ";
	}
}

static void render(struct tui *t)
{
	int lw, dh, rx, rw;

	if (t_winch) {
		t_winch = 0;
		grid_resize(t);
	}
	grid_clear(t);

	if (t->cols < 60 || t->rows < 14) {
		put_text(t, 0, 0, A_BOLD, "lota-install");
		put_text(t, 0, 1, 0,
			 "Terminal is too small (needs at least 60x14).");
		put_text(t, 0, 2, A_DIM, "Resize, or press q to quit.");
		flush_grid(t);
		return;
	}

	/* title bar */
	put_run(t, 0, 0, t->cols, A_INV, " ");
	put_text(t, 1, 0, A_INV | A_BOLD, "LOTA Guided Install");
	put_text(t, t->cols - 16, 0, A_INV, "Ctrl-C to quit");

	/* panes: the stage list gets whatever its longest title needs
	 * (clipped to half the screen as the floor for the right column) */
	lw = stage_list_width(t);
	if (lw > t->cols / 2 + 8)
		lw = t->cols / 2 + 8;
	dh = (t->rows - 2) / 2;
	if (dh < 9)
		dh = 9;
	rx = lw;
	rw = t->cols - lw;

	put_box(t, 0, 1, lw, t->rows - 2, A_DIM, "Stages");
	render_stage_list(t, 2, 2, lw - 4, t->rows - 4);

	put_box(t, rx, 1, rw, dh, A_DIM, "Details");
	render_details(t, rx + 2, 2, rw - 4, dh - 2);

	put_box(t, rx, 1 + dh, rw, t->rows - 2 - dh, A_DIM, "Output");
	render_output(t, rx + 2, 2 + dh, rw - 4, t->rows - 4 - dh);

	/* key bar + flash */
	put_run(t, 0, t->rows - 1, t->cols, A_INV, " ");
	put_clip(t, 0, t->rows - 1, t->cols, A_INV, keybar_text(t));
	if (t->flash[0]) {
		int fx = t->cols - 1 - ui_disp_len(t->flash);

		if (fx < 1)
			fx = 1;
		put_clip(t, fx, t->rows - 1, t->cols - fx, A_INV | A_BOLD,
			 t->flash);
	}

	if (t->mode == M_CONFIRM)
		render_confirm_modal(t);

	flush_grid(t);
}

/* keys */

enum tui_key {
	K_NONE = 0,
	K_UP,
	K_DOWN,
	K_PGUP,
	K_PGDN,
	K_ENTER,
	K_ESC,
	K_CTRL_C,
	K_CHAR, /* in *ch */
};

static enum tui_key read_key(int timeout_ms, char *ch)
{
	struct pollfd pfd = {.fd = STDIN_FILENO, .events = POLLIN};
	unsigned char b;
	ssize_t got;

	if (poll(&pfd, 1, timeout_ms) <= 0)
		return K_NONE;
	got = read(STDIN_FILENO, &b, 1);
	if (got <= 0)
		return K_NONE;

	switch (b) {
	case 0x03:
		return K_CTRL_C;
	case 0x04: /* Ctrl-D scrolls the output down, like PgDn */
		return K_PGDN;
	case 0x15: /* Ctrl-U scrolls the output up, like PgUp */
		return K_PGUP;
	case '\r':
	case '\n':
		return K_ENTER;
	case 0x1b:
		/* possible escape sequence:
		 * lone ESC has no follow-up byte within the grace window */
		if (poll(&pfd, 1, 25) <= 0)
			return K_ESC;
		if (read(STDIN_FILENO, &b, 1) <= 0 || b != '[')
			return K_ESC;
		if (read(STDIN_FILENO, &b, 1) <= 0)
			return K_ESC;
		switch (b) {
		case 'A':
			return K_UP;
		case 'B':
			return K_DOWN;
		case '5':
		case '6': {
			unsigned char tilde;
			enum tui_key k = (b == '5') ? K_PGUP : K_PGDN;

			if (read(STDIN_FILENO, &tilde, 1) <= 0)
				return K_NONE;
			return k;
		}
		default:
			return K_NONE;
		}
	default:
		*ch = (char)b;
		return K_CHAR;
	}
}

/* drains pending keys while a command runs:
 * Ctrl-C arms the abort, everything else is dropped */
static void poll_keys_running(struct tui *t)
{
	char ch;
	enum tui_key k;

	while ((k = read_key(0, &ch)) != K_NONE) {
		if (k == K_CTRL_C) {
			t->abort_req = 1;
			snprintf(t->flash, sizeof(t->flash), "aborting…");
		}
	}
}

/* ui sink */

static void snk_line(void *ud, const char *line)
{
	struct tui *t = ud;

	out_push(t, line);
	render(t);
}

static void snk_status(void *ud, const char *label, int running,
		       enum ui_result r, double secs)
{
	struct tui *t = ud;
	char buf[OUT_CAP];

	if (running) {
		t->running = 1;
		t->abort_req = 0;
		snprintf(t->run_label, sizeof(t->run_label), "%s", label);
		clock_gettime(CLOCK_MONOTONIC, &t->run_start);
		snprintf(buf, sizeof(buf), "→ %s", label);
	} else {
		t->running = 0;
		snprintf(buf, sizeof(buf), "%s %s (%.1fs)",
			 r == UI_OK ? "✔" : "✖", label, secs);
	}
	out_push(t, buf);
	render(t);
}

static void snk_tick(void *ud)
{
	struct tui *t = ud;

	t->spin++;
	poll_keys_running(t);
	render(t);
}

static int snk_abort(void *ud)
{
	struct tui *t = ud;

	return t->abort_req;
}

/* actions */

static void flashf(struct tui *t, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

static void flashf(struct tui *t, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(t->flash, sizeof(t->flash), fmt, ap);
	va_end(ap);
}

static void run_self_check(struct tui *t)
{
	t->mode = M_RUNNING;
	snprintf(t->run_label, sizeof(t->run_label), "self-check");
	clock_gettime(CLOCK_MONOTONIC, &t->run_start);
	render(t);

	t->selfcheck_ok = install_self_check(t->ctx) == 0;
	t->selfcheck_done = 1;
	if (t->selfcheck_ok) {
		t->mode = M_DONE;
		flashf(t, "complete");
	} else {
		t->mode = M_NAV;
		flashf(t, "self-check failed");
	}
}

/* Applies stage `i`.
 * Returns 1 when the auto chain may continue. */
static int do_apply(struct tui *t, int i)
{
	int rc;

	t->mode = M_RUNNING;
	t->flash[0] = '\0';
	snprintf(t->run_label, sizeof(t->run_label), "%s",
		 install_stages[i].title);
	clock_gettime(CLOCK_MONOTONIC, &t->run_start);
	render(t);

	rc = install_stages[i].apply(t->ctx);
	probe_stage(t, i);
	t->mode = M_NAV;

	if (t->abort_req) {
		t->abort_req = 0;
		flashf(t, "Aborted");
		t->auto_run = 0;
		return 0;
	}
	if (rc != 0 || t->st[i] == STAGE_PENDING || t->st[i] == STAGE_BLOCKED ||
	    t->st[i] == STAGE_ERROR) {
		/* boot-chain stages stay un-probeable until the reboot */
		if (rc == 0 && t->ctx->reboot_needed &&
		    t->st[i] == STAGE_PENDING) {
			t->st[i] = STAGE_REBOOT;
			snprintf(t->note[i], sizeof(t->note[i]),
				 "Applied. Takes effect on the next boot.");
			return 1;
		}
		flashf(t, "Stage failed - see Output");
		t->auto_run = 0;
		return 0;
	}
	return 1;
}

/* Advances selection (and the auto chain) to the next actionable stage.
 * Enters CONFIRM / BARRIER / self-check as appropriate. */
static void advance(struct tui *t)
{
	int b = barrier_index();
	int next = first_unmet(t);

	if (next < 0) {
		t->sel = t->n;
		if (t->auto_run) {
			t->auto_run = 0;
			run_self_check(t);
		}
		return;
	}

	t->sel = next;
	if (b >= 0 && next >= b && reboot_pending(t)) {
		/* Everything up to the barrier is done;
		 * Reboot time! */
		probe_stage(t, b);
		t->sel = b;
		t->auto_run = 0;
		t->mode = M_BARRIER;
		return;
	}

	if (!t->auto_run)
		return;

	switch (t->st[next]) {
	case STAGE_PENDING:
		if (install_stages[next].apply) {
			if (t->ctx->opts.yes) {
				if (do_apply(t, next))
					advance(t);
			} else {
				t->mode = M_CONFIRM;
			}
			return;
		}
		t->auto_run = 0;
		return;
	case STAGE_REBOOT:
		probe_stage(t, b >= 0 ? b : next);
		t->auto_run = 0;
		t->mode = M_BARRIER;
		return;
	default:
		/* BLOCKED / ERROR stops the chain on the offender */
		t->auto_run = 0;
		return;
	}
}

static void activate_selected(struct tui *t)
{
	int i = t->sel;

	if (i == t->n) {
		if (t->selfcheck_done && t->selfcheck_ok) {
			flashf(t, "Already complete");
			return;
		}
		if (first_unmet(t) >= 0) {
			flashf(t, "Stages still pending");
			return;
		}
		run_self_check(t);
		return;
	}

	switch (t->st[i]) {
	case STAGE_DONE:
	case STAGE_SKIP:
		flashf(t, "Nothing to do");
		return;
	case STAGE_REBOOT:
		t->mode = M_BARRIER;
		return;
	case STAGE_BLOCKED:
	case STAGE_ERROR:
		flashf(t, "Blocked - see Details");
		return;
	case STAGE_PENDING:
		if (!install_stages[i].apply) {
			flashf(t, "Blocked - see Details");
			return;
		}
		if (t->ctx->opts.yes) {
			if (do_apply(t, i))
				advance(t);
		} else {
			t->mode = M_CONFIRM;
		}
		return;
	}
}

/* main loop */

static int quit_code(struct tui *t)
{
	if (t->selfcheck_done && t->selfcheck_ok)
		return EXIT_INSTALL_OK;
	if (ready_for_reboot(t))
		return EXIT_INSTALL_REBOOT;
	return EXIT_INSTALL_FAIL;
}

/* navigation/apply bound to a printable key in M_NAV / M_CONFIRM */
static void handle_char(struct tui *t, char ch)
{
	switch (ch) {
	case 'q':
		t->quit = 1;
		break;
	case 'j':
		if (t->mode == M_NAV && t->sel < t->n)
			t->sel++;
		break;
	case 'k':
		if (t->mode == M_NAV && t->sel > 0)
			t->sel--;
		break;
	case 'y':
		if (t->mode == M_CONFIRM) {
			t->mode = M_NAV;
			if (do_apply(t, t->sel))
				advance(t);
		}
		break;
	case 'n':
		if (t->mode == M_CONFIRM) {
			t->mode = M_NAV;
			t->auto_run = 0;
		}
		break;
	case 'a':
		if (t->mode == M_NAV) {
			t->auto_run = 1;
			advance(t);
		}
		break;
	case 'r':
		if (t->mode == M_NAV) {
			out_push(t, "Re-probing...");
			render(t);
			probe_all(t);
			out_push(t, "Probe complete.");
		}
		break;
	default:
		break;
	}
}

int tui_run(struct install_ctx *ctx)
{
	static const struct ui_sink sink = {
	    .line = snk_line,
	    .status = snk_status,
	    .tick = snk_tick,
	    .abort = snk_abort,
	};
	struct tui t;
	struct ui_sink bound = sink;
	int code;

	memset(&t, 0, sizeof(t));
	t.ctx = ctx;
	t.n = install_stage_count;
	if (t.n > TUI_MAX_STAGES)
		t.n = TUI_MAX_STAGES;

	bound.ud = &t;

	/* initial probe runs before the screen takeover and logs to
	 * the normal terminal:
	 * the slower probes (lsinitrd, grubby) would otherwise look like
	 * a frozen TUI, and the result stays in the scrollback after exit.
	 * In-TUI re-probes ('r') are user-driven and render live instead. */
	printf("lota-install: probing system state\n");
	fflush(stdout);
	{
		int i;

		for (i = 0; i < t.n; i++) {
			probe_stage(&t, i);
			printf("  %-52s %s\n", install_stages[i].title,
			       state_word(t.st[i]));
			fflush(stdout);
		}
	}

	ctx->ui.sink = &bound;
	if (term_enter() != 0) {
		ctx->ui.sink = NULL;
		fprintf(stderr, "lota-install: Cannot switch the terminal "
				"to raw mode. Falling back to --plain\n");
		return -1; /* caller falls back to the plain flow */
	}
	grid_resize(&t);

	/* mirror the probe results into the Output pane for reference */
	{
		char buf[OUT_CAP];
		int i;

		for (i = 0; i < t.n; i++) {
			snprintf(buf, sizeof(buf), "probe: %s - %s",
				 install_stages[i].title, state_word(t.st[i]));
			out_push(&t, buf);
		}
	}
	t.sel = first_unmet(&t) >= 0 ? first_unmet(&t) : t.n;

	while (!t.quit) {
		char ch = 0;
		enum tui_key k;

		render(&t);
		k = read_key(250, &ch);
		if (k == K_NONE)
			continue;
		t.flash[0] = '\0';

		switch (k) {
		case K_CTRL_C:
			t.quit = 1;
			break;
		case K_UP:
			if (t.mode == M_NAV && t.sel > 0)
				t.sel--;
			break;
		case K_DOWN:
			if (t.mode == M_NAV && t.sel < t.n)
				t.sel++;
			break;
		case K_PGUP:
			if (t.scroll < t.out_n - 1)
				t.scroll += 5;
			break;
		case K_PGDN:
			t.scroll -= 5;
			if (t.scroll < 0)
				t.scroll = 0;
			break;
		case K_ENTER:
			if (t.mode == M_NAV) {
				activate_selected(&t);
			} else if (t.mode == M_CONFIRM) {
				t.mode = M_NAV;
				if (do_apply(&t, t.sel))
					advance(&t);
			}
			break;
		case K_ESC:
			if (t.mode == M_CONFIRM || t.mode == M_BARRIER) {
				t.mode = M_NAV;
				t.auto_run = 0;
			}
			break;
		case K_CHAR:
			handle_char(&t, ch);
			break;
		case K_NONE:
			break;
		}
	}

	code = quit_code(&t);
	ctx->ui.sink = NULL;
	term_restore();
	free(t.grid);
	free(t.fb);

	/* persist the outcome on the normal screen */
	if (code == EXIT_INSTALL_REBOOT) {
		printf("lota-install: Reboot required. Reboot, then run the "
		       "same lota-install command again - it resumes at the "
		       "first unmet stage.\n");
	} else if (code == EXIT_INSTALL_OK) {
		printf("lota-install: Install complete. This host now "
		       "attests to the operator's verifier.\n");
	} else {
		printf("lota-install: Install not finished. Re-run to "
		       "continue (--status shows the remaining stages).\n");
	}
	return code;
}
