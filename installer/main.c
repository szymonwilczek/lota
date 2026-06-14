/* SPDX-License-Identifier: MIT
 *
 * lota-install - Guided, reboot-resumable Player Install
 */

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "install.h"
#include "run.h"
#include "tui.h"
#include "ui.h"

#ifndef LOTA_INSTALL_VERSION
#define LOTA_INSTALL_VERSION "dev"
#endif

static void usage(FILE *out)
{
	fprintf(
	    out,
	    "Usage: lota-install [options]\n"
	    "\n"
	    "Guided, reboot-resumable install of the LOTA player agent.\n"
	    "Each stage probes live system state, explains what it is\n"
	    "about to change and why, and asks before changing it.\n"
	    "Re-running after the mid-install reboot resumes at the\n"
	    "first unmet stage.\n"
	    "\n"
	    "Operator-provided inputs (from the install instructions):\n"
	    "  --ca-server HOST       Attestation CA for enrollment\n"
	    "  --ca-port PORT         Attestation CA port\n"
	    "  --ca-cert FILE         CA TLS certificate (PEM)\n"
	    "  --verifier HOST        Verifier for the final self-check\n"
	    "  --verifier-port PORT   Verifier port\n"
	    "  --policy-pubkey FILE   Operator BPF signing public key\n"
	    "                         (default %s)\n"
	    "  --selinux-module FILE  Compiled LOTA SELinux module\n"
	    "                         (default %s)\n"
	    "\n"
	    "Behaviour:\n"
	    "  --status               Probe and report every stage,\n"
	    "                         change nothing\n"
	    "  --yes                  Do not ask for confirmation\n"
	    "  --plain                Plain log output (no TUI)\n"
	    "  --help, --version\n"
	    "\n"
	    "Lifecycle (after install):\n"
	    "  --pause                Stop the agent gracefully\n"
	    "                         ('lota-agent --shutdown')\n"
	    "  --resume               Explain that resuming needs a reboot,\n"
	    "                         and offer to reboot now\n"
	    "\n"
	    "Exit codes: 0 complete, 1 failed/blocked, 2 usage,\n"
	    "            10 reboot required (re-run to resume).\n",
	    PATH_POLICY_PUB_DEFAULT, PATH_SELINUX_PP_DEFAULT);
}

static int parse_args(int argc, char **argv, struct install_opts *opts)
{
	static const struct option longopts[] = {
	    {"ca-server", required_argument, 0, 1},
	    {"ca-port", required_argument, 0, 2},
	    {"ca-cert", required_argument, 0, 3},
	    {"verifier", required_argument, 0, 4},
	    {"verifier-port", required_argument, 0, 5},
	    {"policy-pubkey", required_argument, 0, 6},
	    {"selinux-module", required_argument, 0, 7},
	    {"status", no_argument, 0, 8},
	    {"yes", no_argument, 0, 'y'},
	    {"plain", no_argument, 0, 9},
	    {"help", no_argument, 0, 'h'},
	    {"version", no_argument, 0, 10},
	    {"pause", no_argument, 0, 11},
	    {"resume", no_argument, 0, 12},
	    {0, 0, 0, 0},
	};
	int c;

	memset(opts, 0, sizeof(*opts));
	opts->policy_pubkey = PATH_POLICY_PUB_DEFAULT;
	opts->selinux_module = PATH_SELINUX_PP_DEFAULT;

	while ((c = getopt_long(argc, argv, "yh", longopts, NULL)) != -1) {
		switch (c) {
		case 1:
			opts->ca_server = optarg;
			break;
		case 2:
			opts->ca_port = optarg;
			break;
		case 3:
			opts->ca_cert = optarg;
			break;
		case 4:
			opts->verifier = optarg;
			break;
		case 5:
			opts->verifier_port = optarg;
			break;
		case 6:
			opts->policy_pubkey = optarg;
			break;
		case 7:
			opts->selinux_module = optarg;
			break;
		case 8:
			opts->status_only = 1;
			break;
		case 'y':
			opts->yes = 1;
			break;
		case 9:
			opts->plain = 1;
			break;
		case 'h':
			usage(stdout);
			exit(EXIT_INSTALL_OK);
		case 10:
			printf("lota-install %s\n", LOTA_INSTALL_VERSION);
			exit(EXIT_INSTALL_OK);
		case 11:
			opts->pause = 1;
			break;
		case 12:
			opts->resume = 1;
			break;
		default:
			usage(stderr);
			exit(EXIT_INSTALL_USAGE);
		}
	}
	if (optind < argc) {
		fprintf(stderr, "lota-install: Unexpected argument '%s'\n",
			argv[optind]);
		usage(stderr);
		exit(EXIT_INSTALL_USAGE);
	}
	if (opts->pause + opts->resume + opts->status_only > 1) {
		fprintf(stderr, "lota-install: --pause, --resume and --status "
				"are mutually exclusive\n");
		usage(stderr);
		exit(EXIT_INSTALL_USAGE);
	}
	return 0;
}

static enum ui_result state_result(enum stage_state st)
{
	switch (st) {
	case STAGE_DONE:
		return UI_DONE;
	case STAGE_REBOOT:
		return UI_REBOOT;
	case STAGE_SKIP:
		return UI_SKIP;
	case STAGE_PENDING:
	case STAGE_BLOCKED:
		return UI_PENDING;
	case STAGE_ERROR:
	default:
		return UI_FAIL;
	}
}

/* Probe-only report.
 * Never mutates, usable before deciding to run */
static int run_status(struct install_ctx *ctx)
{
	char note[STAGE_NOTE_CAP];
	int pending = 0;
	int i;

	if (geteuid() != 0)
		ui_text(&ctx->ui, "Running unprivileged: some probes "
				  "(initramfs content, journal) may report "
				  "errors. Run as root for a reliable "
				  "report.");

	for (i = 0; i < install_stage_count; i++) {
		const struct stage *s = &install_stages[i];
		enum stage_state st = s->probe(ctx, note, sizeof(note));

		ui_stage_begin(&ctx->ui, i + 1, install_stage_count, s->title);
		ui_stage_result(&ctx->ui, state_result(st), s->title, note);
		if (st != STAGE_DONE && st != STAGE_SKIP)
			pending++;
		/* let later probes account for boot-chain stages */
		if (st == STAGE_REBOOT)
			ctx->reboot_needed = 1;
	}

	ui_text(&ctx->ui, "\n%d of %d stages need work.", pending,
		install_stage_count);
	return pending == 0 ? EXIT_INSTALL_OK : EXIT_INSTALL_FAIL;
}

static void print_reboot_box(struct install_ctx *ctx, const char *note)
{
	ui_text(&ctx->ui,
		"\nReboot is required before the install can "
		"continue: %s.",
		note);
	ui_text(&ctx->ui, "PCR 14 - the TPM slot LOTA measures itself into - "
			  "only resets on a hardware reset, so this cannot "
			  "be skipped or faked in software.");
	ui_text(&ctx->ui, "Reboot, run the same lota-install command again, "
			  "and it resumes exactly where it left off.");
}

/* Lifecycle veneer: stop the agent through its graceful path. */
static int do_pause(struct install_ctx *ctx)
{
	const char *const argv[] = {PATH_AGENT_BIN, "--shutdown", NULL};
	int rc;

	if (geteuid() != 0) {
		ui_error(&ctx->ui,
			 "--pause stops the agent and must run as root");
		return EXIT_INSTALL_USAGE;
	}

	ui_text(&ctx->ui,
		"Pausing stops the agent through its own graceful path "
		"('lota-agent --shutdown'). systemd cannot stop the agent - "
		"the anti-tamper hook blocks that - so this dedicated path is "
		"the only clean way down.");
	ui_text(&ctx->ui,
		"On the way down the agent poisons its TPM measurement slot "
		"(PCR 14) on purpose, so this boot can no longer attest. That "
		"is the security contract, not a fault: resuming therefore "
		"needs a reboot (see --resume).");
	if (!ui_confirm(&ctx->ui, "Pause the agent now?", ctx->opts.yes)) {
		ui_text(&ctx->ui, "Left running. Nothing changed.");
		return EXIT_INSTALL_OK;
	}

	rc = run_cmd(&ctx->ui, "lota-agent --shutdown", argv);
	if (rc != 0) {
		ui_error(&ctx->ui,
			 "Could not pause the agent (it may already be "
			 "stopped). See the output above.");
		return EXIT_INSTALL_FAIL;
	}
	ui_text(&ctx->ui, "Agent paused. Resume with a reboot - "
			  "'lota-install --resume' explains why.");
	return EXIT_INSTALL_OK;
}

/* Lifecycle veneer: resuming after a pause is a reboot, by design. */
static int do_resume(struct install_ctx *ctx)
{
	const char *const argv[] = {"systemctl", "reboot", NULL};

	ui_text(&ctx->ui,
		"Resuming LOTA means rebooting. When the agent paused it "
		"poisoned PCR 14, and that slot only clears on a hardware "
		"reset - so same-boot re-attestation is impossible by design, "
		"not a limitation to work around.");
	ui_text(&ctx->ui,
		"After the reboot the agent starts on its own (socket-"
		"activated), re-measures into a fresh PCR 14, and attests "
		"again. Nothing else is needed.");
	ui_text(&ctx->ui,
		"A host left paused still boots normally; the agent simply "
		"refuses to run until then (fail-closed), so pausing never "
		"hands control of the machine to anything else.");

	if (geteuid() != 0) {
		ui_text(&ctx->ui,
			"Reboot when ready: 'sudo systemctl reboot'.");
		return EXIT_INSTALL_OK;
	}
	if (!ui_confirm(&ctx->ui, "Reboot now to resume?", ctx->opts.yes)) {
		ui_text(&ctx->ui,
			"Reboot when ready: 'sudo systemctl reboot'.");
		return EXIT_INSTALL_OK;
	}
	return run_cmd(&ctx->ui, "systemctl reboot", argv) == 0
		   ? EXIT_INSTALL_OK
		   : EXIT_INSTALL_FAIL;
}

int main(int argc, char **argv)
{
	struct install_ctx ctx;
	char note[STAGE_NOTE_CAP];
	int i;

	memset(&ctx, 0, sizeof(ctx));
	parse_args(argc, argv, &ctx.opts);
	ui_init(&ctx.ui, ctx.opts.plain);

	ui_banner(&ctx.ui, "LOTA Guided Install", LOTA_INSTALL_VERSION,
		  "Hardware-rooted Attestation for the player host");

	if (ctx.opts.pause)
		return do_pause(&ctx);
	if (ctx.opts.resume)
		return do_resume(&ctx);

	if (ctx.opts.status_only)
		return run_status(&ctx);

	if (geteuid() != 0) {
		ui_error(&ctx.ui, "lota-install changes system state and "
				  "must run as root (use --status for a "
				  "read-only report)");
		return EXIT_INSTALL_USAGE;
	}
	if (!ctx.opts.yes && !isatty(STDIN_FILENO)) {
		ui_error(&ctx.ui, "No terminal to confirm stages on. Re-run "
				  "interactively or pass --yes");
		return EXIT_INSTALL_USAGE;
	}

	/* interactive terminal:
	 * full-screen frontend drives the same stage table
	 * sequential flow below stays for --plain and non-TTY runs */
	if (ctx.ui.tty && isatty(STDIN_FILENO)) {
		int rc = tui_run(&ctx);

		if (rc >= 0)
			return rc;
		/* raw mode unavailable
		 * degrade to the plain flow */
		ctx.ui.tty = 0;
		ctx.ui.color = 0;
	}

	for (i = 0; i < install_stage_count; i++) {
		const struct stage *s = &install_stages[i];
		enum stage_state st = s->probe(&ctx, note, sizeof(note));

		ui_stage_begin(&ctx.ui, i + 1, install_stage_count, s->title);

		if (st == STAGE_PENDING && s->apply) {
			ui_explain(&ctx.ui, s->explain);
			ui_text(&ctx.ui, "Current state: %s.", note);
			if (!ui_confirm(&ctx.ui, "Apply this stage?",
					ctx.opts.yes)) {
				ui_text(&ctx.ui, "Aborted at your request. "
						 "Nothing further was "
						 "changed. Re-run to "
						 "continue.");
				return EXIT_INSTALL_FAIL;
			}
			if (s->apply(&ctx) != 0) {
				ui_stage_result(&ctx.ui, UI_FAIL, s->title,
						"Change failed. See the "
						"output above");
				return EXIT_INSTALL_FAIL;
			}
			st = s->probe(&ctx, note, sizeof(note));
			/* boot-chain stages stay un-probeable until the reboot
			 * reboot_needed records their success */
			if (st == STAGE_PENDING && ctx.reboot_needed)
				st = STAGE_REBOOT;
		}

		switch (st) {
		case STAGE_DONE:
		case STAGE_SKIP:
			ui_stage_result(&ctx.ui, state_result(st), s->title,
					note);
			break;
		case STAGE_REBOOT:
			ui_stage_result(&ctx.ui, UI_REBOOT, s->title, note);
			if (s->barrier) {
				print_reboot_box(&ctx, note);
				return EXIT_INSTALL_REBOOT;
			}
			ctx.reboot_needed = 1;
			break;
		case STAGE_BLOCKED:
			ui_stage_result(&ctx.ui, UI_FAIL, s->title, NULL);
			ui_text(&ctx.ui, "%s.", note);
			return EXIT_INSTALL_FAIL;
		case STAGE_ERROR:
			ui_stage_result(&ctx.ui, UI_FAIL, s->title, note);
			return EXIT_INSTALL_FAIL;
		case STAGE_PENDING:
			ui_stage_result(&ctx.ui, UI_FAIL, s->title,
					"still unmet after applying");
			return EXIT_INSTALL_FAIL;
		}
	}

	if (install_self_check(&ctx) != 0) {
		ui_error(&ctx.ui, "Self-check failed. Install is laid "
				  "down but the host is not attesting yet. "
				  "Inspect 'journalctl -u lota-agent -b' and "
				  "re-run lota-install.");
		return EXIT_INSTALL_FAIL;
	}

	ui_text(&ctx.ui, "\nLOTA install complete. The agent attests this "
			 "host to the operator's verifier. Games request "
			 "tokens through the local socket.");
	ui_text(&ctx.ui, "Pause any time with 'sudo lota-install --pause' "
			 "(a friendly wrapper over 'lota-agent --shutdown'); "
			 "'sudo lota-install --resume' explains why resuming "
			 "requires a reboot - the agent burns its boot "
			 "measurement on shutdown by design.");
	return EXIT_INSTALL_OK;
}
