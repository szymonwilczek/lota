/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * What an unattended lota-install says where it stops.
 *
 * A package hook runs the installer unattended, and that run leaves the stages
 * that change how the machine boots to a person, then stops at the reboot
 * checkpoint. What it prints there is the operator's only list of the work
 * left, so it names the stages that were left and no others: a host where one
 * of them deferred and the rest reported themselves satisfied in the same run
 * must not be sent back for all of them.
 *
 * The exit code says the same thing: a run that left work to a person has not
 * finished the install, and a caller that reads only the code must see that.
 *
 * A stage the run applied says so in words of its own, apart from a stage that
 * found nothing to do, so an upgrade transcript shows what the upgrade redid.
 *
 * The summary of what a report carries, shown before enrollment, lists the
 * sections of struct lota_attestation_report and nothing it does not carry.
 *
 * A run that stops for a reboot quotes the stage's reason in a sentence of its
 * own, and stage notes mostly end in a full stop already. The checkpoint names
 * the stages that wait for the boot, and says the run changed the boot chain
 * only when it did: a floor configured before the run is not its change.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "test.h"
#include "../installer/install.h"
#include "../installer/run.h"

static char note[4096];

static int stage_named(const char *title)
{
	int i;

	for (i = 0; i < install_stage_count; i++)
		if (strcmp(install_stages[i].title, title) == 0)
			return i;
	fprintf(stderr, "no stage titled '%s'\n", title);
	exit(1);
}

static int says(const char *what)
{
	return strstr(note, what) != NULL;
}

/* Every boot-path stage and the stages the old sentence also named. */
static int names_only(const int *deferred, int n)
{
	int i, j;

	for (i = 0; i < install_stage_count; i++) {
		int left = 0;

		for (j = 0; j < n; j++)
			left |= deferred[j] == i;
		if (says(install_stages[i].title) != left) {
			FAIL(note);
			return 0;
		}
	}
	if (!says("sudo lota-install") || !says(PATH_AUTO_BRINGUP)) {
		FAIL("the command that finishes the job is missing");
		return 0;
	}
	return 1;
}

static void test_one_deferred_stage_is_named_alone(void)
{
	int d[1];

	TEST("one deferred stage is the only one named");
	d[0] = stage_named("Kernel integrity floor on the cmdline");
	install_unattended_checkpoint(note, sizeof(note), d, 1);
	if (says("initramfs") || says("IMA")) {
		FAIL(note);
		return;
	}
	if (names_only(d, 1))
		PASS();
}

static void test_the_initramfs_stage_alone(void)
{
	int d[1];

	TEST("the initramfs stage alone");
	d[0] = stage_named("Boot-time PCR14 lock in the initramfs");
	install_unattended_checkpoint(note, sizeof(note), d, 1);
	if (says("integrity floor") || says("IMA")) {
		FAIL(note);
		return;
	}
	if (names_only(d, 1))
		PASS();
}

static void test_two_deferred_stages_are_both_named(void)
{
	int d[2];

	TEST("two deferred stages are both named");
	d[0] = stage_named("Boot-time PCR14 lock in the initramfs");
	d[1] = stage_named("Kernel integrity floor on the cmdline");
	install_unattended_checkpoint(note, sizeof(note), d, 2);
	if (says("IMA")) {
		FAIL(note);
		return;
	}
	if (names_only(d, 2))
		PASS();
}

/*
 * The deferral has a code of its own: 0 is what --status answers on a host
 * with nothing left, and an automated caller has only the code to go on.
 */
static void test_a_deferral_is_not_success(void)
{
	int d[1];
	int rc;

	TEST("a deferral exits with its own code, not 0");
	d[0] = stage_named("Kernel integrity floor on the cmdline");
	rc = install_unattended_checkpoint(note, sizeof(note), d, 1);
	if (rc != EXIT_INSTALL_DEFERRED) {
		char msg[64];

		snprintf(msg, sizeof(msg), "exit %d, want %d", rc,
			 EXIT_INSTALL_DEFERRED);
		FAIL(msg);
		return;
	}
	PASS();
}

static void test_the_codes_are_distinct(void)
{
	static const int codes[] = { EXIT_INSTALL_OK, EXIT_INSTALL_FAIL,
				     EXIT_INSTALL_USAGE, EXIT_INSTALL_REBOOT,
				     EXIT_INSTALL_DEFERRED };
	size_t i, j;

	TEST("every exit code means one outcome");
	for (i = 0; i < sizeof(codes) / sizeof(codes[0]); i++)
		for (j = 0; j < i; j++)
			if (codes[i] == codes[j]) {
				FAIL("two outcomes share a code");
				return;
			}
	PASS();
}

static void reboot_sentence_ends_once(const char *reason)
{
	char buf[512];
	size_t len;

	install_reboot_required(buf, sizeof(buf), reason);
	len = strlen(buf);
	if (!strstr(buf, "Reboot is required") ||
	    !strstr(buf, "hardware reset"))
		FAIL(buf);
	else if (len < 2 || buf[len - 1] != '.' || buf[len - 2] == '.')
		FAIL(buf);
	else
		PASS();
}

static void test_a_reboot_reason_that_ends_in_a_stop(void)
{
	TEST("a reason with its own full stop gets no second one");
	reboot_sentence_ends_once("PCR14 only resets on a hardware reset.");
}

static void test_a_reboot_reason_without_a_stop(void)
{
	TEST("a reason without a full stop gets one");
	reboot_sentence_ends_once("PCR14 only resets on a hardware reset");
}

static void test_an_applied_stage_says_so(void)
{
	const char *done = ui_result_word(UI_DONE);
	enum ui_result r = install_stage_result(STAGE_DONE, 1);

	TEST("a stage applied in this run is not already satisfied");
	if (r == UI_DONE || strcmp(ui_result_word(r), done) == 0) {
		FAIL(ui_result_word(r));
		return;
	}
	if (!strstr(ui_result_word(r), "applied")) {
		FAIL(ui_result_word(r));
		return;
	}
	PASS();
}

static void test_an_untouched_stage_keeps_its_word(void)
{
	TEST("a stage with nothing to do is still already satisfied");
	if (install_stage_result(STAGE_DONE, 0) != UI_DONE)
		FAIL(ui_result_word(install_stage_result(STAGE_DONE, 0)));
	else
		PASS();
}

static void test_applied_changes_only_a_satisfied_stage(void)
{
	static const enum stage_state other[] = { STAGE_PENDING, STAGE_REBOOT,
						  STAGE_BLOCKED, STAGE_SKIP,
						  STAGE_ERROR };
	size_t i;

	TEST("an applied stage that is not satisfied says what it is");
	for (i = 0; i < sizeof(other) / sizeof(other[0]); i++)
		if (install_stage_result(other[i], 1) !=
		    install_stage_result(other[i], 0)) {
			FAIL(ui_result_word(install_stage_result(other[i], 1)));
			return;
		}
	PASS();
}

/*
 * First place in s where closing punctuation runs straight into a capital,
 * or NULL. A dotted name ("lota.conf") is not caught.
 */
static const char *run_together(const char *s)
{
	for (; s && s[0] && s[1]; s++) {
		if (!strchr(".:;?!)", s[0]))
			continue;
		if (isupper((unsigned char)s[1]))
			return s;
	}
	return NULL;
}

static void test_every_explanation_is_spaced(void)
{
	char msg[64];
	int bad = 0;

	TEST("no stage explanation runs two sentences together");
	for (int i = 0; i < install_stage_count; i++) {
		const char *text = install_stages[i].explain;
		const char *at = run_together(text);

		if (!at)
			continue;
		/* enough either side of the join to find it in the source */
		if (at - text > 12)
			at -= 12;
		printf("\n       stage %d: ...%.30s...", i + 1, at);
		bad++;
	}
	if (!bad) {
		PASS();
		return;
	}
	snprintf(msg, sizeof(msg), "%d explanation(s) above", bad);
	printf("\n      ");
	FAIL(msg);
}

static void test_every_title_is_spaced(void)
{
	TEST("no stage title runs two sentences together");
	for (int i = 0; i < install_stage_count; i++) {
		if (run_together(install_stages[i].title)) {
			FAIL(install_stages[i].title);
			return;
		}
	}
	PASS();
}

/*
 * A stage outside the boot chain that still probes pending after its apply
 * has not worked, whatever an earlier stage did to the boot chain.
 */
static void test_the_report_summary_matches_the_report(void)
{
	static const char *const carried[] = {
		"PCR values",
		"quote",
		"AIK public key",
		"AIK certificate",
		"Agent hash",
		"kernel measurement digest",
		"IOMMU",
		"Security state flags",
		"event log",
		"ESRT",
		"MOK list",
		"TPM quote",
		"LSM is loaded",
		"bench mode",
		"lost events",
		"has none",
		"empty when it cannot be read",
		"ptrace rules",
	};
	static const char *const absent[] = { "recently executed", "PIDs",
					      "endorsement key's public",
					      "policy keys" };
	size_t i;

	TEST("the report summary lists the sections a report carries");
	for (i = 0; i < sizeof(carried) / sizeof(carried[0]); i++)
		if (!strstr(install_telemetry_summary, carried[i])) {
			FAIL(carried[i]);
			return;
		}
	for (i = 0; i < sizeof(absent) / sizeof(absent[0]); i++)
		if (strstr(install_telemetry_summary, absent[i])) {
			FAIL(absent[i]);
			return;
		}
	PASS();
}

static void test_only_a_boot_path_stage_waits_for_the_reboot(void)
{
	struct install_ctx ctx;
	const struct stage *fence;
	const struct stage *cmdline;

	TEST("pending after apply waits for the reboot only on the boot path");
	memset(&ctx, 0, sizeof(ctx));
	ctx.reboot_needed = 1;
	fence = &install_stages[stage_named("SELinux fence on the TPM device")];
	cmdline = &install_stages[stage_named(
		"Kernel integrity floor on the cmdline")];
	if (install_stage_after_apply(fence, &ctx, STAGE_PENDING) !=
	    STAGE_PENDING) {
		FAIL("a failed SELinux stage reads as waiting for the reboot");
		return;
	}
	if (install_stage_after_apply(cmdline, &ctx, STAGE_PENDING) !=
	    STAGE_REBOOT) {
		FAIL("the cmdline stage does not wait for the reboot");
		return;
	}
	PASS();
}

static enum stage_state barrier_note(struct install_ctx *ctx)
{
	const struct stage *b =
		&install_stages[stage_named("Reboot checkpoint")];

	return b->probe(ctx, note, sizeof(note));
}

static void test_a_configured_floor_is_no_change(void)
{
	struct install_ctx ctx;
	int floor = stage_named("Kernel integrity floor on the cmdline");

	TEST("a floor set before this run is not named as a change");
	memset(&ctx, 0, sizeof(ctx));
	install_stage_waits_reboot(&ctx, floor);
	if (barrier_note(&ctx) != STAGE_REBOOT) {
		FAIL("the checkpoint does not wait for the reboot");
		return;
	}
	if (says("changed") || !says(install_stages[floor].title) ||
	    !says("is configured and takes effect on the next boot")) {
		FAIL(note);
		return;
	}
	PASS();
}

static void test_a_rebuilt_initramfs_is_a_change(void)
{
	struct install_ctx ctx;
	int lock = stage_named("Boot-time PCR14 lock in the initramfs");
	int floor = stage_named("Kernel integrity floor on the cmdline");
	char want[256];

	TEST("a run that rebuilt the initramfs names what waits");
	memset(&ctx, 0, sizeof(ctx));
	/* the lock probes DONE after dracut, the floor waits from before */
	ctx.reboot_needed = 1;
	ctx.boot_changed = 1u << lock;
	install_stage_waits_reboot(&ctx, floor);
	if (barrier_note(&ctx) != STAGE_REBOOT) {
		FAIL("the checkpoint does not wait for the reboot");
		return;
	}
	snprintf(want, sizeof(want), "This run changed the boot chain: '%s'.",
		 install_stages[lock].title);
	if (!says(want) || says("IMA")) {
		FAIL(note);
		return;
	}
	snprintf(want, sizeof(want),
		 "'%s' is configured and takes effect on the next boot.",
		 install_stages[floor].title);
	if (!says(want)) {
		FAIL(note);
		return;
	}
	PASS();
}

/* Set once the child says its TERM trap is in place */
static int child_ready;

static void sink_line(void *ud, const char *text)
{
	(void)ud;
	if (strstr(text, "ready"))
		child_ready = 1;
}

static void sink_status(void *ud, const char *label, int running,
			enum ui_result r, double secs)
{
	(void)ud;
	(void)label;
	(void)running;
	(void)r;
	(void)secs;
}

static void sink_tick(void *ud)
{
	(void)ud;
}

static int abort_once_ready(void *ud)
{
	(void)ud;
	return child_ready;
}

/* A child that answers the abort's SIGTERM with exit 0 has not finished */
static void test_an_aborted_command_is_not_a_success(void)
{
	static const char *const argv[] = {
		"sh", "-c",
		"trap 'kill $!; exit 0' TERM; echo ready; sleep 5 & wait", NULL
	};
	const struct ui_sink sink = {
		.line = sink_line,
		.status = sink_status,
		.tick = sink_tick,
		.abort = abort_once_ready,
	};
	struct ui ui;
	int rc;

	TEST("a command the user aborted does not report 0");
	memset(&ui, 0, sizeof(ui));
	ui.sink = &sink;
	rc = run_cmd(&ui, "abort", argv);
	if (rc == 0) {
		FAIL("the aborted command reads as done");
		return;
	}
	PASS();
}

int main(void)
{
	printf("\n=== lota-install: the unattended checkpoint ===\n");

	test_one_deferred_stage_is_named_alone();
	test_the_initramfs_stage_alone();
	test_two_deferred_stages_are_both_named();
	test_a_deferral_is_not_success();
	test_the_codes_are_distinct();
	test_a_reboot_reason_that_ends_in_a_stop();
	test_a_reboot_reason_without_a_stop();
	test_an_applied_stage_says_so();
	test_an_untouched_stage_keeps_its_word();
	test_applied_changes_only_a_satisfied_stage();
	test_every_explanation_is_spaced();
	test_every_title_is_spaced();
	test_the_report_summary_matches_the_report();
	test_only_a_boot_path_stage_waits_for_the_reboot();
	test_a_configured_floor_is_no_change();
	test_a_rebuilt_initramfs_is_a_change();
	test_an_aborted_command_is_not_a_success();

	printf("\nPassed: %d / %d\n", tests_passed, tests_run);
	return tests_passed == tests_run ? 0 : 1;
}
