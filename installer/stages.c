/* SPDX-License-Identifier: MIT
 * Copyright (C) 2026 Szymon Wilczek
 *
 * lota-install - Stage Table
 *
 * Probe semantics mirror the agent's startup gates:
 * stage only reports DONE when the corresponding gate in
 * src/agent/bpf_loader.c / src/agent/tpm.c would pass.
 *
 * Installer therefore cannot finish green on a host the agent refuses.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <unistd.h>
#include <sys/types.h>

#include "install.h"
#include "probe.h"
#include "run.h"
#include "ui.h"

static int file_exists(const char *path)
{
	return access(path, F_OK) == 0;
}

static int tool_exists(const char *name)
{
	static const char *const dirs[] = { "/usr/bin/", "/usr/sbin/", "/bin/",
					    "/sbin/" };
	char path[256];
	size_t i;

	for (i = 0; i < sizeof(dirs) / sizeof(dirs[0]); i++) {
		snprintf(path, sizeof(path), "%s%s", dirs[i], name);
		if (access(path, X_OK) == 0)
			return 1;
	}
	return 0;
}

/* stage 1: preflight */

static enum stage_state st_preflight_probe(struct install_ctx *ctx, char *note,
					   size_t cap)
{
	static const char *const tools[] = { "dracut", "grubby", "systemctl",
					     "udevadm", "lsinitrd" };
	size_t i;
	int sb;

	(void)ctx;

	if (!file_exists("/dev/tpmrm0") && !file_exists("/dev/tpm0")) {
		snprintf(note, cap,
			 "No TPM 2.0 device (/dev/tpmrm0). Enable the TPM "
			 "(Intel PTT / AMD fTPM / discrete) in firmware "
			 "setup. LOTA's hardware root of trust cannot exist "
			 "without it.");
		return STAGE_BLOCKED;
	}

	sb = probe_secureboot();
	if (sb == -ENOENT) {
		snprintf(note, cap,
			 "This host booted via legacy BIOS/CSM, not UEFI. "
			 "LOTA's verifier proves Secure Boot from the TPM "
			 "event log, which needs a UEFI boot. Switch the "
			 "firmware to UEFI mode.");
		return STAGE_BLOCKED;
	}
	if (sb == 0) {
		snprintf(note, cap,
			 "Secure Boot is disabled. The verifier rejects "
			 "hosts that boot with Secure Boot off (it is the "
			 "machine-independent kernel-trust anchor). Enable "
			 "it in firmware setup and re-run. Custom MOK-signed "
			 "kernels keep working with Secure Boot on.");
		return STAGE_BLOCKED;
	}
	if (sb < 0) {
		snprintf(note, cap,
			 "Cannot read the SecureBoot EFI variable "
			 "(%s)",
			 strerror(-sb));
		return STAGE_ERROR;
	}

	for (i = 0; i < sizeof(tools) / sizeof(tools[0]); i++) {
		if (!tool_exists(tools[i])) {
			snprintf(note, cap,
				 "Required tool '%s' is missing. Install it "
				 "with the distribution package manager.",
				 tools[i]);
			return STAGE_BLOCKED;
		}
	}

	snprintf(note, cap, "TPM 2.0 present, Secure Boot on, tooling found");
	return STAGE_DONE;
}

/* stage 2: package artifacts */

static enum stage_state st_artifacts_probe(struct install_ctx *ctx, char *note,
					   size_t cap)
{
	static const char *const files[] = {
		PATH_AGENT_BIN,	    PATH_BPF_OBJ,      PATH_LOCK_HELPER,
		PATH_AGENT_UNIT,    PATH_AGENT_SOCKET, PATH_UDEV_RULE,
		PATH_DRACUT_MODULE,
	};
	size_t i;

	(void)ctx;

	for (i = 0; i < sizeof(files) / sizeof(files[0]); i++) {
		if (!file_exists(files[i])) {
			snprintf(note, cap,
				 "%s is missing. Install the LOTA package "
				 "first (from a release tree: sudo make "
				 "install), then re-run.",
				 files[i]);
			return STAGE_BLOCKED;
		}
	}
	snprintf(note, cap,
		 "agent, BPF object, units, udev rule and dracut "
		 "module are installed.");
	return STAGE_DONE;
}

/* stage 3: operator trust material */

static enum stage_state st_trust_probe(struct install_ctx *ctx, char *note,
				       size_t cap)
{
	char sig[512];
	char out[4096];
	int rc;

	snprintf(sig, sizeof(sig), "%s.sig", PATH_BPF_OBJ);

	if (!file_exists(ctx->opts.policy_pubkey)) {
		snprintf(note, cap,
			 "Operator public key %s is missing. The key that "
			 "signed the BPF enforcement object must come from "
			 "the operator's install bundle - the installer "
			 "never generates trust material on this machine "
			 "(a locally generated key would let local malware "
			 "re-sign a tampered object).",
			 ctx->opts.policy_pubkey);
		return STAGE_BLOCKED;
	}
	if (!file_exists(sig)) {
		snprintf(note, cap,
			 "BPF object signature %s is missing from the "
			 "operator bundle. The agent refuses to load an "
			 "unsigned enforcement object.",
			 sig);
		return STAGE_BLOCKED;
	}

	{
		const char *const argv[] = { PATH_AGENT_BIN,
					     "--verify-policy",
					     PATH_BPF_OBJ,
					     "--policy-pubkey",
					     ctx->opts.policy_pubkey,
					     NULL };

		rc = run_capture(argv, out, sizeof(out));
	}
	if (rc != 0) {
		snprintf(note, cap,
			 "The BPF object signature does not verify against "
			 "%s - the bundle is inconsistent or tampered. "
			 "Obtain a matching bundle from the operator.",
			 ctx->opts.policy_pubkey);
		return STAGE_BLOCKED;
	}

	rc = probe_conf_has_key(PATH_LOTA_CONF, "policy_pubkey");
	if (rc == 1) {
		snprintf(note, cap,
			 "Signature verifies, %s references the "
			 "operator key",
			 PATH_LOTA_CONF);
		return STAGE_DONE;
	}
	snprintf(note, cap,
		 "Signature verifies. %s still needs the "
		 "policy_pubkey reference.",
		 PATH_LOTA_CONF);
	return STAGE_PENDING;
}

static int st_trust_apply(struct install_ctx *ctx)
{
	struct stat sb;
	int fresh;
	int fd;
	FILE *f;

	if (mkdir("/etc/lota", 0755) != 0 && errno != EEXIST)
		return -errno;

	fresh = stat(PATH_LOTA_CONF, &sb) != 0 || sb.st_size == 0;
	/* explicit 0644: fopen("a") would create world-writable (0666) */
	fd = open(PATH_LOTA_CONF, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC,
		  0644);
	if (fd < 0)
		return -errno;
	f = fdopen(fd, "a");
	if (!f) {
		close(fd);
		return -errno;
	}
	if (fresh)
		fprintf(f, "# LOTA agent configuration (created by "
			   "lota-install)\n");
	fprintf(f,
		"\n# Operator key the BPF object signature is verified "
		"against.\npolicy_pubkey = %s\n",
		ctx->opts.policy_pubkey);
	fclose(f);
	return 0;
}

/* stage 4: kernel-enforced binary immutability (fs-verity or signed IMA) */

static enum stage_state st_verity_probe(struct install_ctx *ctx, char *note,
					size_t cap)
{
	int st = probe_fsverity_state(PATH_AGENT_BIN);

	(void)ctx;

	switch (st) {
	case PROBE_VERITY_ENABLED:
		snprintf(note, cap,
			 "Kernel-enforced read-only hash is "
			 "active on %s",
			 PATH_AGENT_BIN);
		return STAGE_DONE;
	case PROBE_VERITY_DISABLED:
		snprintf(note, cap, "fs-verity not yet enabled on %s",
			 PATH_AGENT_BIN);
		return STAGE_PENDING;
	case PROBE_VERITY_UNSUPPORTED:
		/*
		 * no native fs-verity on this filesystem.
		 * Signed security.ima xattr appraised under ima_appraise=enforce
		 * gives the same offline-swap guarantee and the agent accepts it
		 * as equivalent, so IMA-signed binary is done.
		 * Otherwise block with filesystem-specific guidance
		 */
		if (probe_file_ima_signed(PATH_AGENT_BIN) == 1) {
			snprintf(
				note, cap,
				"No fs-verity on this filesystem; %s carries a "
				"signed security.ima xattr enforced by IMA "
				"appraisal instead",
				PATH_AGENT_BIN);
			return STAGE_DONE;
		}
		probe_verity_remediation(probe_path_fstype(PATH_AGENT_BIN),
					 PATH_AGENT_BIN, note, cap);
		return STAGE_BLOCKED;
	default:
		snprintf(note, cap, "fs-verity probe failed: %s",
			 strerror(-st));
		return STAGE_ERROR;
	}
}

static int st_verity_apply(struct install_ctx *ctx)
{
	(void)ctx;
	return probe_fsverity_enable(PATH_AGENT_BIN);
}

/* stage 5: initramfs PCR14 lock module */

static int initrd_has_lock_module(void)
{
	char out[65536];
	const char *const argv[] = { "lsinitrd", NULL };
	int rc = run_capture(argv, out, sizeof(out));

	if (rc != 0)
		return -EIO;
	return strstr(out, "lota-pcr14-lock") != NULL;
}

static enum stage_state st_initrd_probe(struct install_ctx *ctx, char *note,
					size_t cap)
{
	int has = initrd_has_lock_module();

	(void)ctx;

	if (has < 0) {
		snprintf(note, cap,
			 "lsinitrd failed. Cannot inspect the "
			 "current initramfs.");
		return STAGE_ERROR;
	}
	if (has) {
		snprintf(note, cap,
			 "lota-pcr14-lock is inside the current "
			 "kernel's initramfs.");
		return STAGE_DONE;
	}
	snprintf(note, cap,
		 "Current initramfs does not contain the "
		 "PCR14 lock helper.");
	return STAGE_PENDING;
}

static int st_initrd_apply(struct install_ctx *ctx)
{
	const char *const argv[] = { "dracut", "-f", NULL };
	int rc = run_cmd(&ctx->ui, "Regenerating the initramfs (dracut -f)",
			 argv);

	if (rc != 0)
		return rc > 0 ? -EIO : rc;
	ctx->reboot_needed = 1;
	return 0;
}

/* stage 6: kernel cmdline floor */

/* extracts the args="..." value from grubby --info output into buf */
static int grubby_default_args(char *buf, size_t cap)
{
	char out[8192];
	const char *const argv[] = { "grubby", "--info=DEFAULT", NULL };
	char *line;
	int rc = run_capture(argv, out, sizeof(out));

	if (rc != 0)
		return -EIO;

	line = strstr(out, "args=\"");
	if (!line)
		return -EBADMSG;
	line += 6;
	{
		char *end = strchr(line, '"');

		if (!end)
			return -EBADMSG;
		*end = '\0';
	}
	snprintf(buf, cap, "%s", line);
	return 0;
}

/* the floor the agent's startup gates demand from the booted kernel */
struct floor_state {
	int ima_ok; /* ima_appraise=enforce|fix */
	int sig_ok; /* module signature enforcement */
	int lockdown_ok; /* lockdown integrity/confidentiality */
};

static void booted_floor(struct floor_state *st)
{
	st->ima_ok = probe_booted_ima_ok() == 0;
	st->sig_ok = probe_module_sig_enforced() == 0;
	st->lockdown_ok = probe_lockdown_restrictive() == 0;
}

static enum stage_state st_cmdline_probe(struct install_ctx *ctx, char *note,
					 size_t cap)
{
	struct floor_state st;
	char args[4096];

	(void)ctx;

	booted_floor(&st);
	if (st.ima_ok && st.sig_ok && st.lockdown_ok) {
		snprintf(note, cap,
			 "Booted kernel satisfies the integrity "
			 "floor (IMA appraisal, signed modules, "
			 "lockdown).");
		return STAGE_DONE;
	}

	/* not satisfied live;
	 * already configured for the next boot? */
	if (grubby_default_args(args, sizeof(args)) == 0) {
		int ima_cfg = probe_cmdline_ima_ok(args) == 0;
		int sig_cfg =
			st.sig_ok ||
			probe_cmdline_has_token(args, "module.sig_enforce=1");
		int lock_cfg =
			st.lockdown_ok ||
			probe_cmdline_has_token(args, "lockdown=integrity");

		if (ima_cfg && sig_cfg && lock_cfg) {
			snprintf(note, cap,
				 "kernel cmdline is configured. "
				 "The floor takes effect on the "
				 "next boot");
			return STAGE_REBOOT;
		}
	}

	snprintf(note, cap, "Booted kernel lacks:%s%s%s",
		 st.ima_ok ? "" : " ima_appraise",
		 st.sig_ok ? "" : " module.sig_enforce",
		 st.lockdown_ok ? "" : " lockdown");
	return STAGE_PENDING;
}

static int st_cmdline_apply(struct install_ctx *ctx)
{
	struct floor_state st;
	char args[256] = "";
	int rc;

	booted_floor(&st);
	if (!st.ima_ok)
		strcat(args, "ima=on ima_appraise=fix ");
	if (!st.sig_ok)
		strcat(args, "module.sig_enforce=1 ");
	if (!st.lockdown_ok)
		strcat(args, "lockdown=integrity ");
	if (args[0] == '\0')
		return 0;
	args[strlen(args) - 1] = '\0';

	{
		const char *const argv[] = { "grubby", "--update-kernel=ALL",
					     "--args", args, NULL };

		rc = run_cmd(&ctx->ui,
			     "Adding kernel integrity parameters "
			     "(grubby)",
			     argv);
	}
	if (rc != 0)
		return rc > 0 ? -EIO : rc;
	ctx->reboot_needed = 1;
	return 0;
}

/* stage 7: SELinux TPM device fence */

/* Label check for the agent binary.
 * Mirrors the device-label pattern. */
static int agent_label_ok(void)
{
	char lctx[256];
	ssize_t got = getxattr(PATH_AGENT_BIN, "security.selinux", lctx,
			       sizeof(lctx) - 1);

	if (got < 0)
		return errno == ENOTSUP ? 1 : 0;
	lctx[got] = '\0';
	return strstr(lctx, "lota_agent_exec_t") != NULL;
}

static int selinux_module_loaded(void)
{
	char out[16384];
	const char *const argv[] = { "semodule", "-l", NULL };
	char *line;
	int rc;

	if (!tool_exists("semodule"))
		return -ENOENT;
	rc = run_capture(argv, out, sizeof(out));
	if (rc != 0)
		return -EIO;

	for (line = strtok(out, "\n"); line; line = strtok(NULL, "\n")) {
		if (strcmp(line, "lota") == 0 ||
		    strncmp(line, "lota ", 5) == 0 ||
		    strncmp(line, "lota\t", 5) == 0)
			return 1;
	}
	return 0;
}

static enum stage_state st_selinux_probe(struct install_ctx *ctx, char *note,
					 size_t cap)
{
	int dev = probe_selinux_tpm_label();

	if (dev == 0 && agent_label_ok()) {
		snprintf(note, cap,
			 "TPM device and agent binary carry the "
			 "LOTA SELinux labels.");
		return STAGE_DONE;
	}
	if (dev == -ENOENT) {
		snprintf(note, cap, "No TPM device node visible.");
		return STAGE_ERROR;
	}
	if (dev < 0 && dev != -EPERM) {
		snprintf(note, cap, "SELinux label probe failed: %s",
			 strerror(-dev));
		return STAGE_ERROR;
	}

	if (selinux_module_loaded() <= 0 &&
	    !file_exists(ctx->opts.selinux_module)) {
		snprintf(note, cap,
			 "LOTA SELinux policy module is not loaded and "
			 "no module package was found at %s. Point "
			 "--selinux-module at the operator-supplied lota.pp",
			 ctx->opts.selinux_module);
		return STAGE_BLOCKED;
	}

	snprintf(note, cap, "SELinux labels not yet applied.");
	return STAGE_PENDING;
}

static int st_selinux_apply(struct install_ctx *ctx)
{
	int rc;

	if (selinux_module_loaded() == 0) {
		const char *const argv[] = { "semodule", "-i",
					     ctx->opts.selinux_module, NULL };

		rc = run_cmd(&ctx->ui,
			     "Loading the LOTA SELinux policy "
			     "module",
			     argv);
		if (rc != 0)
			return rc > 0 ? -EIO : rc;
	}

	{
		const char *const argv[] = { "udevadm", "control",
					     "--reload-rules", NULL };

		rc = run_cmd(&ctx->ui, "Reloading udev rules", argv);
		if (rc != 0)
			return rc > 0 ? -EIO : rc;
	}
	{
		const char *const argv[] = { "udevadm", "trigger",
					     "/dev/tpmrm0", "/dev/tpm0", NULL };

		rc = run_cmd(&ctx->ui, "Re-labeling the TPM device nodes",
			     argv);
		if (rc != 0)
			return rc > 0 ? -EIO : rc;
	}
	{
		const char *const argv[] = { "restorecon", PATH_AGENT_BIN,
					     NULL };

		rc = run_cmd(&ctx->ui, "Restoring the agent binary label",
			     argv);
		if (rc != 0)
			return rc > 0 ? -EIO : rc;
	}
	return 0;
}

/* stage 8: reboot checkpoint */

static int agent_service_active(void)
{
	char out[256];
	const char *const argv[] = { "systemctl", "is-active",
				     "lota-agent.service", NULL };

	return run_capture(argv, out, sizeof(out)) == 0;
}

static enum stage_state st_barrier_probe(struct install_ctx *ctx, char *note,
					 size_t cap)
{
	int pcr;

	if (ctx->reboot_needed) {
		snprintf(note, cap,
			 "Earlier stages changed the boot chain "
			 "(initramfs or kernel cmdline).");
		return STAGE_REBOOT;
	}

	pcr = probe_pcr14_state();
	switch (pcr) {
	case PROBE_PCR14_LOCK_ONLY:
		snprintf(note, cap,
			 "PCR14 carries the initramfs lock from "
			 "this boot.");
		return STAGE_DONE;
	case PROBE_PCR14_OTHER:
		if (agent_service_active()) {
			snprintf(note, cap,
				 "PCR14 carries this boot's agent "
				 "commitment.");
			return STAGE_DONE;
		}
		snprintf(note, cap,
			 "PCR14 holds a stale value from an "
			 "earlier agent run. PCR14 only resets on "
			 "a hardware reset.");
		return STAGE_REBOOT;
	case PROBE_PCR14_ZERO:
		snprintf(note, cap,
			 "The initramfs PCR14 lock has not run "
			 "during this boot.");
		return STAGE_REBOOT;
	default:
		snprintf(note, cap, "Cannot read PCR14 from sysfs (%s).",
			 strerror(-pcr));
		return STAGE_ERROR;
	}
}

/* stage 9: agent service */

static enum stage_state st_agent_probe(struct install_ctx *ctx, char *note,
				       size_t cap)
{
	(void)ctx;

	if (agent_service_active()) {
		snprintf(note, cap, "lota-agent.service is ACTIVE.");
		return STAGE_DONE;
	}
	snprintf(note, cap, "lota-agent.service is NOT RUNNING.");
	return STAGE_PENDING;
}

static int st_agent_apply(struct install_ctx *ctx)
{
	int rc;

	{
		const char *const argv[] = { "systemctl", "daemon-reload",
					     NULL };

		rc = run_cmd(&ctx->ui, "Reloading systemd units", argv);
		if (rc != 0)
			return rc > 0 ? -EIO : rc;
	}
	{
		const char *const argv[] = { "systemctl",
					     "enable",
					     "--now",
					     "lota-agent.socket",
					     "lota-agent.service",
					     NULL };

		rc = run_cmd(&ctx->ui,
			     "Enabling and starting the LOTA "
			     "agent",
			     argv);
	}
	if (rc != 0 || !agent_service_active()) {
		const char *const argv[] = { "journalctl", "-u",
					     "lota-agent", "-b",
					     "--no-pager", "-n",
					     "15",	   NULL };

		run_cmd(&ctx->ui, "Collecting the agent's startup log", argv);
		return rc != 0 ? (rc > 0 ? -EIO : rc) : -EAGAIN;
	}
	return 0;
}

/* stage 10: enrollment */

static enum stage_state st_enroll_probe(struct install_ctx *ctx, char *note,
					size_t cap)
{
	int days = 0;
	int rc = probe_cert_days_left(PATH_AIK_CERT, &days);

	if (rc == 0 && days > 0) {
		snprintf(note, cap,
			 "AIK certificate present, %d day%s "
			 "left.",
			 days, days == 1 ? "" : "s");
		return STAGE_DONE;
	}
	if (rc == 0) {
		snprintf(note, cap,
			 "AIK certificate expired. Guided "
			 "re-enrollment refreshes it.");
		return STAGE_PENDING;
	}
	if (rc != -ENOENT) {
		snprintf(note, cap, "Cannot parse %s (%s)", PATH_AIK_CERT,
			 strerror(-rc));
		return STAGE_ERROR;
	}

	if (!ctx->opts.ca_server) {
		snprintf(note, cap,
			 "This host has never enrolled and no attestation CA "
			 "endpoint was given. Re-run with --ca-server (and "
			 "usually --ca-cert) from the operator's install "
			 "instructions.");
		return STAGE_BLOCKED;
	}
	snprintf(note, cap,
		 "Not enrolled yet. TPM will prove its "
		 "identity to the operator's CA.");
	return STAGE_PENDING;
}

static int st_enroll_apply(struct install_ctx *ctx)
{
	const char *argv[12];
	int days = 0;
	int n = 0;
	int rc;

	if (probe_cert_days_left(PATH_AIK_CERT, &days) == 0) {
		/* expired certificate: the agent recorded the CA endpoint
		 * at first enrollment, so the guided path needs no flags */
		const char *const rv[] = { PATH_AGENT_BIN, "--reenroll", NULL };

		rc = run_cmd(&ctx->ui,
			     "Refreshing the AIK certificate "
			     "(guided re-enrollment)...",
			     rv);
		return rc == 0 ? 0 : (rc > 0 ? -EIO : rc);
	}

	argv[n++] = PATH_AGENT_BIN;
	argv[n++] = "--enroll";
	argv[n++] = "--ca-server";
	argv[n++] = ctx->opts.ca_server;
	if (ctx->opts.ca_port) {
		argv[n++] = "--ca-port";
		argv[n++] = ctx->opts.ca_port;
	}
	if (ctx->opts.ca_cert) {
		argv[n++] = "--ca-cert";
		argv[n++] = ctx->opts.ca_cert;
	}
	argv[n] = NULL;

	rc = run_cmd(&ctx->ui,
		     "Enrolling with the attestation CA "
		     "(TPM credential activation)...",
		     argv);
	return rc == 0 ? 0 : (rc > 0 ? -EIO : rc);
}

/* self-check + telemetry summary */

static const char telemetry_summary[] =
	"Every attestation report sent to the operator's verifier "
	"contains:\n"
	"  - TPM PCR values and a TPM-signed quote over them\n"
	"  - Boot event log (firmware and bootloader measurements, "
	"including the kernel command line, which carries disk UUIDs)\n"
	"  - Agent and kernel image hashes and the kernel path\n"
	"  - IOMMU status and counts + hashes of recently executed "
	"binaries with their paths, PIDs and UIDs (the BPF telemetry the "
	"anti-cheat verdict is based on)\n"
	"  - Stable device identifier derived by hashing the TPM "
	"endorsement key's public name (the key itself never leaves the "
	"TPM)\n"
	"  - AIK certificate, whose subject is a CA-issued pseudonym\n"
	"During enrollment only, the attestation CA (never the verifier) "
	"additionally receives the TPM's EK certificate to prove the TPM "
	"is genuine.\n"
	"No file contents, no browsing or account data leave this "
	"machine.";

int install_self_check(struct install_ctx *ctx)
{
	struct floor_state st;
	int days = 0;
	int ok = 1;

	ui_stage_begin(&ctx->ui, install_stage_count + 1,
		       install_stage_count + 1, "Self-check");

	booted_floor(&st);
	ui_kv(&ctx->ui, "Kernel integrity floor",
	      st.ima_ok && st.sig_ok && st.lockdown_ok ? "Satisfied" :
							 "NOT satisfied");
	if (!(st.ima_ok && st.sig_ok && st.lockdown_ok))
		ok = 0;

	ui_kv(&ctx->ui, "agent binary immutability",
	      probe_fsverity_state(PATH_AGENT_BIN) == PROBE_VERITY_ENABLED ?
		      "Enforced (fs-verity)" :
	      probe_file_ima_signed(PATH_AGENT_BIN) == 1 ?
		      "Enforced (signed IMA xattr)" :
		      "NOT enforced");

	ui_kv(&ctx->ui, "agent service",
	      agent_service_active() ? "Active" : "NOT active");
	if (!agent_service_active())
		ok = 0;

	if (probe_cert_days_left(PATH_AIK_CERT, &days) == 0 && days > 0) {
		char buf[64];

		snprintf(buf, sizeof(buf), "Valid, %d day%s left", days,
			 days == 1 ? "" : "s");
		ui_kv(&ctx->ui, "AIK certificate", buf);
	} else {
		ui_kv(&ctx->ui, "AIK certificate", "NOT valid");
		ok = 0;
	}

	/* Informational:
	 * tells the player which firmware-update recovery path this machine
	 * will take if the operator runs a self-service re-anchor verifier.
	 * Not a pass/fail gate! */
	ui_kv(&ctx->ui, "Firmware version reporting (ESRT)",
	      probe_esrt_system_firmware_present() ?
		      "present (firmware re-anchor uses the strong path)" :
		      "absent (firmware re-anchor is low-assurance; the first "
		      "one needs operator approval)");

	if (ctx->opts.verifier) {
		const char *argv[8];
		int n = 0;
		int rc;

		argv[n++] = PATH_AGENT_BIN;
		argv[n++] = "--attest";
		argv[n++] = "--server";
		argv[n++] = ctx->opts.verifier;
		if (ctx->opts.verifier_port) {
			argv[n++] = "--port";
			argv[n++] = ctx->opts.verifier_port;
		}
		argv[n] = NULL;

		rc = run_cmd(&ctx->ui,
			     "Attestation round-trip against the "
			     "operator verifier.",
			     argv);
		if (rc != 0)
			ok = 0;
	} else {
		ui_text(&ctx->ui, "Attestation round-trip skipped (no "
				  "--verifier given). First game launch "
				  "performs it.");
	}

	ui_explain(&ctx->ui, telemetry_summary);
	return ok ? 0 : -1;
}

/* stage table */

/*
 * Informational stage:
 * tell the player which firmware-update recovery path this machine qualifies
 * for.
 * Probe-only, changes nothing, always DONE.
 */
static enum stage_state st_firmware_readiness_probe(struct install_ctx *ctx,
						    char *note, size_t cap)
{
	(void)ctx;

	if (probe_esrt_system_firmware_present())
		snprintf(note, cap,
			 "This machine reports its firmware version (ESRT), so "
			 "after a BIOS update the operator's verifier can "
			 "re-establish the baseline automatically.");
	else
		snprintf(
			note, cap,
			"This machine does not report a firmware version "
			"(ESRT) - common on custom builds flashed from a USB "
			"tool. A BIOS update still re-establishes "
			"automatically, on the low-assurance path the operator "
			"reviews after the fact.");
	return STAGE_DONE;
}

const struct stage install_stages[] = {
	{
		.title = "Preflight: Hardware and Host Requirements",
		.explain = "",
		.probe = st_preflight_probe,
	},
	{
		.title = "LOTA Package Artifacts",
		.explain = "",
		.probe = st_artifacts_probe,
	},
	{
		.title = "Operator trust material",
		.explain =
			"The agent only loads a BPF enforcement object signed by "
			"the game operator's key. "
			"This step records the operator public key location in "
			"/etc/lota/lota.conf so the agent knows what to verify against."
			" Nothing is downloaded and no key is generated on this machine.",
		.probe = st_trust_probe,
		.apply = st_trust_apply,
	},
	{
		.title = "Tamper-proofing the agent binary",
		.explain =
			"Kernel must refuse any modified read of /usr/bin/lota-agent "
			"so replacing or patching it breaks attestation visibly. "
			"On ext4/btrfs/f2fs this stage enables fs-verity. "
			"On XFS, ZFS and other filesystems without verity, signed "
			"security.ima xattr appraised under ima_appraise=enforce "
			"gives the same guarantee; the agent accepts either. "
			"fs-verity changes only that one file's state on disk and "
			"is undone by reinstalling the package.",
		.probe = st_verity_probe,
		.apply = st_verity_apply,
	},
	{
		.title = "Boot-time PCR14 lock in the initramfs",
		.explain =
			"LOTA pins TPM PCR 14 very early in boot (inside the "
			"initramfs, before any regular userspace runs) so nothing "
			"can pre-poison the agent's measurement slot."
			"This step regenerates the initramfs with dracut to include "
			"the lock helper. It rewrites /boot/initramfs-*.img - the standard "
			"file every kernel update also rewrites - and requires a reboot to "
			"take effect.",
		.probe = st_initrd_probe,
		.apply = st_initrd_apply,
	},
	{
		.title = "Kernel integrity floor on the cmdline",
		.explain =
			"The agent refuses to start unless the kernel enforces an "
			"integrity floor: IMA appraisal in an enforcing mode "
			"(ima_appraise=fix - it satisfies the floor without "
			"blocking unsigned files), signed kernel modules, and "
			"kernel lockdown."
			"This step appends the missing parameters to the boot "
			"entries via grubby. They appear in /etc/default/grub and "
			"take effect on the next boot. "
			"Removing them restores the previous behaviour.",
		.probe = st_cmdline_probe,
		.apply = st_cmdline_apply,
	},
	{
		.title = "SELinux fence on the TPM device",
		.explain =
			"udev rule labels /dev/tpm* with a LOTA-specific SELinux "
			"type so only the agent's domain (and root tooling) can "
			"talk to the TPM directly."
			"This step loads the LOTA SELinux policy module if needed "
			"and re-triggers udev. It does not change the SELinux mode "
			"of the system.",
		.probe = st_selinux_probe,
		.apply = st_selinux_apply,
	},
	{
		.title = "Reboot checkpoint",
		.explain = "",
		.probe = st_barrier_probe,
		.barrier = 1,
	},
	{
		.title = "LOTA agent service",
		.explain =
			"Enables and starts lota-agent.service (plus its activation "
			"socket)."
			"The agent loads the signed BPF enforcement object, "
			"measures itself into PCR 14 and exposes a local "
			"socket games use to request attestation tokens."
			"Note: a running agent cannot be killed, by design - pausing it is "
			"done with 'lota-agent --shutdown' and resuming requires a "
			"reboot.",
		.probe = st_agent_probe,
		.apply = st_agent_apply,
	},
	{
		.title = "Enrollment with the operator's attestation CA",
		.explain =
			"TPM proves to the operator's CA that it is a genuine "
			"hardware TPM (credential activation) and receives a "
			"short-lived certificate for its attestation key.\n"
			"The CA sees the TPM's endorsement key certificate once, during "
			"this step.\nGame servers only ever see a pseudonym.\n"
			"The certificate lands in /var/lib/lota/aik_cert.der.",
		.probe = st_enroll_probe,
		.apply = st_enroll_apply,
	},
	{
		.title = "Firmware-update readiness",
		.explain =
			"After install, a later BIOS update changes this machine's "
			"firmware measurements. The operator's verifier can re-establish "
			"the trust baseline on its own when the update keeps Secure Boot "
			"intact (same keys, Secure Boot still on), so you keep playing "
			"without re-running this installer."
			"\nThis step only reports which recovery path your hardware "
			"qualifies for - it changes nothing on the system.",
		.probe = st_firmware_readiness_probe,
	},
};

const int install_stage_count =
	(int)(sizeof(install_stages) / sizeof(install_stages[0]));
