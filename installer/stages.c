/* SPDX-License-Identifier: MIT
 * Copyright (C) 2026 Szymon Wilczek
 *
 * lota-install - Stage Table
 */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <unistd.h>
#include <sys/types.h>

#include "install.h"
#include "probe.h"
#include "run.h"
#include "ui.h"
#include "../include/lota_secure_boot.h"
#include "../src/agent/config.h"
#include "../src/agent/policy_pubkey.h"
#include "../src/agent/profile.h"

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

/* a missing tool or a spawn failure reads as bare metal */
static int host_is_virtual(void)
{
	const char *const argv[] = { "systemd-detect-virt", "-q", NULL };
	char out[64];

	return run_capture(argv, out, sizeof(out)) == 0;
}

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
	if (sb == -ENOENT && !probe_firmware_is_uefi()) {
		snprintf(note, cap,
			 "This host booted via legacy BIOS/CSM, not UEFI. "
			 "BIOS is unsupported: it measures neither the "
			 "firmware and Secure Boot state the verifier pins "
			 "nor an EFI variable the event log can carry, so "
			 "the initramfs helper, the agent and the verifier "
			 "each refuse such a host. Switch the firmware to "
			 "UEFI mode and reinstall.");
		return STAGE_BLOCKED;
	}
	if (sb == -ENOENT) {
		if (host_is_virtual())
			snprintf(note, cap,
				 "This guest booted via UEFI, but its firmware "
				 "exposes no Secure Boot variable, so the "
				 "feature is absent from the firmware build. "
				 "Give the VM a "
				 "Secure Boot capable firmware -- on libvirt "
				 "that is an OVMF secboot build with enrolled "
				 "keys -- and boot it again. The verifier pins "
				 "the Secure Boot state, so a guest without it "
				 "cannot attest.");
		else
			snprintf(note, cap,
				 "This host booted via UEFI, but its firmware "
				 "exposes no Secure Boot variable, so the "
				 "feature is absent from this firmware build. "
				 "A firmware update "
				 "from the board vendor is what adds it; there "
				 "is no setting to change on the running "
				 "build. The verifier pins the Secure Boot "
				 "state, so a host without it cannot attest.");
		return STAGE_BLOCKED;
	}
	if (sb == LOTA_SECURE_BOOT_OFF || sb == LOTA_SECURE_BOOT_SETUP_MODE) {
		probe_secureboot_guidance(host_is_virtual(), note, cap);
		return STAGE_BLOCKED;
	}
	if (sb == LOTA_SECURE_BOOT_SHIM_INSECURE) {
		snprintf(note, cap,
			 "Secure Boot is on in the firmware, but shim "
			 "validation is disabled (MokSBStateRT), so the "
			 "kernel boots as if Secure Boot were off. Run "
			 "'mokutil --enable-validation', reboot, confirm "
			 "the request in MokManager, and re-run "
			 "lota-install.");
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

const char *installer_trust_key(const char *named, const char *conf_pubkey,
				const char *override_path,
				const char *packaged_path,
				enum trust_key_source *src)
{
	enum trust_key_source got = TRUST_KEY_NONE;
	const char *key;

	if (named) {
		if (src)
			*src = TRUST_KEY_NAMED;
		return named;
	}

	key = policy_pubkey_resolve(conf_pubkey, override_path, packaged_path);
	if (key == conf_pubkey)
		got = TRUST_KEY_CONFIGURED;
	else if (key == override_path)
		got = TRUST_KEY_OVERRIDE;
	else if (key == packaged_path)
		got = TRUST_KEY_PACKAGED;

	if (src)
		*src = got;
	return key;
}

const char *installer_trust_key_source_says(enum trust_key_source src)
{
	switch (src) {
	case TRUST_KEY_NAMED:
		return "named with --policy-pubkey";
	case TRUST_KEY_CONFIGURED:
		return "named by policy_pubkey in " PATH_LOTA_CONF;
	case TRUST_KEY_OVERRIDE:
		return "this host's own operator key";
	case TRUST_KEY_PACKAGED:
		return "the key the agent package shipped";
	case TRUST_KEY_NONE:
		break;
	}
	return "nowhere -- no readable key was found";
}

static int same_file(const char *a, const char *b)
{
	struct stat sa, sb;

	if (stat(a, &sa) != 0 || stat(b, &sb) != 0)
		return strcmp(a, b) == 0;
	return sa.st_dev == sb.st_dev && sa.st_ino == sb.st_ino;
}

const char *installer_trust_fallback(const char *key, enum trust_key_source src,
				     const char *conf_pubkey,
				     const char *override_path,
				     const char *packaged_path)
{
	const char *next;

	switch (src) {
	case TRUST_KEY_NAMED:
		next = policy_pubkey_resolve(conf_pubkey, override_path,
					     packaged_path);
		break;
	case TRUST_KEY_CONFIGURED:
		next = policy_pubkey_resolve(NULL, override_path,
					     packaged_path);
		break;
	case TRUST_KEY_OVERRIDE:
		next = policy_pubkey_resolve(NULL, NULL, packaged_path);
		break;
	default:
		return NULL;
	}
	if (!next || !key || same_file(key, next))
		return NULL;
	return next;
}

static const char *trust_fallback_step(enum trust_key_source src)
{
	switch (src) {
	case TRUST_KEY_NAMED:
		return "leave out --policy-pubkey and the agent uses";
	case TRUST_KEY_CONFIGURED:
		return "remove policy_pubkey from " PATH_LOTA_CONF
		       " and the agent falls through to";
	default:
		return "move it out of the way and the agent falls through to";
	}
}

void installer_trust_refusal(char *buf, size_t cap, const char *key,
			     enum trust_key_source src, const char *fallback,
			     const char *obj)
{
	char either[1024];

	if (fallback)
		snprintf(either, sizeof(either),
			 "either this key did not sign the shipped object - "
			 "%s %s -",
			 trust_fallback_step(src), fallback);
	else
		snprintf(either, sizeof(either),
			 "nothing else on this host would verify the object in "
			 "its place, so moving this key aside leaves none. "
			 "Either the object, signature or key changed after "
			 "the package installed them - reinstall the agent "
			 "package to put all three back -");

	snprintf(buf, cap,
		 "The BPF object signature does not verify against "
		 "%s, which is %s and is the key the agent resolves "
		 "for this host. The package ships object, signature "
		 "and key together and replaces all three on an "
		 "upgrade, so this means they no longer belong to each "
		 "other: %s or the fleet signs enforcement itself and has to "
		 "re-sign this object "
		 "(lota-agent --sign-policy %s --signing-key <key>). "
		 "The installer never signs on this host by design.",
		 key, installer_trust_key_source_says(src), either, obj);
}

int installer_conf_pubkey(const char *conf_path, char *key, size_t cap)
{
	struct lota_config *cfg = config_new();
	int rc;

	key[0] = '\0';
	if (!cfg)
		return -ENOMEM;
	rc = config_load(cfg, conf_path);
	if (rc == -ENOENT) {
		rc = 0;
	} else if (rc == 0 && cfg->policy_pubkey[0]) {
		rc = -ENAMETOOLONG;
		if (strlen(cfg->policy_pubkey) < cap) {
			strcpy(key, cfg->policy_pubkey);
			rc = 1;
		}
	}
	config_free(cfg);
	return rc;
}

enum stage_state installer_trust_named(const char *named,
				       const char *conf_pubkey,
				       const char *override_path,
				       const char *packaged_path, char *note,
				       size_t cap)
{
	enum trust_key_source src = TRUST_KEY_NONE;
	const char *used;
	char gone[PATH_MAX + 64] = "";

	if (conf_pubkey && same_file(conf_pubkey, named)) {
		snprintf(note, cap, "Signature verifies, %s names the key",
			 PATH_LOTA_CONF);
		return STAGE_DONE;
	}

	used = installer_trust_key(NULL, conf_pubkey, override_path,
				   packaged_path, &src);
	if (conf_pubkey && used != conf_pubkey)
		snprintf(gone, sizeof(gone),
			 " It names %s, which is not readable.", conf_pubkey);
	if (!used)
		snprintf(note, cap,
			 "Signature verifies against the key you named. %s "
			 "still needs the policy_pubkey line for it, and the "
			 "agent has no key until then.%s",
			 PATH_LOTA_CONF, gone);
	else
		snprintf(note, cap,
			 "Signature verifies against the key you named. %s "
			 "still needs the policy_pubkey line for it, and the "
			 "agent verifies against %s (%s) until then.%s",
			 PATH_LOTA_CONF, used,
			 installer_trust_key_source_says(src), gone);
	return STAGE_PENDING;
}

static enum stage_state st_trust_probe(struct install_ctx *ctx, char *note,
				       size_t cap)
{
	enum trust_key_source src = TRUST_KEY_NONE;
	const char *configured = NULL;
	char conf_key[PATH_MAX];
	const char *key;
	char sig[512];
	char out[4096];
	int rc;

	rc = installer_conf_pubkey(PATH_LOTA_CONF, conf_key, sizeof(conf_key));
	if (rc < 0) {
		snprintf(note, cap,
			 "Cannot load %s (%s), and the agent fails to start on "
			 "it. 'lota-agent --dump-config' names each line it "
			 "refuses.",
			 PATH_LOTA_CONF, strerror(-rc));
		return STAGE_BLOCKED;
	}
	if (rc == 1)
		configured = conf_key;
	key = installer_trust_key(ctx->opts.policy_pubkey, configured,
				  PATH_POLICY_PUB_OVERRIDE,
				  PATH_ENFORCEMENT_PUB, &src);

	snprintf(sig, sizeof(sig), "%s.sig", PATH_BPF_OBJ);

	if (!key || !file_exists(key)) {
		snprintf(note, cap,
			 "No key to verify the enforcement object against. "
			 "One ships with the agent package at %s, beside the "
			 "object whoever built that package signed - the "
			 "installer never generates trust material on this "
			 "machine, since a locally generated key would let "
			 "local malware re-sign a tampered object. A fleet "
			 "that signs enforcement itself puts its key at %s.",
			 PATH_ENFORCEMENT_PUB, PATH_POLICY_PUB_OVERRIDE);
		return STAGE_BLOCKED;
	}
	if (!file_exists(sig)) {
		snprintf(note, cap,
			 "BPF object signature %s is missing. It ships with "
			 "the object; a package built without the signing "
			 "step installs enforcement the agent refuses to "
			 "load.",
			 sig);
		return STAGE_BLOCKED;
	}

	{
		const char *argv[6] = { PATH_AGENT_BIN, "--verify-policy",
					PATH_BPF_OBJ,	NULL,
					NULL,		NULL };

		if (ctx->opts.policy_pubkey) {
			argv[3] = "--policy-pubkey";
			argv[4] = ctx->opts.policy_pubkey;
		}
		rc = run_capture(argv, out, sizeof(out));
	}
	if (rc != 0) {
		installer_trust_refusal(
			note, cap, key, src,
			installer_trust_fallback(key, src, configured,
						 PATH_POLICY_PUB_OVERRIDE,
						 PATH_ENFORCEMENT_PUB),
			PATH_BPF_OBJ);
		return STAGE_BLOCKED;
	}

	if (!ctx->opts.policy_pubkey) {
		snprintf(note, cap, "Signature verifies against %s (%s).", key,
			 installer_trust_key_source_says(src));
		return STAGE_DONE;
	}
	return installer_trust_named(ctx->opts.policy_pubkey, configured,
				     PATH_POLICY_PUB_OVERRIDE,
				     PATH_ENFORCEMENT_PUB, note, cap);
}

static int st_trust_apply(struct install_ctx *ctx)
{
	struct stat sb;
	int fresh;
	int fd;
	FILE *f;

	if (!ctx->opts.policy_pubkey)
		return 0;

	if (mkdir(PATH_LOTA_CONF_DIR, 0755) != 0 && errno != EEXIST)
		return -errno;

	fresh = stat(PATH_LOTA_CONF, &sb) != 0 || sb.st_size == 0;
	/* fopen("a") would create 0666 */
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
		"\n# Key the enforcement object's signature is verified "
		"against.\npolicy_pubkey = %s\n",
		ctx->opts.policy_pubkey);
	fclose(f);
	return 0;
}

/*
 * NULL @image: the running kernel's image. An upgrade replaces the helper on
 * disk only, so an image is current when its copy is byte for byte the same.
 */
static int initrd_has_lock_helper(const char *image)
{
	/* lsinitrd -f names the file without its leading '/' */
	const char *const argv[] = { "lsinitrd", "-f", &PATH_LOCK_HELPER[1],
				     image, NULL };
	struct stat st;
	size_t cap;
	size_t len;
	char *out;
	int rc;

	if (stat(PATH_LOCK_HELPER, &st) < 0)
		return -errno;
	/* one byte past the helper tells a longer copy apart */
	cap = (size_t)st.st_size + 2;
	out = malloc(cap);
	if (!out)
		return -ENOMEM;

	rc = run_capture_len(argv, out, cap, &len);
	if (rc != 0) {
		free(out);
		return -EIO;
	}

	rc = probe_file_equals(PATH_LOCK_HELPER, out, len);
	free(out);
	return rc;
}

static enum stage_state st_initrd_probe(struct install_ctx *ctx, char *note,
					size_t cap)
{
	struct probe_kernel_image kernels[PROBE_MAX_KERNELS];
	size_t count = 0;
	size_t missing = 0;
	char missing_names[256] = { 0 };
	size_t used = 0;

	(void)ctx;

	if (probe_installed_kernels(kernels, PROBE_MAX_KERNELS, &count) < 0 ||
	    count == 0) {
		int has = initrd_has_lock_helper(NULL);

		if (has < 0) {
			snprintf(note, cap,
				 "Cannot compare the current initramfs with "
				 "%s: %s.",
				 PATH_LOCK_HELPER,
				 has == -EIO ? "lsinitrd failed" :
					       strerror(-has));
			return STAGE_ERROR;
		}
		if (has) {
			snprintf(note, cap,
				 "The current kernel's initramfs holds the "
				 "installed lota-pcr14-lock.");
			return STAGE_DONE;
		}
		snprintf(note, cap,
			 "The current initramfs holds no PCR14 lock helper, or "
			 "one other than the installed %s.",
			 PATH_LOCK_HELPER);
		return STAGE_PENDING;
	}

	for (size_t i = 0; i < count; i++) {
		int has = initrd_has_lock_helper(kernels[i].image);

		if (has < 0) {
			snprintf(note, cap, "Cannot compare %s with %s: %s.",
				 kernels[i].image, PATH_LOCK_HELPER,
				 has == -EIO ? "lsinitrd failed" :
					       strerror(-has));
			return STAGE_ERROR;
		}
		if (has)
			continue;

		missing++;
		if (used < sizeof(missing_names) - 1)
			used += (size_t)snprintf(missing_names + used,
						 sizeof(missing_names) - used,
						 "%s%s", used ? ", " : "",
						 kernels[i].release);
	}

	if (missing == 0) {
		snprintf(note, cap,
			 "The initramfs of all %zu installed kernel(s) holds "
			 "the installed lota-pcr14-lock.",
			 count);
		return STAGE_DONE;
	}

	snprintf(note, cap,
		 "%zu of %zu installed kernel(s) have no PCR14 lock helper in "
		 "their initramfs, or one other than the installed %s: %s. "
		 "Booting one with none leaves this machine with no boot "
		 "commitment.",
		 missing, count, PATH_LOCK_HELPER, missing_names);
	return STAGE_PENDING;
}

static int st_initrd_apply(struct install_ctx *ctx)
{
	const char *const argv[] = { "dracut", "-f", "--regenerate-all", NULL };
	int rc = run_cmd(&ctx->ui,
			 "Regenerating every kernel's initramfs "
			 "(dracut -f --regenerate-all)",
			 argv);

	if (rc != 0)
		return rc > 0 ? -EIO : rc;
	ctx->reboot_needed = 1;
	return 0;
}

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

static int booted_ima_appraised(void)
{
	return probe_ima_policy_scope(PROBE_IMA_POLICY_PATH, NULL) !=
	       PROBE_IMA_SCOPE_NONE;
}

static void booted_floor(struct probe_floor *st)
{
	char cmdline[4096];

	st->secureboot = probe_secureboot() == LOTA_SECURE_BOOT_ON;
	if (probe_read_text("/proc/cmdline", cmdline, sizeof(cmdline)) < 0)
		cmdline[0] = '\0';
	/* a kernel without appraisal has no mode to set */
	st->ima_built = probe_ima_appraise_built() != 0;
	st->ima_ok = !st->ima_built ||
		     probe_ima_mode_blocking(st->secureboot, cmdline);
	st->sig_ok = probe_module_sig_enforced() == 0;
	st->lockdown_ok = probe_lockdown_restrictive() == 0;
	st->appraised = st->ima_built && booted_ima_appraised();
	st->appraises = probe_ima_policy_appraises(PROBE_IMA_POLICY_PATH) != 0;
}

static enum stage_state st_cmdline_probe(struct install_ctx *ctx, char *note,
					 size_t cap)
{
	struct probe_floor st;
	char args[4096];

	(void)ctx;

	booted_floor(&st);
	if (!st.ima_built && st.sig_ok && st.lockdown_ok) {
		snprintf(note, cap,
			 "Booted kernel has no IMA appraisal, so no "
			 "ima_appraise= mode applies, and carries signed "
			 "modules and lockdown.");
		return STAGE_DONE;
	}
	if (st.ima_ok && st.sig_ok && st.lockdown_ok) {
		snprintf(note, cap,
			 "Booted kernel appraises in a blocking mode%s, and "
			 "carries signed modules and lockdown. The rules that "
			 "mode applies to are the next stage.",
			 st.secureboot ? " (its own built-in one: Secure Boot "
					 "makes the kernel ignore "
					 "ima_appraise=)" :
					 "");
		return STAGE_DONE;
	}

	return probe_cmdline_next_boot_stage(
		&st, grubby_default_args(args, sizeof(args)) == 0 ? args : NULL,
		note, cap);
}

static int st_cmdline_apply(struct install_ctx *ctx)
{
	struct probe_floor st;
	char args[256] = "";
	int rc;

	booted_floor(&st);

	if (!st.ima_ok && !st.appraises)
		strcat(args, "ima_appraise=enforce ");
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

static enum stage_state st_ima_scope_probe(struct install_ctx *ctx, char *note,
					   size_t cap)
{
	struct probe_ima_scope scope = { 0 };

	(void)ctx;

	scope.is_root = geteuid() == 0;
	scope.scope = probe_ima_policy_scope(PROBE_IMA_POLICY_PATH,
					     &scope.policy_signed);
	scope.secureboot = probe_secureboot() == LOTA_SECURE_BOOT_ON;
	scope.no_appraisal = probe_ima_appraise_built() == 0;
	scope.agent_signed = probe_file_ima_signed(PATH_AGENT_BIN) == 1;

	return probe_ima_scope_stage(&scope, note, cap);
}

static int label_ok(const char *path, const char *want)
{
	char lctx[256];
	ssize_t got =
		getxattr(path, "security.selinux", lctx, sizeof(lctx) - 1);

	if (got < 0)
		return errno == ENOTSUP ? 1 : 0;
	lctx[got] = '\0';
	return strstr(lctx, want) != NULL;
}

/* a missing @path passes */
static int label_ok_if_present(const char *path, const char *want)
{
	if (!file_exists(path))
		return 1;
	return label_ok(path, want);
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

static int selinux_port_pending(const struct install_ctx *ctx)
{
	static char out[65536];
	const char *const argv[] = { "semanage", "port", "-l", NULL };
	const char *const ports[] = { ctx->opts.ca_port,
				      ctx->opts.verifier_port };

	if ((!ctx->opts.ca_port && !ctx->opts.verifier_port) ||
	    !tool_exists("semanage") ||
	    run_capture(argv, out, sizeof(out)) != 0)
		return 0;

	for (size_t i = 0; i < sizeof(ports) / sizeof(ports[0]); i++) {
		if (ports[i] && probe_port_needs_label(out, ports[i]) > 0)
			return 1;
	}
	return 0;
}

static enum stage_state st_selinux_probe(struct install_ctx *ctx, char *note,
					 size_t cap)
{
	int dev = probe_selinux_tpm_label();

	if (dev == 0 && label_ok(PATH_AGENT_BIN, "lota_agent_exec_t") &&
	    label_ok_if_present(PATH_LOTA_STATE_DIR, "lota_var_t") &&
	    label_ok_if_present(PATH_LOTA_CONF_DIR, "lota_etc_t") &&
	    !selinux_port_pending(ctx)) {
		snprintf(note, cap,
			 "TPM device, agent binary, state directory and config "
			 "directory carry the LOTA SELinux labels.%s",
			 ctx->opts.selinux_module_named ?
				 " The policy was already in place, so the "
				 "module named by --selinux-module was not "
				 "loaded." :
				 "");
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

	/* SECLABEL applies on an add event; a change event moves no label */
	{
		const char *const argv[] = { "udevadm",	     "trigger",
					     "--action=add", "/dev/tpmrm0",
					     "/dev/tpm0",    NULL };

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
	{
		static char out[65536];
		const char *const list[] = { "semanage", "port", "-l", NULL };
		const char *const ports[] = { ctx->opts.ca_port,
					      ctx->opts.verifier_port };
		int listed = run_capture(list, out, sizeof(out)) == 0;

		for (size_t i = 0; i < sizeof(ports) / sizeof(ports[0]); i++) {
			const char *const argv[] = { "semanage",    "port",
						     "-a",	    "-t",
						     "lota_port_t", "-p",
						     "tcp",	    ports[i],
						     NULL };

			if (!listed || !ports[i] || !ports[i][0] ||
			    probe_port_needs_label(out, ports[i]) <= 0)
				continue;
			(void)run_cmd(&ctx->ui,
				      "Labelling the attestation port", argv);
		}
	}
	if (file_exists(PATH_LOTA_STATE_DIR)) {
		const char *const argv[] = { "restorecon", "-R",
					     PATH_LOTA_STATE_DIR, NULL };

		rc = run_cmd(&ctx->ui,
			     "Restoring the LOTA state directory labels", argv);
		if (rc != 0)
			return rc > 0 ? -EIO : rc;
	}

	/* new files inherit the directory's type */
	if (file_exists(PATH_LOTA_CONF_DIR)) {
		const char *const argv[] = { "restorecon", "-R",
					     PATH_LOTA_CONF_DIR, NULL };

		rc = run_cmd(&ctx->ui,
			     "Restoring the LOTA config directory labels",
			     argv);
		if (rc != 0)
			return rc > 0 ? -EIO : rc;
	}
	return 0;
}

static int agent_service_active(void)
{
	char out[256];
	const char *const argv[] = { "systemctl", "is-active",
				     "lota-agent.service", NULL };

	return run_capture(argv, out, sizeof(out)) == 0;
}

static int unit_enabled(const char *unit)
{
	char out[256];
	const char *const argv[] = { "systemctl", "is-enabled", unit, NULL };

	return run_capture(argv, out, sizeof(out)) == 0;
}

/* automatic restarts, or a failed unit */
static int agent_start_failed(void)
{
	char out[64];
	const char *const restarts[] = { "systemctl", "show",
					 "--value",   "-p",
					 "NRestarts", "lota-agent.service",
					 NULL };
	const char *const failed[] = { "systemctl", "is-failed",
				       "lota-agent.service", NULL };

	if (run_capture(restarts, out, sizeof(out)) == 0 && atoi(out) > 0)
		return 1;
	return run_capture(failed, out, sizeof(out)) == 0;
}

static void read_service_state(struct probe_service_state *s)
{
	s->agent_active = agent_service_active();
	s->agent_enabled = unit_enabled("lota-agent.service");
	s->socket_enabled = unit_enabled("lota-agent.socket");
	s->attest_enabled = unit_enabled("lota-attest.service");
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
	if (pcr < 0) {
		snprintf(note, cap, "Cannot read PCR14 from sysfs (%s).",
			 strerror(-pcr));
		return STAGE_ERROR;
	}

	/* a failure before this run's changes says nothing about them */
	return probe_pcr14_barrier_stage(pcr, probe_pcr14_lock_ran(),
					 agent_service_active(),
					 !ctx->applied && agent_start_failed(),
					 probe_agent_paused(), note, cap);
}

static enum stage_state st_agent_probe(struct install_ctx *ctx, char *note,
				       size_t cap)
{
	struct probe_service_state state;

	(void)ctx;

	read_service_state(&state);
	return probe_agent_service_stage(&state, note, cap);
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
	{
		const char *const argv[] = { "systemctl", "enable", "--now",
					     "lota-attest.service", NULL };

		rc = run_cmd(&ctx->ui, "Enabling the attestation loop", argv);
		if (rc != 0)
			return rc > 0 ? -EIO : rc;
	}
	return 0;
}

static int enroll_profile(const struct install_ctx *ctx,
			  struct profile_paths *paths)
{
	if (!ctx->opts.ca_cert)
		return -EINVAL;
	return profile_paths_from_anchor(ctx->opts.ca_cert, paths);
}

/* two profile_paths and the file are too large for one stack frame */
struct profile_recorded_scratch {
	struct profile_paths want;
	struct profile_paths have;
	char buf[16384];
	char path[PATH_MAX];
};

int installer_profile_recorded(const char *conf_path, const char *anchor)
{
	struct profile_recorded_scratch *s;
	int count;
	int ret = 0;

	if (!conf_path || !anchor)
		return 0;

	s = calloc(1, sizeof(*s));
	if (!s)
		return -ENOMEM;

	if (profile_paths_from_anchor(anchor, &s->want) < 0)
		goto out;
	ret = probe_read_text(conf_path, s->buf, sizeof(s->buf));
	if (ret < 0) {
		if (ret == -ENOENT)
			ret = 0;
		goto out;
	}
	ret = 0;

	count = probe_conf_buf_profile_count(s->buf);
	for (int i = 0; i < count; i++) {
		if (!probe_conf_buf_profile_anchor(s->buf, i, s->path,
						   sizeof(s->path)))
			continue;
		if (profile_paths_from_anchor(s->path, &s->have) < 0)
			continue;
		if (strcmp(s->have.id, s->want.id) == 0) {
			ret = 1;
			break;
		}
	}
out:
	free(s);
	return ret;
}

void installer_add_publisher_argv(const struct install_opts *o,
				  const char *argv[INSTALLER_ADD_PUBLISHER_ARGC])
{
	int n = 0;

	argv[n++] = PATH_AGENT_BIN;
	argv[n++] = "--add-publisher";
	argv[n++] = o->ca_server;
	if (o->ca_port) {
		argv[n++] = "--ca-port";
		argv[n++] = o->ca_port;
	}
	argv[n++] = "--ca-cert";
	argv[n++] = o->ca_cert;
	if (o->verifier && o->verifier[0]) {
		argv[n++] = "--server";
		argv[n++] = o->verifier;
		if (o->verifier_port) {
			argv[n++] = "--port";
			argv[n++] = o->verifier_port;
		}
	}
	argv[n++] = "--reporting";
	argv[n++] = "continuous";
	argv[n] = NULL;
}

static enum stage_state st_enroll_probe(struct install_ctx *ctx, char *note,
					size_t cap)
{
	struct profile_paths paths;
	int days = 0;
	int rc;

	rc = enroll_profile(ctx, &paths);
	if (rc == -EINVAL) {
		snprintf(note, cap,
			 "No attestation CA named, so nothing to enroll with "
			 "yet. The agent enrolls with each publisher the first "
			 "time a title asks for one. With --ca-server and "
			 "--ca-cert it enrolls here.");
		return STAGE_DONE;
	}
	if (rc < 0) {
		snprintf(note, cap, "Cannot read the CA trust anchor %s (%s)",
			 ctx->opts.ca_cert, strerror(-rc));
		return STAGE_ERROR;
	}

	rc = probe_cert_days_left(paths.aik_cert, &days);

	if (rc == 0 && days >= 0 && ctx->opts.ca_server) {
		int rec = installer_profile_recorded(PATH_LOTA_CONF,
						     ctx->opts.ca_cert);

		if (rec < 0) {
			snprintf(note, cap, "Cannot read %s (%s)",
				 PATH_LOTA_CONF, strerror(-rec));
			return STAGE_ERROR;
		}
		if (rec == 0) {
			snprintf(note, cap,
				 "Enrolled, but %s names no publisher for this "
				 "CA, so nothing reports to it. Recording it.",
				 PATH_LOTA_CONF);
			return STAGE_PENDING;
		}
	}
	if (rc == 0 && days > 0) {
		snprintf(note, cap,
			 "AIK certificate present, %d day%s "
			 "left.",
			 days, days == 1 ? "" : "s");
		return STAGE_DONE;
	}
	if (rc == 0 && days == 0) {
		snprintf(note, cap,
			 "AIK certificate present, less than a day left "
			 "(auto-renewal refreshes it before expiry).");
		return STAGE_DONE;
	}
	if (rc == 0) {
		snprintf(note, cap,
			 "AIK certificate expired. Guided "
			 "re-enrollment refreshes it.");
		return STAGE_PENDING;
	}
	if (rc != -ENOENT) {
		snprintf(note, cap, "Cannot parse %s (%s)", paths.aik_cert,
			 strerror(-rc));
		return STAGE_ERROR;
	}

	if (!ctx->opts.ca_server) {
		snprintf(note, cap,
			 "A CA trust anchor was given but no --ca-server to "
			 "enroll against. Pass both, or neither and let the "
			 "agent enroll when a title first asks.");
		return STAGE_BLOCKED;
	}
	snprintf(note, cap,
		 "Not enrolled yet. TPM will prove its "
		 "identity to the operator's CA, which is then recorded "
		 "as a publisher.");
	return STAGE_PENDING;
}

static int record_fleet_publisher(struct install_ctx *ctx)
{
	const char *argv[INSTALLER_ADD_PUBLISHER_ARGC];
	char out[2048];
	int rc;

	if (!ctx->opts.ca_server)
		return 0;
	rc = installer_profile_recorded(PATH_LOTA_CONF, ctx->opts.ca_cert);
	if (rc != 0)
		return rc < 0 ? rc : 0;

	installer_add_publisher_argv(&ctx->opts, argv);
	rc = run_capture(argv, out, sizeof(out));
	if (rc != 0) {
		ui_text(&ctx->ui, "Recording the publisher in %s failed:\n%s",
			PATH_LOTA_CONF, out);
		return rc > 0 ? -EIO : rc;
	}
	ui_text(&ctx->ui, "Recorded the CA as a publisher in %s, reporting %s.",
		PATH_LOTA_CONF,
		ctx->opts.verifier && ctx->opts.verifier[0] ?
			"continuously to the verifier given" :
			"nothing (no --verifier given)");

	{
		const char *const sv[] = { "systemctl", "show",
					   "-p",	"StatusText",
					   "--value",	"lota-attest.service",
					   NULL };

		/* the self-check waits for a status other than this one */
		if (run_capture(sv, ctx->loop_status_before,
				sizeof(ctx->loop_status_before)) != 0)
			ctx->loop_status_before[0] = '\0';
		ctx->loop_status_before[strcspn(ctx->loop_status_before, "\n")] =
			'\0';
	}
	{
		const char *const rv[] = { "systemctl", "try-reload-or-restart",
					   "lota-agent.service",
					   "lota-attest.service", NULL };

		rc = run_cmd(&ctx->ui, "Reloading the agent", rv);
	}
	return rc == 0 ? 0 : (rc > 0 ? -EIO : rc);
}

static int st_enroll_apply(struct install_ctx *ctx)
{
	const char *argv[12];
	struct profile_paths paths;
	int days = 0;
	int n = 0;
	int rc;

	rc = enroll_profile(ctx, &paths);
	if (rc < 0)
		return rc;

	rc = probe_cert_days_left(paths.aik_cert, &days);
	if (rc == 0 && days >= 0)
		return record_fleet_publisher(ctx);
	if (rc == 0) {
		const char *const rv[] = { PATH_AGENT_BIN,
					   "--reenroll",
					   "--publisher",
					   paths.id,
					   "--ca-cert",
					   ctx->opts.ca_cert,
					   NULL };

		rc = run_cmd(&ctx->ui,
			     "Refreshing the AIK certificate "
			     "(guided re-enrollment)...",
			     rv);
		if (rc != 0)
			return rc > 0 ? -EIO : rc;
		return record_fleet_publisher(ctx);
	}

	argv[n++] = PATH_AGENT_BIN;
	argv[n++] = "--enroll";
	argv[n++] = "--ca-server";
	argv[n++] = ctx->opts.ca_server;
	if (ctx->opts.ca_port) {
		argv[n++] = "--ca-port";
		argv[n++] = ctx->opts.ca_port;
	}
	argv[n++] = "--ca-cert";
	argv[n++] = ctx->opts.ca_cert;
	argv[n] = NULL;

	rc = run_cmd(&ctx->ui,
		     "Enrolling with the attestation CA "
		     "(TPM credential activation)...",
		     argv);
	if (rc != 0)
		return rc > 0 ? -EIO : rc;
	return record_fleet_publisher(ctx);
}

/* covers the first round's retries to a fresh profile */
#define SELFCHECK_LOOP_WAIT_SEC 90
#define SELFCHECK_LOOP_POLL_SEC 2

int installer_loop_reports_expected(const char *conf_path)
{
	const size_t cap = 16384;
	char *conf = calloc(1, cap);
	int rc;

	if (!conf)
		return -ENOMEM;
	rc = probe_read_text(conf_path, conf, cap);
	if (rc >= 0)
		rc = probe_conf_buf_continuous_count(conf);
	else if (rc == -ENOENT)
		rc = 0;
	free(conf);
	return rc < 0 ? rc : rc > 1 ? rc : 1;
}

static int wait_for_loop_report(struct install_ctx *ctx)
{
	const char *const argv[] = { "systemctl", "show",
				     "-p",	  "StatusText",
				     "--value",	  "lota-attest.service",
				     NULL };
	char status[512] = { 0 };
	int expected = installer_loop_reports_expected(PATH_LOTA_CONF);

	if (expected < 0) {
		ui_text(&ctx->ui, "Cannot read %s (%s)", PATH_LOTA_CONF,
			strerror(-expected));
		return expected;
	}

	ui_text(&ctx->ui,
		"Waiting up to %d s for the attestation loop to report to the "
		"fleet's verifier.",
		SELFCHECK_LOOP_WAIT_SEC);

	for (int waited = 0;; waited += SELFCHECK_LOOP_POLL_SEC) {
		if (run_capture(argv, status, sizeof(status)) == 0) {
			status[strcspn(status, "\n")] = '\0';
			if (probe_attest_status_covers(status,
						       ctx->loop_status_before,
						       expected)) {
				ui_kv(&ctx->ui, "Attestation loop", status);
				return 0;
			}
		}
		if (waited >= SELFCHECK_LOOP_WAIT_SEC)
			break;
		if (ctx->ui.sink && ctx->ui.sink->abort &&
		    ctx->ui.sink->abort(ctx->ui.sink->ud))
			break;
		sleep(SELFCHECK_LOOP_POLL_SEC);
	}

	ui_kv(&ctx->ui, "Attestation loop",
	      status[0] ? status : "no status reported");
	ui_text(&ctx->ui, "The loop has not attested to the fleet's verifier. "
			  "journalctl -u lota-attest -b says why.");
	return -1;
}

const char install_telemetry_summary[] =
	"Every attestation report sent to the operator's verifier "
	"contains:\n"
	"  - TPM PCR values and a TPM-signed quote over them\n"
	"  - AIK public key and AIK certificate, whose subject is the "
	"device pseudonym the attestation CA issued\n"
	"  - Agent hash, kernel measurement digest and the kernel path\n"
	"  - IOMMU state\n"
	"  - Security state flags: TPM quote, IOMMU, boot measurement, Secure "
	"Boot, kernel lockdown, module signatures, IMA appraisal, PCR 14 boot "
	"commitment and initramfs lock, whether the agent's LSM is loaded and "
	"enforcing, which of its mmap, exec, module, anonymous-exec and "
	"ptrace rules are on, bench mode and lost events\n"
	"  - Boot event log (firmware and bootloader measurements, "
	"including the kernel command line, which carries disk UUIDs)\n"
	"  - ESRT system firmware entry, or a mark that the platform has none\n"
	"  - Shim MOK list, empty when it cannot be read\n"
	"During enrollment only, the attestation CA (never the verifier) "
	"additionally receives the TPM's EK certificate to prove the TPM "
	"is genuine.\n"
	"No file contents, no browsing or account data leave this "
	"machine.";

enum stage_state install_selfcheck_probe(struct install_ctx *ctx, char *note,
					 size_t cap)
{
	struct probe_floor st;
	struct profile_paths paths;
	int days = 0;
	int rc;

	booted_floor(&st);
	if (!(st.ima_ok && st.sig_ok && st.lockdown_ok)) {
		snprintf(note, cap,
			 "Not ready: the kernel integrity floor is not "
			 "satisfied, so the self-check would fail. The floor "
			 "stages above say which part of it.");
		return STAGE_PENDING;
	}
	if (!agent_service_active()) {
		snprintf(note, cap,
			 "Not ready: lota-agent.service is not running, so "
			 "this host is not attesting.");
		return STAGE_PENDING;
	}

	rc = enroll_profile(ctx, &paths);
	if (rc == -EINVAL) {
		snprintf(note, cap,
			 "Ready: floor satisfied, service running, and no "
			 "publisher named yet - the "
			 "certificate arrives when a title first asks. The "
			 "attestation round-trip runs during an install; this "
			 "report performs nothing.");
		return STAGE_DONE;
	}
	if (rc == 0)
		rc = probe_cert_days_left(paths.aik_cert, &days);
	if (rc != 0) {
		snprintf(note, cap,
			 "Not ready: no valid AIK certificate for the CA "
			 "anchor named here, so the round-trip the self-check "
			 "runs would have nothing to present.");
		return STAGE_PENDING;
	}

	snprintf(note, cap,
		 "Ready: floor satisfied, service running, AIK "
		 "certificate valid (%s). The attestation "
		 "round-trip runs during an install; this report performs "
		 "nothing.",
		 days > 0 ? "a day or more left" : "less than a day left");
	return STAGE_DONE;
}

int install_self_check(struct install_ctx *ctx)
{
	struct probe_floor st;
	struct profile_paths paths;
	int days = 0;
	int ok = 1;
	int profiles;
	int rc_cert;
	bool fleet;

	ui_stage_begin(&ctx->ui, install_step_count, install_step_count,
		       install_selfcheck_title);

	booted_floor(&st);
	{
		int floor_ok = st.ima_ok && st.sig_ok && st.lockdown_ok;

		ui_kv(&ctx->ui, "Kernel integrity floor",
		      floor_ok && !st.appraised ?
			      "Satisfied (no exec appraisal LOTA counts; every "
			      "token says so)" :
		      floor_ok ? "Satisfied" :
				 "NOT satisfied");
		if (!floor_ok)
			ok = 0;
	}

	ui_kv(&ctx->ui, "agent service",
	      agent_service_active() ? "Active" : "NOT active");
	if (!agent_service_active())
		ok = 0;

	rc_cert = enroll_profile(ctx, &paths);
	if (rc_cert == -EINVAL) {
		ui_kv(&ctx->ui, "AIK certificate",
		      "None yet (enrolled when a title first asks)");
		goto after_cert;
	}
	if (rc_cert == 0)
		rc_cert = probe_cert_days_left(paths.aik_cert, &days);
	if (rc_cert == 0 && days > 0) {
		char buf[64];

		snprintf(buf, sizeof(buf), "Valid, %d day%s left", days,
			 days == 1 ? "" : "s");
		ui_kv(&ctx->ui, "AIK certificate", buf);
	} else if (rc_cert == 0 && days == 0) {
		ui_kv(&ctx->ui, "AIK certificate",
		      "Valid, less than a day left");
	} else {
		ui_kv(&ctx->ui, "AIK certificate", "NOT valid");
		ok = 0;
	}

after_cert:

	ui_kv(&ctx->ui, "Firmware version reporting (ESRT)",
	      probe_esrt_system_firmware_present() ?
		      "present (firmware re-anchor uses the strong path)" :
		      "absent (firmware re-anchor is low-assurance; the first "
		      "one needs operator approval)");

	profiles = probe_conf_profile_count(PATH_LOTA_CONF);
	if (profiles < 0 && profiles != -ENOENT) {
		char why[128];

		snprintf(why, sizeof(why), "NOT readable: %s",
			 strerror(-profiles));
		ui_kv(&ctx->ui, PATH_LOTA_CONF, why);
		ok = 0;
	}
	if (profiles < 0)
		profiles = 0;

	fleet = false;
	if (ctx->opts.ca_server && ctx->opts.ca_cert) {
		int rec = installer_profile_recorded(PATH_LOTA_CONF,
						     ctx->opts.ca_cert);

		if (rec < 0) {
			ui_kv(&ctx->ui, "Fleet publisher", "NOT readable");
			ok = 0;
		}
		fleet = rec == 1;
	}

	switch (probe_selfcheck_plan(ctx->opts.verifier, profiles, fleet)) {
	case SELFCHECK_LOOP_REPORTS:
		if (wait_for_loop_report(ctx) != 0)
			ok = 0;
		break;
	case SELFCHECK_ONE_ROUND: {
		const char *argv[10];
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
		if (ctx->opts.ca_cert) {
			argv[n++] = "--ca-cert";
			argv[n++] = ctx->opts.ca_cert;
		}
		argv[n] = NULL;

		rc = run_cmd(&ctx->ui,
			     "Attestation round-trip against the "
			     "operator verifier.",
			     argv);
		if (rc != 0)
			ok = 0;
		break;
	}
	case SELFCHECK_PUBLISHERS_REPORT:
		ui_text(&ctx->ui,
			"Attestation round-trip belongs to the %d publisher(s) "
			"this host answers to: they are the agent's target "
			"list, each with its own verifier and cadence, so no "
			"single verifier stands for them. A publisher whose "
			"titles gate on a session is reported to when one of "
			"their titles runs. %slota-agent --list-publishers "
			"says who they are.",
			profiles,
			ctx->opts.verifier ?
				"The --verifier given here is not used for "
				"that reason. " :
				"");
		break;
	case SELFCHECK_SKIP_NO_VERIFIER:
		ui_text(&ctx->ui, "Attestation round-trip skipped (no "
				  "--verifier given). First game launch "
				  "performs it.");
		break;
	}

	ui_explain(&ctx->ui, install_telemetry_summary);
	return ok ? 0 : -1;
}

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

int install_unattended_checkpoint(char *buf, size_t cap, const int *deferred,
				  int n)
{
	char left[1024] = "";
	size_t used = 0;
	int i;

	for (i = 0; i < n && used < sizeof(left); i++) {
		const char *sep = i == 0 ? "" : i == n - 1 ? " and " : ", ";
		int w = snprintf(left + used, sizeof(left) - used, "%s'%s'",
				 sep, install_stages[deferred[i]].title);

		if (w < 0)
			break;
		used += (size_t)w;
	}

	snprintf(buf, cap,
		 "Host-local setup is done. What is left changes how this "
		 "machine boots, so it waits for a person: %s. Run "
		 "'sudo lota-install' to finish %s. To have a package install "
		 "do it too, create %s (or set LOTA_AUTO_BRINGUP=1) before "
		 "installing.",
		 left, n == 1 ? "it" : "them", PATH_AUTO_BRINGUP);
	return EXIT_INSTALL_DEFERRED;
}

void install_reboot_required(char *buf, size_t cap, const char *note)
{
	size_t len = note ? strlen(note) : 0;
	int stop = len && strchr(".!?", note[len - 1]);

	snprintf(buf, cap,
		 "Reboot is required before the install can continue: %s%s",
		 note ? note : "", stop ? "" : ".");
}

enum ui_result install_stage_result(enum stage_state st, int applied)
{
	switch (st) {
	case STAGE_DONE:
		return applied ? UI_APPLIED : UI_DONE;
	case STAGE_REBOOT:
		return UI_REBOOT;
	case STAGE_SKIP:
		return UI_SKIP;
	case STAGE_PENDING:
		return UI_PENDING;
	case STAGE_BLOCKED:
		return UI_BLOCKED;
	case STAGE_ERROR:
	default:
		return UI_FAIL;
	}
}

enum stage_state install_stage_after_apply(const struct stage *s,
					   const struct install_ctx *ctx,
					   enum stage_state st)
{
	if (st == STAGE_PENDING && s->boot_path && ctx->reboot_needed)
		return STAGE_REBOOT;
	return st;
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
		.title = "Enforcement trust material",
		.explain =
			"The agent only loads a BPF enforcement object it can "
			"verify. Enforcement is host-owned -- one kernel, one "
			"LSM -- so the object is signed by whoever built the "
			"agent package, never by a game publisher.\n"
			"This step records the public key location in "
			"/etc/lota/lota.conf so the agent knows what to verify against."
			" Nothing is downloaded and no key is generated on this machine.",
		.probe = st_trust_probe,
		.apply = st_trust_apply,
	},
	{
		.title = "Boot-time PCR14 lock in the initramfs",
		.explain =
			"LOTA pins TPM PCR 14 very early in boot (inside the "
			"initramfs, before any regular userspace runs) so nothing "
			"can pre-poison the agent's measurement slot. "
			"This step regenerates the initramfs of every installed kernel "
			"with dracut to include the lock helper, matching the next "
			"step's scope: a kernel you can select in the boot menu and that "
			"has no lock boots a machine with no commitment. It rewrites "
			"/boot/initramfs-*.img - the standard file every kernel update "
			"also rewrites - and requires a reboot to take effect. A kernel "
			"installed later picks the helper up from the packaged dracut "
			"module on its own; an upgrade of the helper reaches "
			"an existing initramfs only through this step.",
		.probe = st_initrd_probe,
		.apply = st_initrd_apply,
		.boot_path = 1,
	},
	{
		.title = "Kernel integrity floor on the cmdline",
		.explain =
			"The agent refuses to start unless the kernel enforces "
			"signed kernel modules and lockdown. IMA appraisal in "
			"enforce mode lets a token say KERNEL_APPRAISAL; "
			"without it the agent starts with a warning. "
			"This step appends the missing parameters to the boot "
			"entries via grubby, ima_appraise=enforce only while "
			"the loaded IMA policy has no appraise rule. They "
			"appear in /etc/default/grub and take effect on the "
			"next boot. "
			"Removing them restores the previous behaviour.",
		.probe = st_cmdline_probe,
		.apply = st_cmdline_apply,
		.boot_path = 1,
	},
	{
		.title = "IMA appraisal scope",
		.explain =
			"The previous step set the appraisal *mode*; the "
			"kernel applies that mode only to the rules its "
			"loaded IMA policy carries. Tokens say "
			"KERNEL_APPRAISAL only for an appraise rule on "
			"BPRM_CHECK or one without func=; other rules, such "
			"as MMAP_CHECK, are not counted.\n"
			"This step reads the loaded policy and reports "
			"whether such a rule is there.\n"
			"It loads no rules: an IMA rule cannot name a "
			"path, so the rule that appraises the agent appraises "
			"every executable it matches, and on a Secure Boot "
			"host that happens in enforce whatever the cmdline "
			"asked for -- a host whose files carry no signature "
			"would refuse them all at the next boot. The scope "
			"arrives with the signatures, from IMA-signed "
			"distribution packages or an operator image "
			"pipeline.",
		.probe = st_ima_scope_probe,
	},
	{
		.title = "SELinux fence on the TPM device",
		.explain =
			"udev rule labels /dev/tpm* with a LOTA-specific SELinux "
			"type so only the agent's domain (and root tooling) can "
			"talk to the TPM directly. "
			"This step loads the LOTA SELinux policy module if needed, "
			"re-triggers udev with an add event -- a change event "
			"re-applies no SECLABEL -- and restores the labels on the "
			"agent binary, the state directory and the config "
			"directory. It does not change the SELinux mode "
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
			"socket). "
			"The agent loads the signed BPF enforcement object, "
			"measures itself into PCR 14 and exposes a local "
			"socket games use to request attestation tokens. "
			"Note: a running agent cannot be killed, by design - pausing it is "
			"done with 'lota-agent --shutdown' and resuming requires a "
			"reboot.",
		.probe = st_agent_probe,
		.apply = st_agent_apply,
	},
	{
		.title = "Enrollment with a publisher's attestation CA",
		.explain =
			"TPM proves to a publisher's CA that it is a genuine "
			"hardware TPM (credential activation) and receives a "
			"short-lived certificate for its attestation key.\n"
			"The CA sees the TPM's endorsement key certificate once, during "
			"this step.\nGame servers only ever see a pseudonym.\n"
			"Each publisher gets its own key and certificate, under "
			"/var/lib/lota/profiles/.\n"
			"Naming a CA here enrolls with it now; naming none leaves it "
			"to the agent, which enrolls the first time a title asks for "
			"a publisher.",
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

_Static_assert(sizeof(install_stages) / sizeof(install_stages[0]) <=
		       INSTALL_MAX_TUI_STAGES,
	       "the stage table outgrew the interactive view's rows");

const char install_selfcheck_title[] = "Self-check & summary";

const int install_step_count =
	(int)(sizeof(install_stages) / sizeof(install_stages[0])) + 1;
