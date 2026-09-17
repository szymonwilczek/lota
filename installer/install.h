/* SPDX-License-Identifier: MIT
 * Copyright (C) 2026 Szymon Wilczek
 *
 * lota-install - Guided, reboot-resumable Player Install
 *
 * Installer never trusts a state file for progress:
 * every stage owns a probe over live system state (installed files, fs-verity
 * bit, initramfs content, kernel cmdline, PCR14, certificate validity),
 * so a re-run after the mid-install reboot resumes at the first unmet stage
 * automatically.
 *
 * Stages that change the system print what is about to happen, why it is needed
 * and what it changes BEFORE asking for confirmation.
 */

#ifndef LOTA_INSTALL_H
#define LOTA_INSTALL_H

#include <stddef.h>

#include "ui.h"

/* Exit codes */
#define EXIT_INSTALL_OK 0
#define EXIT_INSTALL_FAIL 1
#define EXIT_INSTALL_USAGE 2
#define EXIT_INSTALL_REBOOT 10 /* re-run after reboot to resume */

/* Well-known artifact paths laid down by the LOTA package */
#define PATH_AGENT_BIN "/usr/bin/lota-agent"
#define PATH_BPF_OBJ "/usr/lib/lota/lota_lsm.bpf.o"
#define PATH_LOCK_HELPER "/usr/lib/lota/lota-pcr14-lock"
#define PATH_AGENT_UNIT "/usr/lib/systemd/system/lota-agent.service"
#define PATH_AGENT_SOCKET "/usr/lib/systemd/system/lota-agent.socket"
#define PATH_UDEV_RULE "/usr/lib/udev/rules.d/99-lota-tpm.rules"
#define PATH_DRACUT_MODULE "/usr/lib/dracut/modules.d/90lota/module-setup.sh"
#define PATH_LOTA_CONF_DIR "/etc/lota"
#define PATH_LOTA_CONF "/etc/lota/lota.conf"

/*
 * Enforcement key paths, in the order the agent resolves them:
 * fleet that signs enforcement itself owns the /etc file,
 * and the package owns the other.
 */
#define PATH_POLICY_PUB_OVERRIDE "/etc/lota/policy.pub"
#define PATH_ENFORCEMENT_PUB "/usr/lib/lota/enforcement.pub"
#define PATH_LOTA_STATE_DIR "/var/lib/lota"

/* Presence opts this host into unattended boot-path bring-up */
#define PATH_AUTO_BRINGUP "/etc/lota/auto-bringup"
#define PATH_SELINUX_PP_DEFAULT "/usr/share/lota/selinux/lota.pp"

struct install_opts {
	const char *ca_server; /* Attestation CA host (enrollment) */
	const char *ca_port; /* Attestation CA port */
	const char *ca_cert; /* CA TLS certificate (PEM) */
	const char *verifier; /* Verifier host for the self-check */
	const char *verifier_port; /* Verifier port */
	const char *policy_pubkey; /* Key named with --policy-pubkey, or NULL */
	const char *selinux_module; /* Compiled lota.pp policy package */
	/*
	 * Whether selinux_module above is the operator's word
	 * or the built-in default.
	 */
	int selinux_module_named;
	int yes; /* Skip confirmations */
	int plain; /* Force non-TUI output */
	int status_only; /* Probe + report, change nothing */
	int pause; /* Graceful agent shutdown, then stop */
	int resume; /* Explain that resume means a reboot */
	/*
	 * Driven by package post-install hook rather than by person:
	 * never prompts, never touches the boot path unless the host opted in,
	 * and stops at the reboot checkpoint.
	 */
	int unattended;
	/*
	 * Enable fs-verity on every object named by a runtime manifest,
	 * then stop.
	 * Title's own binaries are what its publisher can make measurable,
	 * and this is the step that does it.
	 */
	const char *verity_manifest;
};

/* Has this host opted into unattended boot-path changes?
 * Reads /etc/lota/auto-bringup and $LOTA_AUTO_BRINGUP. */
int install_auto_bringup_opted_in(void);

struct install_ctx {
	struct install_opts opts;
	struct ui ui;
	int reboot_needed; /* finished stage requires a reboot */
	/* a stage changed this host during this run, so state read from before it
	 * no longer describes what the host would do now */
	int applied;
};

/* Probe verdict for one stage */
enum stage_state {
	STAGE_DONE = 0, /* satisfied, nothing to do */
	STAGE_PENDING, /* apply() can satisfy it now */
	STAGE_REBOOT, /* satisfied only after a reboot */
	STAGE_BLOCKED, /* needs an action the installer must not take */
	STAGE_SKIP, /* not applicable on this host */
	STAGE_ERROR, /* the probe itself failed */
};

/* Holds the longest note stage produces:
 * the Secure-Boot remediation, which names the setting, the route into this
 * machine's firmware setup and what enabling it does not break */
#define STAGE_NOTE_CAP 1024

struct stage {
	const char *title;
	/* printed before the confirmation of a pending stage */
	const char *explain;
	/* fills note with a reason for the returned state */
	enum stage_state (*probe)(struct install_ctx *ctx, char *note,
				  size_t cap);
	/* 0 on success; the engine re-probes afterwards */
	int (*apply)(struct install_ctx *ctx);
	/* reboot checkpoint:
	 * REBOOT verdict stops the run (exit 10) instead of deferring to
	 * a later checkpoint */
	int barrier;
	/*
	 * Rewrites how this machine boots:
	 * the initramfs, or the kernel command line.
	 * Unattended run leaves these alone unless the host asked for them,
	 * because package install that changes the boot path of machine nobody
	 * was sitting at is how player ends up with system that does not come
	 * back the way it went down.
	 */
	int boot_path;
};

/* where the enforcement object's verification key comes from */
enum trust_key_source {
	TRUST_KEY_NONE = 0, /* nothing readable anywhere */
	TRUST_KEY_NAMED, /* --policy-pubkey */
	TRUST_KEY_CONFIGURED, /* policy_pubkey in lota.conf */
	TRUST_KEY_OVERRIDE, /* the operator's own key on disk */
	TRUST_KEY_PACKAGED, /* the key the agent package shipped */
};

/*
 * installer_trust_key - which key the enforcement check will name
 *
 * @named:         --policy-pubkey path, or NULL.
 * @conf_pubkey:   policy_pubkey from the configuration, or NULL.
 * @override_path: operator-owned key no package owns.
 * @packaged_path: key shipped beside the object.
 * @src:           set to the source of the returned path; may be NULL.
 *
 * Paths are parameters so tests need not touch /usr or /etc.
 */
const char *installer_trust_key(const char *named, const char *conf_pubkey,
				const char *override_path,
				const char *packaged_path,
				enum trust_key_source *src);

/* human-readable @src */
const char *installer_trust_key_source_says(enum trust_key_source src);

/*
 * installer_trust_fallback - the key the agent resolves once @key is gone
 *
 * @key:           the key installer_trust_key() returned.
 * @src:           where it came from.
 * @conf_pubkey, @override_path, @packaged_path: as for installer_trust_key().
 *
 * Returns NULL when nothing else would verify the object in its place.
 */
const char *installer_trust_fallback(const char *key, enum trust_key_source src,
				     const char *conf_pubkey,
				     const char *override_path,
				     const char *packaged_path);

/*
 * installer_trust_refusal - the note for an object @key does not verify
 *
 * @fallback: what installer_trust_fallback() returned.
 * @obj:      the enforcement object.
 */
void installer_trust_refusal(char *buf, size_t cap, const char *key,
			     enum trust_key_source src, const char *fallback,
			     const char *obj);

/* Stage table (stages.c); barrier_index marks the reboot checkpoint */
extern const struct stage install_stages[];
extern const int install_stage_count;

/* stage rows the TUI can show; stages.c asserts the table fits */
#define INSTALL_MAX_TUI_STAGES 32

/* Self-check: the last step of every run, outside the stage table;
 * install_step_count includes it */
extern const char install_selfcheck_title[];
extern const int install_step_count;

/* Read-only self-check for --status: floor, agent binary,
 * service and certificate; no attestation round-trip */
enum stage_state install_selfcheck_probe(struct install_ctx *ctx, char *note,
					 size_t cap);

/* Final acceptance run + "what leaves this machine" summary.
 * Returns 0 or -1. */
int install_self_check(struct install_ctx *ctx);

#endif /* LOTA_INSTALL_H */
