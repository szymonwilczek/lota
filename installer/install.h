/* SPDX-License-Identifier: MIT
 * Copyright (C) 2026 Szymon Wilczek
 *
 * lota-install - Guided, reboot-resumable install
 */

#ifndef LOTA_INSTALL_H
#define LOTA_INSTALL_H

#include <stddef.h>

#include "ui.h"

#define EXIT_INSTALL_OK 0
#define EXIT_INSTALL_FAIL 1
#define EXIT_INSTALL_USAGE 2
#define EXIT_INSTALL_REBOOT 10 /* re-run after reboot to resume */
#define EXIT_INSTALL_DEFERRED 11 /* boot-path stages left to a person */

#define PATH_AGENT_BIN "/usr/bin/lota-agent"
#define PATH_BPF_OBJ "/usr/lib/lota/lota_lsm.bpf.o"
#define PATH_LOCK_HELPER "/usr/lib/lota/lota-pcr14-lock"
#define PATH_AGENT_UNIT "/usr/lib/systemd/system/lota-agent.service"
#define PATH_AGENT_SOCKET "/usr/lib/systemd/system/lota-agent.socket"
#define PATH_UDEV_RULE "/usr/lib/udev/rules.d/99-lota-tpm.rules"
#define PATH_DRACUT_MODULE "/usr/lib/dracut/modules.d/90lota/module-setup.sh"
#define PATH_LOTA_CONF_DIR "/etc/lota"
#define PATH_LOTA_CONF "/etc/lota/lota.conf"

#define PATH_POLICY_PUB_OVERRIDE "/etc/lota/policy.pub"
#define PATH_ENFORCEMENT_PUB "/usr/lib/lota/enforcement.pub"
#define PATH_LOTA_STATE_DIR "/var/lib/lota"

/* present: unattended runs may change the boot path */
#define PATH_AUTO_BRINGUP "/etc/lota/auto-bringup"
#define PATH_SELINUX_PP_DEFAULT "/usr/share/lota/selinux/lota.pp"

struct install_opts {
	const char *ca_server;
	const char *ca_port;
	const char *ca_cert;
	const char *verifier;
	const char *verifier_port;
	const char *policy_pubkey; /* NULL unless --policy-pubkey */
	const char *selinux_module;
	int selinux_module_named; /* set by --selinux-module */
	int yes;
	int plain;
	int status_only;
	int pause;
	int resume;
	int unattended; /* sets yes and plain */
	const char *verity_manifest;
};

/**
 * install_auto_bringup_opted_in() - Whether unattended runs may change the
 * boot path.
 *
 * Return: 1 when $LOTA_AUTO_BRINGUP is "1" or PATH_AUTO_BRINGUP exists,
 * otherwise 0.
 */
int install_auto_bringup_opted_in(void);

struct install_ctx {
	struct install_opts opts;
	struct ui ui;
	int reboot_needed;
	int applied; /* a stage was applied during this run */
	/* loop status before this run reloaded it; empty if it did not */
	char loop_status_before[256];
};

enum stage_state {
	STAGE_DONE = 0, /* satisfied, nothing to do */
	STAGE_PENDING, /* apply() can satisfy it now */
	STAGE_REBOOT, /* satisfied only after a reboot */
	STAGE_BLOCKED, /* needs an action the installer does not take */
	STAGE_SKIP, /* not applicable on this host */
	STAGE_ERROR, /* the probe itself failed */
};

#define STAGE_NOTE_CAP 1536

struct stage {
	const char *title;
	const char *explain; /* printed before confirming a pending stage */
	enum stage_state (*probe)(struct install_ctx *ctx, char *note,
				  size_t cap);
	int (*apply)(struct install_ctx *ctx); /* 0 on success; re-probed */
	int barrier; /* REBOOT here ends the run with EXIT_INSTALL_REBOOT */
	int boot_path; /* changes the initramfs or the kernel command line */
};

enum trust_key_source {
	TRUST_KEY_NONE = 0, /* nothing readable */
	TRUST_KEY_NAMED, /* --policy-pubkey */
	TRUST_KEY_CONFIGURED, /* policy_pubkey in lota.conf */
	TRUST_KEY_OVERRIDE, /* PATH_POLICY_PUB_OVERRIDE */
	TRUST_KEY_PACKAGED, /* PATH_ENFORCEMENT_PUB */
};

/**
 * installer_profile_recorded() - Whether lota.conf has a profile for a
 * publisher.
 * @conf_path: configuration file.
 * @anchor:    the publisher's CA certificate.
 *
 * A profile matches when its ca_cert resolves to the same profile id as
 * @anchor, whatever its path.
 *
 * Return: 1 when a profile matches; 0 when none does, @conf_path does not
 * exist or @anchor resolves to no profile id; otherwise -errno (-EFBIG for
 * a file too large to read whole).
 */
int installer_profile_recorded(const char *conf_path, const char *anchor);

/**
 * installer_loop_reports_expected() - Reports one attestation round sends.
 * @conf_path: the configuration.
 *
 * Return: the profiles that report continuously, at least 1, or -errno for
 * a configuration that exists and cannot be read whole.
 */
int installer_loop_reports_expected(const char *conf_path);

#define INSTALLER_ADD_PUBLISHER_ARGC 14 /* terminator included */

/**
 * installer_add_publisher_argv() - Build the lota-agent --add-publisher argv.
 * @o:    install options.
 * @argv: filled with a NULL-terminated argv.
 *
 * The publisher reports continuously. --server and --port are passed only
 * when @o names a verifier.
 */
void installer_add_publisher_argv(
	const struct install_opts *o,
	const char *argv[INSTALLER_ADD_PUBLISHER_ARGC]);

/**
 * installer_trust_key() - Key the agent will verify the enforcement object
 * against.
 * @named:         --policy-pubkey path, or NULL.
 * @conf_pubkey:   policy_pubkey from the configuration, or NULL.
 * @override_path: operator-owned key.
 * @packaged_path: key shipped beside the object.
 * @src:           set to the source of the returned path; may be NULL.
 *
 * @named is returned without checking that it is readable. Otherwise the
 * first readable of @conf_pubkey, @override_path and @packaged_path.
 *
 * Return: the key path, or NULL when none is readable.
 */
const char *installer_trust_key(const char *named, const char *conf_pubkey,
				const char *override_path,
				const char *packaged_path,
				enum trust_key_source *src);

/**
 * installer_trust_key_source_says() - Describe a key source.
 * @src: the source.
 *
 * Return: a static phrase.
 */
const char *installer_trust_key_source_says(enum trust_key_source src);

/**
 * installer_trust_fallback() - Key the agent resolves without @src.
 * @key:           the key installer_trust_key() returned.
 * @src:           where it came from.
 * @conf_pubkey:   as for installer_trust_key().
 * @override_path: as for installer_trust_key().
 * @packaged_path: as for installer_trust_key().
 *
 * Return: the next readable key in resolution order, or NULL when @src is
 * TRUST_KEY_PACKAGED or TRUST_KEY_NONE, when none is readable, or when it
 * is the same file as @key.
 */
const char *installer_trust_fallback(const char *key, enum trust_key_source src,
				     const char *conf_pubkey,
				     const char *override_path,
				     const char *packaged_path);

/**
 * installer_conf_pubkey() - policy_pubkey line of a configuration file.
 * @conf_path: the file, read with the agent's parser.
 * @key:       set to the path the last line in either spelling names,
 *             readable or not.
 * @cap:       size of @key.
 *
 * Return: 1 with @key set, 0 when the file or the line is missing,
 * or the -errno of a file the agent fails to start on; the parser names
 * each refused line on stderr.
 */
int installer_conf_pubkey(const char *conf_path, char *key, size_t cap);

/**
 * installer_trust_named() - State of the trust stage with --policy-pubkey.
 * @named:         the --policy-pubkey path; its signature verifies.
 * @conf_pubkey:   as for installer_trust_key().
 * @override_path: as for installer_trust_key().
 * @packaged_path: as for installer_trust_key().
 * @note:          set to what the stage reports.
 * @cap:           size of @note.
 *
 * Return: STAGE_DONE when @conf_pubkey is the same file as @named,
 * otherwise STAGE_PENDING with the key the agent verifies against until then.
 */
enum stage_state installer_trust_named(const char *named,
				       const char *conf_pubkey,
				       const char *override_path,
				       const char *packaged_path, char *note,
				       size_t cap);

/**
 * installer_trust_refusal() - Note for an object @key does not verify.
 * @buf:      output buffer.
 * @cap:      size of @buf.
 * @key:      the key that failed.
 * @src:      where @key came from.
 * @fallback: what installer_trust_fallback() returned.
 * @obj:      the enforcement object.
 */
void installer_trust_refusal(char *buf, size_t cap, const char *key,
			     enum trust_key_source src, const char *fallback,
			     const char *obj);

/**
 * install_unattended_checkpoint() - Message an unattended run stops with.
 * @buf:      output buffer.
 * @cap:      size of @buf.
 * @deferred: indices into install_stages[] left to a person.
 * @n:        number of entries in @deferred.
 *
 * Return: EXIT_INSTALL_DEFERRED.
 */
int install_unattended_checkpoint(char *buf, size_t cap, const int *deferred,
				  int n);

/**
 * install_reboot_required() - Sentence a run that stops for a reboot opens
 * with.
 * @buf:  output buffer.
 * @cap:  size of @buf.
 * @note: reason given by the stage that asked for the reboot; may be NULL.
 */
void install_reboot_required(char *buf, size_t cap, const char *note);

/**
 * install_stage_result() - Outcome a stage reports.
 * @st:      the stage's latest probe verdict.
 * @applied: 1 when this run applied the stage before that probe.
 *
 * Return: UI_APPLIED for STAGE_DONE with @applied, otherwise the result
 * matching @st.
 */
enum ui_result install_stage_result(enum stage_state st, int applied);

/**
 * install_stage_after_apply() - Verdict of a stage probed after its apply.
 * @s:   the stage.
 * @ctx: the run; reboot_needed says the boot chain changed.
 * @st:  the probe verdict.
 *
 * Return: STAGE_REBOOT for a boot-path stage still pending once the boot
 * chain changed, otherwise @st.
 */
enum stage_state install_stage_after_apply(const struct stage *s,
					   const struct install_ctx *ctx,
					   enum stage_state st);

/* what every attestation report carries, as the player is told */
extern const char install_telemetry_summary[];

extern const struct stage install_stages[];
extern const int install_stage_count;

#define INSTALL_MAX_TUI_STAGES 32 /* stages.c asserts the table fits */

/* the self-check runs after install_stages[]; install_step_count counts it */
extern const char install_selfcheck_title[];
extern const int install_step_count;

/**
 * install_selfcheck_probe() - Self-check readiness for --status.
 * @ctx:  install context.
 * @note: filled with the reason for the verdict.
 * @cap:  size of @note.
 *
 * No attestation round-trip.
 *
 * Return: the stage verdict.
 */
enum stage_state install_selfcheck_probe(struct install_ctx *ctx, char *note,
					 size_t cap);

/**
 * install_self_check() - Final self-check of an install run.
 * @ctx: install context.
 *
 * Return: 0 on success, -1 on failure.
 */
int install_self_check(struct install_ctx *ctx);

#endif /* LOTA_INSTALL_H */
