/* SPDX-License-Identifier: MIT
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
#define PATH_LOTA_CONF "/etc/lota/lota.conf"
#define PATH_POLICY_PUB_DEFAULT "/etc/lota/policy.pub"
#define PATH_AIK_CERT "/var/lib/lota/aik_cert.der"
#define PATH_SELINUX_PP_DEFAULT "/usr/share/lota/selinux/lota.pp"

struct install_opts {
	const char *ca_server;	    /* Attestation CA host (enrollment) */
	const char *ca_port;	    /* Attestation CA port */
	const char *ca_cert;	    /* CA TLS certificate (PEM) */
	const char *verifier;	    /* Verifier host for the self-check */
	const char *verifier_port;  /* Verifier port */
	const char *policy_pubkey;  /* Operator BPF signing public key */
	const char *selinux_module; /* Compiled lota.pp policy package */
	int yes;		    /* Skip confirmations */
	int plain;		    /* Force non-TUI output */
	int status_only;	    /* Probe + report, change nothing */
	int pause;		    /* Graceful agent shutdown, then stop */
	int resume;		    /* Explain that resume means a reboot */
};

struct install_ctx {
	struct install_opts opts;
	struct ui ui;
	int reboot_needed; /* finished stage requires a reboot */
};

/* Probe verdict for one stage */
enum stage_state {
	STAGE_DONE = 0, /* satisfied, nothing to do */
	STAGE_PENDING,	/* apply() can satisfy it now */
	STAGE_REBOOT,	/* satisfied only after a reboot */
	STAGE_BLOCKED,	/* needs an action the installer must not take */
	STAGE_SKIP,	/* not applicable on this host */
	STAGE_ERROR,	/* the probe itself failed */
};

#define STAGE_NOTE_CAP 512

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
};

/* Stage table (stages.c); barrier_index marks the reboot checkpoint */
extern const struct stage install_stages[];
extern const int install_stage_count;

/* Final acceptance run + "what leaves this machine" summary.
 * Returns 0 or -1. */
int install_self_check(struct install_ctx *ctx);

#endif /* LOTA_INSTALL_H */
