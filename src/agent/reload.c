/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */

#include "reload.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/types.h>
#include <syslog.h>

#include "agent.h"
#include "bpf_loader.h"
#include "cli.h"
#include "journal.h"
#include "main_utils.h"
#include "policy_sign.h"
#include "sdnotify.h"
#include "lota.h"

#ifndef EAUTH
#define EAUTH 80
#endif

static void copy_path(char dst[PATH_MAX], const char *src)
{
	size_t len = strnlen(src, PATH_MAX - 1);
	memcpy(dst, src, len);
	dst[len] = '\0';
}

static int read_fd_all_bytes(int fd, uint8_t **out_buf, size_t *out_len)
{
	int dup_fd;
	uint8_t *buf = NULL;
	size_t used = 0;
	size_t cap = 0;

	if (fd < 0 || !out_buf || !out_len)
		return -EINVAL;

	*out_buf = NULL;
	*out_len = 0;

	dup_fd = dup(fd);
	if (dup_fd < 0)
		return -errno;

	if (lseek(dup_fd, 0, SEEK_SET) < 0) {
		int err = -errno;
		close(dup_fd);
		return err;
	}

	for (;;) {
		uint8_t tmp[4096];
		ssize_t n = read(dup_fd, tmp, sizeof(tmp));

		if (n == 0)
			break;
		if (n < 0) {
			int err = -errno;
			close(dup_fd);
			free(buf);
			return err;
		}

		if (used + (size_t)n > cap) {
			size_t new_cap = cap ? cap * 2 : 4096;
			while (new_cap < used + (size_t)n)
				new_cap *= 2;

			uint8_t *new_buf = realloc(buf, new_cap);
			if (!new_buf) {
				close(dup_fd);
				free(buf);
				return -ENOMEM;
			}
			buf = new_buf;
			cap = new_cap;
		}

		memcpy(buf + used, tmp, (size_t)n);
		used += (size_t)n;
	}

	close(dup_fd);
	*out_buf = buf;
	*out_len = used;
	return 0;
}

static int
verify_reload_downgrade_authorization_fd(int config_fd, const char *config_path,
					 const struct lota_config *cfg)
{
	const char *cfg_path = (config_path && config_path[0]) ?
				       config_path :
				       LOTA_CONFIG_DEFAULT_PATH;
	char *sig_path;
	size_t sig_path_len;
	uint8_t *cfg_data = NULL;
	size_t cfg_len = 0;
	uint8_t sig[POLICY_SIG_SIZE];
	int sig_fd = -1;
	int ret;

	if (!cfg || cfg->policy_pubkey[0] == '\0') {
		lota_err("Refusing ENFORCE mode downgrade on reload: "
			 "policy_pubkey is not "
			 "configured");
		return -EAUTH;
	}

	sig_path_len = strlen(cfg_path) + 5; /* .sig + NUL */
	sig_path = malloc(sig_path_len);
	if (!sig_path)
		return -ENOMEM;

	snprintf(sig_path, sig_path_len, "%s.sig", cfg_path);

	ret = read_fd_all_bytes(config_fd, &cfg_data, &cfg_len);
	if (ret < 0) {
		free(sig_path);
		return ret;
	}

	{
		int open_flags = O_RDONLY | O_CLOEXEC;
#ifdef O_NOFOLLOW
		open_flags |= O_NOFOLLOW;
#endif
		sig_fd = open(sig_path, open_flags);
	}
	if (sig_fd < 0) {
		ret = -errno ? -errno : -ENOENT;
		free(cfg_data);
		free(sig_path);
		return ret;
	}

	{
		ssize_t n = read(sig_fd, sig, sizeof(sig));
		if (n != (ssize_t)sizeof(sig)) {
			close(sig_fd);
			free(cfg_data);
			free(sig_path);
			return -EAUTH;
		}

		{
			uint8_t extra;
			if (read(sig_fd, &extra, 1) != 0) {
				close(sig_fd);
				free(cfg_data);
				free(sig_path);
				return -EAUTH;
			}
		}
	}
	close(sig_fd);

	ret = policy_verify_buffer(cfg_data, cfg_len, cfg->policy_pubkey, sig);
	free(cfg_data);
	free(sig_path);

	if (ret < 0) {
		lota_err("Refusing ENFORCE mode downgrade on reload: config "
			 "signature "
			 "verification failed (%s)",
			 strerror(-ret));
		return ret;
	}

	return 0;
}

static void apply_runtime_flags_transactional(
	const struct lota_config *new_cfg, bool *strict_mmap, bool *strict_exec,
	bool *block_ptrace, bool *strict_modules, bool *block_anon_exec)
{
	bool old_strict_mmap = *strict_mmap;
	bool old_strict_exec = *strict_exec;
	bool old_block_ptrace = *block_ptrace;
	bool old_strict_modules = *strict_modules;
	bool old_block_anon_exec = *block_anon_exec;
	bool runtime_flags_failed = false;

	if (new_cfg->strict_mmap != *strict_mmap) {
		if (bpf_loader_set_config(&g_agent.bpf_ctx,
					  LOTA_CFG_STRICT_MMAP,
					  new_cfg->strict_mmap ? 1 : 0) == 0) {
			*strict_mmap = new_cfg->strict_mmap;
		} else {
			lota_err("Failed to apply strict mmap on reload");
			runtime_flags_failed = true;
		}
	}

	if (!runtime_flags_failed && new_cfg->block_ptrace != *block_ptrace) {
		if (bpf_loader_set_config(&g_agent.bpf_ctx,
					  LOTA_CFG_BLOCK_PTRACE,
					  new_cfg->block_ptrace ? 1 : 0) == 0) {
			*block_ptrace = new_cfg->block_ptrace;
		} else {
			lota_err("Failed to apply block ptrace on reload");
			runtime_flags_failed = true;
		}
	}

	if (!runtime_flags_failed && new_cfg->strict_exec != *strict_exec) {
		if (bpf_loader_set_config(&g_agent.bpf_ctx,
					  LOTA_CFG_STRICT_EXEC,
					  new_cfg->strict_exec ? 1 : 0) == 0) {
			*strict_exec = new_cfg->strict_exec;
		} else {
			lota_err("Failed to apply strict exec on reload");
			runtime_flags_failed = true;
		}
	}

	if (!runtime_flags_failed &&
	    new_cfg->strict_modules != *strict_modules) {
		if (bpf_loader_set_config(
			    &g_agent.bpf_ctx, LOTA_CFG_STRICT_MODULES,
			    new_cfg->strict_modules ? 1 : 0) == 0) {
			*strict_modules = new_cfg->strict_modules;
		} else {
			lota_err("Failed to apply strict modules on reload");
			runtime_flags_failed = true;
		}
	}

	if (!runtime_flags_failed &&
	    new_cfg->block_anon_exec != *block_anon_exec) {
		if (bpf_loader_set_config(
			    &g_agent.bpf_ctx, LOTA_CFG_BLOCK_ANON_EXEC,
			    new_cfg->block_anon_exec ? 1 : 0) == 0) {
			*block_anon_exec = new_cfg->block_anon_exec;
		} else {
			lota_err(
				"Failed to apply block anonymous exec on reload");
			runtime_flags_failed = true;
		}
	}

	if (runtime_flags_failed) {
		if (*strict_mmap != old_strict_mmap) {
			if (bpf_loader_set_config(
				    &g_agent.bpf_ctx, LOTA_CFG_STRICT_MMAP,
				    old_strict_mmap ? 1 : 0) == 0) {
				*strict_mmap = old_strict_mmap;
			} else {
				lota_err("Failed to rollback strict mmap after "
					 "reload error");
			}
		}
		if (*block_ptrace != old_block_ptrace) {
			if (bpf_loader_set_config(
				    &g_agent.bpf_ctx, LOTA_CFG_BLOCK_PTRACE,
				    old_block_ptrace ? 1 : 0) == 0) {
				*block_ptrace = old_block_ptrace;
			} else {
				lota_err("Failed to rollback block ptrace "
					 "after reload error");
			}
		}
		if (*strict_exec != old_strict_exec) {
			if (bpf_loader_set_config(
				    &g_agent.bpf_ctx, LOTA_CFG_STRICT_EXEC,
				    old_strict_exec ? 1 : 0) == 0) {
				*strict_exec = old_strict_exec;
			} else {
				lota_err("Failed to rollback strict exec after "
					 "reload error");
			}
		}
		if (*strict_modules != old_strict_modules) {
			if (bpf_loader_set_config(
				    &g_agent.bpf_ctx, LOTA_CFG_STRICT_MODULES,
				    old_strict_modules ? 1 : 0) == 0) {
				*strict_modules = old_strict_modules;
			} else {
				lota_err("Failed to rollback strict modules "
					 "after reload error");
			}
		}
		if (*block_anon_exec != old_block_anon_exec) {
			if (bpf_loader_set_config(
				    &g_agent.bpf_ctx, LOTA_CFG_BLOCK_ANON_EXEC,
				    old_block_anon_exec ? 1 : 0) == 0) {
				*block_anon_exec = old_block_anon_exec;
			} else {
				lota_err("Failed to rollback block anonymous "
					 "exec after reload error");
			}
		}
		lota_warn("Keeping previous runtime enforcement flags after "
			  "reload errors");
		return;
	}

	if (*strict_mmap != old_strict_mmap)
		lota_info("Strict mmap: %s", *strict_mmap ? "ON" : "OFF");
	if (*strict_exec != old_strict_exec)
		lota_info("Strict exec: %s", *strict_exec ? "ON" : "OFF");
	if (*block_ptrace != old_block_ptrace)
		lota_info("Block ptrace: %s", *block_ptrace ? "ON" : "OFF");
	if (*strict_modules != old_strict_modules)
		lota_info("Strict modules: %s", *strict_modules ? "ON" : "OFF");
	if (*block_anon_exec != old_block_anon_exec)
		lota_info("Block anonymous exec: %s",
			  *block_anon_exec ? "ON" : "OFF");
}

/*
 * Keep the enforcement switches the command line turned on.
 *
 * All five flags only enable, and the reload below applies whatever the file says
 * -- whose defaults leave strict_exec and strict_modules off.
 * So a switch an operator passed as an argument would be withdrawn by a reload
 * that merely inherited a default, and the daemon cannot be restarted to read
 * its own command line again.
 *
 * A switch the command line did not pass is untouched here, so the file still
 * decides everything nobody asked for by hand.
 */
static void keep_command_line_switches(struct lota_config *new_cfg)
{
	static const struct {
		uint32_t bit;
		const char *name;
		size_t offset;
	} switches[] = {
		{ LOTA_CLI_SWITCH_STRICT_MMAP, "strict_mmap",
		  offsetof(struct lota_config, strict_mmap) },
		{ LOTA_CLI_SWITCH_STRICT_EXEC, "strict_exec",
		  offsetof(struct lota_config, strict_exec) },
		{ LOTA_CLI_SWITCH_BLOCK_PTRACE, "block_ptrace",
		  offsetof(struct lota_config, block_ptrace) },
		{ LOTA_CLI_SWITCH_STRICT_MODULES, "strict_modules",
		  offsetof(struct lota_config, strict_modules) },
		{ LOTA_CLI_SWITCH_BLOCK_ANON_EXEC, "block_anon_exec",
		  offsetof(struct lota_config, block_anon_exec) },
	};
	uint32_t mask = cli_startup_switch_mask();

	for (size_t i = 0; i < sizeof(switches) / sizeof(switches[0]); i++) {
		bool *field;

		if (!(mask & switches[i].bit))
			continue;

		field = (bool *)((char *)new_cfg + switches[i].offset);
		if (*field)
			continue;

		lota_info(
			"Reload keeps %s on: the command line asked for it, and the configuration does not",
			switches[i].name);
		*field = true;
	}
}

/*
 * Fold what the command line asked for back into the set the file describes.
 *
 * --trust-lib and --protect-pid are arguments to the running daemon, not entries
 * in the file it re-reads, so a reload built from the file alone revokes them:
 * the trusted-library map empties and lota_sb_mount has no inode left to refuse,
 * which is the substitution it exists to stop. There is no way back short of
 * a cold boot, because the agent burns its boot commitment when it stops.
 *
 * Merging here rather than inside the two reload paths keeps their rollback
 * intact and makes the counts they report the real totals.
 *
 * The file still owns what the file says: an entry it drops is dropped,
 * unless the command line asked for that one too.
 */
static void merge_command_line_state(struct lota_config *new_cfg)
{
	const char (*cli_libs)[PATH_MAX] = cli_startup_trust_libs();
	const uint32_t *cli_pids = cli_startup_protect_pids();
	int cli_lib_count = cli_startup_trust_lib_count();
	int cli_pid_count = cli_startup_protect_pid_count();
	int kept_libs = 0;
	int kept_pids = 0;

	for (int i = 0; i < cli_lib_count; i++) {
		bool present = false;

		for (int k = 0; k < new_cfg->trust_lib_count; k++) {
			if (strcmp(new_cfg->trust_libs[k], cli_libs[i]) == 0) {
				present = true;
				break;
			}
		}
		if (present)
			continue;

		if (new_cfg->trust_lib_count >= LOTA_CONFIG_MAX_LIBS) {
			lota_warn("No room to keep trusted library %s asked "
				  "for on the command line (max %d)",
				  cli_libs[i], LOTA_CONFIG_MAX_LIBS);
			break;
		}

		copy_path(new_cfg->trust_libs[new_cfg->trust_lib_count],
			  cli_libs[i]);
		new_cfg->trust_lib_count++;
		kept_libs++;
	}

	for (int i = 0; i < cli_pid_count; i++) {
		bool present = false;

		for (int k = 0; k < new_cfg->protect_pid_count; k++) {
			if (new_cfg->protect_pids[k] == cli_pids[i]) {
				present = true;
				break;
			}
		}
		if (present)
			continue;

		if (new_cfg->protect_pid_count >= LOTA_MAX_PROTECTED_PIDS) {
			lota_warn("No room to keep protected PID %u asked for "
				  "on the command line (max %d)",
				  cli_pids[i], LOTA_MAX_PROTECTED_PIDS);
			break;
		}

		new_cfg->protect_pids[new_cfg->protect_pid_count] = cli_pids[i];
		new_cfg->protect_pid_count++;
		kept_pids++;
	}

	if (kept_libs || kept_pids) {
		lota_info(
			"Reload kept what the command line asked for: %d trusted library entr%s, %d protected PID%s",
			kept_libs, kept_libs == 1 ? "y" : "ies", kept_pids,
			kept_pids == 1 ? "" : "s");
	}
}

static void reload_protected_pids(const struct lota_config *new_cfg,
				  uint32_t **protect_pids,
				  int *protect_pid_count)
{
	int old_protect_pid_count = *protect_pid_count;
	uint32_t *old_protect_pids = *protect_pids;

	for (int k = 0; k < old_protect_pid_count; k++)
		bpf_loader_unprotect_pid(&g_agent.bpf_ctx, old_protect_pids[k]);

	if (new_cfg->protect_pid_count > 0) {
		uint32_t *new_pids = malloc((size_t)new_cfg->protect_pid_count *
					    sizeof(uint32_t));
		if (!new_pids) {
			lota_err("Failed to allocate memory for protected PIDs "
				 "on reload; "
				 "restoring previous PID protection set");
			for (int k = 0; k < old_protect_pid_count; k++) {
				if (bpf_loader_protect_pid(
					    &g_agent.bpf_ctx,
					    old_protect_pids[k]) < 0) {
					lota_err("Failed to restore protected "
						 "PID %u after reload "
						 "allocation failure",
						 old_protect_pids[k]);
				}
			}
			return;
		}

		int applied_pids = 0;
		bool apply_failed = false;
		for (int k = 0; k < new_cfg->protect_pid_count; k++) {
			uint32_t pid = new_cfg->protect_pids[k];
			if (bpf_loader_protect_pid(&g_agent.bpf_ctx, pid) < 0) {
				lota_err("Failed to protect PID %u on reload",
					 pid);
				apply_failed = true;
				break;
			}
			new_pids[applied_pids++] = pid;
		}

		if (apply_failed) {
			for (int k = 0; k < applied_pids; k++)
				bpf_loader_unprotect_pid(&g_agent.bpf_ctx,
							 new_pids[k]);
			for (int k = 0; k < old_protect_pid_count; k++) {
				if (bpf_loader_protect_pid(
					    &g_agent.bpf_ctx,
					    old_protect_pids[k]) < 0) {
					lota_err("Failed to restore protected "
						 "PID %u after reload apply "
						 "failure",
						 old_protect_pids[k]);
				}
			}
			free(new_pids);
			lota_warn("Keeping previous protected PID set after "
				  "reload errors");
			return;
		}

		free(old_protect_pids);
		*protect_pids = new_pids;
		*protect_pid_count = applied_pids;
		return;
	}

	free(old_protect_pids);
	*protect_pids = NULL;
	*protect_pid_count = 0;
}

static void reload_trust_libs(const struct lota_config *new_cfg,
			      char trust_libs[LOTA_CONFIG_MAX_LIBS][PATH_MAX],
			      int *trust_lib_count)
{
	int old_trust_lib_count = *trust_lib_count;
	bool trust_reload_failed = false;
	int applied_libs = 0;

	/*
	 * Rollback snapshot is 256 KB, so it is allocated not held in this frame.
	 * Without it there is no way back to the working set, so a failed allocation
	 * leaves the current set alone instead of starting a change it could not undo.
	 */
	char (*old_trust_libs)[PATH_MAX] =
		calloc(LOTA_CONFIG_MAX_LIBS, sizeof(*old_trust_libs));

	if (!old_trust_libs) {
		lota_err("Failed to allocate the trusted-library rollback "
			 "snapshot; keeping the current set");
		return;
	}

	for (int k = 0; k < old_trust_lib_count; k++) {
		copy_path(old_trust_libs[k], trust_libs[k]);
	}

	for (int k = 0; k < old_trust_lib_count; k++) {
		int untrust_ret = bpf_loader_untrust_lib(&g_agent.bpf_ctx,
							 old_trust_libs[k]);
		if (untrust_ret < 0 && untrust_ret != -ENOENT) {
			lota_err(
				"Failed to remove trusted lib %s on reload: %s",
				old_trust_libs[k], strerror(-untrust_ret));
			trust_reload_failed = true;
			break;
		}
	}

	for (int k = 0; !trust_reload_failed && k < new_cfg->trust_lib_count;
	     k++) {
		const char *lib = new_cfg->trust_libs[k];
		int trust_ret = bpf_loader_trust_lib(&g_agent.bpf_ctx, lib);
		if (trust_ret < 0) {
			lota_err("Failed to trust lib %s on reload: %s", lib,
				 strerror(-trust_ret));
			trust_reload_failed = true;
			break;
		}
		copy_path(trust_libs[applied_libs], lib);
		applied_libs++;
	}

	if (trust_reload_failed) {
		for (int k = 0; k < applied_libs; k++)
			bpf_loader_untrust_lib(&g_agent.bpf_ctx, trust_libs[k]);

		int restored_libs = 0;
		for (int k = 0; k < old_trust_lib_count; k++) {
			int restore_ret = bpf_loader_trust_lib(
				&g_agent.bpf_ctx, old_trust_libs[k]);
			if (restore_ret < 0) {
				lota_err("Failed to restore trusted lib %s "
					 "after reload error: %s",
					 old_trust_libs[k],
					 strerror(-restore_ret));
				continue;
			}
			copy_path(trust_libs[restored_libs], old_trust_libs[k]);
			restored_libs++;
		}
		*trust_lib_count = restored_libs;
		lota_warn(
			"Keeping previous trusted library set after reload errors");
		free(old_trust_libs);
		return;
	}

	*trust_lib_count = applied_libs;
	free(old_trust_libs);
}

static void sync_config_snapshot(
	struct lota_config *cfg, const struct lota_config *new_cfg, int mode,
	bool strict_mmap, bool strict_exec, bool block_ptrace,
	bool strict_modules, bool block_anon_exec, uint32_t *protect_pids,
	int protect_pid_count, char trust_libs[LOTA_CONFIG_MAX_LIBS][PATH_MAX],
	int trust_lib_count)
{
	memcpy(cfg->server, new_cfg->server, sizeof(cfg->server));
	cfg->port = new_cfg->port;
	memcpy(cfg->ca_cert, new_cfg->ca_cert, sizeof(cfg->ca_cert));
	memcpy(cfg->pin_sha256, new_cfg->pin_sha256, sizeof(cfg->pin_sha256));
	memcpy(cfg->bpf_path, new_cfg->bpf_path, sizeof(cfg->bpf_path));
	if (mode == LOTA_MODE_ENFORCE)
		snprintf(cfg->mode, sizeof(cfg->mode), "enforce");
	else if (mode == LOTA_MODE_MAINTENANCE)
		snprintf(cfg->mode, sizeof(cfg->mode), "maintenance");
	else
		snprintf(cfg->mode, sizeof(cfg->mode), "monitor");

	cfg->strict_mmap = strict_mmap;
	cfg->strict_exec = strict_exec;
	cfg->block_ptrace = block_ptrace;
	cfg->strict_modules = strict_modules;
	cfg->block_anon_exec = block_anon_exec;
	cfg->attest_interval = new_cfg->attest_interval;
	cfg->aik_ttl = new_cfg->aik_ttl;
	cfg->aik_handle = new_cfg->aik_handle;
	cfg->daemon = new_cfg->daemon;
	memcpy(cfg->pid_file, new_cfg->pid_file, sizeof(cfg->pid_file));
	memcpy(cfg->signing_key, new_cfg->signing_key,
	       sizeof(cfg->signing_key));
	memcpy(cfg->policy_pubkey, new_cfg->policy_pubkey,
	       sizeof(cfg->policy_pubkey));
	cfg->trust_lib_count = trust_lib_count;
	for (int k = 0; k < trust_lib_count; k++) {
		copy_path(cfg->trust_libs[k], trust_libs[k]);
	}

	/*
	 * Publisher list moves with the file.
	 * lota.conf gains publishers while the daemon runs
	 * -- game's installer writes one -- and the caller rebuilds the attestation
	 *  targets from this snapshot right after, so publisher that is only
	 *  in the file is a publisher no title can name.
	 */
	memcpy(cfg->profiles, new_cfg->profiles, sizeof(cfg->profiles));
	cfg->profile_count = new_cfg->profile_count;

	/* allow_verity is applied only at startup; keep existing snapshot */
	memcpy(cfg->log_level, new_cfg->log_level, sizeof(cfg->log_level));

	cfg->protect_pid_count = 0;
	if (protect_pid_count > 0) {
		int n = protect_pid_count;

		if (n > LOTA_MAX_PROTECTED_PIDS)
			n = LOTA_MAX_PROTECTED_PIDS;
		memcpy(cfg->protect_pids, protect_pids,
		       (size_t)n * sizeof(uint32_t));
		cfg->protect_pid_count = n;
	}
}

int agent_reload_config(const char *config_path, struct lota_config *cfg,
			int *mode, bool *strict_mmap, bool *strict_exec,
			bool *block_ptrace, bool *strict_modules,
			bool *block_anon_exec, uint32_t **protect_pids,
			int *protect_pid_count,
			char trust_libs[LOTA_CONFIG_MAX_LIBS][PATH_MAX],
			int *trust_lib_count)
{
	struct lota_config *new_cfg = NULL;
	const char *cfg_path = (config_path && config_path[0]) ?
				       config_path :
				       LOTA_CONFIG_DEFAULT_PATH;
	int cfg_fd;

	{
		int open_flags = O_RDONLY | O_CLOEXEC;
#ifdef O_NOFOLLOW
		open_flags |= O_NOFOLLOW;
#endif
		cfg_fd = open(cfg_path, open_flags);
	}
	if (cfg_fd < 0) {
		int open_err = -errno;
		if (open_err == -ENOENT) {
			lota_warn("Config file not found on reload, keeping "
				  "current state");
			sdnotify_ready();
			return 0;
		}

		lota_err("Failed to open config on reload: %s",
			 strerror(-open_err));
		sdnotify_ready();
		return open_err;
	}

	/*
	 * Allocated, not declared: this function holds a whole second config
	 * alongside the caller's for the length of the reload, and the struct
	 * is over a megabyte.
	 * Taken after the open succeeds so the paths above keep their plain returns.
	 */
	new_cfg = config_new();
	if (!new_cfg) {
		lota_err("Failed to allocate config for reload");
		close(cfg_fd);
		sdnotify_ready();
		return -ENOMEM;
	}

	int reload_ret = config_load_from_fd(new_cfg, cfg_fd, cfg_path);

	if (reload_ret < 0) {
		lota_err("Failed to reload config: %s", strerror(-reload_ret));
		close(cfg_fd);
		config_free(new_cfg);
		sdnotify_ready();
		return reload_ret;
	}

	int new_mode = parse_mode(new_cfg->mode);
	if (*mode == LOTA_MODE_ENFORCE && (new_mode == LOTA_MODE_MONITOR ||
					   new_mode == LOTA_MODE_MAINTENANCE)) {
		int auth_ret = verify_reload_downgrade_authorization_fd(
			cfg_fd, cfg_path, cfg);
		if (auth_ret < 0) {
			lota_err("Unauthorized ENFORCE mode downgrade request "
				 "ignored");
			close(cfg_fd);
			config_free(new_cfg);
			sdnotify_ready();
			return auth_ret;
		}
	}

	close(cfg_fd);

	if (new_mode >= 0 && new_mode != *mode) {
		if (bpf_loader_set_mode(&g_agent.bpf_ctx, new_mode) == 0) {
			lota_info("Mode changed: %s -> %s",
				  mode_to_string(*mode),
				  mode_to_string(new_mode));
			*mode = new_mode;
		} else {
			lota_err("Failed to apply new mode");
		}
	}

	keep_command_line_switches(new_cfg);

	apply_runtime_flags_transactional(new_cfg, strict_mmap, strict_exec,
					  block_ptrace, strict_modules,
					  block_anon_exec);

	if (new_cfg->log_level[0] &&
	    strcmp(new_cfg->log_level, cfg->log_level) != 0) {
		int lvl = LOG_DEBUG;
		if (strcmp(new_cfg->log_level, "error") == 0)
			lvl = LOG_ERR;
		else if (strcmp(new_cfg->log_level, "warn") == 0)
			lvl = LOG_WARNING;
		else if (strcmp(new_cfg->log_level, "info") == 0)
			lvl = LOG_INFO;
		journal_set_level(lvl);
		lota_info("Log level changed to %s", new_cfg->log_level);
	}

	merge_command_line_state(new_cfg);

	reload_protected_pids(new_cfg, protect_pids, protect_pid_count);
	lota_info("Protected PIDs reloaded (%d entries)", *protect_pid_count);

	reload_trust_libs(new_cfg, trust_libs, trust_lib_count);
	lota_info("Trusted libs reloaded (%d entries)", *trust_lib_count);

	if (new_cfg->allow_verity_count != cfg->allow_verity_count) {
		lota_warn("allow_verity changes require restart; keeping "
			  "previous allowlist");
	} else {
		for (int i = 0; i < new_cfg->allow_verity_count; i++) {
			if (strcmp(new_cfg->allow_verity[i],
				   cfg->allow_verity[i]) != 0) {
				lota_warn(
					"allow_verity changes require restart; "
					"keeping previous allowlist");
				break;
			}
		}
	}

	sync_config_snapshot(cfg, new_cfg, *mode, *strict_mmap, *strict_exec,
			     *block_ptrace, *strict_modules, *block_anon_exec,
			     *protect_pids, *protect_pid_count, trust_libs,
			     *trust_lib_count);

	config_free(new_cfg);

	sdnotify_ready();
	sdnotify_status("Monitoring, mode=%s", mode_to_string(*mode));
	lota_info("Configuration reloaded");

	return 0;
}
