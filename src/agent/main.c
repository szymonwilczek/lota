/* SPDX-License-Identifier: MIT */
/*
 * LOTA Agent
 * Minimalist C daemon for Linux remote attestation
 *
 * Copyright (C) 2026 Szymon Wilczek
 *
 * Usage:
 *   lota-agent [options]
 *
 * Options:
 *   --test-tpm      Test TPM operations and exit
 *   --test-iommu    Test IOMMU verification and exit
 *   --bpf PATH      Path to BPF object file
 *   --server HOST   Remote attestation server
 *   --daemon        Run as daemon
 */
#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/signalfd.h>
#include <unistd.h>

#include "../../include/lota.h"
#include "../../include/lota_ipc.h"
#include "agent.h"
#include "attest.h"
#include "bpf_loader.h"
#include "cli.h"
#include "config.h"
#include "daemon.h"
#include "daemon_loop.h"
#include "dbus.h"
#include "diagnostics.h"
#include "event.h"
#include "hardening.h"
#include "hash_verify.h"
#include "iommu.h"
#include "ipc.h"
#include "journal.h"
#include "main_utils.h"
#include "sdnotify.h"
#include "selftest.h"
#include "shutdown.h"
#include "startup_policy.h"
#include "tpm.h"

/* Global state */
struct agent_globals g_agent = {
    .running = 1,
    .dbus_ctx = NULL,
    .mode = LOTA_MODE_MONITOR,
};

static volatile sig_atomic_t g_reload = 0;

struct run_daemon_params {
	const char *bpf_path;
	const char *bpf_pubkey_path;
	int mode;
	bool strict_mmap;
	bool strict_exec;
	bool block_ptrace;
	bool strict_modules;
	bool block_anon_exec;
	bool allow_mutable_rootfs;
	bool allow_dev_kernel;
	const char *config_path;
	struct lota_config *cfg;
};

static int run_daemon(const struct run_daemon_params *params)
{
	int ret, epoll_fd, sfd;
	uint32_t status_flags = 0;
	uint64_t wd_usec = 0;
	bool wd_enabled;
	bool strict_mmap;
	bool strict_exec;
	bool block_ptrace;
	bool strict_modules;
	bool block_anon_exec;
	const char *bpf_path;
	const char *bpf_pubkey_path;
	const char *config_path;
	struct lota_config *cfg;
	sigset_t mask;
	struct epoll_event ev;

	if (!params)
		return -EINVAL;

	bpf_path = params->bpf_path;
	bpf_pubkey_path = params->bpf_pubkey_path;
	agent_globals_lock(&g_agent);
	g_agent.mode = params->mode;
	agent_globals_unlock(&g_agent);
	strict_mmap = params->strict_mmap;
	strict_exec = params->strict_exec;
	block_ptrace = params->block_ptrace;
	strict_modules = params->strict_modules;
	block_anon_exec = params->block_anon_exec;
	config_path = params->config_path;
	cfg = params->cfg;

	lota_info("LOTA agent starting");

	/*
	 * Daemon-mode hardening: refuse to start under a tracer and install
	 * the seccomp blocklist. Pre-CLI hardening already set
	 * no_new_privs and dumpable=0; running these here keeps the
	 * diagnostic admin paths (--shutdown, --test-tpm, ...) usable
	 * under strace while the long-running daemon remains locked down.
	 */
	{
		int harden_ret = hardening_apply_daemon();
		if (harden_ret < 0) {
			lota_err("Failed to apply daemon hardening: %s",
				 strerror(-harden_ret));
			return harden_ret;
		}
	}

	/* detect watchdog interval */
	wd_enabled = sdnotify_watchdog_enabled(&wd_usec);
	if (wd_enabled)
		lota_info("Watchdog enabled, interval %lu us",
			  (unsigned long)wd_usec);

	/* setup signalfd for synchronous signal handling */
	sigemptyset(&mask);
	sigaddset(&mask, SIGTERM);
	sigaddset(&mask, SIGINT);
	sigaddset(&mask, SIGHUP);

	if (sigprocmask(SIG_BLOCK, &mask, NULL) < 0) {
		lota_err("Failed to block signals: %s", strerror(errno));
		return -errno;
	}

	sfd = signalfd(-1, &mask, SFD_NONBLOCK | SFD_CLOEXEC);
	if (sfd < 0) {
		lota_err("Failed to create signalfd: %s", strerror(errno));
		return -errno;
	}

	epoll_fd = epoll_create1(EPOLL_CLOEXEC);
	if (epoll_fd < 0) {
		lota_err("Failed to create epoll instance: %s",
			 strerror(errno));
		close(sfd);
		return -errno;
	}

	ev.events = EPOLLIN;
	ev.data.fd = sfd;
	if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, sfd, &ev) < 0) {
		lota_err("Failed to add signalfd to epoll: %s",
			 strerror(errno));
		close(sfd);
		close(epoll_fd);
		return -errno;
	}

	ret = hash_verify_init(&g_agent.hash_ctx);
	if (ret < 0) {
		lota_err("Failed to initialize hash verification: %s",
			 strerror(-ret));
		close(sfd);
		close(epoll_fd);
		return ret;
	}
	lota_info(
	    "Hash verification ready (fs-verity backed, no userspace cache)");

	lota_info("Starting IPC server");
	ret = ipc_init_or_activate(&g_agent.ipc_ctx);
	if (ret < 0) {
		lota_err("Failed to initialize IPC: %s", strerror(-ret));
		goto cleanup_epoll;
	}

	ipc_set_mode(&g_agent.ipc_ctx, (uint8_t)g_agent.mode);
	setup_container_listener(&g_agent.ipc_ctx, cfg);
	setup_dbus(&g_agent.ipc_ctx);

	/* IPC epoll fd to main loop */
	int ipc_fd = ipc_get_fd(&g_agent.ipc_ctx);
	if (ipc_fd >= 0) {
		ev.events = EPOLLIN;
		ev.data.fd = ipc_fd;
		epoll_ctl(epoll_fd, EPOLL_CTL_ADD, ipc_fd, &ev);
	}

	if (g_agent.dbus_ctx) {
		int dbus_fd = dbus_get_fd(g_agent.dbus_ctx);
		if (dbus_fd >= 0) {
			ev.events = EPOLLIN;
			ev.data.fd = dbus_fd;
			epoll_ctl(epoll_fd, EPOLL_CTL_ADD, dbus_fd, &ev);
		}
	}

	lota_info("Verifying IOMMU");
	ret = test_iommu();
	if (ret != 0) {
		lota_warn("IOMMU verification failed");
	} else {
		status_flags |= LOTA_STATUS_IOMMU_OK;
	}

	lota_info("Initializing TPM");
	ret = tpm_init(&g_agent.tpm_ctx);
	if (ret < 0) {
		lota_err("Failed to initialize TPM: %s", tpm_strerror(ret));
		goto cleanup_tpm;
	} else {
		lota_info("TPM initialized");
		status_flags |= LOTA_STATUS_TPM_OK;

		lota_info("Provisioning AIK");
		ret = tpm_provision_aik(&g_agent.tpm_ctx);
		if (ret < 0) {
			lota_err("AIK provisioning failed: %s",
				 tpm_strerror(ret));
			goto cleanup_tpm;
		} else {
			ipc_set_tpm(&g_agent.ipc_ctx, &g_agent.tpm_ctx,
				    LOTA_TOKEN_QUOTE_PCR_MASK);
			lota_info("AIK ready, signed tokens enabled");

			ret = tpm_aik_load_metadata(&g_agent.tpm_ctx);
			if (ret < 0) {
				lota_err("Failed to load AIK metadata: %s",
					 tpm_strerror(ret));
				goto cleanup_tpm;
			} else {
				int64_t age = tpm_aik_age(&g_agent.tpm_ctx);
				lota_info(
				    "AIK generation: %lu, age: %ld seconds",
				    (unsigned long)
					g_agent.tpm_ctx.aik_meta.generation,
				    (long)age);
			}
		}

		lota_info("Performing self-measurement");
		ret = self_measure(&g_agent.tpm_ctx);
		if (ret < 0) {
			lota_err("Self-measurement failed: %s",
				 tpm_strerror(ret));
			goto cleanup_tpm;
		} else {
			lota_info("Self-measurement complete (PCR %d extended)",
				  LOTA_PCR_SELF);
		}
	}

	lota_info("Loading BPF program from: %s", bpf_path);
	ret = bpf_loader_init(&g_agent.bpf_ctx);
	if (ret < 0) {
		lota_err("Failed to initialize BPF loader: %s", strerror(-ret));
		goto cleanup_tpm;
	}

	ret = bpf_loader_load(&g_agent.bpf_ctx, bpf_path, bpf_pubkey_path);
	if (ret < 0) {
		lota_err("Failed to load BPF program: %s", strerror(-ret));
		goto cleanup_bpf;
	}
	lota_info("BPF program loaded (attach deferred until startup policy "
		  "applied)");
	status_flags |= LOTA_STATUS_BPF_LOADED;

	struct agent_startup_policy startup_policy = {
	    .mode = g_agent.mode,
	    .strict_mmap = strict_mmap,
	    .strict_exec = strict_exec,
	    .block_ptrace = block_ptrace,
	    .strict_modules = strict_modules,
	    .block_anon_exec = block_anon_exec,
	    .protect_pids = *cli_runtime_protect_pids(),
	    .protect_pid_count = *cli_runtime_protect_pid_count(),
	    .trust_libs = cli_runtime_trust_libs(),
	    .trust_lib_count = *cli_runtime_trust_lib_count(),
	    .allow_verity = cli_runtime_allow_verity(),
	    .allow_verity_count = *cli_runtime_allow_verity_count(),
	    .allow_mutable_rootfs = params->allow_mutable_rootfs,
	    .allow_dev_kernel = params->allow_dev_kernel,
	};

	/*
	 * Write the full enforcement policy (mode + strict_* + block_* +
	 * protected pids + verity allowlist) into lota_config / aux maps
	 * BEFORE BPF programs go live. agent_apply_startup_policy() calls
	 * the bpf_loader_set_* helpers that operate on map fds resolved by
	 * bpf_loader_load(); it does not need attached programs. Doing
	 * this here closes the attach -> startup-policy window: the very
	 * first invocation of every LSM hook below sees the operator
	 * policy, not the post-load default zeros.
	 */
	ret = agent_apply_startup_policy(&startup_policy);
	if (ret < 0)
		goto cleanup_bpf;

	ret = bpf_loader_attach(&g_agent.bpf_ctx);
	if (ret < 0) {
		lota_err("Failed to attach BPF programs: %s", strerror(-ret));
		goto cleanup_bpf;
	}
	lota_info("BPF programs attached under full enforcement policy");

	ret =
	    bpf_loader_setup_ringbuf(&g_agent.bpf_ctx, handle_exec_event, NULL);
	if (ret < 0) {
		lota_err("Failed to setup ring buffer: %s", strerror(-ret));
		goto cleanup_bpf;
	}
	lota_info("Ring buffer ready");

	/* BPF ringbuf epoll fd registered after setup_ringbuf creates it */
	int bpf_fd = bpf_loader_get_event_fd(&g_agent.bpf_ctx);
	if (bpf_fd >= 0) {
		ev.events = EPOLLIN;
		ev.data.fd = bpf_fd;
		epoll_ctl(epoll_fd, EPOLL_CTL_ADD, bpf_fd, &ev);
	}

	ipc_update_status(&g_agent.ipc_ctx, status_flags, 0);

	sdnotify_ready();
	sdnotify_status("Monitoring, mode=%s", mode_to_string(g_agent.mode));
	lota_info("Monitoring binary executions (event-driven)");

	struct agent_loop_ctx loop_ctx = {
	    .epoll_fd = epoll_fd,
	    .sfd = sfd,
	    .wd_enabled = wd_enabled,
	    .wd_usec = wd_usec,
	    .config_path = config_path,
	    .cfg = cfg,
	    .mode = &g_agent.mode,
	    .strict_mmap = &strict_mmap,
	    .strict_exec = &strict_exec,
	    .block_ptrace = &block_ptrace,
	    .strict_modules = &strict_modules,
	    .block_anon_exec = &block_anon_exec,
	    .protect_pids = cli_runtime_protect_pids(),
	    .protect_pid_count = cli_runtime_protect_pid_count(),
	    .trust_libs = cli_runtime_trust_libs(),
	    .trust_lib_count = cli_runtime_trust_lib_count(),
	    .ipc_ctx = &g_agent.ipc_ctx,
	    .dbus_ctx = g_agent.dbus_ctx,
	    .bpf_ctx = &g_agent.bpf_ctx,
	    .running = &g_agent.running,
	};
	ret = agent_run_event_loop(&loop_ctx);

	/* clean shutdown via signal - do not propagate EINTR as failure */
	if (!g_agent.running)
		ret = 0;

	sdnotify_stopping();

	struct bpf_extended_stats stats;
	if (bpf_loader_get_extended_stats(&g_agent.bpf_ctx, &stats) == 0) {
		lota_info(
		    "Shutdown statistics: exec=%lu sent=%lu err=%lu drops=%lu "
		    "mod_blocked=%lu mmap_exec=%lu mmap_blocked=%lu "
		    "ptrace=%lu ptrace_blocked=%lu setuid=%lu bpf_blocked=%lu",
		    stats.total_execs, stats.events_sent, stats.errors,
		    stats.drops, stats.modules_blocked, stats.mmap_execs,
		    stats.mmap_blocked, stats.ptrace_attempts,
		    stats.ptrace_blocked, stats.setuid_events,
		    stats.bpf_syscall_blocked);
	}

	{
		uint64_t h_resolved, h_errors;
		hash_verify_stats(&g_agent.hash_ctx, &h_resolved, &h_errors);
		lota_info("Hash verification: resolved=%lu errors=%lu",
			  h_resolved, h_errors);
	}

cleanup_bpf:
	/*
	 * Dirty-shutdown coverage.
	 *
	 * poison_runtime_pcr() only runs on the clean shutdown path that
	 * reaches this label. A panic, power loss, SIGKILL, or hard reset
	 * leaves PCR14 carrying the last live boot commitment and never
	 * extends it with the poison value, so a verifier that re-attests
	 * the same host after such a stop sees that PCR14 as authentic
	 * even if the on-disk agent binary, library closure, or policy
	 * file was tampered while the host was offline. The TPM itself
	 * cannot detect that mutation: PCR0/PCR1/PCR7 cover firmware /
	 * SecureBoot / cmdline, and PCR14 only binds the running agent
	 * self-hash, not inode contents that were touched after the
	 * agent stopped reading them.
	 *
	 * Closing the dirty-shutdown gap therefore lives outside the
	 * agent's runtime path:
	 *   - fs-verity on /proc/self/exe is enforced at startup by
	 *     bpf_loader_verify_kernel_runtime_hardening() (the
	 *     agent_self_fsverity_enabled() gate), so a hard reset that
	 *     swaps the agent binary on disk fails the next agent start
	 *     and never reaches a fresh attestation;
	 *   - dm-verity or IMA appraisal on the rootfs that hosts the
	 *     policy file, shared libraries, and supporting binaries is
	 *     the operator's deployment contract; the agent already
	 *     requires kernel IMA appraisal at startup.
	 * The --insecure-allow-mutable-rootfs escape hatch keeps the gap
	 * open on legacy hosts and logs a warn-level deviation; the
	 * verifier still binds PCR14 to the live agent self-hash, but
	 * the dirty-shutdown -> tampered-rootfs branch is no longer
	 * authenticated end to end on that host.
	 */
	ret = agent_poison_runtime_pcr_before_bpf_unload(&g_agent.tpm_ctx,
							 &g_agent.bpf_ctx, ret);

	bpf_loader_cleanup(&g_agent.bpf_ctx);
cleanup_tpm:
	tpm_cleanup(&g_agent.tpm_ctx);
	dbus_cleanup(g_agent.dbus_ctx);
	ipc_cleanup(&g_agent.ipc_ctx);
cleanup_epoll:
	hash_verify_cleanup(&g_agent.hash_ctx);
	close(sfd);
	close(epoll_fd);
	return ret;
}

int main(int argc, char *argv[])
{
	struct cli_options opts;
	struct lota_config cfg;
	int rc;

	if (daemon_install_signals(&g_agent.running, &g_reload) < 0) {
		fprintf(stderr, "Failed to install signal handlers: %s\n",
			strerror(errno));
		return 1;
	}

	journal_init("lota-agent");

	rc = hardening_apply_basics();
	if (rc < 0) {
		fprintf(stderr, "Failed to apply process hardening: %s\n",
			strerror(-rc));
		return 1;
	}

	config_init(&cfg);

	rc = cli_parse(argc, argv, &opts, &cfg);
	if (rc == -1)
		return 0; /* --help */
	if (rc != 0)
		return rc;

	rc = cli_finalize_pin(&opts);
	if (rc != 0)
		return rc;

	rc = diagnostics_dispatch(&opts, &cfg);
	if (rc >= 0)
		return rc;

	/*
	 * Mode downgrade guard.
	 *
	 * The packaged systemd unit does not pass --mode and lets the agent
	 * pick up cfg.mode (default enforce). An operator who hand-edits the
	 * unit to add --mode monitor, or who packages their own unit with a
	 * weakened mode, would otherwise silently override the configured
	 * enforce policy. Refuse to start in that case and require the
	 * caller to acknowledge the downgrade explicitly. Maintenance and
	 * monitor are both treated as weakenings of enforce.
	 */
	if (opts.cli_mode_set && opts.config_file_mode == LOTA_MODE_ENFORCE &&
	    g_agent.mode != LOTA_MODE_ENFORCE &&
	    !opts.insecure_allow_mode_downgrade) {
		fprintf(
		    stderr,
		    "ERROR: CLI --mode %s weakens configured mode 'enforce'.\n"
		    "Either remove --mode from the invocation (config drives "
		    "mode)\n"
		    "or pass --insecure-allow-mode-downgrade to acknowledge "
		    "the\n"
		    "downgrade explicitly.\n",
		    mode_to_string(g_agent.mode));
		return 1;
	}

	if (opts.daemon_flag) {
		int dret = daemonize();
		if (dret < 0) {
			fprintf(stderr, "Failed to daemonize: %s\n",
				strerror(-dret));
			return 1;
		}
	}

	int pid_fd = pidfile_create(opts.pid_file_path);
	if (pid_fd == -EEXIST) {
		fprintf(
		    stderr,
		    "Another instance is already running (PID file locked)\n");
		return 1;
	}
	if (pid_fd < 0) {
		fprintf(stderr, "Warning: Failed to create PID file: %s\n",
			strerror(-pid_fd));
		pid_fd = -1; /* non-fatal */
	}

	if (!opts.policy_pubkey_path || opts.policy_pubkey_path[0] == '\0') {
		fprintf(stderr, "ERROR: BPF object signature verification "
				"requires --policy-pubkey\n"
				"Set policy_pubkey in config or pass "
				"--policy-pubkey PATH.\n");
		pidfile_remove(opts.pid_file_path, pid_fd);
		return 1;
	}

	struct run_daemon_params run_params = {
	    .bpf_path = opts.bpf_path,
	    .bpf_pubkey_path = opts.policy_pubkey_path,
	    .mode = g_agent.mode,
	    .strict_mmap = opts.strict_mmap,
	    .strict_exec = opts.strict_exec,
	    .block_ptrace = opts.block_ptrace,
	    .strict_modules = opts.strict_modules,
	    .block_anon_exec = opts.block_anon_exec,
	    .allow_mutable_rootfs = opts.insecure_allow_mutable_rootfs != 0,
	    .allow_dev_kernel = opts.insecure_allow_dev_kernel != 0,
	    .config_path = opts.config_path,
	    .cfg = &cfg,
	};
	rc = run_daemon(&run_params);
	pidfile_remove(opts.pid_file_path, pid_fd);
	return rc;
}
