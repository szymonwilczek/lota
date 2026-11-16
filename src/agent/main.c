/* SPDX-License-Identifier: MIT */
/*
 * LOTA Agent
 *
 * Copyright (C) 2026 Szymon Wilczek
 */
#include <errno.h>
#include <grp.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/signalfd.h>
#include <unistd.h>
#include <stdint.h>

#include "../../include/lota.h"
#include "agent.h"
#include "attest.h"
#include "bench_bpf.h"
#include "bpf_loader.h"
#include "cli.h"
#include "config.h"
#include "daemon.h"
#include "daemon_loop.h"
#include "dbus.h"
#include "diagnostics.h"
#include "event.h"
#include "exit_status.h"
#include "hardening.h"
#include "ipc.h"
#include "journal.h"
#include "kernel_floor_hint.h"
#include "main_utils.h"
#include "profile.h"
#include "runtime_image_measure.h"
#include "sdnotify.h"
#include "selftest.h"
#include "shutdown.h"
#include "startup_hint.h"
#include "startup_policy.h"
#include "status_flags.h"
#include "tpm.h"
#include "watchdog.h"

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
	bool bench;
	const char *config_path;
	struct lota_config *cfg;
};

/* The hooks take no context, so these use the daemon's BPF loader */
static int agent_kernel_hash_file(const char *path, uint64_t dev, uint64_t ino,
				  struct lota_verity_digest_key *out)
{
	return bpf_loader_hash_file(&g_agent.bpf_ctx, path, dev, ino, out);
}

static int agent_kernel_pin_object(const char *path, uint64_t dev, uint64_t ino,
				   int *pinned)
{
	return bpf_loader_pin_mapped_object(&g_agent.bpf_ctx, path, dev, ino,
					    pinned);
}

static void agent_kernel_pin_round_begin(void)
{
	bpf_loader_pin_round_begin(&g_agent.bpf_ctx);
}

static int agent_kernel_pin_sweep(size_t *released)
{
	return bpf_loader_pin_sweep(&g_agent.bpf_ctx, released);
}

static int run_daemon(const struct run_daemon_params *params)
{
	int ret, epoll_fd, sfd;
	struct agent_boot_state boot_state = { 0 };
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
	const struct profile_paths *profile = NULL;
	/* static: the global IPC context keeps the pointer after return */
	static struct attest_target targets[LOTA_CONFIG_MAX_PROFILES];
	size_t target_count = 0;

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
	boot_state.bench = params->bench;
	config_path = params->config_path;
	cfg = params->cfg;

	lota_info("LOTA agent starting");

	{
		int t_ret = attest_targets_build(
			cfg, (cfg && cfg->server[0]) ? cfg->server : NULL,
			cfg ? cfg->port : 0, cfg ? cfg->ca_cert : NULL,
			cfg ? cfg->attest_interval : 0, targets,
			sizeof(targets) / sizeof(targets[0]), &target_count);

		if (t_ret < 0) {
			/* no profile, no server: enforcement needs neither */
			target_count = 0;
			lota_info("No publisher configured; enforcing for the "
				  "host and answering titles for nobody");
		}
	}

	for (size_t i = 0; i < target_count; i++) {
		if (targets[i].profile_error)
			/* a token-only target names no verifier */
			lota_warn("Cannot read the CA trust anchor %s (%s): "
				  "answering for %s without a publisher "
				  "profile",
				  targets[i].ca_cert,
				  strerror(-targets[i].profile_error),
				  targets[i].label);
	}

	/* the TPM stays bound to the first publisher between token requests */
	if (target_count > 0 && targets[0].has_profile)
		profile = &targets[0].paths;

	{
		int harden_ret = hardening_apply_daemon();
		if (harden_ret < 0) {
			lota_err("Failed to apply daemon hardening: %s",
				 strerror(-harden_ret));
			return harden_ret;
		}
	}

	/*
	 * The policy, the object's signature and its integrity map are checked
	 * before self_measure() extends PCR 14. Once BPF is loaded, a refusal
	 * reaches the poison at cleanup_bpf, and the next start of this boot is
	 * refused until reboot. agent_apply_startup_policy() repeats the policy
	 * checks against the live maps.
	 */
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
	};

	ret = agent_validate_startup_policy(&startup_policy);
	if (ret < 0) {
		int status = lota_startup_check_exit_status(ret);

		lota_err("Startup policy refused before the boot commitment "
			 "was spent; the host keeps the agent it is running "
			 "and PCR 14 is untouched.%s%s",
			 status == LOTA_EXIT_OPERATOR_ACTION ? " " : "",
			 status == LOTA_EXIT_OPERATOR_ACTION ?
				 startup_refusal_advice(ret) :
				 "");
		return status;
	}

	/* bpf_loader_load() verifies again the bytes it hands the kernel */
	ret = bpf_loader_verify_object(bpf_path, bpf_pubkey_path);
	if (ret < 0) {
		int status = lota_startup_check_exit_status(ret);

		lota_err("Enforcement object %s refused before the boot "
			 "commitment was spent: %s. The host keeps the agent "
			 "it is running and PCR 14 is untouched.%s",
			 bpf_path, strerror(-ret),
			 status == LOTA_EXIT_OPERATOR_ACTION ?
				 " Re-sign the object for the configured key "
				 "and start again." :
				 "");
		return status;
	}

	ret = bpf_loader_check_object_integrity_layout(bpf_path);
	if (ret < 0) {
		lota_err("Enforcement object %s refused before the boot "
			 "commitment was spent. The host keeps the agent it is "
			 "running and PCR 14 is untouched.",
			 bpf_path);
		return lota_startup_check_exit_status(ret);
	}

	wd_enabled = sdnotify_watchdog_enabled(&wd_usec);
	if (wd_enabled)
		lota_info("Watchdog enabled, interval %lu us",
			  (unsigned long)wd_usec);

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

	lota_info("Starting IPC server");
	ret = ipc_init_or_activate(&g_agent.ipc_ctx);
	if (ret < 0) {
		lota_err("Failed to initialize IPC: %s", strerror(-ret));
		goto cleanup_epoll;
	}

	ipc_set_mode(&g_agent.ipc_ctx, (uint8_t)g_agent.mode);
	ipc_set_policy(&g_agent.ipc_ctx,
		       lota_status_policy_keys(strict_mmap, strict_exec,
					       strict_modules, block_anon_exec,
					       block_ptrace));
	ipc_set_profiles(&g_agent.ipc_ctx, targets, target_count);
	setup_container_listener(&g_agent.ipc_ctx, cfg);
	setup_dbus(&g_agent.ipc_ctx);

	/*
	 * A login can be bound once its runtime directory appears and logind's
	 * tmpfs is mounted over it. A mount fires no inotify event, and
	 * /proc/self/mountinfo reports it as EPOLLPRI.
	 */
	int watch_fd = container_watch_fd(&g_agent.container_watch);
	if (watch_fd >= 0) {
		ev.events = EPOLLIN;
		ev.data.fd = watch_fd;
		epoll_ctl(epoll_fd, EPOLL_CTL_ADD, watch_fd, &ev);
	}

	int mount_fd = container_watch_mount_fd(&g_agent.container_watch);
	if (mount_fd >= 0) {
		ev.events = EPOLLPRI | EPOLLERR;
		ev.data.fd = mount_fd;
		epoll_ctl(epoll_fd, EPOLL_CTL_ADD, mount_fd, &ev);
	}

	/* rebind after a socket-unit restart */
	int sock_watch_fd = ipc_watch_socket_path(&g_agent.ipc_ctx);
	if (sock_watch_fd >= 0) {
		ev.events = EPOLLIN;
		ev.data.fd = sock_watch_fd;
		epoll_ctl(epoll_fd, EPOLL_CTL_ADD, sock_watch_fd, &ev);
	} else {
		lota_warn("cannot watch %s: %s; a socket-unit restart will "
			  "need the agent restarted too",
			  LOTA_IPC_SOCKET_PATH, strerror(-sock_watch_fd));
	}

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
		boot_state.iommu_ok = true;
	}

	boot_state.secure_boot = bpf_loader_secure_boot_enabled() == 0;
	boot_state.kernel_appraisal = bpf_loader_kernel_appraises_exec() == 0;
	lota_info("Kernel appraisal: %s",
		  boot_state.kernel_appraisal ?
			  "executables are appraised" :
			  "nothing is appraised (advisory; tokens say so)");
	lota_info("Secure Boot: %s", boot_state.secure_boot ?
					     "enabled" :
					     "disabled or unreadable");

	/* reads a path, not the chip: refuse before the TPM is opened */
	if (tpm_firmware_refuses_attestation(&g_agent.tpm_ctx)) {
		lota_err("This host cannot attest: it did not boot via UEFI.");
		ret = -ENOTSUP;
		goto cleanup_tpm;
	}

	lota_info("Initializing TPM");
	ret = tpm_init(&g_agent.tpm_ctx);
	if (ret < 0) {
		lota_err("Failed to initialize TPM: %s", tpm_strerror(ret));
		goto cleanup_tpm;
	} else {
		lota_info("TPM initialized");
		boot_state.tpm_ok = true;

		/*
		 * Tokens are quoted with the AIK the enrollment certified, kept
		 * in the profile of the configured CA trust anchor.
		 */
		if (profile) {
			ret = tpm_bind_profile(&g_agent.tpm_ctx, profile);
			if (ret < 0) {
				/* enforcement and PCR 14 need no publisher */
				lota_warn("Cannot bind the publisher profile "
					  "under %s (%s): enforcing without a "
					  "publisher, tokens are signed with "
					  "the host AIK",
					  profile->dir, tpm_strerror(ret));
				lota_warn("Enroll with the publisher to bind "
					  "it: lota-agent --enroll --ca-cert "
					  "%s",
					  cfg && cfg->ca_cert[0] ?
						  cfg->ca_cert :
						  "<publisher CA anchor>");
				profile = NULL;
			}
		}

		/*
		 * Before tpm_provision_aik(): once the key exists,
		 * a missing record reads as -EKEYREVOKED.
		 */
		ret = tpm_aik_load_metadata(&g_agent.tpm_ctx);
		if (ret == -EKEYREVOKED) {
			char advice[1024];

			tpm_aik_no_record_advice(&g_agent.tpm_ctx, advice,
						 sizeof(advice));
			lota_err("%s", advice);
			goto cleanup_tpm;
		}
		if (ret < 0) {
			lota_err("Failed to load AIK metadata: %s",
				 tpm_strerror(ret));
			goto cleanup_tpm;
		}

		if (tpm_aik_key_is_shared(&g_agent.tpm_ctx)) {
			lota_err("%s", TPM_AIK_SHARED_KEY_ADVICE);
			ret = -ENOTSUP;
			goto cleanup_tpm;
		}

		int key_present = tpm_aik_key_present(&g_agent.tpm_ctx);

		lota_info("Provisioning AIK");
		ret = tpm_provision_aik(&g_agent.tpm_ctx);
		if (ret < 0) {
			lota_err("AIK provisioning failed: %s",
				 tpm_strerror(ret));
			goto cleanup_tpm;
		} else {
			attest_warn_cert_orphaned(profile,
						  profile ? profile->id : NULL,
						  key_present);
			ipc_set_tpm(&g_agent.ipc_ctx, &g_agent.tpm_ctx,
				    LOTA_TOKEN_QUOTE_PCR_MASK);
			lota_info("AIK ready, signed tokens enabled");
		}

		lota_info("Performing self-measurement");
		ret = self_measure(&g_agent.tpm_ctx);
		if (ret < 0) {
			lota_err("Self-measurement failed: %s",
				 tpm_strerror(ret));
			goto cleanup_tpm;
		} else if (ret == TPM_BOOT_COMMITMENT_ALREADY_HELD) {
			lota_info(
				"Self-measurement complete (PCR %d already held this boot's commitment; the restart did not spend it)",
				LOTA_PCR_SELF);
			lota_warn(
				"An earlier agent of this boot ended without a shutdown; status and tokens say AGENT_RESTARTED until reboot");
			ipc_set_agent_restarted(&g_agent.ipc_ctx);
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
	boot_state.bpf_loaded = true;

	/* before attach, so the first call of every hook sees the policy */
	ret = agent_apply_startup_policy(&startup_policy);
	if (ret < 0)
		goto cleanup_bpf;

	ret = bpf_loader_attach(&g_agent.bpf_ctx);
	if (ret < 0) {
		lota_err("Failed to attach BPF programs: %s", strerror(-ret));
		goto cleanup_bpf;
	}
	lota_info("BPF programs attached under full enforcement policy");

	/* only once attached: an unattached program answers no open */
	lota_rt_set_content_hasher(agent_kernel_hash_file);
	lota_rt_set_pin_object(agent_kernel_pin_object,
			       agent_kernel_pin_round_begin,
			       agent_kernel_pin_sweep);

	ret = bpf_loader_setup_ringbuf(&g_agent.bpf_ctx, handle_exec_event,
				       NULL);
	if (ret < 0) {
		lota_err("Failed to setup ring buffer: %s", strerror(-ret));
		goto cleanup_bpf;
	}
	lota_info("Ring buffer ready");

	int bpf_fd = bpf_loader_get_event_fd(&g_agent.bpf_ctx);
	if (bpf_fd >= 0) {
		ev.events = EPOLLIN;
		ev.data.fd = bpf_fd;
		epoll_ctl(epoll_fd, EPOLL_CTL_ADD, bpf_fd, &ev);
	}

	boot_state.tpm_lockout = tpm_is_locked_out(&g_agent.tpm_ctx);
	ipc_update_status(&g_agent.ipc_ctx, agent_status_flags(&boot_state), 0);

	sdnotify_ready();
	daemon_notify_started(0);
	sdnotify_status("Monitoring, mode=%s", mode_to_string(g_agent.mode));
	lota_info("Monitoring binary executions (event-driven)");

	static struct bench_state bench;
	struct bench_state *bench_ctx = NULL;

	if (boot_state.bench) {
		struct group *grp = getgrnam("lota");

		if (!grp)
			lota_warn("Bench: group 'lota' not found, %s is "
				  "readable by root only",
				  LOTA_BENCH_PATH);
		bench_state_init(&bench, grp ? grp->gr_gid : 0, bench_now_ns());
		bench.stats_fd = bench_bpf_enable_stats();
		if (bench.stats_fd < 0)
			lota_warn("Bench: BPF run time is not counted: %s",
				  strerror(-bench.stats_fd));
		bench_ctx = &bench;
		lota_info("Bench: writing %s every %d ms", LOTA_BENCH_PATH,
			  LOTA_BENCH_INTERVAL_MS);
	} else {
		bench_remove();
	}

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
		.targets = targets,
		.target_count = &target_count,
		.target_max = sizeof(targets) / sizeof(targets[0]),
		.ipc_ctx = &g_agent.ipc_ctx,
		.dbus_ctx = g_agent.dbus_ctx,
		.bpf_ctx = &g_agent.bpf_ctx,
		.container_watch = &g_agent.container_watch,
		.bench = bench_ctx,
		.running = &g_agent.running,
	};
	/* task_kill refuses systemd's watchdog kill; supervise from inside */
	if (wd_enabled) {
		ret = watchdog_start(wd_usec);
		if (ret < 0) {
			lota_err("Failed to start the watchdog supervisor: %s. "
				 "The unit declares WatchdogSec= and nothing "
				 "else can act on it, so the agent does not "
				 "run without one.",
				 strerror(-ret));
			goto cleanup_bpf;
		}
	}

	ret = agent_run_event_loop(&loop_ctx);
	if (bench_ctx) {
		bench_remove();
		if (bench.stats_fd >= 0)
			close(bench.stats_fd);
	}

	watchdog_stop();

	if (!g_agent.running)
		ret = 0;

	sdnotify_stopping();

	struct bpf_extended_stats stats;
	if (bpf_loader_get_extended_stats(&g_agent.bpf_ctx, &stats) == 0) {
		lota_info(
			"Shutdown statistics: exec=%lu sent=%lu drops=%lu "
			"mod_blocked=%lu mmap_exec=%lu mmap_blocked=%lu "
			"ptrace=%lu ptrace_blocked=%lu setuid=%lu bpf_blocked=%lu "
			"mount_blocked=%lu kill_guard_blocked=%lu "
			"yielded=%lu kill_probes=%lu "
			"mapped_write_blocked=%lu mapped_pin_refused=%lu "
			"exec_history_lost=%lu instance_actors_lost=%lu "
			"instance_stops_lost=%lu",
			stats.total_execs, stats.events_sent, stats.drops,
			stats.modules_blocked, stats.mmap_execs,
			stats.mmap_blocked, stats.ptrace_attempts,
			stats.ptrace_blocked, stats.setuid_events,
			stats.bpf_syscall_blocked, stats.mounts_blocked,
			stats.kill_guard_blocked, stats.events_yielded,
			stats.kill_probes, stats.mapped_write_blocked,
			stats.mapped_pin_refused, stats.exec_history_lost,
			stats.instance_actors_lost, stats.instance_stops_lost);
	}

	{
		uint64_t m_repeated, m_unremembered;
		ipc_runtime_measure_stats(&m_repeated, &m_unremembered);
		lota_info("Runtime measurement reports: repeated=%lu "
			  "unremembered=%lu",
			  m_repeated, m_unremembered);
	}

	{
		uint64_t t_repeated;

		ipc_token_answer_stats(&t_repeated);
		lota_info("Token answer reports: repeated=%lu", t_repeated);
	}

cleanup_bpf:
	ret = agent_poison_runtime_pcr_before_bpf_unload(&g_agent.tpm_ctx,
							 &g_agent.bpf_ctx, ret);

	bpf_loader_cleanup(&g_agent.bpf_ctx);
cleanup_tpm:
	tpm_cleanup(&g_agent.tpm_ctx);
	dbus_cleanup(g_agent.dbus_ctx);
	container_watch_cleanup(&g_agent.container_watch);
	ipc_cleanup(&g_agent.ipc_ctx);
cleanup_epoll:
	close(sfd);
	close(epoll_fd);
	return ret;
}

int main(int argc, char *argv[])
{
	struct cli_options opts;
	struct lota_config *cfg;
	int pid_fd = -1;
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

	/* over a megabyte, so not on the stack */
	cfg = config_new();
	if (!cfg) {
		fprintf(stderr, "Failed to allocate configuration\n");
		return 1;
	}

	rc = cli_parse(argc, argv, &opts, cfg);
	if (rc == -1) {
		rc = 0; /* --help */
		goto out;
	}
	if (rc != 0)
		goto out;

	rc = cli_finalize_pin(&opts);
	if (rc != 0)
		goto out;

	rc = diagnostics_dispatch(&opts, cfg);
	if (rc >= 0)
		goto out;

	/*
	 * A --mode below the file's enforce needs
	 * --insecure-allow-mode-downgrade, so an edited unit cannot lower the
	 * mode silently.
	 */
	if (opts.cli_mode_set && opts.config_file_mode == LOTA_MODE_ENFORCE &&
	    g_agent.mode != LOTA_MODE_ENFORCE &&
	    !opts.insecure_allow_mode_downgrade) {
		fprintf(stderr,
			"ERROR: CLI --mode %s weakens configured mode 'enforce'.\n"
			"Either remove --mode from the invocation (config drives "
			"mode)\n"
			"or pass --insecure-allow-mode-downgrade to acknowledge "
			"the\n"
			"downgrade explicitly.\n",
			mode_to_string(g_agent.mode));
		rc = 1;
		goto out;
	}

	if (opts.daemon_flag) {
		int dret = daemonize();
		if (dret < 0) {
			fprintf(stderr, "Failed to daemonize: %s\n",
				strerror(-dret));
			rc = 1;
			goto out;
		}
		/* stderr is /dev/null from here; refusals go to the journal */
		journal_detached_from_terminal();
	}

	pid_fd = pidfile_create(opts.pid_file_path);
	if (pid_fd == -EEXIST) {
		char busy[512];

		startup_busy_message(cli_startup_protect_pid_count() > 0, busy,
				     sizeof(busy));
		lota_err("%s", busy);
		rc = LOTA_EXIT_ALREADY_RUNNING;
		goto out;
	}
	if (pid_fd < 0) {
		lota_warn("Warning: Failed to create PID file: %s",
			  strerror(-pid_fd));
		pid_fd = -1;
	}

	if (!opts.policy_pubkey_path || opts.policy_pubkey_path[0] == '\0') {
		lota_err(
			"ERROR: no key to verify the enforcement object "
			"against.\n"
			"The agent package ships one at " LOTA_ENFORCEMENT_PUBKEY_PATH
			";\n"
			"a fleet that signs enforcement itself puts its key at " LOTA_POLICY_PUBKEY_OVERRIDE
			"\n"
			"or names one with policy_pubkey / "
			"--policy-pubkey PATH.");
		rc = 1;
		goto out_pidfile;
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
		.bench = opts.bench,
		.config_path = opts.config_path,
		.cfg = cfg,
	};
	rc = run_daemon(&run_params);
	rc = lota_daemon_exit_status(rc, g_agent.tpm_ctx.boot_commitment_state);

out_pidfile:
	pidfile_remove(opts.pid_file_path, pid_fd);
out:
	config_free(cfg);
	/* the first report wins: a daemon that started has reported 0 */
	daemon_notify_started(rc);
	return rc;
}
