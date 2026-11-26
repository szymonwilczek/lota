/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */

#include "main_utils.h"

#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/stat.h>

#include "../../include/lota.h"
#include "../../include/lota_ipc.h"
#include "agent.h"
#include "attest.h"
#include "bench.h"
#include "config.h"
#include "container_watch.h"
#include "daemon.h"
#include "dbus.h"
#include "journal.h"
#include "policy_sign.h"
#include "sdnotify.h"
#include "steam_runtime.h"

const char *mode_to_string(int mode)
{
	switch (mode) {
	case LOTA_MODE_MONITOR:
		return "MONITOR";
	case LOTA_MODE_ENFORCE:
		return "ENFORCE";
	default:
		return "UNKNOWN";
	}
}

int parse_mode(const char *mode_str)
{
	if (strcmp(mode_str, "monitor") == 0)
		return LOTA_MODE_MONITOR;
	if (strcmp(mode_str, "enforce") == 0)
		return LOTA_MODE_ENFORCE;
	return -1;
}

void print_usage(const char *prog, const char *default_bpf_path,
		 int default_verifier_port)
{
	printf("Usage: %s [options]\n", prog);
	printf("\n");
	printf("Options:\n");
	printf("  --config PATH     Configuration file path\n");
	printf("                    (default: %s)\n", LOTA_CONFIG_DEFAULT_PATH);
	printf("  --dump-config     Print loaded configuration and exit\n");
	printf("  --test-tpm        Report on TPM operations and exit.\n"
	       "                    Creates no persistent key: the quote is\n"
	       "                    skipped when the attestation handle is\n"
	       "                    free, since a key made here would\n"
	       "                    outlive the command\n");
	printf("  --test-iommu      Test IOMMU verification and exit\n");
	printf("  --seal            Seal a secret read from stdin to the PCR "
	       "state;\n");
	printf("                    write the sealed blob to stdout and exit. "
	       "Up to\n");
	printf("                    128 bytes seal directly; larger payloads "
	       "(<= 64\n");
	printf("                    KiB) use a TPM-sealed-KEK + AES-256-GCM "
	       "envelope\n");
	printf("  --unseal          Unseal a blob read from stdin; write the "
	       "secret\n");
	printf("                    to stdout and exit (fails closed if the "
	       "boot\n");
	printf("                    state differs from seal time)\n");
	printf("  --seal-pcrs MASK  PCR bitmask for --seal; default is 0x83, "
	       "the\n");
	printf("                    platform set, PCRs 0, 1 and 7. PCR 14 is "
	       "not in\n");
	printf("                    it: it is the agent's own boot commitment, "
	       "so 0x4083\n");
	printf("                    additionally binds the secret to this "
	       "agent\n");
	printf("                    binary and every upgrade then destroys "
	       "it\n");
	printf("  --seal-aik-auth   Seal the AIK userAuth to the current boot "
	       "state\n");
	printf("                    (adopt at-rest sealing without "
	       "re-enrolling)\n");
	printf("  --reprovision-aik Rotate + re-seal the AIK auth after a "
	       "boot-state\n");
	printf("                    change (strict recovery); then re-enroll\n");
	printf("  --seal-persist-primary\n");
	printf("                    Persist the seal storage primary at a handle "
	       "so\n");
	printf("                    seal/unseal skip per-op CreatePrimary (needs "
	       "\n");
	printf("                    seal_persistent_primary=true in lota.conf)\n");
	printf("  --seal-evict-primary\n");
	printf("                    Remove the persistent seal storage primary "
	       "(sealed\n");
	printf("                    blobs stay valid)\n");
	printf("  --test-ipc        Run IPC server with simulated attested "
	       "state\n");
	printf("                    (no TPM: status, D-Bus and profile "
	       "binding only,\n");
	printf("                    GET_TOKEN is refused -- use --test-signed "
	       "for\n");
	printf("                    tokens)\n");
	printf("  --test-signed     Run IPC server with TPM-signed tokens\n");
	printf("                    (requires TPM, for token verification "
	       "testing)\n");
	printf("  --shutdown        Request graceful shutdown via "
	       "authenticated IPC\n");
	printf("  --status          Print the running agent's mode, flags "
	       "and\n"
	       "                    attestation counts, as any caller of "
	       "the\n"
	       "                    socket sees them, and exit\n");
	printf("  --terminate-protected PID\n");
	printf("                    End a process that asked to be protected, "
	       "which\n");
	printf("                    no ordinary signal can reach. Sends "
	       "SIGTERM,\n");
	printf("                    or SIGKILL with --force. Allowed for the "
	       "owner\n");
	printf("                    of the process, or root, and reported to "
	       "the\n");
	printf("                    publisher until the host reboots\n");
	printf("  --export-policy   Export complete YAML policy from live "
	       "system\n");
	printf("                    (verifier-ready, pipe to file)\n");
	printf("  --attest          Attest to the configured verifier.\n");
	printf("                    With publisher profiles in the config this\n");
	printf("                    reports to every one of them on their own\n");
	printf("                    cadence and keeps running, because a single\n");
	printf("                    round against one verifier would leave the\n");
	printf("                    others unattested. With no profiles it is\n");
	printf("                    one round and exit\n");
	printf("  --enroll          Enroll the AIK with the attestation CA via\n");
	printf("                    credential activation and store the issued\n");
	printf("                    certificate, then exit\n");
	printf("  --reenroll        Re-enroll each publisher whose\n");
	printf("                    certificate does not name the key at\n");
	printf("                    its handle, with the endpoint and\n");
	printf("                    anchor its --enroll recorded, then exit\n");
	printf("  --publisher ID    With --reenroll: that publisher only.\n");
	printf("                    --ca-server, --ca-port and --ca-cert\n");
	printf("                    then override the recorded endpoint\n");
	printf("                    and anchor, for ones moved since\n");
	printf("  --ca-server HOST  Attestation CA address (required by "
	       "--enroll)\n");
	printf("  --ca-port PORT    Attestation CA port (default: %d)\n",
	       LOTA_DEFAULT_CA_PORT);
	printf("  --add-publisher HOST\n");
	printf("                    Write a publisher into the "
	       "configuration so a\n");
	printf("                    title of theirs can name it. HOST is "
	       "their\n");
	printf("                    attestation CA; --ca-cert gives their "
	       "trust\n");
	printf("                    anchor, --server/--port their verifier "
	       "(omit them\n");
	printf("                    for a publisher who runs none), and\n");
	printf("                    --publisher-name the label. Records no "
	       "consent:\n");
	printf("                    somebody at this machine still has to "
	       "run\n");
	printf("                    --allow-publisher\n");
	printf("  --publisher-name NAME\n");
	printf("                    Label for --add-publisher (default: a "
	       "prefix of\n");
	printf("                    the publisher identity)\n");
	printf("  --reporting MODE  For --add-publisher: session (default) "
	       "reports\n");
	printf("                    only while one of their titles runs, "
	       "continuous\n");
	printf("                    always, as an operator-owned fleet "
	       "wants\n");
	printf("  --allow-publisher HEX\n");
	printf("                    Record that this machine may answer to "
	       "one\n");
	printf("                    publisher, named by the SHA-256 of their "
	       "CA\n");
	printf("                    trust anchor's public key. Nothing "
	       "enrolls\n");
	printf("                    with a publisher before this\n");
	printf("  --list-publishers Show every publisher this machine "
	       "answers to,\n");
	printf("                    what it stores for each and when it was "
	       "agreed to\n");
	printf("  --forget-publisher HEX\n");
	printf("                    Destroy that publisher's attestation key "
	       "and\n");
	printf("                    everything stored for them. They can ask "
	       "again\n");
	printf("                    and would need consent and a new key\n");
	printf("  --enroll-token-file PATH\n");
	printf("                    File holding a per-tenant enrollment "
	       "token to\n");
	printf("                    present to the CA during --enroll "
	       "(the token,\n");
	printf("                    never the path, is reused by --reenroll "
	       "and\n");
	printf("                    certificate renewal)\n");
	printf("  --attest-interval SECS\n");
	printf("                    Continuous attestation interval in seconds\n");
	printf("                    (%d-%d; default 0: one-shot with --server "
	       "or the\n",
	       MIN_ATTEST_INTERVAL, MAX_ATTEST_INTERVAL);
	printf("                    file's server key, %d s with publishers or "
	       "none\n",
	       DEFAULT_ATTEST_INTERVAL);
	printf("                    named; above %d the minted tokens outlive "
	       "every\n",
	       MAX_ATTEST_INTERVAL);
	printf("                    relying party's freshness window)\n");
	printf("  --server HOST     Verifier server address (default: "
	       "none)\n");
	printf("  --port PORT       Verifier server port (default: %d)\n",
	       default_verifier_port);
	printf("  --ca-cert PATH    CA trust anchor, PEM or DER. Verifies the\n");
	printf("                    TLS peer (default: system CA store) and\n");
	printf("                    names the publisher profile the AIK\n");
	printf("                    certificate and enrollment record live\n");
	printf("                    in, so --enroll requires it\n");
	printf("  --no-verify-tls   Disable TLS certificate verification "
	       "(INSECURE)\n");
	printf("                    Only for development/testing!\n");
	printf("                    Requires: --insecure-allow-no-verify-tls\n");
	printf("  --insecure-allow-no-verify-tls\n");
	printf("                    Acknowledge the risk of --no-verify-tls\n");
	printf("  --pin-sha256 HEX  Pin verifier certificate by SHA-256 "
	       "fingerprint\n");
	printf("                    (64 hex chars, colons/spaces allowed)\n");
	printf("  --bpf PATH        Path to BPF object file\n");
	printf("                    (default: %s)\n", default_bpf_path);
	printf("  --mode MODE       Set enforcement mode:\n");
	printf("                      enforce - refuse what policy refuses "
	       "(default)\n");
	printf("                      monitor - log what policy would refuse\n");
	printf("                    The mode switches policy only; the agent\n");
	printf("                    and protected processes are guarded in both.\n");
	printf("                    A CLI --mode that weakens the configured\n");
	printf("                    'enforce' mode requires:\n");
	printf("                      --insecure-allow-mode-downgrade\n");
	printf("                    In every mode the agent refuses every signal\n");
	printf("                    that could end it, including from root, so\n");
	printf("                    --shutdown is the way to stop one -- and it\n");
	printf("                    spends the PCR 14 boot commitment, which\n");
	printf("                    means a reboot before the host attests\n");
	printf("                    again.\n");
	printf("  --insecure-allow-mode-downgrade\n");
	printf("                    Acknowledge that --mode weakens cfg.mode\n"
	       "                    'enforce' to monitor.\n");
	printf("  --insecure-allow-mutable-rootfs\n");
	printf("                    Start with a warning when /dev/tpm[rm]0\n"
	       "                    lacks the lota_tpm_device_t SELinux\n"
	       "                    label; another root domain can then\n"
	       "                    hold the TPM resource manager.\n");
	/* accepted in any mode, applied in enforce only */
	printf("  --strict-mmap     Block mmap(PROT_EXEC) of untrusted "
	       "libraries\n");
	printf("                    (no effect unless --mode enforce)\n");
	printf("  --strict-exec     Enforce strict executable policy (fs-verity "
	       "allowlist)\n");
	printf("                    (no effect unless --mode enforce; the "
	       "agent\n");
	printf("                    refuses to start without "
	       "--allow-verity)\n");
	printf("  --block-ptrace    Block all ptrace attach attempts\n");
	printf("                    (no effect unless --mode enforce)\n");
	printf("  --strict-modules  Enforce strict module/firmware loading "
	       "policy\n");
	printf("                    (no effect unless --mode enforce; the "
	       "agent\n");
	printf("                    refuses to start without "
	       "--allow-verity)\n");
	printf("  --block-anon-exec Block anonymous executable mappings\n");
	printf("                    (no effect unless --mode enforce)\n");
	printf("  --bench           Write the agent's cost to " LOTA_BENCH_PATH
	       "\n");
	printf("                    each second. Changes no policy; the status "
	       "word\n");
	printf("                    and the attestation report carry it\n");
	printf("  --protect-pid PID Seed this daemon's protected set with PID "
	       "(ptrace\n");
	printf("                    blocked). A startup option, not a request "
	       "to a\n");
	printf("                    daemon that is already running: on a host "
	       "with\n");
	printf("                    one up it does nothing. The process has to "
	       "be\n");
	printf("                    running when the agent starts, and a pid "
	       "that\n");
	printf("                    names none is refused before the boot "
	       "commitment\n");
	printf("                    is spent. A process protects itself "
	       "through the\n");
	printf("                    SDK, with lota_protect_self()\n");
	printf("  --trust-lib PATH  Add library path to trusted whitelist\n");
	printf("  --allow-verity PATH\n");
	printf("                    Allow a fs-verity protected file by digest\n");
	printf("  --daemon          Fork to background (not needed under "
	       "systemd)\n");
	printf("  --pid-file PATH   PID file location\n");
	printf("                    (default: %s)\n", DAEMON_DEFAULT_PID_FILE);
	printf("\nPolicy signing:\n");
	printf("  --gen-signing-key PREFIX\n");
	printf("                    Generate Ed25519 keypair: PREFIX.key + "
	       "PREFIX.pub\n");
	printf("  --sign-policy FILE --signing-key KEY\n");
	printf("                    Sign policy YAML, write detached FILE.sig\n");
	printf("  --verify-policy FILE --policy-pubkey PUB\n");
	printf("                    Verify detached Ed25519 signature on FILE\n");
	printf("  --signing-key PATH   Ed25519 private key (PEM) for signing\n");
	printf("  --policy-pubkey PATH Ed25519 public key (PEM) for "
	       "verification\n");
	printf("                    Reused for BOTH policy YAML signatures and\n");
	printf("                    BPF object signatures (.bpf.o.sig).\n");
	printf("                    Use a separate option/config if you want\n");
	printf("                    distinct keypairs for policy vs BPF.\n");
	printf("\n");
	printf("  --help            Show this help\n");
}

int handle_policy_ops(const struct policy_ops_args *args)
{
	if (!args)
		return -1;

	if (args->gen_signing_key_prefix) {
		char priv_path[PATH_MAX];
		char pub_path[PATH_MAX];
		int ret;

		snprintf(priv_path, sizeof(priv_path), "%s.key",
			 args->gen_signing_key_prefix);
		snprintf(pub_path, sizeof(pub_path), "%s.pub",
			 args->gen_signing_key_prefix);

		ret = policy_sign_generate_keypair(priv_path, pub_path);
		if (ret == -EEXIST) {
			struct stat st;

			fprintf(stderr,
				"Failed to generate keypair: %s already "
				"exists\n",
				lstat(priv_path, &st) == 0 ? priv_path :
							     pub_path);
			return 1;
		}
		if (ret < 0) {
			fprintf(stderr, "Failed to generate keypair: %s\n",
				strerror(-ret));
			return 1;
		}
		printf("Generated Ed25519 keypair:\n");
		printf("  Private key: %s\n", priv_path);
		printf("  Public key:  %s\n", pub_path);
		return 0;
	}

	if (args->sign_policy_file) {
		char sig_path[PATH_MAX];
		int ret;

		if (!args->signing_key_path) {
			fprintf(stderr,
				"--sign-policy requires --signing-key\n");
			return 1;
		}

		snprintf(sig_path, sizeof(sig_path), "%s.sig",
			 args->sign_policy_file);

		ret = policy_sign_file(args->sign_policy_file,
				       args->signing_key_path, sig_path);
		if (ret < 0) {
			fprintf(stderr, "Failed to sign policy: %s\n",
				strerror(-ret));
			return 1;
		}
		printf("Signed: %s\n", args->sign_policy_file);
		printf("Signature: %s\n", sig_path);
		return 0;
	}

	if (args->verify_policy_file) {
		char sig_path[PATH_MAX];
		int ret;

		if (!args->policy_pubkey_path) {
			fprintf(stderr,
				"--verify-policy requires --policy-pubkey\n");
			return 1;
		}

		snprintf(sig_path, sizeof(sig_path), "%s.sig",
			 args->verify_policy_file);

		ret = policy_verify_file(args->verify_policy_file,
					 args->policy_pubkey_path, sig_path);
		if (ret == 0) {
			printf("Signature valid: %s\n",
			       args->verify_policy_file);
			return 0;
		} else if (ret == -EKEYREJECTED) {
			fprintf(stderr, "Signature INVALID: %s\n",
				args->verify_policy_file);
			return 1;
		} else {
			fprintf(stderr, "Verification failed: %s\n",
				strerror(-ret));
			return 1;
		}
	}

	return -1; /* not handled */
}

void setup_dbus(struct ipc_context *ctx)
{
	agent_globals_lock(&g_agent);
	g_agent.dbus_ctx = dbus_init(ctx);
	agent_globals_unlock(&g_agent);
	if (g_agent.dbus_ctx)
		ipc_set_dbus(ctx, g_agent.dbus_ctx);
	else
		lota_warn("D-Bus unavailable, using socket IPC only");
}

/* config_load() refuses more UIDs than the IPC layer has slots for. */
_Static_assert(LOTA_CONFIG_MAX_CONTAINER_LISTENERS <= IPC_MAX_EXTRA_LISTENERS,
	       "container listener cap exceeds ipc extra-listener slots");

static int container_socket_paths(uint32_t uid, char *dir, size_t dirsz,
				  char *path, size_t pathsz)
{
	int n;

	n = snprintf(dir, dirsz, "%s/%u/%s", CONTAINER_WATCH_RUNTIME_ROOT, uid,
		     STEAM_RT_SOCKET_DIR_SUFFIX);
	if (n < 0 || (size_t)n >= dirsz)
		return -ENAMETOOLONG;

	n = snprintf(path, pathsz, "%s/%s", dir, STEAM_RT_SOCKET_NAME);
	if (n < 0 || (size_t)n >= pathsz)
		return -ENAMETOOLONG;

	if (strcmp(path, LOTA_IPC_SOCKET_PATH) == 0)
		return -EINVAL;

	return 0;
}

/* group every container socket directory is handed to; set before any bind */
static gid_t container_dir_gid = (gid_t)-1;

/*
 * Only the daemon, as root, hands the directory to the group.
 * An unprivileged agent has nothing to give and leaves it alone.
 * A missing group is said once here, not at every login.
 */
static int resolve_container_dir_gid(void)
{
	struct group *grp;

	container_dir_gid = (gid_t)-1;
	if (geteuid() != 0)
		return 0;

	grp = getgrnam(STEAM_RT_SOCKET_GROUP);
	if (!grp) {
		lota_err(
			"No '%s' group, so a container socket directory would be root-only and no title could reach the socket in it; no container socket will be served",
			STEAM_RT_SOCKET_GROUP);
		return -ENOENT;
	}
	container_dir_gid = grp->gr_gid;
	return 0;
}

static int add_listener_for_uid(uint32_t uid, void *user)
{
	struct ipc_context *ctx = user;
	char dir[PATH_MAX];
	char path[PATH_MAX];
	int ret;

	ret = container_socket_paths(uid, dir, sizeof(dir), path, sizeof(path));
	if (ret < 0)
		return ret;

	ret = steam_runtime_ensure_socket_dir(dir, container_dir_gid);
	if (ret < 0) {
		/* no login yet, or logind still mounting: the watch retries */
		if (!container_watch_bind_pending(ret))
			lota_err(
				"Cannot prepare the container socket dir %s (%s), so no title of uid %u can reach a socket in it",
				dir, strerror(-ret), uid);
		return ret;
	}

	ret = ipc_add_listener(ctx, path);
	if (ret == -EADDRINUSE) {
		fprintf(stderr,
			"Warning: %s is already served by another agent, so uid %u keeps that listener and this server has none\n",
			path, uid);
		return ret;
	}
	if (ret < 0) {
		if (!container_watch_bind_pending(ret))
			lota_err(
				"Cannot serve the container socket %s (%s), so no title of uid %u can reach the agent through it",
				path, strerror(-ret), uid);
		return ret;
	}

	lota_info("Container listener ready for uid %u at %s", uid, path);
	return 0;
}

/*
 * The socket file goes with the runtime directory logind removed, or under
 * a mount over it, so this releases the slot rather than the file.
 */
static void drop_listener_for_uid(uint32_t uid, void *user)
{
	struct ipc_context *ctx = user;
	char dir[PATH_MAX];
	char path[PATH_MAX];

	if (container_socket_paths(uid, dir, sizeof(dir), path, sizeof(path)) <
	    0)
		return;

	if (ipc_remove_listener(ctx, path) == 0)
		lota_info("Container listener for uid %u released", uid);
}

void setup_container_listener(struct ipc_context *ctx,
			      const struct lota_config *cfg)
{
	struct steam_runtime_info rt_info;
	uint32_t watch_uids[LOTA_CONFIG_MAX_CONTAINER_LISTENERS];
	char runtime_dir[PATH_MAX];
	char dir[PATH_MAX];
	char path[PATH_MAX];
	int watch_count;
	int ret;

	if (steam_runtime_runtime_dir(runtime_dir, sizeof(runtime_dir)) < 0)
		runtime_dir[0] = '\0';

	watch_count = container_watch_plan(
		cfg ? cfg->container_listener_uids : NULL,
		cfg ? cfg->container_listener_uid_count : 0,
		runtime_dir[0] ? runtime_dir : NULL, watch_uids,
		LOTA_CONFIG_MAX_CONTAINER_LISTENERS);

	if (watch_count < 0) {
		lota_err(
			"Cannot decide which logins get a container listener (%s); no container socket will be served",
			strerror(-watch_count));
		return;
	}

	if (watch_count > 0) {
		struct container_watch_ops ops = {
			.bind = add_listener_for_uid,
			.unbind = drop_listener_for_uid,
			.user = ctx,
		};

		if (resolve_container_dir_gid() < 0)
			return;

		/*
		 * The listener a Proton title connects to belongs to a login,
		 * and no one has logged in yet when the daemon starts.
		 * The watch outlives this call so the socket is laid down when
		 * the runtime directory appears.
		 */
		ret = container_watch_init(&g_agent.container_watch, NULL,
					   watch_uids, watch_count, &ops);
		if (ret < 0)
			lota_warn(
				"Cannot watch %s for logins (%s): a container socket "
				"will only appear for a user already logged in",
				CONTAINER_WATCH_RUNTIME_ROOT, strerror(-ret));

		ret = steam_runtime_detect(&rt_info);
		if (ret == 0 && (rt_info.env_flags & STEAM_ENV_STEAM_ACTIVE))
			steam_runtime_log_info(&rt_info);
		return;
	}

	/*
	 * A runtime directory outside /run/user/<uid> names no login to watch
	 * for, so this binds once.
	 */
	ret = steam_runtime_container_socket_dir(dir, sizeof(dir));
	if (ret < 0)
		return;

	ret = steam_runtime_container_socket_path(path, sizeof(path));
	if (ret < 0)
		return;

	if (strcmp(path, LOTA_IPC_SOCKET_PATH) == 0)
		return;

	if (resolve_container_dir_gid() < 0)
		return;

	ret = steam_runtime_ensure_socket_dir(dir, container_dir_gid);
	if (ret < 0) {
		lota_err(
			"Cannot create the container socket dir %s (%s), and this runtime directory names no login to wait for, so no container socket will appear until the agent is started again with the directory in place. A host whose runtime directory is %s/<uid> gets one when its user logs in; name the uid with container_listener_uid to have that watched explicitly",
			dir, strerror(-ret), CONTAINER_WATCH_RUNTIME_ROOT);
		return;
	}

	ret = ipc_add_listener(ctx, path);
	if (ret < 0) {
		lota_err(
			"Cannot serve the container socket %s (%s), so no title can reach the agent through it",
			path, strerror(-ret));
		return;
	}

	ret = steam_runtime_detect(&rt_info);
	if (ret == 0 && (rt_info.env_flags & STEAM_ENV_STEAM_ACTIVE))
		steam_runtime_log_info(&rt_info);
}

int ipc_init_or_activate(struct ipc_context *ctx)
{
	int n, fd, ret;

	n = sdnotify_listen_fds();
	if (n > 0) {
		for (fd = SD_LISTEN_FDS_START; fd < SD_LISTEN_FDS_START + n;
		     fd++) {
			if (sdnotify_is_unix_socket(fd)) {
				lota_info("Using socket-activated fd %d", fd);
				ret = ipc_init_activated(ctx, fd);
				if (ret == 0)
					return 0;
				lota_warn("Failed to use activated fd %d: %s",
					  fd, strerror(-ret));
			}
		}
		lota_warn("No suitable activated socket, creating own");
	}

	return ipc_init(ctx);
}

int self_measure(struct tpm_context *ctx)
{
	uint8_t self_hash[LOTA_HASH_SIZE];
	int fd;
	int ret;

	if (!ctx || !ctx->initialized)
		return -EINVAL;

	fd = open("/proc/self/exe", O_RDONLY);
	if (fd < 0)
		return -errno;

	ret = tpm_hash_fd(fd, self_hash);
	close(fd);
	if (ret < 0)
		return ret;

	/*
	 * Chained onto the value the initramfs lock helper left.
	 * No clock counter goes in: a TPM obfuscates resetCount and
	 * restartCount per signing key.
	 */
	ret = tpm_extend_boot_commitment(ctx, self_hash);
	if (ret < 0) {
		/* every refusal is -EBADMSG; the state names it */
		if (ret == -EBADMSG) {
			switch (ctx->boot_commitment_state) {
			case TPM_PCR14_BINARY_CHANGED:
				lota_err(
					"This is not the lota-agent build PCR 14 "
					"committed to when the host booted, so it "
					"cannot attest in this boot. Install this "
					"build and reboot; the register is not "
					"rewritable while the host is up.");
				break;
			case TPM_PCR14_SPENT_BY_SHUTDOWN:
				lota_err(
					"The agent is paused on this host: its "
					"boot commitment was spent by a "
					"shutdown requested here. Reboot to "
					"attest again.");
				break;
			case TPM_PCR14_LOCK_MISSING:
				lota_err(
					"PCR 14 never received the initramfs lock "
					"this boot, so there is nothing for the "
					"boot commitment to chain onto. See the "
					"preceding log for the dracut step.");
				break;
			case TPM_PCR14_HANDOFF_CHANGED:
				lota_err(
					"The initramfs baseline handoff on /run "
					"is not the one this boot's commitment "
					"was built on, so the derivation misses "
					"while PCR 14 itself agrees with what "
					"the agent recorded. Reboot to have the "
					"helper write the handoff again; see the "
					"preceding SECURITY log for the state "
					"that leaves the same evidence.");
				break;
			default:
				lota_err(
					"PCR14 boot-commitment refused; see the "
					"preceding SECURITY log for the exact "
					"recovery path.");
				break;
			}
		}
		return ret;
	}

	/* reports carry the committed hash even after the file is replaced */
	memcpy(ctx->self_hash, self_hash, LOTA_HASH_SIZE);
	ctx->self_hash_ready = true;

	return (int)tpm_boot_commitment_outcome(ctx->boot_commitment_state);
}
