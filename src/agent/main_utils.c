/* SPDX-License-Identifier: MIT */

#include "main_utils.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../../include/lota.h"
#include "../../include/lota_ipc.h"
#include "agent.h"
#include "attest.h"
#include "config.h"
#include "daemon.h"
#include "dbus.h"
#include "journal.h"
#include "policy_sign.h"
#include "sdnotify.h"
#include "steam_runtime.h"

#ifndef EAUTH
#define EAUTH 80
#endif

extern struct dbus_context *g_dbus_ctx;

const char *mode_to_string(int mode) {
  switch (mode) {
  case LOTA_MODE_MAINTENANCE:
    return "MAINTENANCE";
  case LOTA_MODE_MONITOR:
    return "MONITOR";
  case LOTA_MODE_ENFORCE:
    return "ENFORCE";
  default:
    return "UNKNOWN";
  }
}

int parse_mode(const char *mode_str) {
  if (strcmp(mode_str, "monitor") == 0)
    return LOTA_MODE_MONITOR;
  if (strcmp(mode_str, "enforce") == 0)
    return LOTA_MODE_ENFORCE;
  if (strcmp(mode_str, "maintenance") == 0)
    return LOTA_MODE_MAINTENANCE;
  return -1;
}

void print_usage(const char *prog, const char *default_bpf_path,
                 int default_verifier_port) {
  printf("Usage: %s [options]\n", prog);
  printf("\n");
  printf("Options:\n");
  printf("  --config PATH     Configuration file path\n");
  printf("                    (default: %s)\n", LOTA_CONFIG_DEFAULT_PATH);
  printf("  --dump-config     Print loaded configuration and exit\n");
  printf("  --test-tpm        Test TPM operations and exit\n");
  printf("  --test-iommu      Test IOMMU verification and exit\n");
  printf("  --test-ipc        Run IPC server with simulated attested state\n");
  printf("                    (unsigned tokens, for protocol testing)\n");
  printf("  --test-signed     Run IPC server with TPM-signed tokens\n");
  printf(
      "                    (requires TPM, for token verification testing)\n");
  printf("  --export-policy   Export complete YAML policy from live system\n");
  printf("                    (verifier-ready, pipe to file)\n");
  printf("  --attest          Perform remote attestation and exit\n");
  printf("  --attest-interval SECS\n");
  printf("                    Continuous attestation interval in seconds\n");
  printf("                    (default: 0=one-shot, min: %d for continuous)\n",
         MIN_ATTEST_INTERVAL);
  printf("  --server HOST     Verifier server address (default: localhost)\n");
  printf("  --port PORT       Verifier server port (default: %d)\n",
         default_verifier_port);
  printf("  --ca-cert PATH    CA certificate for verifier TLS verification\n");
  printf("                    (default: use system CA store)\n");
  printf(
      "  --no-verify-tls   Disable TLS certificate verification (INSECURE)\n");
  printf("                    Only for development/testing!\n");
  printf("  --pin-sha256 HEX  Pin verifier certificate by SHA-256 "
         "fingerprint\n");
  printf("                    (64 hex chars, colons/spaces allowed)\n");
  printf("  --bpf PATH        Path to BPF object file\n");
  printf("                    (default: %s)\n", default_bpf_path);
  printf("  --mode MODE       Set enforcement mode:\n");
  printf("                      monitor     - log events only (default)\n");
  printf("                      enforce     - block unauthorized modules\n");
  printf("                      maintenance - allow all, minimal logging\n");
  printf("  --strict-mmap     Block mmap(PROT_EXEC) of untrusted libraries\n");
  printf("                    (requires --mode enforce)\n");
  printf("  --block-ptrace    Block all ptrace attach attempts\n");
  printf("                    (requires --mode enforce)\n");
  printf("  --strict-modules  Enforce strict module/firmware loading policy\n");
  printf("                    (requires --mode enforce)\n");
  printf("  --block-anon-exec Block anonymous executable mappings\n");
  printf("                    (requires --mode enforce)\n");
  printf("  --protect-pid PID Add PID to protected set (ptrace blocked)\n");
  printf("  --trust-lib PATH  Add library path to trusted whitelist\n");
  printf("  --daemon          Fork to background (not needed under systemd)\n");
  printf("  --pid-file PATH   PID file location\n");
  printf("                    (default: %s)\n", DAEMON_DEFAULT_PID_FILE);
  printf("  --aik-ttl SECS    AIK key lifetime in seconds before rotation\n");
  printf("                    (default: 30 days, min: 3600)\n");
  printf("\nPolicy signing:\n");
  printf("  --gen-signing-key PREFIX\n");
  printf("                    Generate Ed25519 keypair: PREFIX.key + "
         "PREFIX.pub\n");
  printf("  --sign-policy FILE --signing-key KEY\n");
  printf("                    Sign policy YAML, write detached FILE.sig\n");
  printf("  --verify-policy FILE --policy-pubkey PUB\n");
  printf("                    Verify detached Ed25519 signature on FILE\n");
  printf("  --signing-key PATH   Ed25519 private key (PEM) for signing\n");
  printf("  --policy-pubkey PATH Ed25519 public key (PEM) for verification\n");
  printf("\n");
  printf("  --help            Show this help\n");
}

int handle_policy_ops(const char *gen_signing_key_prefix,
                      const char *sign_policy_file,
                      const char *verify_policy_file,
                      const char *signing_key_path,
                      const char *policy_pubkey_path) {
  if (gen_signing_key_prefix) {
    char priv_path[PATH_MAX];
    char pub_path[PATH_MAX];
    int ret;

    snprintf(priv_path, sizeof(priv_path), "%s.key", gen_signing_key_prefix);
    snprintf(pub_path, sizeof(pub_path), "%s.pub", gen_signing_key_prefix);

    ret = policy_sign_generate_keypair(priv_path, pub_path);
    if (ret < 0) {
      fprintf(stderr, "Failed to generate keypair: %s\n", strerror(-ret));
      return 1;
    }
    printf("Generated Ed25519 keypair:\n");
    printf("  Private key: %s\n", priv_path);
    printf("  Public key:  %s\n", pub_path);
    return 0;
  }

  if (sign_policy_file) {
    char sig_path[PATH_MAX];
    int ret;

    if (!signing_key_path) {
      fprintf(stderr, "--sign-policy requires --signing-key\n");
      return 1;
    }

    snprintf(sig_path, sizeof(sig_path), "%s.sig", sign_policy_file);

    ret = policy_sign_file(sign_policy_file, signing_key_path, sig_path);
    if (ret < 0) {
      fprintf(stderr, "Failed to sign policy: %s\n", strerror(-ret));
      return 1;
    }
    printf("Signed: %s\n", sign_policy_file);
    printf("Signature: %s\n", sig_path);
    return 0;
  }

  if (verify_policy_file) {
    char sig_path[PATH_MAX];
    int ret;

    if (!policy_pubkey_path) {
      fprintf(stderr, "--verify-policy requires --policy-pubkey\n");
      return 1;
    }

    snprintf(sig_path, sizeof(sig_path), "%s.sig", verify_policy_file);

    ret = policy_verify_file(verify_policy_file, policy_pubkey_path, sig_path);
    if (ret == 0) {
      printf("Signature valid: %s\n", verify_policy_file);
      return 0;
    } else if (ret == -EAUTH) {
      fprintf(stderr, "Signature INVALID: %s\n", verify_policy_file);
      return 1;
    } else {
      fprintf(stderr, "Verification failed: %s\n", strerror(-ret));
      return 1;
    }
  }

  return -1; /* not handled */
}

void setup_dbus(struct ipc_context *ctx) {
  g_dbus_ctx = dbus_init(ctx);
  if (g_dbus_ctx)
    ipc_set_dbus(ctx, g_dbus_ctx);
  else
    lota_warn("D-Bus unavailable, using socket IPC only");
}

void setup_container_listener(struct ipc_context *ctx) {
  char dir[PATH_MAX];
  char path[PATH_MAX];
  struct steam_runtime_info rt_info;
  int ret;

  ret = steam_runtime_container_socket_dir(dir, sizeof(dir));
  if (ret < 0)
    return; /* XDG_RUNTIME_DIR not set, nothing to do */

  ret = steam_runtime_container_socket_path(path, sizeof(path));
  if (ret < 0)
    return;

  if (strcmp(path, LOTA_IPC_SOCKET_PATH) == 0)
    return;

  ret = steam_runtime_ensure_socket_dir(dir);
  if (ret < 0) {
    fprintf(stderr, "Warning: cannot create container socket dir %s: %s\n", dir,
            strerror(-ret));
    return;
  }

  ret = ipc_add_listener(ctx, path);
  if (ret < 0) {
    fprintf(stderr, "Warning: container listener %s: %s\n", path,
            strerror(-ret));
    return;
  }

  /* log detected Steam Runtime environment */
  ret = steam_runtime_detect(&rt_info);
  if (ret == 0 && (rt_info.env_flags & STEAM_ENV_STEAM_ACTIVE))
    steam_runtime_log_info(&rt_info);
}

int ipc_init_or_activate(struct ipc_context *ctx) {
  int n, fd, ret;

  n = sdnotify_listen_fds();
  if (n > 0) {
    for (fd = SD_LISTEN_FDS_START; fd < SD_LISTEN_FDS_START + n; fd++) {
      if (sdnotify_is_unix_socket(fd)) {
        lota_info("Using socket-activated fd %d", fd);
        ret = ipc_init_activated(ctx, fd);
        if (ret == 0)
          return 0;
        lota_warn("Failed to use activated fd %d: %s", fd, strerror(-ret));
      }
    }
    lota_warn("No suitable activated socket, creating own");
  }

  return ipc_init(ctx);
}

int self_measure(struct tpm_context *ctx) {
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

  ret = tpm_pcr_extend(ctx, LOTA_PCR_SELF, self_hash);
  if (ret < 0)
    return ret;

  return 0;
}
