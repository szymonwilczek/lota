/* SPDX-License-Identifier: MIT */
/*
 * LOTA Agent - Configuration file parser
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#include "config.h"
#include "tpm.h"

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int safe_parse_long(const char *s, long *out) {
  char *end;
  errno = 0;
  long v = strtol(s, &end, 10);
  if (errno != 0 || end == s || *end != '\0')
    return -1;
  *out = v;
  return 0;
}

/*
 * Trims leading and trailing whitespace in-place.
 * Returns pointer into the same buffer (no allocation).
 */
static char *trim(char *s) {
  char *end;

  while (*s && isspace((unsigned char)*s))
    s++;

  if (*s == '\0')
    return s;

  end = s + strlen(s) - 1;
  while (end > s && isspace((unsigned char)*end))
    *end-- = '\0';

  return s;
}

static bool parse_bool(const char *val) {
  return (strcmp(val, "true") == 0 || strcmp(val, "yes") == 0 ||
          strcmp(val, "1") == 0);
}

/*
 * Safe string copy into fixed-size buffer.
 * Always NUL-terminates.
 */
static void set_str(char *dst, size_t dst_size, const char *src) {
  size_t len = strlen(src);

  if (len >= dst_size)
    len = dst_size - 1;

  memcpy(dst, src, len);
  dst[len] = '\0';
}

void config_init(struct lota_config *cfg) {
  if (!cfg)
    return;

  memset(cfg, 0, sizeof(*cfg));

  set_str(cfg->server, sizeof(cfg->server), "localhost");
  cfg->port = 8443;
  cfg->no_verify_tls = false;

  set_str(cfg->bpf_path, sizeof(cfg->bpf_path), "/usr/lib/lota/lota_lsm.bpf.o");
  set_str(cfg->mode, sizeof(cfg->mode), "monitor");
  cfg->strict_mmap = false;
  cfg->block_ptrace = false;

  cfg->attest_interval = 0;
  cfg->aik_ttl = 0;
  cfg->aik_handle = TPM_AIK_HANDLE;

  cfg->daemon = false;
  set_str(cfg->pid_file, sizeof(cfg->pid_file), "/run/lota/lota-agent.pid");

  set_str(cfg->log_level, sizeof(cfg->log_level), "info");
}

/*
 * Apply a single key = value pair to the config struct.
 *
 * Returns:
 *   0  if the key was recognised and applied
 *   1  if the key was unknown (caller should warn)
 */
static int apply_key(struct lota_config *cfg, const char *key,
                     const char *value, const char *filepath, int lineno) {
  /* verifier connection */
  if (strcmp(key, "server") == 0) {
    set_str(cfg->server, sizeof(cfg->server), value);
    return 0;
  }
  if (strcmp(key, "port") == 0) {
    long v;
    if (safe_parse_long(value, &v) != 0 || v <= 0 || v > 65535) {
      fprintf(stderr, "%s:%d: invalid port '%s' (expected 1-65535)\n", filepath,
              lineno, value);
      return 0; /* keep current value, not a fatal error */
    }
    cfg->port = (int)v;
    return 0;
  }
  if (strcmp(key, "ca_cert") == 0 || strcmp(key, "ca-cert") == 0) {
    set_str(cfg->ca_cert, sizeof(cfg->ca_cert), value);
    return 0;
  }
  if (strcmp(key, "no_verify_tls") == 0 || strcmp(key, "no-verify-tls") == 0) {
    cfg->no_verify_tls = parse_bool(value);
    return 0;
  }
  if (strcmp(key, "pin_sha256") == 0 || strcmp(key, "pin-sha256") == 0) {
    set_str(cfg->pin_sha256, sizeof(cfg->pin_sha256), value);
    return 0;
  }

  /* bpf / enforcement */
  if (strcmp(key, "bpf_path") == 0 || strcmp(key, "bpf-path") == 0 ||
      strcmp(key, "bpf") == 0) {
    set_str(cfg->bpf_path, sizeof(cfg->bpf_path), value);
    return 0;
  }
  if (strcmp(key, "mode") == 0) {
    set_str(cfg->mode, sizeof(cfg->mode), value);
    return 0;
  }
  if (strcmp(key, "strict_mmap") == 0 || strcmp(key, "strict-mmap") == 0) {
    cfg->strict_mmap = parse_bool(value);
    return 0;
  }
  if (strcmp(key, "block_ptrace") == 0 || strcmp(key, "block-ptrace") == 0) {
    cfg->block_ptrace = parse_bool(value);
    return 0;
  }

  /* attestation */
  if (strcmp(key, "attest_interval") == 0 ||
      strcmp(key, "attest-interval") == 0) {
    long v;
    if (safe_parse_long(value, &v) != 0 || v < 0 || v > INT_MAX) {
      fprintf(stderr, "%s:%d: invalid attest_interval '%s'\n", filepath, lineno,
              value);
      return -1;
    }
    cfg->attest_interval = (int)v;
    return 0;
  }
  if (strcmp(key, "aik_ttl") == 0 || strcmp(key, "aik-ttl") == 0) {
    long v;
    if (safe_parse_long(value, &v) != 0 || v < 0 || v > (long)UINT32_MAX) {
      fprintf(stderr, "%s:%d: invalid aik_ttl '%s'\n", filepath, lineno, value);
      return -1;
    }
    cfg->aik_ttl = (uint32_t)v;
    return 0;
  }
  if (strcmp(key, "aik_handle") == 0 || strcmp(key, "aik-handle") == 0) {
    char *end;
    errno = 0;
    unsigned long v = strtoul(value, &end, 0);
    if (errno != 0 || end == value || *end != '\0' || v == 0 ||
        v > UINT32_MAX) {
      fprintf(stderr, "%s:%d: invalid aik_handle '%s'\n", filepath, lineno,
              value);
      return -1;
    }
    cfg->aik_handle = (uint32_t)v;
    return 0;
  }

  /* daemon */
  if (strcmp(key, "daemon") == 0) {
    cfg->daemon = parse_bool(value);
    return 0;
  }
  if (strcmp(key, "pid_file") == 0 || strcmp(key, "pid-file") == 0) {
    set_str(cfg->pid_file, sizeof(cfg->pid_file), value);
    return 0;
  }

  /* policy signing */
  if (strcmp(key, "signing_key") == 0 || strcmp(key, "signing-key") == 0) {
    set_str(cfg->signing_key, sizeof(cfg->signing_key), value);
    return 0;
  }
  if (strcmp(key, "policy_pubkey") == 0 || strcmp(key, "policy-pubkey") == 0) {
    set_str(cfg->policy_pubkey, sizeof(cfg->policy_pubkey), value);
    return 0;
  }

  /* lists */
  if (strcmp(key, "trust_lib") == 0 || strcmp(key, "trust-lib") == 0) {
    if (cfg->trust_lib_count < LOTA_CONFIG_MAX_LIBS) {
      set_str(cfg->trust_libs[cfg->trust_lib_count], sizeof(cfg->trust_libs[0]),
              value);
      cfg->trust_lib_count++;
    }
    return 0;
  }
  if (strcmp(key, "protect_pid") == 0 || strcmp(key, "protect-pid") == 0) {
    if (cfg->protect_pid_count >= LOTA_CONFIG_MAX_PIDS) {
      fprintf(stderr, "%s:%d: protect_pid limit (%d) exceeded\n", filepath,
              lineno, LOTA_CONFIG_MAX_PIDS);
      return -1;
    }
    long v;
    if (safe_parse_long(value, &v) != 0 || v <= 0 || v > (long)UINT32_MAX) {
      fprintf(stderr, "%s:%d: invalid protect_pid '%s'\n", filepath, lineno,
              value);
      return -1;
    }
    cfg->protect_pids[cfg->protect_pid_count++] = (uint32_t)v;
    return 0;
  }

  /* logging */
  if (strcmp(key, "log_level") == 0 || strcmp(key, "log-level") == 0) {
    set_str(cfg->log_level, sizeof(cfg->log_level), value);
    return 0;
  }

  return 1; /* unknown key */
}

int config_load(struct lota_config *cfg, const char *path) {
  FILE *f;
  char line[LOTA_CONFIG_MAX_LINE];
  int lineno = 0;
  int errors = 0;
  const char *filepath;

  if (!cfg)
    return -EINVAL;

  filepath = path ? path : LOTA_CONFIG_DEFAULT_PATH;

  f = fopen(filepath, "r");
  if (!f)
    return -errno;

  while (fgets(line, sizeof(line), f)) {
    char *trimmed;
    char *eq;
    char *key;
    char *value;
    size_t len;

    lineno++;

    len = strlen(line);
    if (len > 0 && line[len - 1] != '\n' && !feof(f)) {
      int ch;
      fprintf(stderr, "%s:%d: line exceeds %d characters, skipping\n", filepath,
              lineno, LOTA_CONFIG_MAX_LINE - 1);
      errors++;
      while ((ch = fgetc(f)) != EOF && ch != '\n')
        ;
      continue;
    }

    trimmed = trim(line);

    if (*trimmed == '\0' || *trimmed == '#')
      continue;

    eq = strchr(trimmed, '=');
    if (!eq) {
      fprintf(stderr, "%s:%d: malformed line (no '=' separator)\n", filepath,
              lineno);
      errors++;
      continue;
    }

    *eq = '\0';
    key = trim(trimmed);
    value = trim(eq + 1);

    if (*key == '\0') {
      fprintf(stderr, "%s:%d: empty key\n", filepath, lineno);
      errors++;
      continue;
    }

    int ret = apply_key(cfg, key, value, filepath, lineno);
    if (ret == 1) {
      fprintf(stderr, "%s:%d: unknown key '%s'\n", filepath, lineno, key);
    } else if (ret < 0) {
      errors++;
    }
  }

  fclose(f);

  return errors > 0 ? -EINVAL : 0;
}

void config_dump(const struct lota_config *cfg, FILE *fp) {
  if (!cfg || !fp)
    return;

  fprintf(fp, "# LOTA Agent effective configuration\n\n");

  fprintf(fp, "# Verifier connection\n");
  fprintf(fp, "server = %s\n", cfg->server);
  fprintf(fp, "port = %d\n", cfg->port);
  if (cfg->ca_cert[0])
    fprintf(fp, "ca_cert = %s\n", cfg->ca_cert);
  fprintf(fp, "no_verify_tls = %s\n", cfg->no_verify_tls ? "true" : "false");
  if (cfg->pin_sha256[0])
    fprintf(fp, "pin_sha256 = %s\n", cfg->pin_sha256);

  fprintf(fp, "\n# BPF / enforcement\n");
  fprintf(fp, "bpf_path = %s\n", cfg->bpf_path);
  fprintf(fp, "mode = %s\n", cfg->mode);
  fprintf(fp, "strict_mmap = %s\n", cfg->strict_mmap ? "true" : "false");
  fprintf(fp, "block_ptrace = %s\n", cfg->block_ptrace ? "true" : "false");

  fprintf(fp, "\n# Attestation\n");
  fprintf(fp, "attest_interval = %d\n", cfg->attest_interval);
  fprintf(fp, "aik_ttl = %u\n", cfg->aik_ttl);
  fprintf(fp, "aik_handle = 0x%08X\n", cfg->aik_handle);

  fprintf(fp, "\n# Daemon\n");
  fprintf(fp, "daemon = %s\n", cfg->daemon ? "true" : "false");
  fprintf(fp, "pid_file = %s\n", cfg->pid_file);

  fprintf(fp, "\n# Policy signing\n");
  if (cfg->signing_key[0])
    fprintf(fp, "signing_key = %s\n", cfg->signing_key);
  if (cfg->policy_pubkey[0])
    fprintf(fp, "policy_pubkey = %s\n", cfg->policy_pubkey);

  fprintf(fp, "\n# Logging\n");
  fprintf(fp, "log_level = %s\n", cfg->log_level);

  if (cfg->trust_lib_count > 0) {
    fprintf(fp, "\n# Trusted libraries\n");
    for (int i = 0; i < cfg->trust_lib_count; i++)
      fprintf(fp, "trust_lib = %s\n", cfg->trust_libs[i]);
  }

  if (cfg->protect_pid_count > 0) {
    fprintf(fp, "\n# Protected PIDs\n");
    for (int i = 0; i < cfg->protect_pid_count; i++)
      fprintf(fp, "protect_pid = %u\n", cfg->protect_pids[i]);
  }
}
