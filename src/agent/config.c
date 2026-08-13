/* SPDX-License-Identifier: MIT */
/*
 * LOTA Agent - Configuration file parser
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#include "config.h"
#include "io_utils.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/types.h>

#include "attest.h"
#include "lota.h"
#include "parse_utils.h"
#include "path_validate.h"
#include "tpm.h"

/*
 * Trims leading and trailing whitespace in-place.
 * Returns pointer into the same buffer (no allocation).
 */
static char *trim(char *s)
{
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

static int parse_bool_strict(const char *val, bool *out)
{
	if (!val || !out)
		return -1;

	if (strcmp(val, "true") == 0 || strcmp(val, "yes") == 0 ||
	    strcmp(val, "1") == 0) {
		*out = true;
		return 0;
	}

	if (strcmp(val, "false") == 0 || strcmp(val, "no") == 0 ||
	    strcmp(val, "0") == 0) {
		*out = false;
		return 0;
	}

	return -1;
}

static int parse_mode_strict(const char *value)
{
	if (!value)
		return -1;

	if (strcmp(value, "monitor") == 0 || strcmp(value, "enforce") == 0 ||
	    strcmp(value, "maintenance") == 0)
		return 0;

	return -1;
}

/*
 * Safe string copy into fixed-size buffer.
 * Always NUL-terminates.
 */
static void set_str(char *dst, size_t dst_size, const char *src)
{
	size_t len = strlen(src);

	if (len >= dst_size)
		len = dst_size - 1;

	memcpy(dst, src, len);
	dst[len] = '\0';
}

static int validate_path_value(const char *key, const char *value,
			       const char *filepath, int lineno)
{
	if (!key || !value)
		return -1;

	/* allow clearing optional fields by setting empty value */
	if (value[0] == '\0')
		return 0;

	if (lota_str_has_control(value)) {
		fprintf(stderr,
			"%s:%d: invalid %s: contains control characters\n",
			filepath, lineno, key);
		return -1;
	}

	if (!lota_path_is_abs(value)) {
		fprintf(stderr, "%s:%d: invalid %s: expected absolute path\n",
			filepath, lineno, key);
		return -1;
	}

	if (lota_path_has_dotdot_segment(value)) {
		fprintf(stderr,
			"%s:%d: invalid %s: '..' path traversal is not allowed\n",
			filepath, lineno, key);
		return -1;
	}

	/*
	 * Note: this validates only the path string shape.
	 * It intentionally does not canonicalize (realpath) or resolve
	 * symlinks. Callers that treat these files as security boundaries
	 * should open them safely (e.g. O_NOFOLLOW + fstat) and/or rely on
	 * higher-level trust models (fs-verity / measured boot / remote
	 * attestation).
	 */

	return 0;
}

static int config_validate_file_security(int fd, const char *filepath)
{
	struct stat st;
	uid_t euid;

	if (fd < 0 || !filepath)
		return -EINVAL;
	if (fstat(fd, &st) != 0)
		return -errno;

	if (!S_ISREG(st.st_mode)) {
		fprintf(stderr, "%s: config must be a regular file\n",
			filepath);
		return -EINVAL;
	}

	euid = geteuid();

	if (st.st_mode & (S_IWGRP | S_IWOTH)) {
		fprintf(stderr,
			"%s: refusing to load group/world-writable config "
			"(mode %o)\n",
			filepath, (unsigned)(st.st_mode & 0777));
		return -EPERM;
	}

	/*
	 * Ownership policy:
	 * - root agent: config must be root-owned
	 * - non-root agent: config must be owned by current euid or by root
	 */
	if (euid == 0) {
		if (st.st_uid != 0) {
			fprintf(stderr,
				"%s: refusing to load config not owned by root\n",
				filepath);
			return -EPERM;
		}
	} else {
		if (st.st_uid != euid && st.st_uid != 0) {
			fprintf(stderr,
				"%s: refusing to load config not owned by "
				"current user/root\n",
				filepath);
			return -EPERM;
		}
	}

	return 0;
}

void config_init(struct lota_config *cfg)
{
	if (!cfg)
		return;

	memset(cfg, 0, sizeof(*cfg));

	set_str(cfg->server, sizeof(cfg->server), "localhost");
	cfg->port = LOTA_DEFAULT_VERIFIER_PORT;

	cfg->allow_verity_count = 0;
	set_str(cfg->bpf_path, sizeof(cfg->bpf_path),
		"/usr/lib/lota/lota_lsm.bpf.o");
	set_str(cfg->mode, sizeof(cfg->mode), "enforce");
	cfg->strict_mmap = true;
	/*
	 * strict_exec and strict_modules require at least one
	 * allow_verity entry (startup_policy.c::apply_startup_policy)
	 * because both gates check the BPF allowlist before honouring
	 * an exec / kernel_read_file. A fresh install has no
	 * allow_verity entries until the operator runs the fs-verity
	 * provisioning step, so defaulting either flag to true bricks
	 * the agent on first start. Operators opt into strict mode by
	 * setting strict_exec / strict_modules = true in
	 * /etc/lota/lota.conf alongside the allow_verity list.
	 */
	cfg->strict_exec = false;
	cfg->block_ptrace = true;
	cfg->strict_modules = false;
	cfg->block_anon_exec = true;
	cfg->seal_aik_auth = false;
	cfg->seal_aik_auth_strict = false;
	cfg->seal_persistent_primary = false;

	cfg->attest_interval = 0;
	cfg->aik_ttl = 0;
	cfg->aik_handle = TPM_AIK_HANDLE;

	cfg->daemon = false;
	set_str(cfg->pid_file, sizeof(cfg->pid_file),
		"/run/lota/lota-agent.pid");

	cfg->protect_pid_count = 0;
	cfg->profile_count = 0;

	set_str(cfg->log_level, sizeof(cfg->log_level), "info");
}

/*
 * Shared by the top-level attest_interval and the per-profile interval:
 * 0 has a meaning at each level, anything else has to sit between the bounds
 * the attestation loop can actually mint verifiable tokens within.
 */
static int check_attest_interval(long v, const char *key, const char *filepath,
				 int lineno)
{
	if (v == 0 || (v >= MIN_ATTEST_INTERVAL && v <= MAX_ATTEST_INTERVAL))
		return 0;

	fprintf(stderr,
		"%s:%d: %s %ld out of range (0 or %d-%d; above %d the minted "
		"tokens outlive every relying party's freshness window)\n",
		filepath, lineno, key, v, MIN_ATTEST_INTERVAL,
		MAX_ATTEST_INTERVAL, MAX_ATTEST_INTERVAL);
	return -1;
}

/*
 * Apply a single key = value pair to the profile a [profile "name"] header
 * opened.
 *
 * Returns 0 applied, 1 unknown key, -1 invalid value.
 * Top-level key used inside profile section lands here as unknown, which is
 * the fail-closed answer: the operator meant one of the two and the file
 * cannot say which.
 */
static int apply_profile_key(struct lota_profile *p, const char *key,
			     const char *value, const char *filepath,
			     int lineno)
{
	if (strcmp(key, "ca") == 0) {
		set_str(p->ca, sizeof(p->ca), value);
		return 0;
	}
	if (strcmp(key, "ca_port") == 0 || strcmp(key, "ca-port") == 0) {
		long v;
		if (safe_parse_long(value, &v) != 0 || v <= 0 || v > 65535) {
			fprintf(stderr,
				"%s:%d: invalid ca_port '%s' (expected 1-65535)\n",
				filepath, lineno, value);
			return -1;
		}
		p->ca_port = (int)v;
		return 0;
	}
	if (strcmp(key, "ca_cert") == 0 || strcmp(key, "ca-cert") == 0) {
		if (validate_path_value("ca_cert", value, filepath, lineno) !=
		    0)
			return -1;
		set_str(p->ca_cert, sizeof(p->ca_cert), value);
		return 0;
	}
	if (strcmp(key, "verifier") == 0) {
		/*
		 * Publisher verifies tokens in their own backend
		 * and runs no verifier here.
		 * Spelled out rather than inferred from absent key,
		 * so a typo stays a refused config.
		 */
		if (strcmp(value, "none") == 0) {
			p->token_only = true;
			p->verifier[0] = '\0';
			return 0;
		}
		p->token_only = false;
		set_str(p->verifier, sizeof(p->verifier), value);
		return 0;
	}
	if (strcmp(key, "verifier_port") == 0 ||
	    strcmp(key, "verifier-port") == 0) {
		long v;
		if (safe_parse_long(value, &v) != 0 || v <= 0 || v > 65535) {
			fprintf(stderr,
				"%s:%d: invalid verifier_port '%s' (expected "
				"1-65535)\n",
				filepath, lineno, value);
			return -1;
		}
		p->verifier_port = (int)v;
		return 0;
	}
	if (strcmp(key, "reporting") == 0) {
		if (strcmp(value, "session") == 0) {
			p->session_gated = true;
			return 0;
		}
		if (strcmp(value, "continuous") == 0) {
			p->session_gated = false;
			return 0;
		}
		fprintf(stderr,
			"%s:%d: invalid reporting '%s' (expected session or "
			"continuous)\n",
			filepath, lineno, value);
		return -1;
	}
	if (strcmp(key, "interval") == 0) {
		long v;
		if (safe_parse_long(value, &v) != 0 || v < 0 || v > INT_MAX) {
			fprintf(stderr, "%s:%d: invalid interval '%s'\n",
				filepath, lineno, value);
			return -1;
		}
		if (check_attest_interval(v, "interval", filepath, lineno) != 0)
			return -1;
		p->attest_interval = (int)v;
		return 0;
	}

	return 1;
}

/*
 * Parse a [profile "name"] header and open the profile it names.
 *
 * @line is the trimmed line, known to start with '['.
 * Returns 0 with *out set, or -1 with a reason on stderr.
 */
static int open_profile_section(struct lota_config *cfg, char *line,
				const char *filepath, int lineno,
				struct lota_profile **out)
{
	static const char kw[] = "profile";
	char *p = line + 1;
	char *name;
	char *end;
	struct lota_profile *prof;

	while (*p == ' ' || *p == '\t')
		p++;

	if (strncmp(p, kw, sizeof(kw) - 1) != 0) {
		fprintf(stderr, "%s:%d: unknown section header '%s'\n",
			filepath, lineno, line);
		return -1;
	}
	p += sizeof(kw) - 1;

	while (*p == ' ' || *p == '\t')
		p++;

	if (*p != '"') {
		fprintf(stderr,
			"%s:%d: malformed profile header (expected [profile "
			"\"name\"])\n",
			filepath, lineno);
		return -1;
	}
	name = ++p;

	end = strchr(name, '"');
	if (!end) {
		fprintf(stderr, "%s:%d: unterminated profile name\n", filepath,
			lineno);
		return -1;
	}
	*end++ = '\0';

	while (*end == ' ' || *end == '\t')
		end++;
	if (strcmp(end, "]") != 0) {
		fprintf(stderr,
			"%s:%d: trailing content after profile header\n",
			filepath, lineno);
		return -1;
	}

	if (name[0] == '\0' || strlen(name) >= LOTA_CONFIG_MAX_PROFILE_NAME) {
		fprintf(stderr, "%s:%d: profile name must be 1-%d characters\n",
			filepath, lineno, LOTA_CONFIG_MAX_PROFILE_NAME - 1);
		return -1;
	}
	if (lota_str_has_control(name)) {
		fprintf(stderr,
			"%s:%d: profile name contains control characters\n",
			filepath, lineno);
		return -1;
	}

	for (int i = 0; i < cfg->profile_count; i++) {
		if (strcmp(cfg->profiles[i].name, name) == 0) {
			fprintf(stderr, "%s:%d: duplicate profile '%s'\n",
				filepath, lineno, name);
			return -1;
		}
	}

	if (cfg->profile_count >= LOTA_CONFIG_MAX_PROFILES) {
		fprintf(stderr, "%s:%d: too many profiles (max %d)\n", filepath,
			lineno, LOTA_CONFIG_MAX_PROFILES);
		return -1;
	}

	prof = &cfg->profiles[cfg->profile_count++];
	memset(prof, 0, sizeof(*prof));
	set_str(prof->name, sizeof(prof->name), name);
	prof->ca_port = LOTA_DEFAULT_CA_PORT;
	prof->verifier_port = LOTA_DEFAULT_VERIFIER_PORT;
	prof->session_gated = true;

	*out = prof;
	return 0;
}

/*
 * Profile that names no CA, no anchor or no verifier cannot enroll or report,
 * and the identity everything else will be keyed by is derived from the anchor.
 * Incomplete is refused rather than half-configured.
 */
static int validate_profiles(const struct lota_config *cfg,
			     const char *filepath)
{
	int errors = 0;

	for (int i = 0; i < cfg->profile_count; i++) {
		const struct lota_profile *p = &cfg->profiles[i];
		const char *missing = NULL;

		if (p->ca[0] == '\0')
			missing = "ca";
		else if (p->ca_cert[0] == '\0')
			missing = "ca_cert";
		else if (p->verifier[0] == '\0' && !p->token_only)
			missing = "verifier";

		if (missing) {
			fprintf(stderr, "%s: profile '%s' is missing %s\n",
				filepath, p->name, missing);
			errors++;
		}

		/*
		 * Port for a verifier that was declared absent is a contradiction,
		 * and ignoring the key an operator deliberately wrote is worse
		 * than refusing it.
		 */
		if (p->token_only &&
		    p->verifier_port != LOTA_DEFAULT_VERIFIER_PORT) {
			fprintf(stderr,
				"%s: profile '%s' says verifier = none and "
				"still sets verifier_port\n",
				filepath, p->name);
			errors++;
		}
	}

	return errors;
}

/*
 * Apply a single key = value pair to the config struct.
 *
 * Returns:
 *   0  if the key was recognised and applied
 *   1  if the key was unknown (caller should warn)
 */
static int apply_key(struct lota_config *cfg, const char *key,
		     const char *value, const char *filepath, int lineno)
{
	/* verifier connection */
	if (strcmp(key, "server") == 0) {
		set_str(cfg->server, sizeof(cfg->server), value);
		return 0;
	}
	if (strcmp(key, "port") == 0) {
		long v;
		if (safe_parse_long(value, &v) != 0 || v <= 0 || v > 65535) {
			fprintf(stderr,
				"%s:%d: invalid port '%s' (expected 1-65535)\n",
				filepath, lineno, value);
			return -1;
		}
		cfg->port = (int)v;
		return 0;
	}
	if (strcmp(key, "ca_cert") == 0 || strcmp(key, "ca-cert") == 0) {
		if (validate_path_value("ca_cert", value, filepath, lineno) !=
		    0)
			return -1;
		set_str(cfg->ca_cert, sizeof(cfg->ca_cert), value);
		return 0;
	}
	if (strcmp(key, "no_verify_tls") == 0 ||
	    strcmp(key, "no-verify-tls") == 0) {
		fprintf(stderr,
			"%s:%d: no_verify_tls is a security-critical option "
			"and cannot\n"
			"be set via config file. Use --no-verify-tls CLI flag "
			"instead.\n",
			filepath, lineno);
		return -1;
	}
	if (strcmp(key, "pin_sha256") == 0 || strcmp(key, "pin-sha256") == 0) {
		set_str(cfg->pin_sha256, sizeof(cfg->pin_sha256), value);
		return 0;
	}

	if (strcmp(key, "allow_verity") == 0 ||
	    strcmp(key, "allow-verity") == 0) {
		if (cfg->allow_verity_count >= LOTA_CONFIG_MAX_VERITY) {
			fprintf(stderr,
				"%s:%d: too many allow_verity entries (max %d)\n",
				filepath, lineno, LOTA_CONFIG_MAX_VERITY);
			return -1;
		}

		if (validate_path_value("allow_verity", value, filepath,
					lineno) != 0)
			return -1;
		set_str(cfg->allow_verity[cfg->allow_verity_count],
			sizeof(cfg->allow_verity[0]), value);
		cfg->allow_verity_count++;
		return 0;
	}
	/* bpf / enforcement */
	if (strcmp(key, "bpf_path") == 0 || strcmp(key, "bpf-path") == 0 ||
	    strcmp(key, "bpf") == 0) {
		if (validate_path_value("bpf_path", value, filepath, lineno) !=
		    0)
			return -1;
		set_str(cfg->bpf_path, sizeof(cfg->bpf_path), value);
		return 0;
	}
	if (strcmp(key, "mode") == 0) {
		if (parse_mode_strict(value) != 0) {
			fprintf(stderr,
				"%s:%d: invalid mode '%s' (valid: "
				"monitor/enforce/maintenance)\n",
				filepath, lineno, value);
			return -1;
		}
		set_str(cfg->mode, sizeof(cfg->mode), value);
		return 0;
	}
	if (strcmp(key, "strict_mmap") == 0 ||
	    strcmp(key, "strict-mmap") == 0) {
		bool parsed;
		if (parse_bool_strict(value, &parsed) != 0) {
			fprintf(stderr,
				"%s:%d: invalid strict_mmap '%s' (use "
				"true/false)\n",
				filepath, lineno, value);
			return -1;
		}
		cfg->strict_mmap = parsed;
		return 0;
	}
	if (strcmp(key, "strict_exec") == 0 ||
	    strcmp(key, "strict-exec") == 0) {
		bool parsed;
		if (parse_bool_strict(value, &parsed) != 0) {
			fprintf(stderr,
				"%s:%d: invalid strict_exec '%s' (use "
				"true/false)\n",
				filepath, lineno, value);
			return -1;
		}
		cfg->strict_exec = parsed;
		return 0;
	}
	if (strcmp(key, "block_ptrace") == 0 ||
	    strcmp(key, "block-ptrace") == 0) {
		bool parsed;
		if (parse_bool_strict(value, &parsed) != 0) {
			fprintf(stderr,
				"%s:%d: invalid block_ptrace '%s' (use "
				"true/false)\n",
				filepath, lineno, value);
			return -1;
		}
		cfg->block_ptrace = parsed;
		return 0;
	}
	if (strcmp(key, "strict_modules") == 0 ||
	    strcmp(key, "strict-modules") == 0) {
		bool parsed;
		if (parse_bool_strict(value, &parsed) != 0) {
			fprintf(stderr,
				"%s:%d: invalid strict_modules '%s' (use "
				"true/false)\n",
				filepath, lineno, value);
			return -1;
		}
		cfg->strict_modules = parsed;
		return 0;
	}
	if (strcmp(key, "block_anon_exec") == 0 ||
	    strcmp(key, "block-anon-exec") == 0) {
		bool parsed;
		if (parse_bool_strict(value, &parsed) != 0) {
			fprintf(stderr,
				"%s:%d: invalid block_anon_exec '%s' (use "
				"true/false)\n",
				filepath, lineno, value);
			return -1;
		}
		cfg->block_anon_exec = parsed;
		return 0;
	}
	if (strcmp(key, "seal_aik_auth") == 0 ||
	    strcmp(key, "seal-aik-auth") == 0) {
		bool parsed;
		if (parse_bool_strict(value, &parsed) != 0) {
			fprintf(stderr,
				"%s:%d: invalid seal_aik_auth '%s' (use "
				"true/false)\n",
				filepath, lineno, value);
			return -1;
		}
		cfg->seal_aik_auth = parsed;
		return 0;
	}
	if (strcmp(key, "seal_aik_auth_strict") == 0 ||
	    strcmp(key, "seal-aik-auth-strict") == 0) {
		bool parsed;
		if (parse_bool_strict(value, &parsed) != 0) {
			fprintf(stderr,
				"%s:%d: invalid seal_aik_auth_strict '%s' (use "
				"true/false)\n",
				filepath, lineno, value);
			return -1;
		}
		cfg->seal_aik_auth_strict = parsed;
		return 0;
	}
	if (strcmp(key, "seal_persistent_primary") == 0 ||
	    strcmp(key, "seal-persistent-primary") == 0) {
		bool parsed;
		if (parse_bool_strict(value, &parsed) != 0) {
			fprintf(stderr,
				"%s:%d: invalid seal_persistent_primary '%s' "
				"(use true/false)\n",
				filepath, lineno, value);
			return -1;
		}
		cfg->seal_persistent_primary = parsed;
		return 0;
	}

	/* attestation */
	if (strcmp(key, "attest_interval") == 0 ||
	    strcmp(key, "attest-interval") == 0) {
		long v;
		if (safe_parse_long(value, &v) != 0 || v < 0 || v > INT_MAX) {
			fprintf(stderr, "%s:%d: invalid attest_interval '%s'\n",
				filepath, lineno, value);
			return -1;
		}
		if (check_attest_interval(v, "attest_interval", filepath,
					  lineno) != 0)
			return -1;
		cfg->attest_interval = (int)v;
		return 0;
	}
	if (strcmp(key, "aik_ttl") == 0 || strcmp(key, "aik-ttl") == 0) {
		long v;
		if (safe_parse_long(value, &v) != 0 || v < 0 ||
		    v > (long)UINT32_MAX) {
			fprintf(stderr, "%s:%d: invalid aik_ttl '%s'\n",
				filepath, lineno, value);
			return -1;
		}
		cfg->aik_ttl = (uint32_t)v;
		return 0;
	}
	if (strcmp(key, "aik_handle") == 0 || strcmp(key, "aik-handle") == 0) {
		unsigned long v;
		if (safe_parse_ulong_base(value, 0, &v) != 0 || v == 0 ||
		    v > UINT32_MAX) {
			fprintf(stderr, "%s:%d: invalid aik_handle '%s'\n",
				filepath, lineno, value);
			return -1;
		}
		cfg->aik_handle = (uint32_t)v;
		return 0;
	}
	if (strcmp(key, "kernel_path") == 0 ||
	    strcmp(key, "kernel-path") == 0) {
		if (validate_path_value("kernel_path", value, filepath,
					lineno) != 0)
			return -1;
		set_str(cfg->kernel_path, sizeof(cfg->kernel_path), value);
		return 0;
	}

	/* daemon */
	if (strcmp(key, "daemon") == 0) {
		bool parsed;
		if (parse_bool_strict(value, &parsed) != 0) {
			fprintf(stderr,
				"%s:%d: invalid daemon '%s' (use true/false)\n",
				filepath, lineno, value);
			return -1;
		}
		cfg->daemon = parsed;
		return 0;
	}
	if (strcmp(key, "pid_file") == 0 || strcmp(key, "pid-file") == 0) {
		if (validate_path_value("pid_file", value, filepath, lineno) !=
		    0)
			return -1;
		set_str(cfg->pid_file, sizeof(cfg->pid_file), value);
		return 0;
	}

	/* policy signing */
	if (strcmp(key, "signing_key") == 0 ||
	    strcmp(key, "signing-key") == 0) {
		if (validate_path_value("signing_key", value, filepath,
					lineno) != 0)
			return -1;
		set_str(cfg->signing_key, sizeof(cfg->signing_key), value);
		return 0;
	}
	if (strcmp(key, "policy_pubkey") == 0 ||
	    strcmp(key, "policy-pubkey") == 0) {
		if (validate_path_value("policy_pubkey", value, filepath,
					lineno) != 0)
			return -1;
		set_str(cfg->policy_pubkey, sizeof(cfg->policy_pubkey), value);
		return 0;
	}

	/* lists */
	if (strcmp(key, "trust_lib") == 0 || strcmp(key, "trust-lib") == 0) {
		if (cfg->trust_lib_count >= LOTA_CONFIG_MAX_LIBS) {
			fprintf(stderr,
				"%s:%d: too many trust_lib entries (max %d)\n",
				filepath, lineno, LOTA_CONFIG_MAX_LIBS);
			return -1;
		}

		if (validate_path_value("trust_lib", value, filepath, lineno) !=
		    0)
			return -1;
		set_str(cfg->trust_libs[cfg->trust_lib_count],
			sizeof(cfg->trust_libs[0]), value);
		cfg->trust_lib_count++;
		return 0;
	}
	if (strcmp(key, "protect_pid") == 0 ||
	    strcmp(key, "protect-pid") == 0) {
		long v;
		if (safe_parse_long(value, &v) != 0 || v <= 0 ||
		    v > (long)UINT32_MAX) {
			fprintf(stderr, "%s:%d: invalid protect_pid '%s'\n",
				filepath, lineno, value);
			return -1;
		}

		if (cfg->protect_pid_count >= LOTA_MAX_PROTECTED_PIDS) {
			fprintf(stderr,
				"%s:%d: too many protect_pid entries (max %d)\n",
				filepath, lineno, LOTA_MAX_PROTECTED_PIDS);
			return -1;
		}

		cfg->protect_pids[cfg->protect_pid_count++] = (uint32_t)v;
		return 0;
	}

	if (strcmp(key, "container_listener_uid") == 0 ||
	    strcmp(key, "container-listener-uid") == 0) {
		long v;
		if (safe_parse_long(value, &v) != 0 || v < 0 ||
		    v > (long)UINT32_MAX) {
			fprintf(stderr,
				"%s:%d: invalid container_listener_uid '%s'\n",
				filepath, lineno, value);
			return -1;
		}
		if (cfg->container_listener_uid_count >=
		    LOTA_CONFIG_MAX_CONTAINER_LISTENERS) {
			fprintf(stderr,
				"%s:%d: too many container_listener_uid "
				"entries (max %d)\n",
				filepath, lineno,
				LOTA_CONFIG_MAX_CONTAINER_LISTENERS);
			return -1;
		}
		for (int i = 0; i < cfg->container_listener_uid_count; i++) {
			if (cfg->container_listener_uids[i] == (uint32_t)v) {
				fprintf(stderr,
					"%s:%d: duplicate "
					"container_listener_uid '%s'\n",
					filepath, lineno, value);
				return -1;
			}
		}
		cfg->container_listener_uids[cfg->container_listener_uid_count++] =
			(uint32_t)v;
		return 0;
	}

	/* logging */
	if (strcmp(key, "log_level") == 0 || strcmp(key, "log-level") == 0) {
		set_str(cfg->log_level, sizeof(cfg->log_level), value);
		return 0;
	}

	return 1; /* unknown key */
}

static int config_load_stream(struct lota_config *cfg, FILE *f,
			      const char *filepath)
{
	char line[LOTA_CONFIG_MAX_LINE];
	struct lota_profile *profile = NULL;
	bool in_section = false;
	int lineno = 0;
	int errors = 0;

	if (!cfg || !f || !filepath)
		return -EINVAL;

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
			fprintf(stderr,
				"%s:%d: line exceeds %d characters, skipping\n",
				filepath, lineno, LOTA_CONFIG_MAX_LINE - 1);
			errors++;
			while ((ch = fgetc(f)) != EOF && ch != '\n')
				;
			continue;
		}

		trimmed = trim(line);

		if (*trimmed == '\0' || *trimmed == '#')
			continue;

		if (*trimmed == '[') {
			/*
			 * rejected header leaves the section open with no profile
			 * behind it, so the keys that follow are skipped rather
			 * than landing in the previous profile or at the top level
			 */
			in_section = true;
			if (open_profile_section(cfg, trimmed, filepath, lineno,
						 &profile) != 0) {
				profile = NULL;
				errors++;
			}
			continue;
		}

		eq = strchr(trimmed, '=');
		if (!eq) {
			fprintf(stderr,
				"%s:%d: malformed line (no '=' separator)\n",
				filepath, lineno);
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

		if (in_section && !profile)
			continue;

		int ret = profile ?
				  apply_profile_key(profile, key, value,
						    filepath, lineno) :
				  apply_key(cfg, key, value, filepath, lineno);
		if (ret == 1) {
			if (profile)
				fprintf(stderr,
					"%s:%d: unknown key '%s' in profile "
					"'%s'\n",
					filepath, lineno, key, profile->name);
			else
				fprintf(stderr, "%s:%d: unknown key '%s'\n",
					filepath, lineno, key);
			errors++;
		} else if (ret < 0) {
			errors++;
		}
	}

	errors += validate_profiles(cfg, filepath);

	if (ferror(f))
		return -EIO;

	return errors > 0 ? -EINVAL : 0;
}

int config_load_from_fd(struct lota_config *cfg, int fd, const char *path)
{
	FILE *f;
	int dup_fd;
	int sec_ret;
	const char *filepath = (path && path[0]) ? path : "(fd)";

	if (!cfg || fd < 0)
		return -EINVAL;

	sec_ret = config_validate_file_security(fd, filepath);
	if (sec_ret != 0)
		return sec_ret;

	dup_fd = dup(fd);
	if (dup_fd < 0)
		return -errno;

	if (lseek(dup_fd, 0, SEEK_SET) < 0) {
		int err = -errno;
		close(dup_fd);
		return err;
	}

	f = fdopen(dup_fd, "r");
	if (!f) {
		int err = errno;
		close(dup_fd);
		return -err;
	}

	int ret = config_load_stream(cfg, f, filepath);
	fclose(f);
	return ret;
}

int config_load(struct lota_config *cfg, const char *path)
{
	FILE *f;
	int fd;
	const char *filepath;

	if (!cfg)
		return -EINVAL;

	filepath = path ? path : LOTA_CONFIG_DEFAULT_PATH;

	int open_flags = O_RDONLY | O_CLOEXEC;
#ifdef O_NOFOLLOW
	/* avoid reading config through symlink indirection */
	open_flags |= O_NOFOLLOW;
#endif

	fd = open(filepath, open_flags);
	if (fd < 0)
		return -errno;

	int sec_ret = config_validate_file_security(fd, filepath);
	if (sec_ret != 0) {
		close(fd);
		return sec_ret;
	}

	f = fdopen(fd, "r");
	if (!f) {
		int err = errno;
		close(fd);
		return -err;
	}

	int ret = config_load_stream(cfg, f, filepath);
	fclose(f);
	return ret;
}

void config_dump(const struct lota_config *cfg, FILE *fp)
{
	if (!cfg || !fp)
		return;

	fprintf(fp, "# LOTA Agent effective configuration\n\n");

	fprintf(fp, "# Verifier connection\n");
	fprintf(fp, "server = %s\n", cfg->server);
	fprintf(fp, "port = %d\n", cfg->port);
	if (cfg->ca_cert[0])
		fprintf(fp, "ca_cert = %s\n", cfg->ca_cert);
	if (cfg->pin_sha256[0])
		fprintf(fp, "pin_sha256 = %s\n", cfg->pin_sha256);

	fprintf(fp, "\n# BPF / enforcement\n");
	fprintf(fp, "bpf_path = %s\n", cfg->bpf_path);
	fprintf(fp, "mode = %s\n", cfg->mode);
	fprintf(fp, "strict_mmap = %s\n", cfg->strict_mmap ? "true" : "false");
	fprintf(fp, "strict_exec = %s\n", cfg->strict_exec ? "true" : "false");
	fprintf(fp, "block_ptrace = %s\n",
		cfg->block_ptrace ? "true" : "false");
	fprintf(fp, "strict_modules = %s\n",
		cfg->strict_modules ? "true" : "false");
	fprintf(fp, "block_anon_exec = %s\n",
		cfg->block_anon_exec ? "true" : "false");

	fprintf(fp, "\n# Attestation\n");
	fprintf(fp, "attest_interval = %d\n", cfg->attest_interval);
	fprintf(fp, "aik_ttl = %u\n", cfg->aik_ttl);
	fprintf(fp, "aik_handle = 0x%08X\n", cfg->aik_handle);
	if (cfg->kernel_path[0])
		fprintf(fp, "kernel_path = %s\n", cfg->kernel_path);

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

	if (cfg->allow_verity_count > 0) {
		fprintf(fp, "\n# Allowed fs-verity files\n");
		for (int i = 0; i < cfg->allow_verity_count; i++)
			fprintf(fp, "allow_verity = %s\n",
				cfg->allow_verity[i]);
	}

	if (cfg->protect_pid_count > 0) {
		fprintf(fp, "\n# Protected PIDs\n");
		for (int i = 0; i < cfg->protect_pid_count; i++)
			fprintf(fp, "protect_pid = %u\n", cfg->protect_pids[i]);
	}

	if (cfg->container_listener_uid_count > 0) {
		fprintf(fp, "\n# Container-accessible IPC listeners "
			    "(per operator UID)\n");
		for (int i = 0; i < cfg->container_listener_uid_count; i++)
			fprintf(fp, "container_listener_uid = %u\n",
				cfg->container_listener_uids[i]);
	}

	/*
	 * profiles come last, and nothing top-level may follow them:
	 * every key after section header belongs to that section, so dump that
	 * emitted them earlier would not parse back as what it printed
	 */
	for (int i = 0; i < cfg->profile_count; i++) {
		const struct lota_profile *p = &cfg->profiles[i];

		fprintf(fp, "\n# Publisher profile\n");
		fprintf(fp, "[profile \"%s\"]\n", p->name);
		fprintf(fp, "ca = %s\n", p->ca);
		fprintf(fp, "ca_port = %d\n", p->ca_port);
		fprintf(fp, "ca_cert = %s\n", p->ca_cert);
		if (p->token_only) {
			fprintf(fp, "verifier = none\n");
		} else {
			fprintf(fp, "verifier = %s\n", p->verifier);
			fprintf(fp, "verifier_port = %d\n", p->verifier_port);
		}
		fprintf(fp, "reporting = %s\n",
			p->session_gated ? "session" : "continuous");
		if (p->attest_interval)
			fprintf(fp, "interval = %d\n", p->attest_interval);
	}
}

const char *config_resolve_policy_pubkey(const char *configured,
					 const char *override_path,
					 const char *packaged_path)
{
	/*
	 * Named key wins -- but only while it is there.
	 * Path that has stopped resolving is not an operator's choice any more,
	 * it is leftover: the installer used to write this key into lota.conf,
	 * and the file it named is one an upgrade can take away.
	 * Treating that as "verify against nothing" would stop enforcement on
	 * host whose package brought a perfectly good key with it.
	 */
	if (configured && configured[0] && access(configured, R_OK) == 0)
		return configured;

	/*
	 * Operator's own key wins over the packaged one whenever it is there.
	 * No package owns that path, so fleet that signs enforcement itself
	 * keeps its answer across every upgrade, and host that never made that
	 * choice follows the object the package installed.
	 */
	if (override_path && access(override_path, R_OK) == 0)
		return override_path;
	if (packaged_path && access(packaged_path, R_OK) == 0)
		return packaged_path;
	return NULL;
}

/*
 * Whether @text already carries a `[profile "name"]` header, and how many profile
 * sections it holds.
 * Deliberately text scan rather than a parse:
 * the file may hold keys this build does not know, and refusing to add publisher
 * because of one would be the wrong answer.
 */
static int profile_section_scan(const char *text, const char *name,
				int *out_count)
{
	const char *p = text;
	int count = 0;
	int found = 0;

	while ((p = strstr(p, "[profile")) != NULL) {
		const char *q = strchr(p, '"');
		const char *r = q ? strchr(q + 1, '"') : NULL;

		count++;
		if (q && r && name) {
			size_t len = (size_t)(r - q - 1);

			if (len == strlen(name) &&
			    strncmp(q + 1, name, len) == 0)
				found = 1;
		}
		p += 8;
	}

	if (out_count)
		*out_count = count;
	return found;
}

/* The profile as the parser reads it back.
 * Keys are written in the order the documentation lists them so a file
 * an installer touched still reads like one a person wrote. */
static int profile_section_render(const struct lota_profile *p, char *buf,
				  size_t cap)
{
	int n;

	n = snprintf(buf, cap,
		     "\n[profile \"%s\"]\n"
		     "ca = %s\n"
		     "ca_port = %d\n"
		     "ca_cert = %s\n"
		     "verifier = %s\n"
		     "verifier_port = %d\n"
		     "reporting = %s\n",
		     p->name, p->ca, p->ca_port, p->ca_cert,
		     p->verifier[0] ? p->verifier : "none", p->verifier_port,
		     p->session_gated ? "session" : "continuous");
	if (n < 0 || (size_t)n >= cap)
		return -EOVERFLOW;

	if (p->attest_interval > 0) {
		int m = snprintf(buf + n, cap - (size_t)n, "interval = %d\n",
				 p->attest_interval);

		if (m < 0 || (size_t)(n + m) >= cap)
			return -EOVERFLOW;
		n += m;
	}

	return n;
}

int config_profile_append_text(const char *existing,
			       const struct lota_profile *p, char *out,
			       size_t out_cap)
{
	char section[1024];
	size_t existing_len;
	int count = 0;
	int rendered;

	if (!existing || !p || !out || out_cap == 0)
		return -EINVAL;

	/* parser refuses a profile without these, so refuse to write one */
	if (!p->name[0] || !p->ca[0] || !p->ca_cert[0])
		return -EINVAL;

	/*
	 * A publisher is its trust anchor, not its label.
	 * The same anchor already in the file is the installer running twice
	 * -- or the same publisher configured under another name -- and either
	 * way a second section would resolve to one profile directory and one
	 * AIK, burning a slot and attesting twice to the same place.
	 */
	{
		char probe[PATH_MAX + 64];
		int n = snprintf(probe, sizeof(probe), "ca_cert = %s",
				 p->ca_cert);

		if (n > 0 && (size_t)n < sizeof(probe) &&
		    strstr(existing, probe) != NULL) {
			if (strlen(existing) >= out_cap)
				return -EOVERFLOW;
			memcpy(out, existing, strlen(existing) + 1);
			return 0;
		}
	}

	/* label already spoken for by a different anchor is two publishers claiming
	 * one name, which only the operator can resolve */
	if (profile_section_scan(existing, p->name, &count))
		return -EEXIST;

	if (count >= LOTA_CONFIG_MAX_PROFILES)
		return -E2BIG;

	rendered = profile_section_render(p, section, sizeof(section));
	if (rendered < 0)
		return rendered;

	existing_len = strlen(existing);
	if (existing_len + (size_t)rendered + 1 > out_cap)
		return -EOVERFLOW;

	memcpy(out, existing, existing_len);
	memcpy(out + existing_len, section, (size_t)rendered + 1);
	return 1;
}

int config_profile_append(const char *path, const struct lota_profile *p)
{
	char tmp_path[PATH_MAX];
	char *existing = NULL;
	char *updated = NULL;
	size_t existing_len = 0;
	size_t cap;
	int ret;
	int fd;

	if (!path || !p)
		return -EINVAL;

	/* A file that is not there yet is an empty one:
	 * the agent ships a config, but a host may have removed it and the verb
	 * still has to work rather than telling the player to create one.
	 * The reader reports a missing file as zero bytes, which is the same thing. */
	existing = calloc(1, LOTA_CONFIG_MAX_FILE + 1);
	if (!existing)
		return -ENOMEM;

	ret = lota_read_file_bounded(path, existing, LOTA_CONFIG_MAX_FILE,
				     &existing_len);
	if (ret < 0) {
		free(existing);
		return ret;
	}
	existing[existing_len] = '\0';

	cap = existing_len + 2048;
	updated = calloc(1, cap);
	if (!updated) {
		free(existing);
		return -ENOMEM;
	}

	ret = config_profile_append_text(existing, p, updated, cap);
	free(existing);
	if (ret <= 0) {
		free(updated);
		return ret;
	}

	/*
	 * Rename into place so crash mid-write leaves the old config rather than
	 * half of one:
	 * the agent reads this file on every start, and a truncated one is host
	 * that will not come back.
	 */
	if (snprintf(tmp_path, sizeof(tmp_path), "%s.new", path) >=
	    (int)sizeof(tmp_path)) {
		free(updated);
		return -ENAMETOOLONG;
	}

	int tmp_flags = O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC;
#ifdef O_NOFOLLOW
	tmp_flags |= O_NOFOLLOW;
#endif

	fd = open(tmp_path, tmp_flags, 0644);
	if (fd < 0) {
		ret = -errno;
		free(updated);
		return ret;
	}

	{
		size_t len = strlen(updated);
		ssize_t written = write(fd, updated, len);

		if (written < 0 || (size_t)written != len) {
			ret = written < 0 ? -errno : -EIO;
			close(fd);
			unlink(tmp_path);
			free(updated);
			return ret;
		}
	}

	if (fsync(fd) < 0) {
		ret = -errno;
		close(fd);
		unlink(tmp_path);
		free(updated);
		return ret;
	}
	close(fd);
	free(updated);

	if (rename(tmp_path, path) < 0) {
		ret = -errno;
		unlink(tmp_path);
		return ret;
	}

	return 1;
}
