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
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <syslog.h>
#include <unistd.h>
#include <sys/types.h>

#include "attest.h"
#include "lota.h"
#include "parse_utils.h"
#include "path_validate.h"
#include "pin.h"
#include "tpm.h"

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

	if (strcmp(value, "monitor") == 0 || strcmp(value, "enforce") == 0)
		return 0;

	return -1;
}

/* Leaves @dst unchanged when @src does not fit. */
static int set_str(char *dst, size_t dst_size, const char *src)
{
	size_t len = strlen(src);

	if (len >= dst_size)
		return -1;

	memcpy(dst, src, len + 1);
	return 0;
}

static int set_value(char *dst, size_t dst_size, const char *key,
		     const char *value, const char *filepath, int lineno)
{
	if (set_str(dst, dst_size, value) == 0)
		return 0;
	fprintf(stderr, "%s:%d: %s is too long (%zu bytes, max %zu)\n",
		filepath, lineno, key, strlen(value), dst_size - 1);
	return -1;
}

int config_log_priority(const char *name)
{
	if (!name)
		return -1;
	if (strcmp(name, "error") == 0)
		return LOG_ERR;
	if (strcmp(name, "warn") == 0)
		return LOG_WARNING;
	if (strcmp(name, "info") == 0)
		return LOG_INFO;
	if (strcmp(name, "debug") == 0)
		return LOG_DEBUG;
	return -1;
}

static int validate_path_value(const char *key, const char *value,
			       const char *filepath, int lineno)
{
	if (!key || !value)
		return -1;

	/* passes: clears a single-value key */
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

	/* the string's shape only: no symlink is resolved */

	return 0;
}

static int validate_list_value(const char *key, const char *value,
			       const char *filepath, int lineno)
{
	if (value[0] == '\0') {
		fprintf(stderr, "%s:%d: invalid %s: empty path\n", filepath,
			lineno, key);
		return -1;
	}
	return validate_path_value(key, value, filepath, lineno);
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

	/* server stays empty: there is no default verifier */
	cfg->port = LOTA_DEFAULT_VERIFIER_PORT;

	cfg->allow_verity_count = 0;
	set_str(cfg->bpf_path, sizeof(cfg->bpf_path),
		"/usr/lib/lota/lota_lsm.bpf.o");
	set_str(cfg->mode, sizeof(cfg->mode), "enforce");
	/*
	 * strict_exec and strict_modules also need an allow_verity entry:
	 * startup_policy.c refuses them without one.
	 */
	cfg->strict_mmap = false;
	cfg->strict_exec = false;
	cfg->block_ptrace = false;
	cfg->strict_modules = false;
	cfg->block_anon_exec = false;
	cfg->seal_aik_auth = false;
	cfg->seal_aik_auth_strict = false;
	cfg->seal_persistent_primary = false;

	cfg->attest_interval = 0;
	cfg->aik_handle = TPM_AIK_HANDLE;

	cfg->daemon = false;
	set_str(cfg->pid_file, sizeof(cfg->pid_file),
		"/run/lota/lota-agent.pid");

	cfg->protect_pid_count = 0;
	cfg->profile_count = 0;

	set_str(cfg->log_level, sizeof(cfg->log_level), "info");
}

struct lota_config *config_new(void)
{
	struct lota_config *cfg = calloc(1, sizeof(*cfg));

	if (!cfg)
		return NULL;

	config_init(cfg);
	return cfg;
}

void config_free(struct lota_config *cfg)
{
	free(cfg);
}

static int check_attest_interval(long v, const char *key, const char *filepath,
				 int lineno)
{
	if (v == 0 || (v >= MIN_ATTEST_INTERVAL && v <= MAX_ATTEST_INTERVAL))
		return 0;

	fprintf(stderr,
		"%s:%d: %s %ld out of range (0 or %d-%d; above %d a minted "
		"token outlives the token age the SDK verifiers accept and "
		"spends their clock skew)\n",
		filepath, lineno, key, v, MIN_ATTEST_INTERVAL,
		MAX_ATTEST_INTERVAL, MAX_ATTEST_INTERVAL);
	return -1;
}

/* Returns 0 applied, 1 unknown key, -1 invalid value. */
static int apply_profile_key(struct lota_profile *p, const char *key,
			     const char *value, const char *filepath,
			     int lineno)
{
	if (strcmp(key, "ca") == 0) {
		return set_value(p->ca, sizeof(p->ca), key, value, filepath,
				 lineno);
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
		return set_value(p->ca_cert, sizeof(p->ca_cert), key, value,
				 filepath, lineno);
	}
	if (strcmp(key, "verifier") == 0) {
		if (strcmp(value, "none") == 0) {
			p->token_only = true;
			p->verifier[0] = '\0';
			return 0;
		}
		p->token_only = false;
		return set_value(p->verifier, sizeof(p->verifier), key, value,
				 filepath, lineno);
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
		p->verifier_port_set = true;
		return 0;
	}
	if (strcmp(key, "pin_sha256") == 0 || strcmp(key, "pin-sha256") == 0) {
		uint8_t bin[LOTA_PIN_SHA256_LEN];

		if (lota_pin_sha256_parse(value, bin) != 0) {
			fprintf(stderr,
				"%s:%d: invalid pin_sha256 '%s' (expected 64 "
				"hex characters; colons and spaces allowed)\n",
				filepath, lineno, value);
			return -1;
		}
		return set_value(p->pin_sha256, sizeof(p->pin_sha256), key,
				 value, filepath, lineno);
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

int config_profile_name_defect(const char *name, char *why, size_t why_cap)
{
	const unsigned char *p;

	if (!why || why_cap == 0)
		return -EINVAL;

	if (!name || name[0] == '\0') {
		snprintf(why, why_cap, "is empty");
		return -EINVAL;
	}

	if (strlen(name) >= LOTA_CONFIG_MAX_PROFILE_NAME) {
		snprintf(why, why_cap,
			 "is %zu characters; the parser reads at most %d",
			 strlen(name), LOTA_CONFIG_MAX_PROFILE_NAME - 1);
		return -EILSEQ;
	}

	for (p = (const unsigned char *)name; *p; p++) {
		if (*p == '"') {
			snprintf(why, why_cap,
				 "contains a quote (0x22), which is what ends "
				 "the section header");
			return -EILSEQ;
		}
		if (iscntrl(*p)) {
			snprintf(why, why_cap,
				 "contains a control character (0x%02x)", *p);
			return -EILSEQ;
		}
	}

	return 0;
}

/*
 * Why the parser would not read non-empty @value back as written on a line of
 * @key, or 0 when it would.
 */
static int value_defect(const char *key, const char *value, char *why,
			size_t why_cap)
{
	const unsigned char *p;
	size_t line;

	for (p = (const unsigned char *)value; *p; p++) {
		if (iscntrl(*p)) {
			snprintf(why, why_cap,
				 "contains a control character (0x%02x), which "
				 "would start a line of its own",
				 *p);
			return -EILSEQ;
		}
	}

	if (isspace((unsigned char)value[0]) ||
	    isspace((unsigned char)value[strlen(value) - 1])) {
		snprintf(why, why_cap,
			 "begins or ends with whitespace, which the parser "
			 "trims away");
		return -EILSEQ;
	}

	line = strlen(key) + strlen(" = ") + strlen(value);
	if (line > LOTA_CONFIG_MAX_LINE - 2) {
		snprintf(why, why_cap,
			 "needs a %zu-character line; the parser reads at most "
			 "%d",
			 line, LOTA_CONFIG_MAX_LINE - 2);
		return -EILSEQ;
	}

	return 0;
}

/*
 * host:port or [v6]:port; a bare IPv6 literal has two colons or more and
 * the resolver takes no brackets.
 */
static bool host_has_port(const char *host)
{
	const char *c = strchr(host, ':');

	return host[0] == '[' || (c && c == strrchr(host, ':'));
}

int config_profile_defect(const struct lota_profile *p, char *why,
			  size_t why_cap)
{
	char sub[160];
	int ret;

	if (!p || !why || why_cap == 0)
		return -EINVAL;

	ret = config_profile_name_defect(p->name, sub, sizeof(sub));
	if (ret) {
		snprintf(why, why_cap, "the label %s", sub);
		return ret;
	}

	if (!p->ca[0]) {
		snprintf(why, why_cap, "no CA host is named");
		return -EINVAL;
	}
	if (!p->ca_cert[0]) {
		snprintf(why, why_cap, "no trust anchor is named");
		return -EINVAL;
	}

	if (value_defect("ca", p->ca, sub, sizeof(sub))) {
		snprintf(why, why_cap, "the CA host %s", sub);
		return -EILSEQ;
	}
	if (host_has_port(p->ca)) {
		snprintf(why, why_cap,
			 "the CA host carries a port after ':' or brackets, "
			 "which the resolver does not strip; pass the bare "
			 "host and the port with --ca-port");
		return -EILSEQ;
	}

	if (value_defect("ca_cert", p->ca_cert, sub, sizeof(sub))) {
		snprintf(why, why_cap, "the trust anchor %s", sub);
		return -EILSEQ;
	}
	if (!lota_path_is_abs(p->ca_cert)) {
		snprintf(why, why_cap,
			 "the trust anchor is not an absolute path, which the "
			 "parser requires");
		return -EILSEQ;
	}
	if (lota_path_has_dotdot_segment(p->ca_cert)) {
		snprintf(why, why_cap,
			 "the trust anchor traverses '..', which the parser "
			 "refuses");
		return -EILSEQ;
	}

	if (p->pin_sha256[0]) {
		uint8_t bin[LOTA_PIN_SHA256_LEN];

		if (value_defect("pin_sha256", p->pin_sha256, sub,
				 sizeof(sub))) {
			snprintf(why, why_cap, "the certificate pin %s", sub);
			return -EILSEQ;
		}
		if (lota_pin_sha256_parse(p->pin_sha256, bin) != 0) {
			snprintf(why, why_cap,
				 "the certificate pin is not 64 hex "
				 "characters, which the parser requires");
			return -EILSEQ;
		}
	}

	if (!p->token_only && p->verifier[0] &&
	    value_defect("verifier", p->verifier, sub, sizeof(sub))) {
		snprintf(why, why_cap, "the verifier host %s", sub);
		return -EILSEQ;
	}
	if (!p->token_only && host_has_port(p->verifier)) {
		snprintf(why, why_cap,
			 "the verifier host carries a port after ':' or "
			 "brackets, which the resolver does not strip; pass "
			 "the bare host and the port with --port");
		return -EILSEQ;
	}
	if (!p->token_only && strcmp(p->verifier, "none") == 0) {
		snprintf(why, why_cap,
			 "the verifier host is none, which the parser reads as "
			 "no verifier; leave out --server for a publisher who "
			 "runs none");
		return -EILSEQ;
	}

	return 0;
}

/*
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

	{
		char why[160];

		if (config_profile_name_defect(name, why, sizeof(why))) {
			fprintf(stderr, "%s:%d: profile name %s\n", filepath,
				lineno, why);
			return -1;
		}
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

/* Returns the number of problems it reported on stderr. */
static int validate_profiles(const struct lota_config *cfg,
			     const char *filepath)
{
	int errors = 0;

	if (cfg->profile_count > 0 && cfg->pin_sha256[0]) {
		fprintf(stderr,
			"%s: pin_sha256 outside a profile pins one verifier's "
			"certificate, but %d publisher profile(s) are "
			"configured.\nMove it into the profile whose verifier "
			"presents that certificate.\n",
			filepath, cfg->profile_count);
		errors++;
	}

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

		if (p->token_only && p->verifier_port_set) {
			fprintf(stderr,
				"%s: profile '%s' says verifier = none and "
				"still sets verifier_port\n",
				filepath, p->name);
			errors++;
		}
	}

	return errors;
}

/* Returns 0 applied, 1 unknown key, -1 invalid value. */
static int apply_key(struct lota_config *cfg, const char *key,
		     const char *value, const char *filepath, int lineno)
{
	if (strcmp(key, "server") == 0) {
		return set_value(cfg->server, sizeof(cfg->server), key, value,
				 filepath, lineno);
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
		return set_value(cfg->ca_cert, sizeof(cfg->ca_cert), key, value,
				 filepath, lineno);
	}
	if (strcmp(key, "no_verify_tls") == 0 ||
	    strcmp(key, "no-verify-tls") == 0) {
		fprintf(stderr,
			"%s:%d: no_verify_tls is a security-critical option "
			"and cannot\n"
			"be set via config file. Pass --no-verify-tls on the "
			"command line.\n",
			filepath, lineno);
		return -1;
	}
	if (strcmp(key, "pin_sha256") == 0 || strcmp(key, "pin-sha256") == 0) {
		uint8_t bin[LOTA_PIN_SHA256_LEN];

		if (lota_pin_sha256_parse(value, bin) != 0) {
			fprintf(stderr,
				"%s:%d: invalid pin_sha256 '%s' (expected 64 "
				"hex characters; colons and spaces allowed)\n",
				filepath, lineno, value);
			return -1;
		}
		return set_value(cfg->pin_sha256, sizeof(cfg->pin_sha256), key,
				 value, filepath, lineno);
	}

	if (strcmp(key, "allow_verity") == 0 ||
	    strcmp(key, "allow-verity") == 0) {
		if (cfg->allow_verity_count >= LOTA_CONFIG_MAX_VERITY) {
			fprintf(stderr,
				"%s:%d: too many allow_verity entries (max %d)\n",
				filepath, lineno, LOTA_CONFIG_MAX_VERITY);
			return -1;
		}

		if (validate_list_value("allow_verity", value, filepath,
					lineno) != 0)
			return -1;
		if (set_value(cfg->allow_verity[cfg->allow_verity_count],
			      sizeof(cfg->allow_verity[0]), key, value,
			      filepath, lineno) != 0)
			return -1;
		cfg->allow_verity_count++;
		return 0;
	}
	if (strcmp(key, "bpf_path") == 0 || strcmp(key, "bpf-path") == 0 ||
	    strcmp(key, "bpf") == 0) {
		if (validate_path_value("bpf_path", value, filepath, lineno) !=
		    0)
			return -1;
		return set_value(cfg->bpf_path, sizeof(cfg->bpf_path), key,
				 value, filepath, lineno);
	}
	if (strcmp(key, "mode") == 0) {
		if (parse_mode_strict(value) != 0) {
			fprintf(stderr,
				"%s:%d: invalid mode '%s' (valid: "
				"monitor/enforce)\n",
				filepath, lineno, value);
			return -1;
		}
		return set_value(cfg->mode, sizeof(cfg->mode), key, value,
				 filepath, lineno);
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
	if (strcmp(key, "bench") == 0) {
		bool parsed;
		if (parse_bool_strict(value, &parsed) != 0) {
			fprintf(stderr,
				"%s:%d: invalid bench '%s' (use true/false)\n",
				filepath, lineno, value);
			return -1;
		}
		cfg->bench = parsed;
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
		return set_value(cfg->kernel_path, sizeof(cfg->kernel_path),
				 key, value, filepath, lineno);
	}

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
		return set_value(cfg->pid_file, sizeof(cfg->pid_file), key,
				 value, filepath, lineno);
	}

	if (strcmp(key, "policy_pubkey") == 0 ||
	    strcmp(key, "policy-pubkey") == 0) {
		if (validate_path_value("policy_pubkey", value, filepath,
					lineno) != 0)
			return -1;
		return set_value(cfg->policy_pubkey, sizeof(cfg->policy_pubkey),
				 key, value, filepath, lineno);
	}

	if (strcmp(key, "trust_lib") == 0 || strcmp(key, "trust-lib") == 0) {
		if (cfg->trust_lib_count >= LOTA_CONFIG_MAX_LIBS) {
			fprintf(stderr,
				"%s:%d: too many trust_lib entries (max %d)\n",
				filepath, lineno, LOTA_CONFIG_MAX_LIBS);
			return -1;
		}

		if (validate_list_value("trust_lib", value, filepath, lineno) !=
		    0)
			return -1;
		if (set_value(cfg->trust_libs[cfg->trust_lib_count],
			      sizeof(cfg->trust_libs[0]), key, value, filepath,
			      lineno) != 0)
			return -1;
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

	if (strcmp(key, "log_level") == 0 || strcmp(key, "log-level") == 0) {
		if (config_log_priority(value) < 0) {
			fprintf(stderr,
				"%s:%d: invalid log_level '%s' (valid: "
				"error/warn/info/debug)\n",
				filepath, lineno, value);
			return -1;
		}
		return set_value(cfg->log_level, sizeof(cfg->log_level), key,
				 value, filepath, lineno);
	}

	return 1;
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
			fprintf(stderr, "%s:%d: line exceeds %d characters\n",
				filepath, lineno, LOTA_CONFIG_MAX_LINE - 2);
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
			 * a rejected header leaves the section open with no
			 * profile, so the keys that follow are skipped
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
	open_flags |= O_NOFOLLOW;
#endif

	/* a FIFO with no writer reaches the regular-file check, not a wait */
	fd = open(filepath, open_flags | O_NONBLOCK);
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

int config_inert_strict_flags_of(bool mode_is_enforce,
				 const bool flags[LOTA_STRICT_FLAG_COUNT],
				 const char *names[], int max)
{
	static const char *const keys[LOTA_STRICT_FLAG_COUNT] = {
		"strict_mmap", "strict_exec", "block_ptrace", "strict_modules",
		"block_anon_exec"
	};
	int n = 0;

	if (!flags || !names || max < 0)
		return -EINVAL;

	if (mode_is_enforce)
		return 0;

	for (int i = 0; i < LOTA_STRICT_FLAG_COUNT; i++) {
		if (!flags[i])
			continue;
		if (n >= max)
			return -ENOSPC;
		names[n++] = keys[i];
	}

	return n;
}

int config_inert_strict_flags(const struct lota_config *cfg,
			      const char *names[], int max)
{
	if (!cfg)
		return -EINVAL;

	const bool flags[LOTA_STRICT_FLAG_COUNT] = {
		cfg->strict_mmap, cfg->strict_exec, cfg->block_ptrace,
		cfg->strict_modules, cfg->block_anon_exec
	};

	return config_inert_strict_flags_of(strcmp(cfg->mode, "enforce") == 0,
					    flags, names, max);
}

void config_dump(const struct lota_config *cfg, FILE *fp)
{
	const char *inert[LOTA_STRICT_FLAG_COUNT];
	int inert_count;

	if (!cfg || !fp)
		return;

	fprintf(fp, "# LOTA Agent effective configuration\n\n");

	fprintf(fp, "# Verifier connection\n");
	if (cfg->server[0])
		fprintf(fp, "server = %s\n", cfg->server);
	fprintf(fp, "port = %d\n", cfg->port);
	if (cfg->ca_cert[0])
		fprintf(fp, "ca_cert = %s\n", cfg->ca_cert);
	if (cfg->pin_sha256[0])
		fprintf(fp, "pin_sha256 = %s\n", cfg->pin_sha256);

	fprintf(fp, "\n# BPF / enforcement\n");
	fprintf(fp, "bpf_path = %s\n", cfg->bpf_path);
	fprintf(fp, "mode = %s\n", cfg->mode);

	inert_count =
		config_inert_strict_flags(cfg, inert, LOTA_STRICT_FLAG_COUNT);
	if (inert_count > 0) {
		fprintf(fp, "# mode = %s leaves inert:", cfg->mode);
		for (int i = 0; i < inert_count; i++)
			fprintf(fp, "%s %s", i ? "," : "", inert[i]);
		fprintf(fp, "\n# each of those gates returns early outside "
			    "enforce mode, so the\n");
		fprintf(fp, "# key records a protection this host is not "
			    "applying\n");
	}

	fprintf(fp, "strict_mmap = %s\n", cfg->strict_mmap ? "true" : "false");
	fprintf(fp, "strict_exec = %s\n", cfg->strict_exec ? "true" : "false");
	fprintf(fp, "block_ptrace = %s\n",
		cfg->block_ptrace ? "true" : "false");
	fprintf(fp, "strict_modules = %s\n",
		cfg->strict_modules ? "true" : "false");
	fprintf(fp, "block_anon_exec = %s\n",
		cfg->block_anon_exec ? "true" : "false");
	fprintf(fp, "bench = %s\n", cfg->bench ? "true" : "false");

	fprintf(fp, "\n# Attestation\n");
	fprintf(fp, "attest_interval = %d\n", cfg->attest_interval);
	fprintf(fp, "aik_handle = 0x%08X\n", cfg->aik_handle);
	if (cfg->kernel_path[0])
		fprintf(fp, "kernel_path = %s\n", cfg->kernel_path);

	fprintf(fp, "\n# Daemon\n");
	fprintf(fp, "daemon = %s\n", cfg->daemon ? "true" : "false");
	fprintf(fp, "pid_file = %s\n", cfg->pid_file);

	fprintf(fp, "\n# At-rest sealing\n");
	fprintf(fp, "seal_persistent_primary = %s\n",
		cfg->seal_persistent_primary ? "true" : "false");
	fprintf(fp, "seal_aik_auth = %s\n",
		cfg->seal_aik_auth ? "true" : "false");
	fprintf(fp, "seal_aik_auth_strict = %s\n",
		cfg->seal_aik_auth_strict ? "true" : "false");

	fprintf(fp, "\n# Policy signing\n");
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
	 * profiles come last: every key after a section header belongs to
	 * that section
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
		if (p->pin_sha256[0])
			fprintf(fp, "pin_sha256 = %s\n", p->pin_sha256);
		fprintf(fp, "reporting = %s\n",
			p->session_gated ? "session" : "continuous");
		if (p->attest_interval)
			fprintf(fp, "interval = %d\n", p->attest_interval);
	}
}

static int profile_section_render(const struct lota_profile *p, char *buf,
				  size_t cap)
{
	/*
	 * validate_profiles() refuses an absent verifier key, so a profile with
	 * none says verifier = none
	 */
	bool no_verifier = p->token_only || p->verifier[0] == '\0';
	int n;

	if (no_verifier)
		n = snprintf(buf, cap,
			     "\n[profile \"%s\"]\n"
			     "ca = %s\n"
			     "ca_port = %d\n"
			     "ca_cert = %s\n"
			     "verifier = none\n"
			     "reporting = %s\n",
			     p->name, p->ca, p->ca_port, p->ca_cert,
			     p->session_gated ? "session" : "continuous");
	else
		n = snprintf(buf, cap,
			     "\n[profile \"%s\"]\n"
			     "ca = %s\n"
			     "ca_port = %d\n"
			     "ca_cert = %s\n"
			     "verifier = %s\n"
			     "verifier_port = %d\n"
			     "reporting = %s\n",
			     p->name, p->ca, p->ca_port, p->ca_cert,
			     p->verifier, p->verifier_port,
			     p->session_gated ? "session" : "continuous");
	if (n < 0 || (size_t)n >= cap)
		return -EOVERFLOW;

	if (p->pin_sha256[0]) {
		int m = snprintf(buf + n, cap - (size_t)n, "pin_sha256 = %s\n",
				 p->pin_sha256);

		if (m < 0 || (size_t)(n + m) >= cap)
			return -EOVERFLOW;
		n += m;
	}

	if (p->attest_interval > 0) {
		int m = snprintf(buf + n, cap - (size_t)n, "interval = %d\n",
				 p->attest_interval);

		if (m < 0 || (size_t)(n + m) >= cap)
			return -EOVERFLOW;
		n += m;
	}

	return n;
}

static int profile_append_text(const char *label, const char *existing,
			       const struct lota_profile *p, char *out,
			       size_t out_cap)
{
	struct lota_config *cur;
	char section[1024];
	size_t existing_len;
	int rendered;
	int ret;

	if (!existing || !p || !out || out_cap == 0)
		return -EINVAL;

	{
		char why[192];
		int defect = config_profile_defect(p, why, sizeof(why));

		if (defect) {
			fprintf(stderr,
				"Refusing to write this publisher: %s\n", why);
			return defect;
		}
	}

	existing_len = strlen(existing);
	cur = config_new();
	if (!cur)
		return -ENOMEM;
	if (existing_len > 0) {
		FILE *f = fmemopen((void *)existing, existing_len, "r");

		if (!f) {
			ret = -errno;
			config_free(cur);
			return ret;
		}
		ret = config_load_stream(cur, f, label);
		fclose(f);
		if (ret < 0) {
			config_free(cur);
			return -EBADMSG;
		}
	}

	/*
	 * A second section with the same ca_cert would resolve to the same
	 * profile directory, so the publisher counts as present under any
	 * label.
	 */
	ret = 1;
	for (int i = 0; i < cur->profile_count && ret == 1; i++)
		if (strcmp(cur->profiles[i].ca_cert, p->ca_cert) == 0)
			ret = 0;
	for (int i = 0; i < cur->profile_count && ret == 1; i++)
		if (strcmp(cur->profiles[i].name, p->name) == 0)
			ret = -EEXIST;
	if (ret == 1 && cur->profile_count >= LOTA_CONFIG_MAX_PROFILES)
		ret = -E2BIG;
	config_free(cur);

	if (ret == 0) {
		if (existing_len >= out_cap)
			return -EOVERFLOW;
		memcpy(out, existing, existing_len + 1);
		return 0;
	}
	if (ret < 0)
		return ret;

	rendered = profile_section_render(p, section, sizeof(section));
	if (rendered < 0)
		return rendered;

	if (existing_len + (size_t)rendered + 1 > out_cap)
		return -EOVERFLOW;

	memcpy(out, existing, existing_len);
	memcpy(out + existing_len, section, (size_t)rendered + 1);
	return 1;
}

int config_profile_append_text(const char *existing,
			       const struct lota_profile *p, char *out,
			       size_t out_cap)
{
	return profile_append_text("(text)", existing, p, out, out_cap);
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

	/* the reader reports a missing file as zero bytes */
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

	ret = profile_append_text(path, existing, p, updated, cap);
	free(existing);
	if (ret <= 0) {
		free(updated);
		return ret;
	}

	if (snprintf(tmp_path, sizeof(tmp_path), "%s.new", path) >=
	    (int)sizeof(tmp_path)) {
		free(updated);
		return -ENAMETOOLONG;
	}

	struct stat live;
	bool have_live = stat(path, &live) == 0;

	if (!have_live && errno != ENOENT) {
		ret = -errno;
		free(updated);
		return ret;
	}
	if (unlink(tmp_path) < 0 && errno != ENOENT) {
		ret = -errno;
		free(updated);
		return ret;
	}

	int tmp_flags = O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC;
#ifdef O_NOFOLLOW
	tmp_flags |= O_NOFOLLOW;
#endif

	fd = open(tmp_path, tmp_flags, 0600);
	if (fd < 0) {
		ret = -errno;
		free(updated);
		return ret;
	}

	ret = have_live ? fchown(fd, live.st_uid, live.st_gid) : 0;
	if (ret == 0)
		ret = fchmod(fd, have_live ? live.st_mode & 07777 : 0644);
	if (ret < 0) {
		ret = -errno;
		close(fd);
		unlink(tmp_path);
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

	{
		struct lota_config *readback = config_new();
		int lret;

		if (!readback) {
			unlink(tmp_path);
			return -ENOMEM;
		}

		lret = config_load(readback, tmp_path);
		config_free(readback);
		if (lret < 0) {
			fprintf(stderr,
				"Refusing to replace %s: the result does not "
				"parse, so the host would start with no "
				"configuration.\n"
				"%s is unchanged; the errors above are from "
				"reading the replacement back.\n",
				path, path);
			unlink(tmp_path);
			return -EPROTO;
		}
	}

	/*
	 * The replacement takes the live file's SELinux label; a failure to
	 * carry it only warns.
	 */
	{
		int lret = lota_copy_xattr(path, tmp_path, "security.selinux");

		if (lret < 0 && lret != -ENOENT)
			fprintf(stderr,
				"Warning: could not carry the SELinux label of "
				"%s onto its replacement: %s\n"
				"Run 'restorecon %s' if this host is "
				"enforcing.\n",
				path, strerror(-lret), path);
	}

	if (rename(tmp_path, path) < 0) {
		ret = -errno;
		unlink(tmp_path);
		return ret;
	}

	return 1;
}
