/* SPDX-License-Identifier: MIT */
/*
 * LOTA - BPF Program Loader
 * Implementation using libbpf
 *
 * Copyright (C) 2026 Szymon Wilczek
 */
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/xattr.h>
#include <time.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <bpf/libbpf_legacy.h>
#include <linux/bpf.h>
#include <stdarg.h>
#include <sys/types.h>

#include <linux/fsverity.h>
#include <linux/openat2.h>

#include "../../include/lota.h"
#include "../../include/lota_ima_policy_scope.h"
#include "../../include/lota_ima_xattr.h"
#include "bpf_loader.h"
#include "cgroup_guard.h"
#include "journal.h"
#include "kernel_floor_hint.h"
#include "policy_sign.h"
#include "sb_dev.h"

#ifndef EAUTH
#define EAUTH 80
#endif

/* Where the kernel publishes the boot parameters and the loaded IMA policy */
#define IMA_CMDLINE_PATH "/proc/cmdline"
#define IMA_POLICY_PATH "/sys/kernel/security/ima/policy"

/* The rule set this package ships, named in the refusal that needs it */
#define LOTA_IMA_POLICY_ASSET "/usr/share/lota/ima/lota-ima-policy"

/* Stats map indices - must match BPF program */
#define STAT_TOTAL_EXECS 0
#define STAT_EVENTS_SENT 1
#define STAT_RINGBUF_DROPS 3
#define STAT_MODULES_BLOCKED 4
#define STAT_MMAP_EXECS 5
#define STAT_MMAP_BLOCKED 6
#define STAT_PTRACE_ATTEMPTS 7
#define STAT_PTRACE_BLOCKED 8
#define STAT_SETUID_EVENTS 9
#define STAT_BPF_SYSCALL_BLOCKED 13
#define STAT_BLOCKED_EVENTS_SUPPRESSED 15
#define STAT_MOUNTS_BLOCKED 16
#define STAT_KILL_GUARD_BLOCKED 17
#define STAT_EVENTS_YIELDED 18
#define STAT_KILL_PROBES 19
#define STAT_MAPPED_WRITE_BLOCKED 20
#define STAT_MAPPED_PIN_REFUSED 21
#define STAT_EXEC_HISTORY_LOST 22
#define STAT_INSTANCE_ACTORS_LOST 23
#define STAT_INSTANCE_STOPS_LOST 24

struct protected_pid_entry {
	uint64_t start_time_ticks;
};

struct lota_task_auth_entry {
	uint32_t flags;
	uint32_t pad;
};

/* mirrors struct lota_instance_entry in lota_lsm.bpf.c */
struct lota_instance_entry {
	uint64_t root_start_ticks;
	uint32_t root_tgid;
	uint32_t pad;
};

/* mirrors struct lota_instance_stops in lota_lsm.bpf.c */
struct lota_instance_stops {
	uint32_t lock;
	uint32_t stopped_threads;
	uint64_t since_ns;
	uint64_t total_ns;
};

#define LOTA_TASK_AUTH_ADMIN (1U << 0)
#define LOTA_TASK_AUTH_AGENT (1U << 1)

struct trusted_lib_key {
	uint64_t dev;
	uint64_t ino;
};

static int harden_fd_cloexec(int fd, const char *label)
{
	int flags;

	if (fd < 0)
		return -EINVAL;

	flags = fcntl(fd, F_GETFD, 0);
	if (flags < 0)
		return -errno;

	if ((flags & FD_CLOEXEC) != 0)
		return 0;

	if (fcntl(fd, F_SETFD, flags | FD_CLOEXEC) < 0)
		return -errno;

	lota_info("Applied FD_CLOEXEC hardening on %s fd=%d",
		  label ? label : "fd", fd);
	return 0;
}

static int running_in_initial_pidns(void)
{
	FILE *fp;
	char line[512];
	int nspid_count = 0;

	fp = fopen("/proc/self/status", "r");
	if (!fp)
		return -errno;

	while (fgets(line, sizeof(line), fp)) {
		if (strncmp(line, "NSpid:\t", 7) != 0)
			continue;

		char *p = line + 7;
		while (*p != '\0') {
			char *end = NULL;
			unsigned long v;

			while (*p == ' ' || *p == '\t')
				p++;
			if (*p == '\0' || *p == '\n')
				break;

			errno = 0;
			v = strtoul(p, &end, 10);
			if (errno != 0 || end == p)
				break;
			(void)v;
			nspid_count++;
			p = end;
		}
		break;
	}

	fclose(fp);

	if (nspid_count <= 0)
		return -EINVAL;

	return (nspid_count == 1) ? 1 : 0;
}

static int read_pid_start_time_ticks(uint32_t pid, uint64_t *start_time_ticks)
{
	static int pidns_state = -1;
	char path[64];
	FILE *fp;
	char line[4096];
	char *rparen;
	char *field;
	char *saveptr = NULL;
	int field_index = 3;

	if (!start_time_ticks)
		return -EINVAL;

	if (pidns_state < 0)
		pidns_state = running_in_initial_pidns();
	if (pidns_state <= 0)
		return (pidns_state < 0) ? pidns_state : -EOPNOTSUPP;

	snprintf(path, sizeof(path), "/proc/%u/stat", pid);
	fp = fopen(path, "r");
	if (!fp)
		return -errno;

	if (!fgets(line, sizeof(line), fp)) {
		int err = ferror(fp) ? -errno : -EIO;
		fclose(fp);
		return err;
	}
	fclose(fp);

	rparen = strrchr(line, ')');
	if (!rparen)
		return -EINVAL;

	field = rparen + 2; /* skip ") " before field 3 */
	if (*field == '\0')
		return -EINVAL;

	for (char *tok = strtok_r(field, " ", &saveptr); tok;
	     tok = strtok_r(NULL, " ", &saveptr), field_index++) {
		if (field_index == 22) {
			char *end = NULL;
			unsigned long long val;

			errno = 0;
			val = strtoull(tok, &end, 10);
			if (errno != 0 || end == tok || (end && *end != '\0'))
				return -EINVAL;

			*start_time_ticks = (uint64_t)val;
			return 0;
		}
	}

	return -EINVAL;
}

static int set_task_auth_flags(int task_auth_fd, pid_t pid, uint32_t flags)
{
	int pidfd;
	struct lota_task_auth_entry value = { 0 };

	if (task_auth_fd < 0 || pid <= 0 || flags == 0)
		return -EINVAL;

#ifndef SYS_pidfd_open
	return -ENOTSUP;
#else
	pidfd = (int)syscall(SYS_pidfd_open, pid, 0);
	if (pidfd < 0)
		return -errno;

	value.flags = flags;
	if (bpf_map_update_elem(task_auth_fd, &pidfd, &value, BPF_ANY) < 0) {
		int err = -errno;
		close(pidfd);
		return err;
	}

	close(pidfd);
	return 0;
#endif
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
			   va_list args)
{
	if (level == LIBBPF_DEBUG)
		return 0;

	fprintf(stderr, "libbpf: ");
	int n = vfprintf(stderr, format, args);
	return n;
}

/*
 * libbpf_refusal - -errno for a libbpf call that returned NULL, or @fallback
 * when it set none; never 0, which callers read as loaded.
 * Call sites clear errno first.
 */
static int libbpf_refusal(int fallback)
{
	int err = errno;

	return err > 0 ? -err : fallback;
}

int bpf_loader_build_integrity_config(struct integrity_data *cfg,
				      const char *sig_enforce_path,
				      const char *lockdown_path)
{
	int sig_ret;
	int lockdown_ret;

	if (!cfg)
		return -EINVAL;

	sig_ret = bpf_loader_kernel_module_sig_enforced(sig_enforce_path);
	lockdown_ret = bpf_loader_kernel_lockdown_restrictive(lockdown_path);

	memset(cfg, 0, sizeof(*cfg));
	cfg->sig_enforce = sig_ret == 0;
	cfg->lockdown = lockdown_ret == 0;

	return 0;
}

int bpf_loader_object_integrity_layout(const char *bpf_obj_path,
				       uint32_t *key_size, uint32_t *value_size)
{
	struct bpf_object *obj;
	struct bpf_map *map;

	if (!bpf_obj_path || !key_size || !value_size)
		return -EINVAL;

	obj = bpf_object__open_file(bpf_obj_path, NULL);
	if (!obj)
		return -EIO;

	map = bpf_object__find_map_by_name(obj, "integrity_cfg");
	if (!map) {
		bpf_object__close(obj);
		return -ENOENT;
	}

	*key_size = bpf_map__key_size(map);
	*value_size = bpf_map__value_size(map);
	bpf_object__close(obj);
	return 0;
}

int bpf_loader_check_object_integrity_layout(const char *bpf_obj_path)
{
	uint32_t key_size = 0;
	uint32_t value_size = 0;
	int ret;

	ret = bpf_loader_object_integrity_layout(bpf_obj_path, &key_size,
						 &value_size);
	if (ret < 0) {
		lota_err("Cannot read the integrity map of %s: %s",
			 bpf_obj_path ? bpf_obj_path : "(none)",
			 strerror(-ret));
		return ret;
	}

	if (key_size != sizeof(uint32_t) ||
	    value_size != sizeof(struct integrity_data)) {
		lota_err(
			"Enforcement object %s carries an integrity map this agent cannot read: key %u bytes, value %u bytes, where this build reads key %zu, value %zu. The kernel copies the map's own value size on every lookup, so the object and the agent have to come from the same release",
			bpf_obj_path, key_size, value_size, sizeof(uint32_t),
			sizeof(struct integrity_data));
		return -ENOTSUP;
	}

	lota_info(
		"Enforcement object integrity map: key %u bytes, value %u bytes",
		key_size, value_size);
	return 0;
}

bool bpf_loader_integrity_config_satisfied(const struct integrity_data *cfg)
{
	if (!cfg)
		return false;

	return cfg->sig_enforce && cfg->lockdown;
}

static int read_text_file(const char *path, char *buf, size_t buf_size,
			  size_t *out_len)
{
	int fd;
	ssize_t n;

	if (!path || !buf || buf_size < 2)
		return -EINVAL;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -errno;

	n = read(fd, buf, buf_size - 1);
	if (n < 0) {
		int err = -errno;
		close(fd);
		return err;
	}

	close(fd);
	buf[n] = '\0';
	if (out_len)
		*out_len = (size_t)n;
	return 0;
}

int bpf_loader_kernel_lockdown_restrictive(const char *lockdown_path)
{
	char buf[256];
	size_t len = 0;
	char *lb;
	char *rb;

	int ret = read_text_file(lockdown_path, buf, sizeof(buf), &len);
	if (ret < 0)
		return ret;

	if (len == 0)
		return -EIO;

	lb = strchr(buf, '[');
	rb = lb ? strchr(lb + 1, ']') : NULL;
	if (!lb || !rb || rb <= lb + 1)
		return -EPERM;

	*rb = '\0';
	if (strcmp(lb + 1, "integrity") == 0 ||
	    strcmp(lb + 1, "confidentiality") == 0)
		return 0;

	return -EPERM;
}

/*
 * Returns 0 when a rule of the loaded policy appraises an executable, -ENOENT
 * when none does, -EACCES when the file could not be read, with the errno in
 * @read_err.
 */
static int ima_policy_appraises_exec(const char *policy_path, int *read_err)
{
	char line[LOTA_IMA_POLICY_RULE_MAX];
	FILE *fp;
	int found = 0;

	*read_err = 0;

	fp = fopen(policy_path, "re");
	if (!fp) {
		*read_err = -errno;
		return -EACCES;
	}

	while (fgets(line, sizeof(line), fp)) {
		if (lota_ima_policy_rule_appraises_exec(line)) {
			found = 1;
			break;
		}
	}

	fclose(fp);
	return found ? 0 : -ENOENT;
}

int bpf_loader_ima_appraisal_active(const char *cmdline_path,
				    const char *policy_path, int secureboot)
{
	char buf[4096];
	size_t len = 0;
	char *tok;
	char *save = NULL;
	int read_err = 0;
	int ret;

	if (secureboot) {
		ret = ima_policy_appraises_exec(policy_path, &read_err);
		if (ret == -EACCES)
			lota_dbg("IMA appraisal blocks (Secure Boot leaves "
				 "the kernel's built-in mode in force) but %s "
				 "could not be read (%s), so the scope is "
				 "unknown",
				 policy_path, strerror(-read_err));
		return ret;
	}

	ret = read_text_file(cmdline_path, buf, sizeof(buf), &len);
	if (ret < 0)
		return ret;
	if (len == 0)
		return -EIO;
	if (buf[len - 1] == '\n')
		buf[len - 1] = '\0';

	for (tok = strtok_r(buf, " \t", &save); tok;
	     tok = strtok_r(NULL, " \t", &save)) {
		const char *val;

		if (strncmp(tok, "ima_appraise=", 13) != 0)
			continue;
		val = tok + 13;
		if (strcmp(val, "enforce") != 0 && strcmp(val, "fix") != 0)
			return -EPERM;

		ret = ima_policy_appraises_exec(policy_path, &read_err);
		if (ret == -EACCES)
			/* debug, not warn: asked every round */
			lota_dbg("IMA appraisal mode is %s but %s could not "
				 "be read (%s), so the scope is unknown",
				 val, policy_path, strerror(-read_err));
		return ret;
	}
	return -EPERM;
}

int bpf_loader_kernel_module_sig_enforced(const char *sig_enforce_path)
{
	char buf[16];
	size_t len = 0;
	int ret = read_text_file(sig_enforce_path, buf, sizeof(buf), &len);
	if (ret < 0)
		return ret;
	if (len == 0)
		return -EIO;
	if (buf[0] == 'Y' || buf[0] == '1')
		return 0;
	return -EPERM;
}

/* efivarfs: 4 bytes of attributes, then SecureBoot's byte, 1 when enabled */
int bpf_loader_secure_boot_enabled(void)
{
	static const char path[] =
		"/sys/firmware/efi/efivars/"
		"SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c";
	uint8_t buf[5];
	int fd;
	ssize_t n;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -errno;

	n = read(fd, buf, sizeof(buf));
	if (n < 0) {
		int err = -errno;
		close(fd);
		return err;
	}
	close(fd);

	if (n < (ssize_t)sizeof(buf))
		return -EIO;
	if (buf[4] == 1)
		return 0;
	return -EPERM;
}

/*
 * Returns 0 when each TPM device present carries lota_tpm_device_t, the type
 * configs/udev/99-lota-tpm.rules sets at device add, -ENOENT when none is
 * present, another negative errno otherwise.
 *
 * Reads the xattr: no libselinux at link time, and the label reads the same in
 * permissive mode.
 */
static int tpm_device_selinux_label_ok(void)
{
	static const char *const tpm_paths[] = { "/dev/tpmrm0", "/dev/tpm0" };
	const char *expected = "lota_tpm_device_t";
	bool any_present = false;

	for (size_t i = 0; i < sizeof(tpm_paths) / sizeof(tpm_paths[0]); i++) {
		char ctx[256];
		ssize_t got = getxattr(tpm_paths[i], "security.selinux", ctx,
				       sizeof(ctx) - 1);
		if (got < 0) {
			if (errno == ENOENT)
				continue;
			if (errno == ENOTSUP) {
				/* no SELinux xattrs here, no label to check */
				return 0;
			}
			lota_err("getxattr(security.selinux) failed on %s: %s",
				 tpm_paths[i], strerror(errno));
			return -errno;
		}
		any_present = true;
		ctx[got] = '\0';
		if (!strstr(ctx, expected)) {
			lota_err("TPM device %s carries SELinux label %s; "
				 "expected %s "
				 "(udev rule configs/udev/99-lota-tpm.rules "
				 "did not relabel the "
				 "device, so any other root domain can rw the "
				 "TPM and DoS LOTA "
				 "attestation availability)",
				 tpm_paths[i], ctx, expected);
			return -EPERM;
		}
	}

	if (!any_present)
		return -ENOENT;
	return 0;
}

/*
 * Returns 0 when /proc/self/exe has fs-verity enabled, -ENODATA when it does
 * not or the filesystem has none, another negative errno otherwise.
 * The digest is not compared with anything.
 */
static int agent_self_fsverity_enabled(void)
{
	int fd = open("/proc/self/exe", O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -errno;

	/* room for the largest digest */
	union {
		uint8_t buf[sizeof(struct fsverity_digest) +
			    LOTA_VERITY_DIGEST_MAX_SIZE];
		struct fsverity_digest hdr;
	} d;
	memset(&d, 0, sizeof(d));
	d.hdr.digest_size = (uint16_t)LOTA_VERITY_DIGEST_MAX_SIZE;

	int ret = 0;
	if (ioctl(fd, FS_IOC_MEASURE_VERITY, &d) != 0) {
		int err = errno;
		if (err == ENODATA || err == ENOTTY || err == EOPNOTSUPP)
			ret = -ENODATA;
		else
			ret = -err;
	}
	close(fd);
	return ret;
}

/* RSA-8192 + IMA v2 header ~1 KiB; ERANGE past this counts as unsigned */
#define LOTA_IMA_XATTR_READ_MAX 4096

/*
 * Returns 0 when the security.ima of /proc/self/exe is of a signature type,
 * negative errno otherwise. Reads the type alone: whether the kernel appraised
 * the file is bpf_loader_kernel_appraises_exec()'s question.
 *
 * A digest does not count: whoever swaps the file offline can recompute it.
 */
static int agent_self_ima_signed(void)
{
	uint8_t xattr[LOTA_IMA_XATTR_READ_MAX];
	ssize_t n = getxattr("/proc/self/exe", "security.ima", xattr,
			     sizeof(xattr));

	if (n < 0)
		return -errno;
	if (!lota_ima_xattr_is_signature(xattr, (size_t)n))
		return -ENODATA;
	return 0;
}

static int agent_self_immutability_enforced(void)
{
	int ret = agent_self_fsverity_enabled();

	if (ret == 0)
		return 0;
	if (agent_self_ima_signed() == 0)
		return 0;
	return ret;
}

int bpf_loader_kernel_appraises_exec(void)
{
	return bpf_loader_ima_appraisal_active(
		IMA_CMDLINE_PATH, IMA_POLICY_PATH,
		bpf_loader_secure_boot_enabled() == 0);
}

int bpf_loader_verify_kernel_runtime_hardening(bool allow_mutable_rootfs)
{
	int verity = agent_self_fsverity_enabled();
	bool secureboot = bpf_loader_secure_boot_enabled() == 0;
	char floor_msg[512];
	int ret;

	ret = bpf_loader_kernel_lockdown_restrictive(LOTA_KERNEL_LOCKDOWN_PATH);
	if (ret < 0) {
		kernel_floor_message(LOTA_KERNEL_FLOOR_LOCKDOWN, secureboot,
				     floor_msg, sizeof(floor_msg));
		lota_err("%s", floor_msg);
		return ret;
	}

	ret = bpf_loader_kernel_module_sig_enforced(
		LOTA_MODULE_SIG_ENFORCE_PATH);
	if (ret < 0) {
		kernel_floor_message(LOTA_KERNEL_FLOOR_MODULE_SIG, secureboot,
				     floor_msg, sizeof(floor_msg));
		lota_err("%s", floor_msg);
		return ret;
	}

	ret = bpf_loader_kernel_appraises_exec();
	if (ret < 0 &&
	    (lota_ima_scope_is_advisory(verity == 0) || allow_mutable_rootfs)) {
		lota_warn(
			"The kernel appraises no executable on this host "
			"(%s), so nothing but LOTA's own bindings covers what "
			"this machine runs: the agent binary is held by "
			"fs-verity and the PCR 14 boot commitment, and every "
			"token says KERNEL_APPRAISAL is clear. IMA-signed "
			"distribution packages, or an image pipeline that "
			"signs the executables and enrols its certificate, "
			"are what set it",
			ret == -ENOENT ? "the loaded policy carries no "
					 "appraise rule that reaches an exec" :
			ret == -EACCES ? "the loaded policy could not be read, "
					 "so no rule of it is known" :
					 "IMA appraisal is not in a blocking "
					 "mode");
		ret = 0;
	} else if (ret == -EACCES) {
		/* unread is not empty: pass, with the token's bit clear */
		lota_warn("Whether the kernel appraises any executable on "
			  "this host could not be determined: %s could not be "
			  "read, so no rule of the loaded policy is known. A "
			  "kernel built without CONFIG_IMA_READ_POLICY never "
			  "publishes it. The agent starts, and every token "
			  "says KERNEL_APPRAISAL is clear, because the scope "
			  "was unverified rather than verified empty",
			  IMA_POLICY_PATH);
		ret = 0;
	} else if (ret == -ENOENT) {
		lota_err("IMA appraisal is in a blocking mode but %s carries "
			 "no appraise rule that reaches an executable, so no "
			 "executable on this host is appraised -- and this "
			 "agent has no fs-verity of its own, so a signed "
			 "security.ima xattr nothing appraises is all that "
			 "stands between its binary and an offline swap. The "
			 "scope "
			 "comes with the signatures the rules verify: "
			 "IMA-signed distribution packages with the "
			 "distribution's certificate on the .ima keyring, or "
			 "an image pipeline that signs the executables and "
			 "enrols its certificate -- both are in the production "
			 "bringup guide. Loading rules over unsigned "
			 "executables refuses them instead, and the developer "
			 "baseline at %s is not exempt from that; a host whose "
			 "policy carries 'appraise func=POLICY_CHECK "
			 "appraise_type=imasig' refuses to load it unsigned in "
			 "the first place",
			 IMA_POLICY_PATH, LOTA_IMA_POLICY_ASSET);
		return ret;
	}
	if (ret < 0) {
		lota_err("IMA appraisal is not in an enforcing mode "
			 "(ima_appraise=enforce or fix required on the kernel "
			 "cmdline; log and the default off do not block on "
			 "integrity failures). This host booted without Secure "
			 "Boot, where the parameter is the whole answer, and "
			 "its agent binary carries no fs-verity, so appraisal "
			 "is the only thing that could bind it");
		return ret;
	}

	ret = tpm_device_selinux_label_ok();
	if (ret == -ENOENT) {
		lota_warn("No /dev/tpm[rm]0 devices present at hardening gate; "
			  "skipping SELinux confinement check");
	} else if (ret < 0) {
		if (allow_mutable_rootfs) {
			lota_warn("INSECURE: TPM device SELinux label check "
				  "failed and "
				  "--insecure-allow-mutable-rootfs was set; "
				  "another root "
				  "domain can DoS the TPM resource manager and "
				  "reduce "
				  "attestation availability");
		} else {
			return ret;
		}
	}

	ret = agent_self_immutability_enforced();
	if (ret < 0) {
		if (allow_mutable_rootfs) {
			lota_warn(
				"INSECURE: agent binary (/proc/self/exe) is "
				"neither fs-verity protected nor covered by a "
				"signed security.ima xattr, and "
				"--insecure-allow-mutable-rootfs "
				"was set. Dirty shutdown "
				"(panic/power-loss/SIGKILL) on "
				"this host cannot detect a swapped agent binary, "
				"library "
				"closure, or policy file across a hard reset; the "
				"verifier "
				"will accept the same PCR14 boot commitment after "
				"the "
				"next boot even if those inputs were tampered "
				"while the "
				"host was offline.");
		} else {
			lota_err(
				"Agent binary (/proc/self/exe) is not "
				"protected against offline tampering "
				"(needs fs-verity, or a signed security.ima "
				"xattr appraised under ima_appraise=enforce on "
				"filesystems without verity such as XFS or ZFS; "
				"required to detect tampering across "
				"panic/power-loss/SIGKILL, where "
				"dirty shutdown cannot run "
				"poison_runtime_pcr() and the verifier "
				"has no other way to notice a swapped binary "
				"on a measured rootfs)");
			return ret;
		}
	}

	return 0;
}

/*
 * Arm guarded_files with the agent's cgroup.kill and cgroup.freeze and each
 * ancestor's: a write there SIGKILLs or stops the agent past lota_task_kill.
 * No unified hierarchy is not a failure; any other error is.
 */
static int arm_kill_guard(struct bpf_loader_ctx *ctx)
{
	struct cgroup_guard_file files[LOTA_CGROUP_GUARD_MAX];
	char cgroup_path[PATH_MAX];
	int count;
	int ret;

	ret = cgroup_guard_self_path("/proc/self/cgroup", cgroup_path,
				     sizeof(cgroup_path));
	if (ret == -ENOENT) {
		lota_info(
			"No unified cgroup hierarchy: no cgroup road to guard");
		return 0;
	}
	if (ret < 0) {
		lota_err("Failed to read the agent's own cgroup: %s",
			 strerror(-ret));
		return ret;
	}

	count = cgroup_guard_collect(LOTA_CGROUP_MOUNT_ROOT, cgroup_path, files,
				     LOTA_CGROUP_GUARD_MAX);
	if (count < 0) {
		lota_err("Failed to resolve the guarded cgroup files of %s: %s",
			 cgroup_path, strerror(-count));
		return count;
	}
	if (count == 0) {
		lota_info("cgroup %s carries no cgroup.kill or cgroup.freeze",
			  cgroup_path);
		return 0;
	}

	for (int i = 0; i < count; i++) {
		struct trusted_lib_key key = { .dev = files[i].dev,
					       .ino = files[i].ino };
		uint32_t kind = files[i].kind;

		if (bpf_map_update_elem(ctx->guarded_files_fd, &key, &kind,
					BPF_ANY) < 0) {
			ret = -errno;
			lota_err("Failed to guard a cgroup file: %s",
				 strerror(-ret));
			return ret;
		}
	}

	if (bpf_map_freeze(ctx->guarded_files_fd) < 0) {
		ret = -errno;
		lota_err("Failed to freeze guarded_files map: %s",
			 strerror(-ret));
		return ret;
	}

	lota_info("Kill guard armed on %d cgroup file(s) above %s", count,
		  cgroup_path);
	return 0;
}

int bpf_loader_init(struct bpf_loader_ctx *ctx)
{
	if (!ctx)
		return -EINVAL;

	memset(ctx, 0, sizeof(*ctx));
	ctx->ringbuf_fd = -1;
	ctx->stats_fd = -1;
	ctx->config_fd = -1;
	ctx->task_auth_fd = -1;
	ctx->trusted_libs_fd = -1;
	ctx->guarded_files_fd = -1;
	ctx->protected_pids_fd = -1;
	ctx->instance_fd = -1;
	ctx->instance_stops_fd = -1;
	ctx->born_protected_fd = -1;
	ctx->allow_verity_digest_fd = -1;
	ctx->exe_hash_slots_fd = -1;
	ctx->mapped_exec_fd = -1;
	ctx->exec_history_fd = -1;
	ctx->instance_actors_fd = -1;

	libbpf_set_print(libbpf_print_fn);
	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

	return 0;
}

/*
 * Verify the detached signature at <bpf_obj_path>.sig. On success the verified
 * bytes go to the caller, to free, so the load uses what was checked.
 */
static int verify_bpf_object_signature(const char *bpf_obj_path,
				       const char *bpf_pubkey_pem_path,
				       uint8_t **out_obj_data,
				       size_t *out_obj_len)
{
	char *sig_path = NULL;
	size_t sig_path_len;
	uint8_t *obj_data = NULL;
	size_t obj_len = 0;
	uint8_t sig[POLICY_SIG_SIZE];
	FILE *f = NULL;
	long fsize;
	size_t nread;
	int ret;

	if (!bpf_obj_path || !bpf_pubkey_pem_path ||
	    bpf_pubkey_pem_path[0] == '\0' || !out_obj_data || !out_obj_len)
		return -EINVAL;

	*out_obj_data = NULL;
	*out_obj_len = 0;

	f = fopen(bpf_obj_path, "rb");
	if (!f)
		return -errno;

	if (fseek(f, 0, SEEK_END) != 0) {
		ret = -errno;
		goto out;
	}

	fsize = ftell(f);
	if (fsize < 0) {
		ret = -EIO;
		goto out;
	}

	if ((size_t)fsize > LOTA_MAX_SIGNED_OBJECT_SIZE) {
		ret = -EFBIG;
		goto out;
	}

	if (fseek(f, 0, SEEK_SET) != 0) {
		ret = -errno;
		goto out;
	}

	obj_data = malloc((size_t)fsize);
	if (!obj_data) {
		ret = -ENOMEM;
		goto out;
	}

	nread = fread(obj_data, 1, (size_t)fsize, f);
	if (nread != (size_t)fsize) {
		ret = -EIO;
		goto out;
	}
	obj_len = (size_t)fsize;

	fclose(f);
	f = NULL;

	sig_path_len = strlen(bpf_obj_path) + 5; /* ".sig" + NUL */
	sig_path = calloc(sig_path_len, 1);
	if (!sig_path) {
		ret = -ENOMEM;
		goto out;
	}

	snprintf(sig_path, sig_path_len, "%s.sig", bpf_obj_path);

	f = fopen(sig_path, "rb");
	if (!f) {
		ret = -errno ? -errno : -ENOENT;
		goto out;
	}

	nread = fread(sig, 1, POLICY_SIG_SIZE, f);
	if (nread != POLICY_SIG_SIZE) {
		ret = -EAUTH;
		goto out;
	}

	ret = policy_verify_buffer(obj_data, obj_len, bpf_pubkey_pem_path, sig);
	if (ret == 0) {
		*out_obj_data = obj_data;
		*out_obj_len = obj_len;
		obj_data = NULL;
	}

out:
	if (f)
		fclose(f);
	free(sig_path);
	free(obj_data);
	return ret;
}

int bpf_loader_verify_object(const char *bpf_obj_path,
			     const char *bpf_pubkey_pem_path)
{
	uint8_t *obj_data = NULL;
	size_t obj_len = 0;
	int ret;

	if (!bpf_obj_path)
		return -EINVAL;

	if (!bpf_pubkey_pem_path || bpf_pubkey_pem_path[0] == '\0')
		return -EINVAL;

	ret = verify_bpf_object_signature(bpf_obj_path, bpf_pubkey_pem_path,
					  &obj_data, &obj_len);

	free(obj_data);
	return ret;
}

/*
 * The kernel copies the map's own value_size to and from the caller's buffer,
 * so a map wider than the struct overruns it.
 * The pre-flight read the object on disk; this reads the map the kernel holds.
 */
static int integrity_map_fits(int map_fd)
{
	struct bpf_map_info info = { 0 };
	uint32_t len = sizeof(info);

	if (bpf_map_get_info_by_fd(map_fd, &info, &len) < 0)
		return -errno;

	if (info.key_size != sizeof(uint32_t) ||
	    info.value_size != sizeof(struct integrity_data)) {
		lota_err(
			"Loaded integrity map is key %u bytes, value %u bytes, where this build reads key %zu, value %zu",
			info.key_size, info.value_size, sizeof(uint32_t),
			sizeof(struct integrity_data));
		return -ENOTSUP;
	}

	return 0;
}

int bpf_loader_load(struct bpf_loader_ctx *ctx, const char *bpf_obj_path,
		    const char *bpf_pubkey_pem_path)
{
	struct bpf_program *prog;
	int err;
	int ret;

	if (!ctx || !bpf_obj_path)
		return -EINVAL;

	if (!bpf_pubkey_pem_path || bpf_pubkey_pem_path[0] == '\0') {
		lota_err("BPF public key is required to verify %s signature",
			 bpf_obj_path);
		return -EINVAL;
	}

	if (ctx->loaded)
		return -EALREADY;

	uint8_t *obj_data = NULL;
	size_t obj_len = 0;

	ret = verify_bpf_object_signature(bpf_obj_path, bpf_pubkey_pem_path,
					  &obj_data, &obj_len);
	if (ret < 0) {
		lota_err("BPF object signature verification failed for %s: %s",
			 bpf_obj_path, strerror(-ret));
		return ret;
	}

	struct bpf_object_open_opts opts = {
		.sz = sizeof(struct bpf_object_open_opts),
		.kernel_log_level = 1,
	};

	/*
	 * The verified bytes: the file can change after the check.
	 * libbpf is done with the buffer when open returns.
	 */
	errno = 0;
	ctx->obj = bpf_object__open_mem(obj_data, obj_len, &opts);
	free(obj_data);
	obj_data = NULL;
	if (!ctx->obj) {
		int open_err = libbpf_refusal(-ENOEXEC);

		lota_err("Failed to open BPF object %s: %s", bpf_obj_path,
			 strerror(-open_err));
		return open_err;
	}

	bpf_object__for_each_program(prog, ctx->obj) {
		bpf_program__set_log_level(prog, 2);
	}

	err = bpf_object__load(ctx->obj);
	if (err) {
		lota_err("Failed to load BPF object: %d", err);
		goto err_close;
	}

	ctx->ringbuf_fd = bpf_object__find_map_fd_by_name(ctx->obj, "events");
	if (ctx->ringbuf_fd < 0) {
		err = ctx->ringbuf_fd;
		lota_err("Failed to find events map");
		goto err_close;
	}
	err = harden_fd_cloexec(ctx->ringbuf_fd, "events map");
	if (err < 0) {
		lota_err("Failed to harden events map fd: %s", strerror(-err));
		goto err_close;
	}

	ctx->stats_fd = bpf_object__find_map_fd_by_name(ctx->obj, "stats");
	if (ctx->stats_fd < 0) {
		ctx->stats_fd = -1;
	} else {
		err = harden_fd_cloexec(ctx->stats_fd, "stats map");
		if (err < 0) {
			lota_err("Failed to harden stats map fd: %s",
				 strerror(-err));
			goto err_close;
		}
	}

	ctx->config_fd =
		bpf_object__find_map_fd_by_name(ctx->obj, "lota_config");
	if (ctx->config_fd < 0) {
		ctx->config_fd = -1;
	} else {
		err = harden_fd_cloexec(ctx->config_fd, "lota_config map");
		if (err < 0) {
			lota_err("Failed to harden lota_config map fd: %s",
				 strerror(-err));
			goto err_close;
		}
	}

	ctx->task_auth_fd =
		bpf_object__find_map_fd_by_name(ctx->obj, "lota_task_auth");
	if (ctx->task_auth_fd < 0) {
		err = ctx->task_auth_fd;
		lota_err("Failed to find lota_task_auth map");
		goto err_close;
	}
	err = harden_fd_cloexec(ctx->task_auth_fd, "lota_task_auth map");
	if (err < 0) {
		lota_err("Failed to harden lota_task_auth map fd: %s",
			 strerror(-err));
		goto err_close;
	}

	ret = set_task_auth_flags(ctx->task_auth_fd, getpid(),
				  LOTA_TASK_AUTH_ADMIN | LOTA_TASK_AUTH_AGENT);
	if (ret < 0) {
		lota_err("Failed to register task auth flags: %s",
			 strerror(-ret));
		err = ret;
		goto err_close;
	}

	if (bpf_map_freeze(ctx->task_auth_fd) < 0) {
		err = -errno;
		lota_err("Failed to freeze lota_task_auth map: %s",
			 strerror(errno));
		goto err_close;
	}

	if (ctx->config_fd >= 0) {
		uint32_t lock_key = LOTA_CFG_LOCK_BPF;
		uint32_t lock_val = 1;

		if (bpf_map_update_elem(ctx->config_fd, &lock_key, &lock_val,
					BPF_ANY) < 0) {
			lota_err("Failed to enable early LOCK_BPF: %s",
				 strerror(errno));
			err = -errno;
			goto err_close;
		}
		lota_info("Early BPF map lock enabled during loader init");
	} else {
		lota_err(
			"lota_config map unavailable, early LOCK_BPF not applied");
	}

	ctx->integrity_fd =
		bpf_object__find_map_fd_by_name(ctx->obj, "integrity_cfg");
	if (ctx->integrity_fd >= 0) {
		err = harden_fd_cloexec(ctx->integrity_fd,
					"integrity_config map");
		if (err < 0) {
			lota_err("Failed to harden integrity_config map fd: %s",
				 strerror(-err));
			goto err_close;
		}

		struct integrity_data cfg = { 0 };

		bpf_loader_build_integrity_config(&cfg,
						  LOTA_MODULE_SIG_ENFORCE_PATH,
						  LOTA_KERNEL_LOCKDOWN_PATH);

		if (bpf_loader_integrity_config_satisfied(&cfg)) {
			lota_info(
				"Kernel integrity baseline: module signatures enforced, lockdown at integrity or above");
		} else {
			lota_err(
				"Kernel integrity baseline not met (module signatures enforced: %s, lockdown at integrity or above: %s); module and firmware loads are refused in enforce mode",
				cfg.sig_enforce ? "yes" : "no",
				cfg.lockdown ? "yes" : "no");
		}

		uint32_t key = 0;

		err = integrity_map_fits(ctx->integrity_fd);
		if (err < 0) {
			lota_err("Refusing to write the integrity map of %s",
				 bpf_obj_path);
			goto err_close;
		}

		if (bpf_map_update_elem(ctx->integrity_fd, &key, &cfg,
					BPF_ANY) < 0) {
			lota_err("Failed to update integrity_config map: %s",
				 strerror(errno));
		}
	} else {
		lota_err("integrity_config map not found in BPF object");
	}

	ctx->trusted_libs_fd =
		bpf_object__find_map_fd_by_name(ctx->obj, "trusted_libs");
	if (ctx->trusted_libs_fd < 0) {
		ctx->trusted_libs_fd = -1;
	} else {
		err = harden_fd_cloexec(ctx->trusted_libs_fd,
					"trusted_libs map");
		if (err < 0) {
			lota_err("Failed to harden trusted_libs map fd: %s",
				 strerror(-err));
			goto err_close;
		}
	}

	ctx->protected_pids_fd =
		bpf_object__find_map_fd_by_name(ctx->obj, "protected_pids");
	if (ctx->protected_pids_fd < 0) {
		ctx->protected_pids_fd = -1;
	} else {
		err = harden_fd_cloexec(ctx->protected_pids_fd,
					"protected_pids map");
		if (err < 0) {
			lota_err("Failed to harden protected_pids map fd: %s",
				 strerror(-err));
			goto err_close;
		}
	}

	/* optional: without it no process joins the set through its creator */
	ctx->instance_fd =
		bpf_object__find_map_fd_by_name(ctx->obj, "lota_instance");
	if (ctx->instance_fd < 0) {
		ctx->instance_fd = -1;
	} else {
		err = harden_fd_cloexec(ctx->instance_fd, "lota_instance map");
		if (err < 0) {
			lota_err("Failed to harden lota_instance map fd: %s",
				 strerror(-err));
			goto err_close;
		}
	}

	/* optional: without it every instance reports no stopped time */
	ctx->instance_stops_fd =
		bpf_object__find_map_fd_by_name(ctx->obj, "instance_stops");
	if (ctx->instance_stops_fd < 0) {
		ctx->instance_stops_fd = -1;
		ctx->born_protected_fd = -1;
	} else {
		err = harden_fd_cloexec(ctx->instance_stops_fd,
					"instance_stops map");
		if (err < 0) {
			lota_err("Failed to harden instance_stops map fd: %s",
				 strerror(-err));
			goto err_close;
		}
	}

	/* optional: without it no list claims to start at the exec */
	ctx->born_protected_fd =
		bpf_object__find_map_fd_by_name(ctx->obj, "born_protected");
	if (ctx->born_protected_fd < 0) {
		ctx->born_protected_fd = -1;
	} else {
		err = harden_fd_cloexec(ctx->born_protected_fd,
					"born_protected map");
		if (err < 0) {
			lota_err("Failed to harden born_protected map fd: %s",
				 strerror(-err));
			goto err_close;
		}
	}

	/* required: without it cgroup.kill ends the agent past the signal gate */
	ctx->guarded_files_fd =
		bpf_object__find_map_fd_by_name(ctx->obj, "guarded_files");
	if (ctx->guarded_files_fd < 0) {
		err = ctx->guarded_files_fd;
		lota_err("Failed to find guarded_files map");
		goto err_close;
	}
	err = harden_fd_cloexec(ctx->guarded_files_fd, "guarded_files map");
	if (err < 0) {
		lota_err("Failed to harden guarded_files map fd: %s",
			 strerror(-err));
		goto err_close;
	}
	err = arm_kill_guard(ctx);
	if (err < 0)
		goto err_close;

	/* optional: without it bpf_loader_hash_file() returns -ENOSYS */
	ctx->exe_hash_slots_fd =
		bpf_object__find_map_fd_by_name(ctx->obj, "exe_hash_slots");
	if (ctx->exe_hash_slots_fd < 0) {
		ctx->exe_hash_slots_fd = -1;
	} else {
		err = harden_fd_cloexec(ctx->exe_hash_slots_fd,
					"exe_hash_slots map");
		if (err < 0) {
			lota_err("Failed to harden exe_hash_slots map fd: %s",
				 strerror(-err));
			goto err_close;
		}
	}

	/* optional: without it no library is measured */
	ctx->mapped_exec_fd =
		bpf_object__find_map_fd_by_name(ctx->obj, "mapped_exec");
	if (ctx->mapped_exec_fd < 0) {
		ctx->mapped_exec_fd = -1;
	} else {
		err = harden_fd_cloexec(ctx->mapped_exec_fd, "mapped_exec map");
		if (err < 0) {
			lota_err("Failed to harden mapped_exec map fd: %s",
				 strerror(-err));
			goto err_close;
		}
	}

	/* optional: without it no unmapped object is listed */
	ctx->exec_history_fd =
		bpf_object__find_map_fd_by_name(ctx->obj, "exec_history");
	if (ctx->exec_history_fd < 0) {
		ctx->exec_history_fd = -1;
	} else {
		err = harden_fd_cloexec(ctx->exec_history_fd,
					"exec_history map");
		if (err < 0) {
			lota_err("Failed to harden exec_history map fd: %s",
				 strerror(-err));
			goto err_close;
		}
	}

	/* optional: without it no actor of an instance is listed */
	ctx->instance_actors_fd =
		bpf_object__find_map_fd_by_name(ctx->obj, "instance_actors");
	if (ctx->instance_actors_fd < 0) {
		ctx->instance_actors_fd = -1;
	} else {
		err = harden_fd_cloexec(ctx->instance_actors_fd,
					"instance_actors map");
		if (err < 0) {
			lota_err("Failed to harden instance_actors map fd: %s",
				 strerror(-err));
			goto err_close;
		}
	}

	ctx->allow_verity_digest_fd =
		bpf_object__find_map_fd_by_name(ctx->obj, "allow_verity");
	if (ctx->allow_verity_digest_fd < 0) {
		ctx->allow_verity_digest_fd = -1;
	} else {
		err = harden_fd_cloexec(ctx->allow_verity_digest_fd,
					"allow_verity_digest map");
		if (err < 0) {
			lota_err(
				"Failed to harden allow_verity_digest map fd: %s",
				strerror(-err));
			goto err_close;
		}
	}

	ctx->loaded = true;
	return 0;

err_close:
	for (int i = 0; i < ctx->link_count; i++) {
		bpf_link__destroy(ctx->links[i]);
		ctx->links[i] = NULL;
	}
	ctx->link_count = 0;
	bpf_object__close(ctx->obj);
	ctx->obj = NULL;
	return err;
}

int bpf_loader_attach(struct bpf_loader_ctx *ctx)
{
	struct bpf_program *prog;
	struct bpf_link *link;
	int err;

	if (!ctx)
		return -EINVAL;

	if (!ctx->loaded)
		return -EINVAL;

	if (ctx->attached)
		return -EALREADY;

	static const char *const required_programs[] = {
		"lota_ptrace_access_check",
		"lota_agent_exit",
		"lota_no_core",
		"lota_agent_moved",
		"lota_stop_enter",
		"lota_stop_leave",
	};
	const size_t required_count =
		sizeof(required_programs) / sizeof(required_programs[0]);
	bool required_attached[sizeof(required_programs) /
			       sizeof(required_programs[0])] = { false };

	bpf_object__for_each_program(prog, ctx->obj) {
		enum bpf_prog_type prog_type = bpf_program__type(prog);

		if (prog_type != BPF_PROG_TYPE_LSM &&
		    prog_type != BPF_PROG_TYPE_TRACING)
			continue;

		errno = 0;
		link = bpf_program__attach(prog);
		if (!link) {
			err = libbpf_refusal(-EIO);
			lota_err("Failed to attach program %s: %s",
				 bpf_program__name(prog), strerror(-err));
			goto err_detach;
		}

		if (ctx->link_count < BPF_MAX_LSM_LINKS) {
			ctx->links[ctx->link_count++] = link;
		} else {
			lota_err("Too many attached BPF programs, increase "
				 "BPF_MAX_LSM_LINKS");
			bpf_link__destroy(link);
			err = -E2BIG;
			goto err_detach;
		}

		const char *attached_name = bpf_program__name(prog);
		lota_info("Attached BPF program: %s", attached_name);

		for (size_t i = 0; i < required_count; i++) {
			if (strcmp(attached_name, required_programs[i]) == 0) {
				required_attached[i] = true;
				break;
			}
		}
	}

	for (size_t i = 0; i < required_count; i++) {
		if (!required_attached[i]) {
			lota_err("Required BPF program %s not attached; "
				 "refusing to run with "
				 "ptrace policy gap",
				 required_programs[i]);
			err = -ENOENT;
			goto err_detach;
		}
	}

	ctx->attached = true;
	return 0;

err_detach:
	for (int i = 0; i < ctx->link_count; i++) {
		bpf_link__destroy(ctx->links[i]);
		ctx->links[i] = NULL;
	}
	ctx->link_count = 0;
	return err;
}

int bpf_loader_setup_ringbuf(struct bpf_loader_ctx *ctx,
			     bpf_event_handler_t handler, void *handler_ctx)
{
	if (!ctx || !ctx->loaded || !handler)
		return -EINVAL;

	if (ctx->ringbuf)
		return -EALREADY;

	errno = 0;
	ctx->ringbuf = ring_buffer__new(ctx->ringbuf_fd,
					(ring_buffer_sample_fn)handler,
					handler_ctx, NULL);
	if (!ctx->ringbuf) {
		int rb_err = libbpf_refusal(-EIO);

		lota_err("Failed to create ring buffer: %s", strerror(-rb_err));
		return rb_err;
	}

	return 0;
}

int bpf_loader_get_event_fd(struct bpf_loader_ctx *ctx)
{
	if (!ctx || !ctx->ringbuf)
		return -EINVAL;
	return ring_buffer__epoll_fd(ctx->ringbuf);
}

int bpf_loader_consume(struct bpf_loader_ctx *ctx)
{
	if (!ctx || !ctx->ringbuf)
		return -EINVAL;
	return ring_buffer__consume(ctx->ringbuf);
}

void bpf_loader_cleanup(struct bpf_loader_ctx *ctx)
{
	if (!ctx)
		return;

	if (ctx->ringbuf) {
		ring_buffer__free(ctx->ringbuf);
		ctx->ringbuf = NULL;
	}

	/*
	 * The links stay open: the kernel closes them when this process exits,
	 * after lota_agent_exit has ended what the agent protected.
	 */
	ctx->link_count = 0;

	if (ctx->obj) {
		bpf_object__close(ctx->obj);
		ctx->obj = NULL;
	}

	ctx->loaded = false;
	ctx->attached = false;
	ctx->ringbuf_fd = -1;
	ctx->stats_fd = -1;
	ctx->config_fd = -1;
	ctx->task_auth_fd = -1;
	ctx->integrity_fd = -1;
	ctx->trusted_libs_fd = -1;
	ctx->guarded_files_fd = -1;
	ctx->protected_pids_fd = -1;
	ctx->instance_fd = -1;
	ctx->instance_stops_fd = -1;
	ctx->allow_verity_digest_fd = -1;
	ctx->exe_hash_slots_fd = -1;
	ctx->mapped_exec_fd = -1;
	ctx->exec_history_fd = -1;
	ctx->instance_actors_fd = -1;

	free(ctx->pins);
	ctx->pins = NULL;
	ctx->pin_count = 0;
	ctx->pin_cap = 0;
}

int bpf_loader_allow_verity_digest(struct bpf_loader_ctx *ctx,
				   const struct lota_verity_digest_key *key)
{
	uint32_t value = 1;

	if (!ctx || !ctx->loaded || !key)
		return -EINVAL;

	if (!LOTA_VERITY_DIGEST_LEN_SUPPORTED(key->len))
		return -EINVAL;

	if (ctx->allow_verity_digest_fd < 0)
		return -ENOTSUP;

	if (bpf_map_update_elem(ctx->allow_verity_digest_fd, key, &value,
				BPF_ANY) < 0)
		return -errno;

	return 0;
}

static int open_regular_file_nofollow(const char *path)
{
	int fd = -1;

	if (!path)
		return -EINVAL;

	if (path[0] == '\0')
		return -EINVAL;

#ifndef O_NOFOLLOW
	return -ENOTSUP;
#else
	if (path[0] != '/')
		return -EINVAL;

	{
		struct open_how how = {
			.flags = O_RDONLY | O_CLOEXEC,
			.resolve = RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS,
		};

		fd = (int)syscall(SYS_openat2, AT_FDCWD, path, &how,
				  sizeof(how));
		if (fd < 0 && errno != ENOSYS && errno != EINVAL)
			return -errno;
	}

	if (fd < 0) {
		int dirfd = -1;
		const char *p = path;

		dirfd = open("/", O_PATH | O_DIRECTORY | O_CLOEXEC);
		if (dirfd < 0)
			return -errno;

		while (*p == '/')
			p++;

		while (*p != '\0') {
			char name[NAME_MAX + 1];
			const char *slash = strchr(p, '/');
			size_t n = slash ? (size_t)(slash - p) : strlen(p);
			int nextfd;

			if (n == 0) {
				p++;
				continue;
			}
			if (n > NAME_MAX) {
				close(dirfd);
				return -ENAMETOOLONG;
			}

			memcpy(name, p, n);
			name[n] = '\0';

			if (slash) {
				nextfd = openat(dirfd, name,
						O_PATH | O_DIRECTORY |
							O_NOFOLLOW | O_CLOEXEC);
				close(dirfd);
				if (nextfd < 0)
					return -errno;
				dirfd = nextfd;

				p = slash + 1;
				while (*p == '/')
					p++;
				continue;
			}

			fd = openat(dirfd, name,
				    O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
			close(dirfd);
			if (fd < 0)
				return -errno;
			break;
		}

		if (fd < 0)
			return -EINVAL;
	}

	return fd;
#endif
}

static int measure_fsverity_digest(const char *path,
				   struct lota_verity_digest_key *out)
{
	int fd;
	struct stat st = { 0 };
	int ret = 0;

	if (!path || !out)
		return -EINVAL;

	fd = open_regular_file_nofollow(path);
	if (fd < 0)
		return fd;

	if (fstat(fd, &st) != 0) {
		ret = -errno;
		close(fd);
		return ret;
	}

	if (!S_ISREG(st.st_mode)) {
		close(fd);
		return -EINVAL;
	}

	/* fsverity_digest has a flexible array; reserve max supported size */
	{
		union {
			uint8_t buf[sizeof(struct fsverity_digest) +
				    LOTA_VERITY_DIGEST_MAX_SIZE];
			struct fsverity_digest hdr;
		} d;

		memset(&d, 0, sizeof(d));
		d.hdr.digest_size = (uint16_t)LOTA_VERITY_DIGEST_MAX_SIZE;

		if (ioctl(fd, FS_IOC_MEASURE_VERITY, &d) != 0) {
			ret = -errno;
			close(fd);
			return ret;
		}

		if (!LOTA_VERITY_DIGEST_LEN_SUPPORTED(d.hdr.digest_size)) {
			close(fd);
			return -EINVAL;
		}

		memset(out, 0, sizeof(*out));
		out->len = d.hdr.digest_size;
		memcpy(out->digest, d.hdr.digest, (size_t)out->len);
	}

	close(fd);
	return 0;
}

int bpf_loader_measure_verity_digest(const char *path,
				     struct lota_verity_digest_key *out)
{
	return measure_fsverity_digest(path, out);
}

int bpf_loader_disallow_verity_digest(struct bpf_loader_ctx *ctx,
				      const struct lota_verity_digest_key *key)
{
	if (!ctx || !ctx->loaded || !key)
		return -EINVAL;

	if (!LOTA_VERITY_DIGEST_LEN_SUPPORTED(key->len))
		return -EINVAL;

	if (ctx->allow_verity_digest_fd < 0)
		return -ENOTSUP;

	if (bpf_map_delete_elem(ctx->allow_verity_digest_fd, key) < 0)
		return -errno;

	return 0;
}

int bpf_loader_set_mode(struct bpf_loader_ctx *ctx, uint32_t mode)
{
	uint32_t key = LOTA_CFG_MODE;

	if (!ctx || !ctx->loaded || ctx->config_fd < 0)
		return -EINVAL;

	if (mode > LOTA_MODE_ENFORCE)
		return -EINVAL;

	return bpf_map_update_elem(ctx->config_fd, &key, &mode, BPF_ANY);
}

int bpf_loader_get_mode(struct bpf_loader_ctx *ctx, uint32_t *mode)
{
	uint32_t key = LOTA_CFG_MODE;
	uint32_t value;
	int err;

	if (!ctx || !ctx->loaded || ctx->config_fd < 0 || !mode)
		return -EINVAL;

	err = bpf_map_lookup_elem(ctx->config_fd, &key, &value);
	if (err < 0)
		return err;

	*mode = value;
	return 0;
}

int bpf_loader_set_config(struct bpf_loader_ctx *ctx, uint32_t key,
			  uint32_t value)
{
	if (!ctx || !ctx->loaded || ctx->config_fd < 0)
		return -EINVAL;

	return bpf_map_update_elem(ctx->config_fd, &key, &value, BPF_ANY);
}

int bpf_loader_verify_integrity_config(struct bpf_loader_ctx *ctx)
{
	uint32_t key = 0;
	struct integrity_data current = { 0 };
	struct integrity_data expected = { 0 };
	int ret;

	if (!ctx || !ctx->loaded)
		return -EINVAL;

	if (ctx->integrity_fd < 0)
		return -ENOTSUP;

	ret = integrity_map_fits(ctx->integrity_fd);
	if (ret < 0)
		return ret;

	if (bpf_map_lookup_elem(ctx->integrity_fd, &key, &current) < 0)
		return -errno;

	bpf_loader_build_integrity_config(&expected,
					  LOTA_MODULE_SIG_ENFORCE_PATH,
					  LOTA_KERNEL_LOCKDOWN_PATH);

	if (current.sig_enforce != expected.sig_enforce ||
	    current.lockdown != expected.lockdown) {
		lota_err("integrity_config mismatch: map(sig_enforce=%u "
			 "lockdown=%u) expected(sig_enforce=%u lockdown=%u)",
			 current.sig_enforce, current.lockdown,
			 expected.sig_enforce, expected.lockdown);
		return -EPERM;
	}

	return 0;
}

/* Digest length of a hash_info algorithm id, 0 if LOTA takes none */
static uint32_t exe_hash_digest_len(uint32_t algo)
{
	switch (algo) {
	case LOTA_EXE_HASH_ALGO_SHA256:
		return 32;
	case LOTA_EXE_HASH_ALGO_SHA512:
		return 64;
	default:
		return 0;
	}
}

/*
 * Ask file_post_open about one file during this thread's open of it.
 * want picks the question: hash its content, or only report its write guard.
 */
static int exe_hash_ask(struct bpf_loader_ctx *ctx, const char *path,
			uint64_t expect_dev, uint64_t expect_ino, uint32_t want,
			struct lota_exe_hash_slot *slot)
{
	struct stat st;
	uint32_t tid;
	int ret = 0;
	int fd;

	memset(slot, 0, sizeof(*slot));

	tid = (uint32_t)syscall(SYS_gettid);
	slot->state = want;
	if (bpf_map_update_elem(ctx->exe_hash_slots_fd, &tid, slot, BPF_ANY) <
	    0)
		return -errno;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		ret = -errno;
		goto out_delete;
	}

	/* the magic link may now point at another object */
	if (fstat(fd, &st) < 0) {
		ret = -errno;
		goto out_close;
	}
	if ((uint64_t)st.st_dev != expect_dev ||
	    (uint64_t)st.st_ino != expect_ino) {
		ret = -ESTALE;
		goto out_close;
	}

	if (bpf_map_lookup_elem(ctx->exe_hash_slots_fd, &tid, slot) < 0) {
		ret = -errno;
		goto out_close;
	}

	if (slot->state != LOTA_EXE_HASH_ANSWERED) {
		/* untouched: no program attached, or the open missed it */
		ret = -ENXIO;
		goto out_close;
	}
	if (slot->err != 0)
		ret = -(int)slot->err;

out_close:
	close(fd);
out_delete:
	bpf_map_delete_elem(ctx->exe_hash_slots_fd, &tid);
	return ret;
}

int bpf_loader_hash_file(struct bpf_loader_ctx *ctx, const char *path,
			 uint64_t expect_dev, uint64_t expect_ino,
			 struct lota_verity_digest_key *out)
{
	struct lota_exe_hash_slot slot;
	uint32_t len;
	int ret;

	if (!ctx || !ctx->loaded || !path || !out)
		return -EINVAL;

	if (ctx->exe_hash_slots_fd < 0)
		return -ENOSYS;

	ret = exe_hash_ask(ctx, path, expect_dev, expect_ino,
			   LOTA_EXE_HASH_ASKED, &slot);
	if (ret != 0)
		return ret;

	len = exe_hash_digest_len(slot.algo);
	if (!LOTA_VERITY_DIGEST_LEN_SUPPORTED(len))
		return -EPROTO;

	memset(out, 0, sizeof(*out));
	out->len = len;
	memcpy(out->digest, slot.digest, len);
	return 0;
}

/* Record an inode as pinned this round, or restamp it */
static int pin_record(struct bpf_loader_ctx *ctx, uint64_t dev, uint64_t ino)
{
	struct mapped_exec_pin *grown;
	size_t at;
	size_t cap;

	at = mapped_pins_find(ctx->pins, ctx->pin_count, dev, ino);
	if (at != ctx->pin_count) {
		ctx->pins[at].round = ctx->pin_round;
		return 0;
	}

	if (ctx->pin_count == ctx->pin_cap) {
		cap = ctx->pin_cap ? ctx->pin_cap * 2 : 64;
		if (cap > LOTA_MAX_MAPPED_EXEC_GUARDS)
			cap = LOTA_MAX_MAPPED_EXEC_GUARDS;
		if (cap == ctx->pin_cap)
			return -ENOSPC;
		grown = realloc(ctx->pins, cap * sizeof(*grown));
		if (!grown)
			return -ENOMEM;
		ctx->pins = grown;
		ctx->pin_cap = cap;
	}

	ctx->pins[ctx->pin_count].dev = dev;
	ctx->pins[ctx->pin_count].ino = ino;
	ctx->pins[ctx->pin_count].round = ctx->pin_round;
	ctx->pin_count++;
	return 0;
}

int bpf_loader_pin_mapped_object(struct bpf_loader_ctx *ctx, const char *path,
				 uint64_t expect_dev, uint64_t expect_ino,
				 int *guarded)
{
	struct lota_exe_hash_slot slot;
	struct trusted_lib_key key = { 0 };
	uint32_t one = 1;
	int ret;

	if (!ctx || !ctx->loaded || !path || !guarded)
		return -EINVAL;

	*guarded = 0;

	if (ctx->exe_hash_slots_fd < 0 || ctx->mapped_exec_fd < 0)
		return -ENOSYS;

	ret = exe_hash_ask(ctx, path, expect_dev, expect_ino,
			   LOTA_EXE_HASH_ASKED_PIN, &slot);
	if (ret != 0)
		return ret;

	if (slot.dev == 0 || slot.ino == 0)
		return -ENODATA;

	/* still pinned from an earlier round: opens for write refused since */
	if (slot.guard) {
		ret = pin_record(ctx, slot.dev, slot.ino);
		if (ret < 0)
			return ret;
		*guarded = 1;
		return 0;
	}

	/* not provably the mapped bytes: leave unmeasured */
	if (slot.seen != LOTA_EXE_MAP_SEEN_OK) {
		lota_dbg("mapped object not pinned: %s (%s)", path,
			 slot.seen == LOTA_EXE_MAP_SEEN_CHANGED ?
				 "written since it was mapped" :
				 "no record of it being mapped");
		return 0;
	}
	if (slot.writers > 0) {
		lota_dbg("mapped object not pinned: %s (%u writer%s)", path,
			 slot.writers, slot.writers == 1 ? "" : "s");
		return 0;
	}

	key.dev = slot.dev;
	key.ino = slot.ino;
	if (bpf_map_update_elem(ctx->mapped_exec_fd, &key, &one, BPF_ANY) < 0) {
		ret = -errno;
		lota_warn("Failed to pin mapped object %s: %s", path,
			  strerror(-ret));
		return ret;
	}

	ret = pin_record(ctx, slot.dev, slot.ino);
	if (ret < 0) {
		/* An unrecorded pin is one no sweep could ever release */
		bpf_map_delete_elem(ctx->mapped_exec_fd, &key);
		return ret;
	}

	*guarded = 1;
	return 0;
}

void bpf_loader_pin_round_begin(struct bpf_loader_ctx *ctx)
{
	if (ctx)
		ctx->pin_round++;
}

#define OWNED_MAP_KEY_MAX 64
#define OWNED_MAP_FIRST_CAP 64

/*
 * Read up to @max entries of the map @fd into buffers that grow with them,
 * then delete those of a process @alive denies; @owner names the process of
 * a key. On success @kp and @vp hold @n live entries, packed at the front.
 */
static int read_owned_map(int fd, size_t max, size_t ksz, size_t vsz, void **kp,
			  void **vp, size_t *n,
			  void (*owner)(const void *key, uint32_t *tgid,
					uint64_t *start_ticks),
			  int (*alive)(uint32_t tgid, uint64_t start_ticks))
{
	uint8_t cur[OWNED_MAP_KEY_MAX];
	uint8_t next[OWNED_MAP_KEY_MAX];
	size_t cap = OWNED_MAP_FIRST_CAP;
	uint8_t *k = malloc(cap * ksz);
	uint8_t *v = malloc(cap * vsz);
	size_t count = 0;
	size_t kept = 0;
	void *prev = NULL;

	if (!k || !v)
		goto nomem;

	while (count < max && bpf_map_get_next_key(fd, prev, next) == 0) {
		if (count == cap) {
			uint8_t *grown;

			cap = cap * 2 < max ? cap * 2 : max;
			grown = realloc(k, cap * ksz);
			if (!grown)
				goto nomem;
			k = grown;
			grown = realloc(v, cap * vsz);
			if (!grown)
				goto nomem;
			v = grown;
		}
		memcpy(cur, next, ksz);
		prev = cur;
		if (bpf_map_lookup_elem(fd, cur, v + count * vsz) < 0)
			continue;
		memcpy(k + count * ksz, cur, ksz);
		count++;
	}

	/* deleted after the walk: a delete during it restarts the walk */
	for (size_t i = 0; i < count; i++) {
		uint32_t tgid = 0;
		uint64_t ticks = 0;

		owner(k + i * ksz, &tgid, &ticks);
		if (!alive(tgid, ticks)) {
			(void)bpf_map_delete_elem(fd, k + i * ksz);
			continue;
		}
		if (kept != i) {
			memcpy(k + kept * ksz, k + i * ksz, ksz);
			memcpy(v + kept * vsz, v + i * vsz, vsz);
		}
		kept++;
	}
	*kp = k;
	*vp = v;
	*n = kept;
	return 0;
nomem:
	free(k);
	free(v);
	return -ENOMEM;
}

static void exec_history_owner(const void *key, uint32_t *tgid,
			       uint64_t *start_ticks)
{
	const struct lota_exec_history_key *h = key;

	*tgid = h->tgid;
	*start_ticks = h->start_ticks;
}

_Static_assert(sizeof(struct lota_exec_history_key) <= OWNED_MAP_KEY_MAX,
	       "exec history key fits the walk buffer");

int bpf_loader_exec_history(struct bpf_loader_ctx *ctx,
			    int (*alive)(uint32_t tgid, uint64_t start_ticks),
			    struct lota_exec_history_key **keys,
			    struct lota_exec_history_val **vals, size_t *n)
{
	struct lota_exec_history_val *v;
	void *k, *raw_v;
	size_t count;
	int ret;

	if (!ctx || !alive || !keys || !vals || !n)
		return -EINVAL;
	*keys = NULL;
	*vals = NULL;
	*n = 0;
	if (ctx->exec_history_fd < 0)
		return -ENOENT;

	ret = read_owned_map(ctx->exec_history_fd, LOTA_MAX_EXEC_HISTORY,
			     sizeof(**keys), sizeof(*v), &k, &raw_v, &count,
			     exec_history_owner, alive);
	if (ret)
		return ret;
	v = raw_v;
	for (size_t i = 0; i < count; i++)
		v[i].name[sizeof(v[i].name) - 1] = '\0';

	*keys = k;
	*vals = v;
	*n = count;
	return 0;
}

static void instance_actor_owner(const void *key, uint32_t *tgid,
				 uint64_t *start_ticks)
{
	const struct lota_instance_actor_key *p = key;

	*tgid = p->root_tgid;
	*start_ticks = p->root_start_ticks;
}

_Static_assert(sizeof(struct lota_instance_actor_key) <= OWNED_MAP_KEY_MAX,
	       "instance actor key fits the walk buffer");

int bpf_loader_instance_actors(struct bpf_loader_ctx *ctx,
			       int (*alive)(uint32_t tgid,
					    uint64_t start_ticks),
			       struct lota_instance_actor_key **keys,
			       struct lota_instance_actor_val **vals, size_t *n)
{
	struct lota_instance_actor_val *v;
	void *k, *raw_v;
	size_t count;
	int ret;

	if (!ctx || !alive || !keys || !vals || !n)
		return -EINVAL;
	*keys = NULL;
	*vals = NULL;
	*n = 0;
	if (ctx->instance_actors_fd < 0)
		return -ENOENT;

	ret = read_owned_map(ctx->instance_actors_fd, LOTA_MAX_INSTANCE_ACTORS,
			     sizeof(**keys), sizeof(*v), &k, &raw_v, &count,
			     instance_actor_owner, alive);
	if (ret)
		return ret;
	v = raw_v;
	for (size_t i = 0; i < count; i++) {
		v[i].comm[sizeof(v[i].comm) - 1] = '\0';
		v[i].owner_comm[sizeof(v[i].owner_comm) - 1] = '\0';
	}

	*keys = k;
	*vals = v;
	*n = count;
	return 0;
}

int bpf_loader_pin_sweep(struct bpf_loader_ctx *ctx, size_t *released)
{
	struct trusted_lib_key key = { 0 };
	size_t write_at;
	size_t kept = 0;
	size_t gone = 0;
	int ret = 0;

	if (!ctx || !ctx->loaded)
		return -EINVAL;

	if (ctx->mapped_exec_fd < 0)
		return -ENOSYS;

	kept = mapped_pins_partition(ctx->pins, ctx->pin_count, ctx->pin_round);

	/* compact; a pin the map would not drop stays */
	write_at = kept;
	for (size_t i = kept; i < ctx->pin_count; i++) {
		key.dev = ctx->pins[i].dev;
		key.ino = ctx->pins[i].ino;
		if (bpf_map_delete_elem(ctx->mapped_exec_fd, &key) < 0 &&
		    errno != ENOENT) {
			ret = -errno;
			ctx->pins[write_at++] = ctx->pins[i];
			continue;
		}
		gone++;
	}

	ctx->pin_count = write_at;
	if (released)
		*released = gone;
	return ret;
}

int bpf_loader_protected_pids(const struct bpf_loader_ctx *ctx, uint32_t *pid,
			      uint64_t *start, size_t max)
{
	struct protected_pid_entry value;
	uint32_t key, next;
	size_t n = 0;
	int ret;

	if (!ctx || !ctx->loaded || ctx->protected_pids_fd < 0)
		return -ENOTSUP;

	ret = bpf_map_get_next_key(ctx->protected_pids_fd, NULL, &next);
	while (ret == 0 && n < max) {
		key = next;
		if (bpf_map_lookup_elem(ctx->protected_pids_fd, &key, &value) ==
		    0) {
			pid[n] = key;
			start[n] = value.start_time_ticks;
			n++;
		}
		ret = bpf_map_get_next_key(ctx->protected_pids_fd, &key, &next);
	}
	if (ret < 0 && errno != ENOENT)
		return -errno;
	return (int)n;
}

int bpf_loader_protect_pid(struct bpf_loader_ctx *ctx, uint32_t pid)
{
	struct protected_pid_entry value = { 0 };
	int ret;

	if (!ctx || !ctx->loaded)
		return -EINVAL;

	if (ctx->protected_pids_fd < 0)
		return -ENOTSUP;

	ret = read_pid_start_time_ticks(pid, &value.start_time_ticks);
	if (ret < 0)
		return ret;

	if (value.start_time_ticks == 0)
		return -EINVAL;

	if (bpf_map_update_elem(ctx->protected_pids_fd, &pid, &value, BPF_ANY) <
	    0)
		return -errno;

	return 0;
}

int bpf_loader_adopt_instance_member(struct bpf_loader_ctx *ctx, uint32_t pid)
{
	struct protected_pid_entry value = { 0 };
	struct lota_instance_entry entry;
	int pidfd;
	int ret;

	if (!ctx || !ctx->loaded || pid == 0)
		return -EINVAL;

	if (ctx->protected_pids_fd < 0 || ctx->instance_fd < 0)
		return -ENOTSUP;

#ifndef SYS_pidfd_open
	return -ENOTSUP;
#else
	pidfd = (int)syscall(SYS_pidfd_open, (pid_t)pid, 0);
	if (pidfd < 0)
		return -errno;

	if (bpf_map_lookup_elem(ctx->instance_fd, &pidfd, &entry) < 0) {
		ret = errno == ENOENT ? 0 : -errno;
		goto out;
	}

	ret = read_pid_start_time_ticks(pid, &value.start_time_ticks);
	if (ret < 0)
		goto out;
	if (value.start_time_ticks == 0) {
		ret = -EINVAL;
		goto out;
	}

	/* still alive: the start time read was its own, not a successor's */
	if (bpf_map_lookup_elem(ctx->instance_fd, &pidfd, &entry) < 0) {
		ret = errno == ENOENT ? 0 : -errno;
		goto out;
	}

	if (bpf_map_update_elem(ctx->protected_pids_fd, &pid, &value, BPF_ANY) <
	    0) {
		ret = -errno;
		goto out;
	}
	ret = 1;
out:
	close(pidfd);
	return ret;
#endif
}

int bpf_loader_probe_protect_pid(uint32_t pid)
{
	uint64_t start_time_ticks = 0;
	int ret;

	ret = read_pid_start_time_ticks(pid, &start_time_ticks);
	if (ret < 0)
		return ret;

	if (start_time_ticks == 0)
		return -EINVAL;

	return 0;
}

/* the clock bpf_ktime_get_ns() reads */
static uint64_t monotonic_ns(void)
{
	struct timespec now;

	if (clock_gettime(CLOCK_MONOTONIC, &now) < 0)
		return 0;
	return (uint64_t)now.tv_sec * 1000000000ULL + (uint64_t)now.tv_nsec;
}

int bpf_loader_instance_stopped_ms(struct bpf_loader_ctx *ctx, uint32_t pid,
				   uint64_t *ms)
{
	struct lota_instance_stops stops;
	struct lota_instance_entry entry;
	uint64_t root_ticks = 0;
	uint64_t ticks = 0;
	uint32_t root = pid;
	int pidfd;
	int ret;

	if (!ctx || !ms || pid == 0)
		return -EINVAL;

	*ms = 0;
	if (!ctx->loaded || ctx->instance_fd < 0 || ctx->instance_stops_fd < 0)
		return 0;

#ifndef SYS_pidfd_open
	return 0;
#else
	pidfd = (int)syscall(SYS_pidfd_open, (pid_t)pid, 0);
	if (pidfd < 0)
		return errno == ESRCH ? 0 : -errno;

	if (bpf_map_lookup_elem(ctx->instance_fd, &pidfd, &entry) == 0) {
		root = entry.root_tgid;
		root_ticks = entry.root_start_ticks;
	} else if (errno != ENOENT) {
		ret = errno == ESRCH ? 0 : -errno;
		close(pidfd);
		return ret;
	}

	if (root != pid) {
		close(pidfd);
		pidfd = (int)syscall(SYS_pidfd_open, (pid_t)root, 0);
		if (pidfd < 0)
			return errno == ESRCH ? 0 : -errno;

		/* pidfd first: a PID reused after this read fails the lookup */
		ret = read_pid_start_time_ticks(root, &ticks);
		if (ret < 0) {
			ret = ret == -ENOENT ? 0 : ret;
			goto out;
		}
		if (ticks != root_ticks) {
			ret = 0;
			goto out;
		}
	}

	if (bpf_map_lookup_elem_flags(ctx->instance_stops_fd, &pidfd, &stops,
				      BPF_F_LOCK) < 0) {
		ret = (errno == ENOENT || errno == ESRCH) ? 0 : -errno;
		goto out;
	}

	*ms = lota_stopped_ns(stops.total_ns, stops.stopped_threads,
			      stops.since_ns, monotonic_ns()) /
	      1000000ULL;
	ret = 0;
out:
	close(pidfd);
	return ret;
#endif
}

/*
 * A thread of an unprotected process leaves its stop unseen, and the count it
 * holds would run on through a later protection. Keep the total, close the
 * period.
 */
static void close_instance_stops(struct bpf_loader_ctx *ctx, uint32_t pid)
{
	struct lota_instance_stops stops;
	int pidfd;

	if (ctx->instance_stops_fd < 0)
		return;

#ifdef SYS_pidfd_open
	pidfd = (int)syscall(SYS_pidfd_open, (pid_t)pid, 0);
	if (pidfd < 0)
		return;

	if (bpf_map_lookup_elem_flags(ctx->instance_stops_fd, &pidfd, &stops,
				      BPF_F_LOCK) == 0 &&
	    stops.stopped_threads) {
		stops.total_ns =
			lota_stopped_ns(stops.total_ns, stops.stopped_threads,
					stops.since_ns, monotonic_ns());
		stops.stopped_threads = 0;
		(void)bpf_map_update_elem(ctx->instance_stops_fd, &pidfd,
					  &stops, BPF_EXIST | BPF_F_LOCK);
	}
	close(pidfd);
#endif
}

int bpf_loader_born_protected(struct bpf_loader_ctx *ctx, uint32_t pid,
			      uint64_t start_ticks)
{
	uint64_t ticks = 0;
	uint32_t born;
	int pidfd;
	int ret;

	if (!ctx || pid == 0)
		return -EINVAL;

	if (!ctx->loaded || ctx->born_protected_fd < 0 || start_ticks == 0)
		return 0;

#ifndef SYS_pidfd_open
	return 0;
#else
	pidfd = (int)syscall(SYS_pidfd_open, (pid_t)pid, 0);
	if (pidfd < 0)
		return errno == ESRCH ? 0 : -errno;

	/* pidfd first: a PID reused after this read fails the lookup */
	ret = read_pid_start_time_ticks(pid, &ticks);
	if (ret < 0) {
		ret = ret == -ENOENT ? 0 : ret;
		goto out;
	}
	if (ticks != start_ticks) {
		ret = 0;
		goto out;
	}

	if (bpf_map_lookup_elem(ctx->born_protected_fd, &pidfd, &born) < 0)
		ret = (errno == ENOENT || errno == ESRCH) ? 0 : -errno;
	else
		ret = 1;
out:
	close(pidfd);
	return ret;
#endif
}

/* history stops with protection, so a later one starts past the exec */
static void forget_born_protected(struct bpf_loader_ctx *ctx, uint32_t pid)
{
	int pidfd;

	if (ctx->born_protected_fd < 0)
		return;

#ifdef SYS_pidfd_open
	pidfd = (int)syscall(SYS_pidfd_open, (pid_t)pid, 0);
	if (pidfd < 0)
		return;

	(void)bpf_map_delete_elem(ctx->born_protected_fd, &pidfd);
	close(pidfd);
#endif
}

int bpf_loader_unprotect_pid(struct bpf_loader_ctx *ctx, uint32_t pid)
{
	if (!ctx || !ctx->loaded)
		return -EINVAL;

	if (ctx->protected_pids_fd < 0)
		return -ENOTSUP;

	if (bpf_map_delete_elem(ctx->protected_pids_fd, &pid) < 0)
		return -errno;

	forget_born_protected(ctx, pid);
	close_instance_stops(ctx, pid);
	return 0;
}

static int stat_regular_file_nofollow(const char *path, struct stat *st,
				      unsigned long long *sb_dev)
{
	int fd = -1;
	int ret = 0;

	if (!path || !st)
		return -EINVAL;

	if (path[0] == '\0')
		return -EINVAL;

	fd = open_regular_file_nofollow(path);
	if (fd < 0)
		return fd;

	if (fstat(fd, st) != 0) {
		ret = -errno;
		close(fd);
		return ret;
	}

	if (sb_dev) {
		ret = sb_dev_from_fd(fd, sb_dev);
		if (ret < 0) {
			close(fd);
			return ret;
		}
	}

	close(fd);
	if (!S_ISREG(st->st_mode))
		return -EINVAL;

	return 0;
}

/*
 * The hooks look these keys up with inode->i_sb->s_dev, which on btrfs differs
 * from stat(2)'s st_dev: a subvolume has its own anonymous device.
 * A path whose superblock device cannot be read is refused.
 */
static int trusted_lib_key_for_file(const char *path,
				    struct trusted_lib_key *key)
{
	unsigned long long sb_dev = 0;
	struct stat st = { 0 };
	int ret;

	ret = stat_regular_file_nofollow(path, &st, &sb_dev);
	if (ret < 0) {
		if (ret == -ENOTSUP || ret == -ENODEV)
			lota_err(
				"Cannot read the superblock device of %s: %s; "
				"the kernel would never match a trusted-library key for it",
				path, strerror(-ret));
		return ret;
	}

	key->dev = sb_dev;
	key->ino = (uint64_t)st.st_ino;
	if (key->dev == 0 || key->ino == 0)
		return -EINVAL;

	return 0;
}

int bpf_loader_probe_trusted_lib(const char *path)
{
	struct trusted_lib_key key = { 0 };

	if (!path)
		return -EINVAL;

	return trusted_lib_key_for_file(path, &key);
}

int bpf_loader_trust_lib(struct bpf_loader_ctx *ctx, const char *path)
{
	struct trusted_lib_key key = { 0 };
	uint32_t value = 1;
	int ret;

	if (!ctx || !ctx->loaded || !path)
		return -EINVAL;

	if (ctx->trusted_libs_fd < 0)
		return -ENOTSUP;

	ret = trusted_lib_key_for_file(path, &key);
	if (ret < 0)
		return ret;

	if (bpf_map_update_elem(ctx->trusted_libs_fd, &key, &value, BPF_ANY) <
	    0)
		return -errno;

	return 0;
}

int bpf_loader_untrust_lib(struct bpf_loader_ctx *ctx, const char *path)
{
	struct trusted_lib_key key = { 0 };
	int ret;

	if (!ctx || !ctx->loaded || !path)
		return -EINVAL;

	if (ctx->trusted_libs_fd < 0)
		return -ENOTSUP;

	ret = trusted_lib_key_for_file(path, &key);
	if (ret < 0)
		return ret;

	if (bpf_map_delete_elem(ctx->trusted_libs_fd, &key) < 0 &&
	    errno != ENOENT)
		return -errno;

	return 0;
}

static int read_stat(int stats_fd, uint32_t key, uint64_t *out)
{
	uint64_t value;
	int err;

	err = bpf_map_lookup_elem(stats_fd, &key, &value);
	*out = (err == 0) ? value : 0;
	return 0;
}

int bpf_loader_get_extended_stats(struct bpf_loader_ctx *ctx,
				  struct bpf_extended_stats *stats)
{
	if (!ctx || !stats || !ctx->loaded || ctx->stats_fd < 0)
		return -EINVAL;

	read_stat(ctx->stats_fd, STAT_TOTAL_EXECS, &stats->total_execs);
	read_stat(ctx->stats_fd, STAT_EVENTS_SENT, &stats->events_sent);
	read_stat(ctx->stats_fd, STAT_RINGBUF_DROPS, &stats->drops);
	read_stat(ctx->stats_fd, STAT_MODULES_BLOCKED, &stats->modules_blocked);
	read_stat(ctx->stats_fd, STAT_MMAP_EXECS, &stats->mmap_execs);
	read_stat(ctx->stats_fd, STAT_MMAP_BLOCKED, &stats->mmap_blocked);
	read_stat(ctx->stats_fd, STAT_PTRACE_ATTEMPTS, &stats->ptrace_attempts);
	read_stat(ctx->stats_fd, STAT_PTRACE_BLOCKED, &stats->ptrace_blocked);
	read_stat(ctx->stats_fd, STAT_SETUID_EVENTS, &stats->setuid_events);
	read_stat(ctx->stats_fd, STAT_BPF_SYSCALL_BLOCKED,
		  &stats->bpf_syscall_blocked);
	read_stat(ctx->stats_fd, STAT_MOUNTS_BLOCKED, &stats->mounts_blocked);
	read_stat(ctx->stats_fd, STAT_KILL_GUARD_BLOCKED,
		  &stats->kill_guard_blocked);
	read_stat(ctx->stats_fd, STAT_MAPPED_WRITE_BLOCKED,
		  &stats->mapped_write_blocked);
	read_stat(ctx->stats_fd, STAT_MAPPED_PIN_REFUSED,
		  &stats->mapped_pin_refused);
	read_stat(ctx->stats_fd, STAT_EXEC_HISTORY_LOST,
		  &stats->exec_history_lost);
	read_stat(ctx->stats_fd, STAT_INSTANCE_ACTORS_LOST,
		  &stats->instance_actors_lost);
	read_stat(ctx->stats_fd, STAT_INSTANCE_STOPS_LOST,
		  &stats->instance_stops_lost);
	read_stat(ctx->stats_fd, STAT_EVENTS_YIELDED, &stats->events_yielded);
	read_stat(ctx->stats_fd, STAT_BLOCKED_EVENTS_SUPPRESSED,
		  &stats->blocked_suppressed);
	read_stat(ctx->stats_fd, STAT_KILL_PROBES, &stats->kill_probes);

	return 0;
}
