// SPDX-License-Identifier: MIT
/*
 * syzkaller/lota_bpf_fuzz.c
 *
 * Standalone bring-up harness that makes the LOTA BPF LSM layer live
 * inside a syzkaller VM so the fuzzer actually exercises it.
 *
 * syzkaller fuzzes the kernel through syscalls and measures kernel
 * coverage (KCOV). LOTA's security logic that lives in the kernel is
 * the set of BPF LSM programs in lota_lsm.bpf.o. Unless those programs
 * are loaded, attached, and configured into enforce mode, none of that
 * code runs and the fuzzer only re-tests the bare kernel -- which is
 * what the previous setup did.
 *
 * This loader pulls in the *production* lota_lsm.bpf.o (the same object
 * the agent ships), populates the config + protected-PID maps, attaches
 * every LSM hook, and idles. From that point every exec, mmap, mprotect,
 * ptrace, signal, module load, mount, setuid and bpf() the fuzzer emits
 * runs through the LOTA hooks under KCOV/KASAN. It deliberately does not
 * touch the agent, TPM, attestation or IPC: it is a kernel-surface fuzz
 * harness, not a second agent, and it bypasses no agent security path.
 *
 * Map writes happen BEFORE attach: once the lota_bpf / lota_bpf_map
 * hooks are live they reject writes from non-agent tasks (this loader
 * included), which is the behaviour the fuzzer then probes.
 *
 * Build: make -C .. syzkaller-fuzz-loader  (needs libbpf >= 1.0)
 * Run:   ./lota_bpf_fuzz /usr/lib/lota/lota_lsm.bpf.o [extra_pid ...]
 */

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../include/lota.h"

/* Mirrors struct protected_pid_entry in src/bpf/lota_lsm.bpf.c. */
struct protected_pid_entry {
	uint64_t start_time_ticks;
};

#define MAX_VICTIMS 4
#define MAX_LINKS 32

static volatile sig_atomic_t g_stop;

static void on_signal(int sig)
{
	(void)sig;
	g_stop = 1;
}

/*
 * Read field 22 (starttime, clock ticks) of /proc/<pid>/stat. The comm
 * field can contain spaces and parentheses, so scan past the final ')'
 * before counting space-separated fields.
 */
static int read_start_ticks(uint32_t pid, uint64_t *out)
{
	char path[64];
	char line[4096];
	char *rparen;
	char *field;
	char *saveptr = NULL;
	int idx = 3;
	FILE *fp;

	snprintf(path, sizeof(path), "/proc/%u/stat", pid);
	fp = fopen(path, "r");
	if (!fp)
		return -errno;
	if (!fgets(line, sizeof(line), fp)) {
		fclose(fp);
		return -EIO;
	}
	fclose(fp);

	rparen = strrchr(line, ')');
	if (!rparen || rparen[1] == '\0')
		return -EINVAL;
	field = rparen + 2;

	for (char *tok = strtok_r(field, " ", &saveptr); tok;
	     tok = strtok_r(NULL, " ", &saveptr), idx++) {
		if (idx == 22) {
			*out = strtoull(tok, NULL, 10);
			return *out ? 0 : -EINVAL;
		}
	}
	return -EINVAL;
}

static int set_cfg(int fd, uint32_t key, uint32_t val)
{
	if (bpf_map_update_elem(fd, &key, &val, BPF_ANY) < 0) {
		fprintf(stderr, "config[%u]=%u failed: %s\n", key, val,
			strerror(errno));
		return -1;
	}
	return 0;
}

static int protect_pid(int fd, uint32_t pid)
{
	struct protected_pid_entry e = {0};

	if (read_start_ticks(pid, &e.start_time_ticks) < 0) {
		fprintf(stderr, "start_time for pid %u failed\n", pid);
		return -1;
	}
	if (bpf_map_update_elem(fd, &pid, &e, BPF_ANY) < 0) {
		fprintf(stderr, "protect pid %u failed: %s\n", pid,
			strerror(errno));
		return -1;
	}
	return 0;
}

int main(int argc, char *argv[])
{
	const char *obj_path =
	    (argc > 1) ? argv[1] : "/usr/lib/lota/lota_lsm.bpf.o";
	struct bpf_object *obj;
	struct bpf_program *prog;
	struct bpf_link *links[MAX_LINKS];
	int cfg_fd, pp_fd;
	int attached = 0;
	pid_t victims[MAX_VICTIMS];
	int nvictims = 0;

	signal(SIGTERM, on_signal);
	signal(SIGINT, on_signal);

	obj = bpf_object__open_file(obj_path, NULL);
	if (libbpf_get_error(obj)) {
		fprintf(stderr, "open %s failed\n", obj_path);
		return 1;
	}
	if (bpf_object__load(obj)) {
		fprintf(stderr, "load failed: %s\n", strerror(errno));
		return 1;
	}

	cfg_fd = bpf_object__find_map_fd_by_name(obj, "lota_config");
	pp_fd = bpf_object__find_map_fd_by_name(obj, "protected_pids");
	if (cfg_fd < 0 || pp_fd < 0) {
		fprintf(stderr, "required maps not found\n");
		return 1;
	}

	/*
	 * Spawn idle victims before attach so we can register them while
	 * the bpf_map hook is still inactive. They give the fuzzer live
	 * protected targets for the ptrace / task_kill / mprotect gates.
	 */
	for (int i = 0; i < MAX_VICTIMS; i++) {
		pid_t p = fork();

		if (p == 0) {
			while (1)
				pause();
			_exit(0);
		}
		if (p > 0)
			victims[nvictims++] = p;
	}

	/*
	 * Enforce, but only the flags that are safe on a stock guest with
	 * no trust allowlist. STRICT_MMAP / STRICT_EXEC / STRICT_MODULES /
	 * BLOCK_ANON_EXEC are global gates: with an empty trusted_libs /
	 * allow_verity set they reject every exec and executable mapping
	 * on the system, which kills sshd and syz-executor and bricks the
	 * VM ("can't ssh into the instance"). BLOCK_PTRACE is PID-scoped to
	 * the protected victims and LOCK_BPF only guards LOTA's own maps,
	 * so both are safe. Every hook is still attached and runs its
	 * prologue (mode + is_protected_task lookup + map reads) on every
	 * matching syscall, which is the coverage syzkaller needs.
	 */
	set_cfg(cfg_fd, LOTA_CFG_MODE, LOTA_MODE_ENFORCE);
	set_cfg(cfg_fd, LOTA_CFG_BLOCK_PTRACE, 1);
	set_cfg(cfg_fd, LOTA_CFG_LOCK_BPF, 1);

	protect_pid(pp_fd, (uint32_t)getpid());
	for (int i = 0; i < nvictims; i++)
		protect_pid(pp_fd, (uint32_t)victims[i]);
	for (int i = 2; i < argc; i++)
		protect_pid(pp_fd, (uint32_t)strtoul(argv[i], NULL, 10));

	bpf_object__for_each_program(prog, obj)
	{
		struct bpf_link *link = bpf_program__attach(prog);

		if (libbpf_get_error(link)) {
			fprintf(stderr, "attach %s failed: %s\n",
				bpf_program__name(prog), strerror(errno));
			continue;
		}
		if (attached < MAX_LINKS)
			links[attached] = link;
		attached++;
	}
	if (!attached) {
		fprintf(stderr,
			"no LSM programs attached (need lsm=...,bpf)\n");
		return 1;
	}

	printf("lota-bpf-fuzz: %d hooks attached, %d victims protected; "
	       "victim pids:",
	       attached, nvictims);
	for (int i = 0; i < nvictims; i++)
		printf(" %d", victims[i]);
	printf("\nready for syz-executor\n");
	fflush(stdout);

	while (!g_stop)
		pause();

	/*
	 * Detach the hooks before reaping the victims: while task_kill is
	 * live it blocks signals to the protected victims (this loader is
	 * not the agent), so they would be unkillable otherwise.
	 */
	for (int i = 0; i < attached && i < MAX_LINKS; i++)
		bpf_link__destroy(links[i]);
	for (int i = 0; i < nvictims; i++)
		kill(victims[i], SIGKILL);
	return 0;
}
