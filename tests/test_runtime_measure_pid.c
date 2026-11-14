/* SPDX-License-Identifier: MIT */
/*
 * LOTA kernel-anchored per-process measurement - Unit Tests
 *
 * Full fs-verity measurement path is validated on a verity-enabled filesystem
 * in the VM scenarios; here is the pinned fail-closed contract that matters
 * even without fs-verity: the function never reports success with an absent
 * measurement, and it rejects unmeasurable inputs.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/sysmacros.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <signal.h>

#include "test.h"
#include "../src/agent/runtime_image_measure.h"
#include "../src/agent/registry.h"
#include "lota.h"
#include "lota_devt.h"
#include "lota_ipc.h"
#include "lota_registry_digest.h"

#include <openssl/evp.h>

static int maps_reads;
static void (*before_second_maps_read)(void);

FILE *__real_fopen(const char *path, const char *mode);
FILE *__wrap_fopen(const char *path, const char *mode);
int __real_openat(int dirfd, const char *path, int flags, ...);
int __wrap_openat(int dirfd, const char *path, int flags, ...);

FILE *__wrap_fopen(const char *path, const char *mode)
{
	size_t len = strlen(path);

	if (len >= 5 && strcmp(path + len - 5, "/maps") == 0)
		maps_reads++;
	if (maps_reads == 2 && before_second_maps_read)
		before_second_maps_read();
	return __real_fopen(path, mode);
}

/* a filesystem that refuses this file to the agent, as FUSE does to root */
static const char *refuse_open;
static int refuse_exe_stat;

int __real_stat(const char *path, struct stat *st);
int __wrap_stat(const char *path, struct stat *st);

int __wrap_stat(const char *path, struct stat *st)
{
	size_t len = strlen(path);

	if (refuse_exe_stat && len >= 4 &&
	    strcmp(path + len - 4, "/exe") == 0) {
		errno = EACCES;
		return -1;
	}
	return __real_stat(path, st);
}

/* opening a map_files link takes CAP_CHECKPOINT_RESTORE, reading it does not */
int __wrap_openat(int dirfd, const char *path, int flags, ...)
{
	char target[PATH_MAX];
	ssize_t len = readlinkat(dirfd, path, target, sizeof(target) - 1);

	if (len <= 0)
		return __real_openat(dirfd, path, flags);
	target[len] = '\0';
	if (refuse_open && strcmp(target, refuse_open) == 0) {
		errno = EACCES;
		return -1;
	}
	return __real_openat(AT_FDCWD, target, flags);
}

static int fake_content_hash(const char *path, uint64_t dev, uint64_t ino,
			     struct lota_verity_digest_key *out)
{
	(void)path;
	(void)dev;
	(void)ino;
	memset(out, 0, sizeof(*out));
	out->len = LOTA_VERITY_DIGEST_SHA256_SIZE;
	out->digest[0] = 1;
	return 0;
}

#define MAPPING_SIZE 4096

static void *mapping;
static int other_file = -1;

static void unmap_mapping(void)
{
	munmap(mapping, MAPPING_SIZE);
}

static void replace_mapping(void)
{
	mmap(mapping, MAPPING_SIZE, PROT_READ | PROT_EXEC,
	     MAP_PRIVATE | MAP_FIXED, other_file, 0);
}

/* a file of its own next to the test binary, whose filesystem may execute */
static int open_scratch_file(char *path, size_t size, const char *suffix)
{
	char exe[PATH_MAX];
	ssize_t len = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
	int fd;

	if (len <= 0)
		return -1;
	exe[len] = '\0';
	if ((size_t)snprintf(path, size, "%s%s", exe, suffix) >= size)
		return -1;
	fd = __real_openat(AT_FDCWD, path,
			   O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	if (fd >= 0 && ftruncate(fd, MAPPING_SIZE) != 0) {
		close(fd);
		return -1;
	}
	return fd;
}

/* the process measures, and path is listed with nothing read from it */
static int walk_leaves_gap(const char *path)
{
	struct lota_rt_object_record *objs =
		calloc(LOTA_RUNTIME_IMAGE_MAX_MODULES, sizeof(*objs));
	struct lota_runtime_measure_coverage cov;
	uint8_t digest[LOTA_RUNTIME_IMAGE_DIGEST_SIZE];
	size_t n = 0;
	int ret;
	int ok = 0;

	if (!objs)
		return 0;
	lota_rt_set_content_hasher(fake_content_hash);
	ret = lota_runtime_measure_pid_objects(getpid(), digest, &cov, NULL,
					       objs, &n);
	lota_rt_set_content_hasher(NULL);
	for (size_t i = 0; i < n; i++) {
		if (strcmp(objs[i].entry.path, path) == 0)
			ok = ret == 0 && cov.unmeasurable > 0 &&
			     objs[i].size == 0;
	}
	free(objs);
	return ok;
}

/* lowest free descriptor, so a leak moves it */
static int next_fd(void)
{
	int fd = __real_openat(AT_FDCWD, "/dev/null", O_RDONLY | O_CLOEXEC);

	if (fd >= 0)
		close(fd);
	return fd;
}

static int digest_is_zero(const uint8_t d[32])
{
	for (int i = 0; i < 32; i++)
		if (d[i] != 0)
			return 0;
	return 1;
}

static void test_long_path_keeps_tail(void)
{
	char path[401];
	char out[LOTA_RT_MAP_PATH_MAX];
	size_t len;

	TEST("a path past the buffer keeps its tail, marked");
	memset(path, 'd', sizeof(path) - 1);
	path[0] = '/';
	memcpy(path + sizeof(path) - 10, "/game.bin", 10);
	lota_rt_path_keep_tail(path, out, sizeof(out));
	len = strlen(out);
	if (len != sizeof(out) - 1 ||
	    strncmp(out, LOTA_RT_PATH_CUT, strlen(LOTA_RT_PATH_CUT)) != 0 ||
	    strcmp(out + len - 9, "/game.bin") != 0 ||
	    strcmp(out + strlen(LOTA_RT_PATH_CUT),
		   path + strlen(path) - (len - strlen(LOTA_RT_PATH_CUT))) !=
		    0) {
		FAIL(out);
		return;
	}

	lota_rt_path_keep_tail("/usr/bin/game", out, sizeof(out));
	if (strcmp(out, "/usr/bin/game") != 0) {
		FAIL("a short path is changed");
		return;
	}
	PASS();
}

static int copy_file(const char *from, const char *to)
{
	char buf[8192];
	ssize_t n;
	int in, out, ret = 0;

	in = open(from, O_RDONLY | O_CLOEXEC);
	if (in < 0)
		return -1;
	out = open(to, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0755);
	if (out < 0) {
		close(in);
		return -1;
	}
	while ((n = read(in, buf, sizeof(buf))) > 0)
		if (write(out, buf, (size_t)n) != n)
			ret = -1;
	if (n < 0)
		ret = -1;
	close(in);
	if (close(out) != 0)
		ret = -1;
	return ret;
}

/* each component is 100 bytes: four of them put the path past the buffer */
static void test_long_path_process_is_measured(void)
{
	static struct lota_rt_object_record objs[LOTA_RUNTIME_IMAGE_MAX_MODULES];
	char dir[PATH_MAX], exe[PATH_MAX] = "", link[PATH_MAX];
	size_t n = 0, len, root_len;
	uint8_t digest[32];
	int found = 0, ret = -1, d = 0;
	pid_t pid = -1;

	TEST("a process at a path past the buffer is measured, tail kept");
	snprintf(dir, sizeof(dir), "/tmp/lota-longpath.XXXXXX");
	if (!mkdtemp(dir)) {
		FAIL("mkdtemp");
		return;
	}
	root_len = strlen(dir);
	for (d = 0; d < 4; d++) {
		len = strlen(dir);
		if (len + 102 >= sizeof(dir))
			goto out;
		dir[len] = '/';
		memset(dir + len + 1, 'd', 100);
		dir[len + 101] = '\0';
		if (mkdir(dir, 0700) != 0) {
			dir[len] = '\0';
			goto out;
		}
	}
	len = strlen(dir);
	if (len + sizeof("/game.bin") > sizeof(exe))
		goto out;
	memcpy(exe, dir, len);
	memcpy(exe + len, "/game.bin", sizeof("/game.bin"));
	if (copy_file("/bin/sleep", exe) != 0)
		goto out;

	pid = fork();
	if (pid == 0) {
		execl(exe, "game.bin", "30", (char *)NULL);
		_exit(127);
	}
	if (pid < 0)
		goto out;
	for (int i = 0; i < 200; i++) {
		char proc[64];
		ssize_t l;

		snprintf(proc, sizeof(proc), "/proc/%d/exe", (int)pid);
		l = readlink(proc, link, sizeof(link) - 1);
		if (l > 0) {
			link[l] = '\0';
			if (strcmp(link, exe) == 0)
				break;
		}
		usleep(10000);
	}

	ret = lota_runtime_measure_pid_objects(pid, digest, NULL, NULL, objs,
					       &n);
	for (size_t i = 0; i < n; i++) {
		len = strlen(objs[i].entry.path);
		if (strcmp(objs[i].entry.soname, "game.bin") == 0 &&
		    len == sizeof(objs[i].entry.path) - 1 &&
		    strncmp(objs[i].entry.path, LOTA_RT_PATH_CUT,
			    strlen(LOTA_RT_PATH_CUT)) == 0 &&
		    strcmp(objs[i].entry.path + len - 9, "/game.bin") == 0)
			found = 1;
	}

out:
	if (pid > 0) {
		kill(pid, SIGKILL);
		waitpid(pid, NULL, 0);
	}
	if (exe[0])
		unlink(exe);
	while (strlen(dir) > root_len) {
		rmdir(dir);
		*strrchr(dir, '/') = '\0';
	}
	rmdir(dir);
	if (ret != -ENAMETOOLONG && found)
		PASS();
	else
		FAIL("long path refused or not cut to its tail");
}

int main(void)
{
	uint8_t digest[32];
	struct lota_runtime_measure_failure mfail;
	struct lota_runtime_measure_coverage cov;
	int ret;

	printf("Kernel-anchored per-process measurement tests:\n");

	test_long_path_keeps_tail();
	test_long_path_process_is_measured();

	TEST("measure_pid never reports success with an absent digest");
	memset(digest, 0, sizeof(digest));
	ret = lota_runtime_measure_pid(getpid(), digest, &cov, &mfail);
	/*
	 * Without fs-verity on the freshly built test binary the call fails
	 * closed; with fs-verity it must yield a non-zero digest.
	 * Either way it must never return success while leaving the digest
	 * unset.
	 */
	if (ret < 0 || !digest_is_zero(digest))
		PASS();
	else
		FAIL("success with zero digest");

	/*
	 * The failure integrator reads has to say which object stopped measurement;
	 * refusal with no object named is the state this test exists to keep out.
	 */
	TEST("a refused measurement names the object that stopped it");
	if (ret == 0 || mfail.soname[0] != '\0')
		PASS();
	else
		FAIL("refused with no object named");

	TEST("measure_pid rejects a nonexistent process");
	if (lota_runtime_measure_pid(-1, digest, NULL, NULL) < 0)
		PASS();
	else
		FAIL("accepted bad pid");

	TEST("measure_pid rejects NULL output");
	if (lota_runtime_measure_pid(getpid(), NULL, NULL, NULL) < 0)
		PASS();
	else
		FAIL("accepted NULL output");

	TEST("open_mapping rejects an unbacked range");
	{
		struct lota_rt_map_entry e;
		struct stat st;

		memset(&e, 0, sizeof(e));
		strcpy(e.soname, "none");
		if (lota_rt_open_mapping(AT_FDCWD, &e, &st) == -EINVAL)
			PASS();
		else
			FAIL("accepted unbacked range");
	}

	TEST("measure_pid_objects lists the mappings of a failed measurement");
	{
		static struct lota_rt_object_record
			objs[LOTA_RUNTIME_IMAGE_MAX_MODULES];
		char exe[LOTA_RT_MAP_PATH_MAX] = "";
		size_t n = 0;
		int found = 0;
		ssize_t elen = readlink("/proc/self/exe", exe, sizeof(exe) - 1);

		if (elen > 0)
			exe[elen] = '\0';
		(void)lota_runtime_measure_pid_objects(getpid(), digest, NULL,
						       NULL, objs, &n);
		for (size_t i = 0; i < n; i++)
			if (strcmp(objs[i].entry.path, exe) == 0)
				found = 1;
		if (n > 0 && found)
			PASS();
		else
			FAIL("own executable missing from the objects");
	}

	TEST("measure_pid_objects refuses objects with nowhere to count them");
	{
		static struct lota_rt_object_record objs[1];

		if (lota_runtime_measure_pid_objects(getpid(), digest, NULL,
						     NULL, objs,
						     NULL) == -EINVAL)
			PASS();
		else
			FAIL("accepted objects without a count");
	}

	TEST("registry pages every object and binds the round");
	{
		static struct lota_rt_object_record objs[40];
		struct lota_ipc_registry_actor actors[30];
		struct registry cur = { 0 };
		struct registry next = { 0 };
		const struct registry_process *p;
		uint8_t folded[32];
		uint8_t buf[2048];
		uint32_t start = 0, pages = 0, seen = 0, seen_actors = 0;
		int ok = 1;

		memset(actors, 0, sizeof(actors));
		for (int i = 0; i < 30; i++) {
			actors[i].tgid = 5000u + (uint32_t)i;
			actors[i].kind = LOTA_IPC_REGISTRY_ACTOR_CONNECT;
			snprintf(actors[i].comm, sizeof(actors[i].comm),
				 "actor%02d", i);
		}

		memset(folded, 0xab, sizeof(folded));
		for (int i = 0; i < 40; i++) {
			memset(&objs[i], 0, sizeof(objs[i]));
			snprintf(objs[i].entry.soname,
				 sizeof(objs[i].entry.soname), "lib%02d.so", i);
			snprintf(objs[i].entry.path, sizeof(objs[i].entry.path),
				 "/opt/title/lib%02d.so", i);
			objs[i].size = 4096u * (uint64_t)i;
			if (i % 3 != 0) {
				objs[i].digest.len = 32;
				objs[i].digest.digest[0] = (uint8_t)i;
				objs[i].content_hashed = (i % 3 == 2);
			}
		}
		ok &= registry_add(&next, 1234, 51, 1000, 0, folded, objs, 40,
				   actors, 30) == 0;
		ok &= registry_add(&next, 1235, 52, 1000,
				   LOTA_IPC_REGISTRY_HISTORY_LOST |
					   LOTA_IPC_REGISTRY_FROM_EXEC |
					   LOTA_IPC_REGISTRY_MEASURED,
				   NULL, NULL, 0, NULL, 0) == 0;
		registry_replace(&cur, &next);
		ok &= cur.round == 1 && next.count == 0;

		p = registry_find(&cur, 1234, 51);
		ok &= p != NULL && registry_find(&cur, 99, 51) == NULL;
		ok &= registry_find(&cur, 1234, 52) == NULL;
		while (ok && p && start < p->count + p->actor_count) {
			struct lota_ipc_registry_page hdr;
			size_t len = 0, off = sizeof(hdr);
			int c = registry_encode_page(p, cur.round, start, buf,
						     sizeof(buf), &len);

			if (c <= 0) {
				ok = 0;
				break;
			}
			memcpy(&hdr, buf, sizeof(hdr));
			ok &= hdr.round == 1 && hdr.pid == 1234 &&
			      hdr.total == 40 && hdr.actor_total == 30 &&
			      hdr.start == start && hdr.count == (uint16_t)c &&
			      (hdr.flags & LOTA_IPC_REGISTRY_MEASURED) &&
			      memcmp(hdr.registry_digest, folded, 32) == 0;
			for (int k = 0; k < c; k++) {
				struct lota_ipc_registry_entry e;
				struct lota_ipc_registry_actor q;
				uint32_t idx = start + (uint32_t)k;
				uint8_t want;

				/* the actors follow the last object */
				if (idx >= 40) {
					memcpy(&q, buf + off, sizeof(q));
					off += sizeof(q);
					ok &= q.tgid == 5000u + (idx - 40) &&
					      strcmp(q.comm,
						     actors[idx - 40].comm) ==
						      0;
					seen_actors++;
					continue;
				}
				want = idx % 3 == 0 ?
					       LOTA_IPC_REGISTRY_ROAD_NONE :
				       idx % 3 == 2 ?
					       LOTA_IPC_REGISTRY_ROAD_CONTENT :
					       LOTA_IPC_REGISTRY_ROAD_VERITY;

				memcpy(&e, buf + off, sizeof(e));
				off += sizeof(e);
				ok &= e.road == want &&
				      e.size == 4096u * (uint64_t)idx &&
				      e.soname_len == 8 &&
				      memcmp(buf + off, objs[idx].entry.soname,
					     8) == 0;
				off += e.soname_len + e.path_len;
				seen++;
			}
			ok &= off == len;
			start += (uint32_t)c;
			pages++;
		}
		ok &= seen == 40 && seen_actors == 30 && pages > 1;
		{
			size_t len = 0;

			ok &= registry_encode_page(p, cur.round, 71, buf,
						   sizeof(buf),
						   &len) == -ERANGE;
			ok &= registry_encode_page(p, cur.round, 0, buf, 100,
						   &len) == -ENOSPC;
			p = registry_find(&cur, 1235, 52);
			ok &= p &&
			      p->flags == (LOTA_IPC_REGISTRY_HISTORY_LOST |
					   LOTA_IPC_REGISTRY_FROM_EXEC) &&
			      registry_encode_page(p, cur.round, 0, buf,
						   sizeof(buf), &len) == 0 &&
			      len == sizeof(struct lota_ipc_registry_page);
		}
		registry_clear(&cur);
		if (ok)
			PASS();
		else
			FAIL("registry paging lost or misdescribed an object");
	}

	TEST("registry lists what the maps no longer show");
	{
		static struct lota_rt_object_record objs[4];
		struct lota_exec_history_key keys[5];
		struct lota_exec_history_val vals[5];
		const uint64_t dev = LOTA_DEVT_MKDEV(8, 3);
		size_t n;
		int overflow = 0;
		int ok = 1;

		memset(objs, 0, sizeof(objs));
		memset(keys, 0, sizeof(keys));
		memset(vals, 0, sizeof(vals));
		for (int i = 0; i < 2; i++) {
			objs[i].entry.dev_major = 8;
			objs[i].entry.dev_minor = 3;
			objs[i].entry.ino = 10u + (uint64_t)i;
			snprintf(objs[i].entry.soname,
				 sizeof(objs[i].entry.soname), "lib%d.so", i);
		}
		/* still mapped, so already listed */
		keys[0] = (struct lota_exec_history_key){ 7, 0, 99, dev, 10 };
		vals[0].flags = LOTA_EXEC_HISTORY_WRITABLE;
		keys[1] = (struct lota_exec_history_key){ 7, 0, 99, dev, 12 };
		vals[1].size = 512;
		vals[1].flags = LOTA_EXEC_HISTORY_MEMORY;
		strcpy(vals[1].name, "inject.so");
		/* an earlier process under the same PID */
		keys[2] = (struct lota_exec_history_key){ 7, 0, 98, dev, 13 };
		/* another process */
		keys[3] = (struct lota_exec_history_key){ 8, 0, 99, dev, 14 };
		/* the kernel found no name */
		keys[4] = (struct lota_exec_history_key){ 7, 0, 99, dev, 15 };

		n = registry_merge_history(objs, 2, 4, keys, vals, 5, 7, 99,
					   &overflow);
		ok &= n == 4 && !overflow && !objs[0].unmapped &&
		      !objs[1].unmapped;
		ok &= objs[0].history_flags == LOTA_EXEC_HISTORY_WRITABLE &&
		      objs[1].history_flags == 0 &&
		      objs[2].history_flags == LOTA_EXEC_HISTORY_MEMORY &&
		      objs[3].history_flags == 0;
		ok &= objs[2].unmapped && objs[2].entry.ino == 12 &&
		      objs[2].entry.dev_major == 8 &&
		      objs[2].entry.dev_minor == 3 && objs[2].size == 512 &&
		      strcmp(objs[2].entry.soname, "inject.so") == 0 &&
		      objs[2].entry.path[0] == '\0' && objs[2].digest.len == 0;
		ok &= objs[3].unmapped && objs[3].entry.ino == 15 &&
		      strcmp(objs[3].entry.soname, "?") == 0;

		n = registry_merge_history(objs, 2, 3, keys, vals, 5, 7, 99,
					   &overflow);
		ok &= n == 3 && overflow;
		if (ok)
			PASS();
		else
			FAIL("history merge kept, lost or misnamed an object");
	}

	TEST("registry lists who reached the instance from outside");
	{
		struct lota_instance_actor_key keys[4];
		struct lota_instance_actor_val vals[4];
		struct lota_ipc_registry_actor out[2];
		size_t n;
		int overflow = 0;
		int ok = 1;

		memset(keys, 0, sizeof(keys));
		memset(vals, 0, sizeof(vals));
		/* root 7 started at 99 */
		keys[0] = (struct lota_instance_actor_key){
			99, 300, 7, 40, 8, LOTA_IPC_REGISTRY_ACTOR_CONNECT
		};
		vals[0].count = 3;
		vals[0].exe_dev = LOTA_DEVT_MKDEV(8, 3);
		vals[0].exe_ino = 55;
		vals[0].uid = 1000;
		memcpy(vals[0].comm, "injector", 8);
		memcpy(vals[0].owner_comm, "wineserver", 10);
		/* an earlier root under the same PID */
		keys[1] = (struct lota_instance_actor_key){
			98, 301, 7, 41, 7, LOTA_IPC_REGISTRY_ACTOR_SEND
		};
		/* another instance */
		keys[2] = (struct lota_instance_actor_key){
			99, 302, 9, 42, 9, LOTA_IPC_REGISTRY_ACTOR_SEND
		};
		/* a name that fills the kernel's buffer */
		keys[3] = (struct lota_instance_actor_key){
			99, 303, 7, 43, 7, LOTA_IPC_REGISTRY_ACTOR_SIGNAL
		};
		memset(vals[3].comm, 'a', sizeof(vals[3].comm));

		n = registry_collect_actors(out, 2, keys, vals, 4, 7, 99,
					    &overflow);
		ok &= n == 2 && !overflow;
		ok &= out[0].tgid == 40 && out[0].start_ticks == 300 &&
		      out[0].owner_tgid == 8 && out[0].count == 3 &&
		      out[0].exe_dev == makedev(8, 3) && out[0].exe_ino == 55 &&
		      out[0].uid == 1000 &&
		      out[0].kind == LOTA_IPC_REGISTRY_ACTOR_CONNECT &&
		      strcmp(out[0].comm, "injector") == 0 &&
		      strcmp(out[0].owner_comm, "wineserver") == 0;
		ok &= out[1].tgid == 43 && strlen(out[1].comm) == 15 &&
		      out[1].kind == LOTA_IPC_REGISTRY_ACTOR_SIGNAL;

		n = registry_collect_actors(out, 1, keys, vals, 4, 7, 99,
					    &overflow);
		ok &= n == 1 && overflow;
		if (ok)
			PASS();
		else
			FAIL("actor collection kept, lost or misnamed an actor");
	}

	TEST("registry digest is the hash of the listed pages");
	{
		static struct lota_rt_object_record objs[3];
		struct lota_ipc_registry_actor actors[2];
		struct registry cur = { 0 };
		struct registry next = { 0 };
		const struct registry_process *p;
		const uint16_t flags = LOTA_IPC_REGISTRY_HISTORY_LOST;
		uint8_t want[32], got[32], other[32];
		uint8_t buf[2048];
		size_t len = 0, off = sizeof(struct lota_ipc_registry_page);
		EVP_MD_CTX *md = EVP_MD_CTX_new();
		int ok = md != NULL;

		memset(objs, 0, sizeof(objs));
		for (int i = 0; i < 3; i++) {
			snprintf(objs[i].entry.soname,
				 sizeof(objs[i].entry.soname), "lib%d.so", i);
			objs[i].entry.ino = 20u + (uint64_t)i;
			objs[i].size = 100u * (uint64_t)i;
		}
		strcpy(objs[0].entry.path, "/opt/title/lib0.so");
		objs[0].digest.len = 32;
		memset(objs[0].digest.digest, 0x5a, 32);
		objs[2].unmapped = 1;
		objs[1].history_flags = LOTA_EXEC_HISTORY_WRITABLE |
					LOTA_EXEC_HISTORY_MEMORY;

		memset(actors, 0, sizeof(actors));
		actors[0] = (struct lota_ipc_registry_actor){
			.count = 2,
			.tgid = 600,
			.kind = LOTA_IPC_REGISTRY_ACTOR_SEND
		};
		strcpy(actors[0].comm, "probe");
		strcpy(actors[0].owner_comm, "title");
		actors[1] = actors[0];
		actors[1].tgid = 601;

		ok &= registry_digest(flags | LOTA_IPC_REGISTRY_MEASURED, objs,
				      3, actors, 2, want) == 0;
		ok &= registry_add(&next, 77, 53, 1000, flags, want, objs, 3,
				   actors, 2) == 0;
		registry_replace(&cur, &next);
		p = registry_find(&cur, 77, 53);
		if (!p)
			ok = 0;
		else
			ok &= p->flags ==
				      (flags | LOTA_IPC_REGISTRY_MEASURED) &&
			      registry_encode_page(p, cur.round, 0, buf,
						   sizeof(buf), &len) == 5;

		/* what a relying party does with the page it received */
		if (ok) {
			struct lota_ipc_registry_page hdr;

			memcpy(&hdr, buf, sizeof(hdr));
			ok &= lota_registry_digest_begin(md, hdr.flags,
							 hdr.total,
							 hdr.actor_total) == 0;
			for (int i = 0; ok && i < (int)hdr.total; i++) {
				struct lota_ipc_registry_entry e;
				const char *s;

				memcpy(&e, buf + off, sizeof(e));
				off += sizeof(e);
				s = (const char *)buf + off;
				off += e.soname_len + e.path_len;
				ok &= (i == 2) ==
				      !!(e.flags &
					 LOTA_IPC_REGISTRY_ENTRY_UNMAPPED);
				ok &= (i == 1) ==
				      (e.flags ==
				       (LOTA_IPC_REGISTRY_ENTRY_WRITABLE |
					LOTA_IPC_REGISTRY_ENTRY_MEMORY));
				ok &= lota_registry_digest_entry(
					      md, &e, s, s + e.soname_len) == 0;
			}
			for (int i = 0; ok && i < (int)hdr.actor_total; i++) {
				struct lota_ipc_registry_actor q;

				memcpy(&q, buf + off, sizeof(q));
				off += sizeof(q);
				ok &= lota_registry_digest_actor(md, &q) == 0;
			}
			ok &= off == len;
			ok &= lota_registry_digest_final(md, got) == 0 &&
			      memcmp(got, want, 32) == 0 &&
			      memcmp(hdr.registry_digest, want, 32) == 0;
		}

		/* an object without a digest is bound all the same */
		ok &= registry_digest(flags | LOTA_IPC_REGISTRY_MEASURED, objs,
				      2, actors, 2, other) == 0 &&
		      memcmp(other, want, 32) != 0;
		/* and so is every actor */
		ok &= registry_digest(flags | LOTA_IPC_REGISTRY_MEASURED, objs,
				      3, actors, 1, other) == 0 &&
		      memcmp(other, want, 32) != 0;
		EVP_MD_CTX_free(md);
		registry_clear(&cur);
		if (ok)
			PASS();
		else
			FAIL("the pages do not hash to the token's entry");
	}

	TEST("coverage reads the maps twice however many objects there are");
	{
		uint32_t past = 0;
		struct lota_rt_map_entry *e =
			calloc(LOTA_RUNTIME_IMAGE_MAX_MODULES, sizeof(*e));
		size_t n = 0;

		ret = e ? lota_rt_collect_exec_maps(
				  getpid(), e, LOTA_RUNTIME_IMAGE_MAX_MODULES,
				  &n, &past) :
			  -ENOMEM;
		free(e);
		maps_reads = 0;
		if (ret == 0 && n > 2 &&
		    lota_runtime_coverage_pid(getpid(), &cov) == 0 &&
		    cov.measured + cov.unmeasurable == n && maps_reads == 2)
			PASS();
		else
			FAIL("maps read once per object");
	}

	TEST("measurement reads the maps twice however many objects there are");
	{
		lota_rt_set_content_hasher(fake_content_hash);
		maps_reads = 0;
		ret = lota_runtime_measure_pid(getpid(), digest, &cov, NULL);
		lota_rt_set_content_hasher(NULL);
		if (ret == 0 && cov.unmeasurable > 1 && maps_reads == 2)
			PASS();
		else
			FAIL("maps read once per object");
	}

	TEST("a mapped file on tmpfs is a gap in coverage");
	{
		char path[] = "/dev/shm/lota-test-XXXXXX";
		int fd = mkstemp(path);
		void *m = MAP_FAILED;

		if (fd >= 0 && ftruncate(fd, MAPPING_SIZE) == 0)
			m = mmap(NULL, MAPPING_SIZE, PROT_READ | PROT_EXEC,
				 MAP_PRIVATE, fd, 0);
		if (m == MAP_FAILED) {
			PASS();
		} else if (lota_runtime_coverage_pid(getpid(), &cov) == 0 &&
			   cov.unmeasurable > 0) {
			PASS();
		} else {
			FAIL("a file on tmpfs stopped the walk");
		}
		if (m != MAP_FAILED)
			munmap(m, MAPPING_SIZE);
		if (fd >= 0) {
			close(fd);
			unlink(path);
		}
	}

	TEST("a file on tmpfs mapped before protection is listed as memory");
	{
		static struct lota_rt_object_record
			objs[LOTA_RUNTIME_IMAGE_MAX_MODULES];
		char path[] = "/dev/shm/lota-test-XXXXXX";
		int fd = mkstemp(path);
		void *m = MAP_FAILED;
		size_t n = 0;
		uint32_t flags = 0;

		if (fd >= 0 && ftruncate(fd, MAPPING_SIZE) == 0)
			m = mmap(NULL, MAPPING_SIZE, PROT_READ | PROT_EXEC,
				 MAP_PRIVATE, fd, 0);
		lota_rt_set_content_hasher(fake_content_hash);
		if (m != MAP_FAILED)
			(void)lota_runtime_measure_pid_objects(
				getpid(), digest, &cov, NULL, objs, &n);
		lota_rt_set_content_hasher(NULL);
		for (size_t i = 0; i < n; i++) {
			if (strcmp(objs[i].entry.path, path) == 0)
				flags = objs[i].history_flags;
		}
		if (m == MAP_FAILED || flags == LOTA_EXEC_HISTORY_MEMORY)
			PASS();
		else
			FAIL("no memory flag on a file on tmpfs");
		if (m != MAP_FAILED)
			munmap(m, MAPPING_SIZE);
		if (fd >= 0) {
			close(fd);
			unlink(path);
		}
	}

	TEST("a walk leaves no mapping open");
	{
		int before = next_fd();

		(void)lota_runtime_coverage_pid(getpid(), &cov);
		(void)lota_runtime_measure_pid(getpid(), digest, NULL, NULL);
		(void)lota_runtime_coverage_pid(-1, &cov);
		if (before >= 0 && next_fd() == before)
			PASS();
		else
			FAIL("descriptor left open");
	}

	{
		char path[PATH_MAX + 16], other[PATH_MAX + 16];
		int fd = open_scratch_file(path, sizeof(path), ".map0");
		int before;

		other_file = open_scratch_file(other, sizeof(other), ".map1");
		mapping = fd < 0 || other_file < 0 ? MAP_FAILED :
						     mmap(NULL, MAPPING_SIZE,
							  PROT_READ | PROT_EXEC,
							  MAP_PRIVATE, fd, 0);
		before = next_fd();

		TEST("a mapping replaced by the check is a gap");
		before_second_maps_read = replace_mapping;
		maps_reads = 0;
		if (mapping != MAP_FAILED && walk_leaves_gap(path))
			PASS();
		else
			FAIL("not a gap");

		TEST("a mapping gone by the check is a gap");
		before_second_maps_read = unmap_mapping;
		maps_reads = 0;
		if (mapping != MAP_FAILED &&
		    lota_runtime_coverage_pid(getpid(), &cov) == 0 &&
		    cov.unmeasurable > 0)
			PASS();
		else
			FAIL("not a gap");
		before_second_maps_read = NULL;

		TEST("a stale walk leaves no mapping open");
		if (next_fd() == before)
			PASS();
		else
			FAIL("descriptor left open");

		if (fd >= 0)
			close(fd);
		if (other_file >= 0)
			close(other_file);
		unlink(path);
		unlink(other);
	}

	{
		static char path[PATH_MAX + 16];
		int fd = open_scratch_file(path, sizeof(path), ".map2");
		void *m = fd < 0 ? MAP_FAILED :
				   mmap(NULL, MAPPING_SIZE,
					PROT_READ | PROT_EXEC, MAP_PRIVATE, fd,
					0);

		TEST("a mapping that will not open is a gap");
		refuse_open = path;
		if (m != MAP_FAILED && walk_leaves_gap(path) &&
		    lota_runtime_coverage_pid(getpid(), &cov) == 0 &&
		    cov.unmeasurable > 0)
			PASS();
		else
			FAIL("not a gap");
		refuse_open = NULL;

		if (m != MAP_FAILED)
			munmap(m, MAPPING_SIZE);
		if (fd >= 0)
			close(fd);
		unlink(path);
	}

	TEST("an own executable that will not open is refused");
	{
		struct lota_runtime_measure_failure refused;
		static char exe[PATH_MAX];
		ssize_t len = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
		int refusal;

		exe[len > 0 ? len : 0] = '\0';
		refuse_open = exe;
		lota_rt_set_content_hasher(fake_content_hash);
		refusal = lota_runtime_measure_pid(getpid(), digest, &cov,
						   &refused);
		lota_rt_set_content_hasher(NULL);
		refuse_open = NULL;
		if (refusal == -EACCES && strcmp(refused.path, exe) == 0)
			PASS();
		else
			FAIL("the executable did not stop the walk");
	}

	TEST("an own executable the agent may not stat is named");
	{
		struct lota_runtime_measure_failure refused;
		char exe[PATH_MAX];
		ssize_t len = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
		int refusal;

		exe[len > 0 ? len : 0] = '\0';
		refuse_exe_stat = 1;
		refusal = lota_runtime_measure_pid(getpid(), digest, &cov,
						   &refused);
		refuse_exe_stat = 0;
		if (refusal == -EACCES && strcmp(refused.path, exe) == 0 &&
		    refused.role == LOTA_RT_ROLE_EXECUTABLE)
			PASS();
		else
			FAIL("the refusal names nothing");
	}

	TEST("a walk out of descriptors fails without a gap");
	{
		struct rlimit old;
		struct rlimit low;
		int measured = 0;
		int counted = 0;

		if (getrlimit(RLIMIT_NOFILE, &old) == 0) {
			low = old;
			/* the map_files directory fits, a mapping does not */
			low.rlim_cur = (rlim_t)next_fd() + 1;
			if (setrlimit(RLIMIT_NOFILE, &low) == 0) {
				lota_rt_set_content_hasher(fake_content_hash);
				measured = lota_runtime_measure_pid(
					getpid(), digest, &cov, NULL);
				lota_rt_set_content_hasher(NULL);
				counted = lota_runtime_coverage_pid(getpid(),
								    &cov);
				(void)setrlimit(RLIMIT_NOFILE, &old);
			}
		}
		if (measured == -EMFILE && counted == -EMFILE)
			PASS();
		else
			FAIL("read the agent's own limit as a gap");
	}

	TEST("a process past the object limit is measured up to the limit");
	{
		enum {
			COUNT = LOTA_RUNTIME_IMAGE_MAX_MODULES
		};
		static void *many[COUNT];
		static char many_path[COUNT][PATH_MAX + 16];
		static struct lota_rt_object_record objs[COUNT];
		struct lota_runtime_measure_coverage walk;
		char why[LOTA_RT_REASON_MAX];
		size_t n = 0;
		int ok = 1;

		for (int i = 0; ok && i < COUNT; i++) {
			char suffix[32];
			int fd;

			snprintf(suffix, sizeof(suffix), ".many%d", i);
			fd = open_scratch_file(many_path[i],
					       sizeof(many_path[i]), suffix);
			ok = fd >= 0;
			if (!ok)
				break;
			many[i] = mmap(NULL, MAPPING_SIZE,
				       PROT_READ | PROT_EXEC, MAP_PRIVATE, fd,
				       0);
			ok = many[i] != MAP_FAILED;
			close(fd);
		}
		lota_rt_set_content_hasher(fake_content_hash);
		ret = ok ? lota_runtime_measure_pid_objects(
				   getpid(), digest, &cov, &mfail, objs, &n) :
			   -EIO;
		lota_rt_set_content_hasher(NULL);
		ok &= lota_runtime_coverage_pid(getpid(), &walk) == 0;
		for (int i = 0; i < COUNT; i++) {
			if (many[i] && many[i] != MAP_FAILED)
				munmap(many[i], MAPPING_SIZE);
			if (many_path[i][0])
				unlink(many_path[i]);
		}
		lota_rt_failure_reason(&mfail, -ENODATA, why, sizeof(why));
		if (ok && ret == 0 && n == COUNT && cov.measured >= 1 &&
		    cov.past_limit > 0 && walk.past_limit == cov.past_limit &&
		    walk.unmeasurable >= cov.past_limit &&
		    cov.measured + cov.unmeasurable == COUNT + cov.past_limit &&
		    mfail.past_limit == cov.past_limit &&
		    strstr(why, "past the"))
			PASS();
		else
			FAIL("measurement refused the whole process");
	}

	printf("\n%d/%d kernel-anchored measurement tests passed\n",
	       tests_passed, tests_run);
	return tests_passed == tests_run ? 0 : 1;
}
