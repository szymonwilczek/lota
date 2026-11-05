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
#include <sys/sysmacros.h>

#include "test.h"
#include "../src/agent/runtime_image_measure.h"
#include "../src/agent/registry.h"
#include "lota.h"
#include "lota_devt.h"
#include "lota_ipc.h"
#include "lota_registry_digest.h"

#include <openssl/evp.h>

static int maps_reads;

FILE *__real_fopen(const char *path, const char *mode);
FILE *__wrap_fopen(const char *path, const char *mode);
int __real_openat(int dirfd, const char *path, int flags, ...);
int __wrap_openat(int dirfd, const char *path, int flags, ...);

FILE *__wrap_fopen(const char *path, const char *mode)
{
	size_t len = strlen(path);

	if (len >= 5 && strcmp(path + len - 5, "/maps") == 0)
		maps_reads++;
	return __real_fopen(path, mode);
}

/* opening a map_files link takes CAP_CHECKPOINT_RESTORE, reading it does not */
int __wrap_openat(int dirfd, const char *path, int flags, ...)
{
	char target[PATH_MAX];
	ssize_t len = readlinkat(dirfd, path, target, sizeof(target) - 1);

	if (len <= 0)
		return __real_openat(dirfd, path, flags);
	target[len] = '\0';
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

static int digest_is_zero(const uint8_t d[32])
{
	for (int i = 0; i < 32; i++)
		if (d[i] != 0)
			return 0;
	return 1;
}

int main(void)
{
	uint8_t digest[32];
	struct lota_runtime_measure_failure mfail;
	struct lota_runtime_measure_coverage cov;
	int ret;

	printf("Kernel-anchored per-process measurement tests:\n");

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

	TEST("measure_entry_verity rejects an unbacked range");
	{
		struct lota_rt_map_entry e;
		struct lota_verity_digest_key v;
		memset(&e, 0, sizeof(e));
		strcpy(e.soname, "none");
		if (lota_rt_measure_entry_verity(getpid(), &e, &v, NULL, NULL) <
		    0)
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
		ok &= registry_add(&next, 1234, 1000, 0, folded, objs, 40,
				   actors, 30) == 0;
		ok &= registry_add(&next, 1235, 1000,
				   LOTA_IPC_REGISTRY_HISTORY_LOST |
					   LOTA_IPC_REGISTRY_FROM_EXEC |
					   LOTA_IPC_REGISTRY_MEASURED,
				   NULL, NULL, 0, NULL, 0) == 0;
		registry_replace(&cur, &next);
		ok &= cur.round == 1 && next.count == 0;

		p = registry_find(&cur, 1234);
		ok &= p != NULL && registry_find(&cur, 99) == NULL;
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
			      memcmp(hdr.image_digest, folded, 32) == 0;
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
			p = registry_find(&cur, 1235);
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
		ok &= registry_add(&next, 77, 1000, flags, want, objs, 3,
				   actors, 2) == 0;
		registry_replace(&cur, &next);
		p = registry_find(&cur, 77);
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
			      memcmp(hdr.image_digest, want, 32) == 0;
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
		struct lota_rt_map_entry *e =
			calloc(LOTA_RUNTIME_IMAGE_MAX_MODULES, sizeof(*e));
		size_t n = 0;

		ret = e ? lota_rt_collect_exec_maps(
				  getpid(), e, LOTA_RUNTIME_IMAGE_MAX_MODULES,
				  &n) :
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

	printf("\n%d/%d kernel-anchored measurement tests passed\n",
	       tests_passed, tests_run);
	return tests_passed == tests_run ? 0 : 1;
}
