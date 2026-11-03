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
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>

#include "test.h"
#include "../src/agent/runtime_image_measure.h"
#include "../src/agent/registry.h"
#include "lota.h"
#include "lota_devt.h"
#include "lota_ipc.h"

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
		struct registry cur = { 0 };
		struct registry next = { 0 };
		const struct registry_process *p;
		uint8_t folded[32];
		uint8_t buf[2048];
		uint32_t start = 0, pages = 0, seen = 0;
		int ok = 1;

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
		ok &= registry_add(&next, 1234, 1000, 0, folded, objs, 40) == 0;
		ok &= registry_add(&next, 1235, 1000,
				   LOTA_IPC_REGISTRY_HISTORY_LOST |
					   LOTA_IPC_REGISTRY_MEASURED,
				   NULL, NULL, 0) == 0;
		registry_replace(&cur, &next);
		ok &= cur.round == 1 && next.count == 0;

		p = registry_find(&cur, 1234);
		ok &= p != NULL && registry_find(&cur, 99) == NULL;
		while (ok && p && start < p->count) {
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
			      hdr.total == 40 && hdr.start == start &&
			      hdr.count == (uint16_t)c &&
			      (hdr.flags & LOTA_IPC_REGISTRY_MEASURED) &&
			      memcmp(hdr.image_digest, folded, 32) == 0;
			for (int k = 0; k < c; k++) {
				struct lota_ipc_registry_entry e;
				uint32_t idx = start + (uint32_t)k;
				uint8_t want =
					idx % 3 == 0 ?
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
		ok &= seen == 40 && pages > 1;
		{
			size_t len = 0;

			ok &= registry_encode_page(p, cur.round, 41, buf,
						   sizeof(buf),
						   &len) == -ERANGE;
			ok &= registry_encode_page(p, cur.round, 0, buf, 100,
						   &len) == -ENOSPC;
			p = registry_find(&cur, 1235);
			ok &= p && p->flags == LOTA_IPC_REGISTRY_HISTORY_LOST &&
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
		keys[1] = (struct lota_exec_history_key){ 7, 0, 99, dev, 12 };
		vals[1].size = 512;
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

	printf("\n%d/%d kernel-anchored measurement tests passed\n",
	       tests_passed, tests_run);
	return tests_passed == tests_run ? 0 : 1;
}
