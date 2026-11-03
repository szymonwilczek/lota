/* SPDX-License-Identifier: MIT */
/*
 * The code objects each protected process had mapped when the last token
 * round measured it.
 *
 * The token carries one image digest per process, folded from the soname
 * and digest of every object that has one. The registry keeps the objects
 * themselves, the unmeasured ones and those already unmapped included, so a
 * relying party can see what was loaded and check the list against the
 * digest it was given.
 *
 * Split out of ipc.c so the paging is tested on its own rather than through
 * a socket.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */
#ifndef LOTA_AGENT_REGISTRY_H
#define LOTA_AGENT_REGISTRY_H

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sysmacros.h>

#include "../../include/lota.h"
#include "../../include/lota_devt.h"
#include "../../include/lota_ipc.h"
#include "runtime_image_measure.h"

struct registry_process {
	uint32_t pid;
	uint32_t uid; /* owner when measured */
	uint16_t flags; /* LOTA_IPC_REGISTRY_* */
	uint8_t image_digest[32];
	size_t count;
	struct lota_rt_object_record *objects;
};

struct registry {
	uint64_t round;
	size_t count;
	struct registry_process *procs;
};

/* Free every process record; the round number stays. */
static inline void registry_clear(struct registry *r)
{
	if (!r)
		return;
	for (size_t i = 0; i < r->count; i++)
		free(r->procs[i].objects);
	free(r->procs);
	r->procs = NULL;
	r->count = 0;
}

/*
 * Append a copy of @n objects mapped in @pid.
 * @digest is the value folded into the token, or NULL when none was.
 * @flags carries LOTA_IPC_REGISTRY_* other than MEASURED.
 * Returns 0 or -ENOMEM; on failure @r is unchanged.
 */
static inline int registry_add(struct registry *r, uint32_t pid, uint32_t uid,
			       uint16_t flags, const uint8_t *digest,
			       const struct lota_rt_object_record *objs,
			       size_t n)
{
	struct registry_process *procs;
	struct registry_process *p;
	struct lota_rt_object_record *copy = NULL;

	if (!r || (n > 0 && !objs))
		return -EINVAL;

	if (n > 0) {
		copy = calloc(n, sizeof(*copy));
		if (!copy)
			return -ENOMEM;
		memcpy(copy, objs, n * sizeof(*copy));
	}

	procs = realloc(r->procs, (r->count + 1) * sizeof(*procs));
	if (!procs) {
		free(copy);
		return -ENOMEM;
	}
	r->procs = procs;

	p = &r->procs[r->count++];
	memset(p, 0, sizeof(*p));
	p->pid = pid;
	p->uid = uid;
	p->count = n;
	p->objects = copy;
	p->flags = flags & (uint16_t)~LOTA_IPC_REGISTRY_MEASURED;
	if (digest) {
		p->flags |= LOTA_IPC_REGISTRY_MEASURED;
		memcpy(p->image_digest, digest, sizeof(p->image_digest));
	}
	return 0;
}

/*
 * Make @next the current registry under the following round number.
 * @next is left empty.
 */
static inline void registry_replace(struct registry *cur, struct registry *next)
{
	uint64_t round = cur->round + 1;

	registry_clear(cur);
	*cur = *next;
	cur->round = round;
	memset(next, 0, sizeof(*next));
}

static inline const struct registry_process *
registry_find(const struct registry *r, uint32_t pid)
{
	for (size_t i = 0; r && i < r->count; i++) {
		if (r->procs[i].pid == pid)
			return &r->procs[i];
	}
	return NULL;
}

static inline uint8_t registry_road(const struct lota_rt_object_record *o)
{
	if (o->digest.len == 0)
		return LOTA_IPC_REGISTRY_ROAD_NONE;
	return o->content_hashed ? LOTA_IPC_REGISTRY_ROAD_CONTENT :
				   LOTA_IPC_REGISTRY_ROAD_VERITY;
}

/*
 * Append to @objs, holding @n of @cap, every history item of the process
 * @tgid started at @start_ticks that the maps no longer show.
 * Returns the new count; sets *@overflow when one did not fit.
 */
static inline size_t
registry_merge_history(struct lota_rt_object_record *objs, size_t n, size_t cap,
		       const struct lota_exec_history_key *keys,
		       const struct lota_exec_history_val *vals, size_t n_hist,
		       uint32_t tgid, uint64_t start_ticks, int *overflow)
{
	size_t mapped = n;

	for (size_t i = 0; i < n_hist; i++) {
		const struct lota_exec_history_key *h = &keys[i];
		const struct lota_exec_history_val *v = &vals[i];
		unsigned int major = (unsigned int)LOTA_DEVT_MAJOR(h->dev);
		unsigned int minor = (unsigned int)LOTA_DEVT_MINOR(h->dev);
		struct lota_rt_object_record *o;
		int listed = 0;

		if (h->tgid != tgid || h->start_ticks != start_ticks)
			continue;
		for (size_t j = 0; j < mapped && !listed; j++)
			listed = objs[j].entry.dev_major == major &&
				 objs[j].entry.dev_minor == minor &&
				 objs[j].entry.ino == h->ino;
		if (listed)
			continue;
		if (n >= cap) {
			*overflow = 1;
			break;
		}

		o = &objs[n++];
		memset(o, 0, sizeof(*o));
		o->entry.dev_major = major;
		o->entry.dev_minor = minor;
		o->entry.ino = h->ino;
		o->size = v->size;
		o->unmapped = 1;
		if (v->name[0] == '\0')
			memcpy(o->entry.soname, "?", 2);
		else
			snprintf(o->entry.soname, sizeof(o->entry.soname),
				 "%.*s", (int)sizeof(v->name), v->name);
	}
	return n;
}

/*
 * Encode the page of @p starting at object @start into @buf.
 *
 * As many entries as fit in @cap follow the header.
 * Returns the number of entries written and sets *@len,
 * -ERANGE when @start is past the last object,
 * or -ENOSPC when not even one entry fits.
 */
static inline int registry_encode_page(const struct registry_process *p,
				       uint64_t round, uint32_t start,
				       uint8_t *buf, size_t cap, size_t *len)
{
	struct lota_ipc_registry_page hdr;
	size_t off = sizeof(hdr);
	uint16_t count = 0;

	if (!p || !buf || !len)
		return -EINVAL;
	if (start > p->count)
		return -ERANGE;
	if (cap < sizeof(hdr))
		return -ENOSPC;

	for (size_t i = start; i < p->count && count < UINT16_MAX; i++) {
		const struct lota_rt_object_record *o = &p->objects[i];
		struct lota_ipc_registry_entry e;
		size_t slen = strnlen(o->entry.soname, sizeof(o->entry.soname));
		size_t plen = strnlen(o->entry.path, sizeof(o->entry.path));

		if (cap - off < sizeof(e) + slen + plen)
			break;

		memset(&e, 0, sizeof(e));
		e.size = o->size;
		e.dev = makedev(o->entry.dev_major, o->entry.dev_minor);
		e.ino = o->entry.ino;
		e.road = registry_road(o);
		if (e.road != LOTA_IPC_REGISTRY_ROAD_NONE) {
			e.digest_len = (uint8_t)o->digest.len;
			memcpy(e.digest, o->digest.digest, o->digest.len);
		}
		e.soname_len = (uint16_t)slen;
		e.path_len = (uint16_t)plen;
		if (o->unmapped)
			e.flags |= LOTA_IPC_REGISTRY_ENTRY_UNMAPPED;

		memcpy(buf + off, &e, sizeof(e));
		off += sizeof(e);
		memcpy(buf + off, o->entry.soname, slen);
		off += slen;
		memcpy(buf + off, o->entry.path, plen);
		off += plen;
		count++;
	}

	if (count == 0 && start < p->count)
		return -ENOSPC;

	memset(&hdr, 0, sizeof(hdr));
	hdr.round = round;
	hdr.pid = p->pid;
	hdr.total = (uint32_t)p->count;
	hdr.start = start;
	hdr.count = count;
	hdr.flags = p->flags;
	memcpy(hdr.image_digest, p->image_digest, sizeof(hdr.image_digest));
	memcpy(buf, &hdr, sizeof(hdr));

	*len = off;
	return count;
}

#endif /* LOTA_AGENT_REGISTRY_H */
