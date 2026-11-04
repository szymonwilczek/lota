/* SPDX-License-Identifier: MIT */
/*
 * The code objects each protected process had mapped when the last token
 * round measured it.
 *
 * The registry keeps the objects themselves, the unmeasured ones and those
 * already unmapped included, and the processes outside the instance that
 * reached one of its unix sockets. The token carries one digest per process
 * over that whole list (lota_registry_digest.h), so a relying party can see
 * what was loaded and who reached in, and check the list against the digest
 * it was given.
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
#include "../../include/lota_registry_digest.h"
#include "runtime_image_measure.h"

#include <openssl/evp.h>

struct registry_process {
	uint32_t pid;
	uint32_t uid; /* owner when measured */
	uint16_t flags; /* LOTA_IPC_REGISTRY_* */
	uint8_t image_digest[32];
	size_t count;
	struct lota_rt_object_record *objects;
	size_t actor_count;
	struct lota_ipc_registry_actor *actors;
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
	for (size_t i = 0; i < r->count; i++) {
		free(r->procs[i].objects);
		free(r->procs[i].actors);
	}
	free(r->procs);
	r->procs = NULL;
	r->count = 0;
}

/*
 * Append a copy of @n objects mapped in @pid and @n_actors actors of its
 * instance.
 * @digest is the token's entry, or NULL when the round put none there.
 * @flags carries LOTA_IPC_REGISTRY_* other than MEASURED.
 * Returns 0 or -ENOMEM; on failure @r is unchanged.
 */
static inline int registry_add(struct registry *r, uint32_t pid, uint32_t uid,
			       uint16_t flags, const uint8_t *digest,
			       const struct lota_rt_object_record *objs,
			       size_t n,
			       const struct lota_ipc_registry_actor *actors,
			       size_t n_actors)
{
	struct registry_process *procs;
	struct registry_process *p;
	struct lota_rt_object_record *copy = NULL;
	struct lota_ipc_registry_actor *actor_copy = NULL;

	if (!r || (n > 0 && !objs) || (n_actors > 0 && !actors))
		return -EINVAL;

	if (n > 0) {
		copy = calloc(n, sizeof(*copy));
		if (!copy)
			return -ENOMEM;
		memcpy(copy, objs, n * sizeof(*copy));
	}
	if (n_actors > 0) {
		actor_copy = calloc(n_actors, sizeof(*actor_copy));
		if (!actor_copy) {
			free(copy);
			return -ENOMEM;
		}
		memcpy(actor_copy, actors, n_actors * sizeof(*actor_copy));
	}

	procs = realloc(r->procs, (r->count + 1) * sizeof(*procs));
	if (!procs) {
		free(copy);
		free(actor_copy);
		return -ENOMEM;
	}
	r->procs = procs;

	p = &r->procs[r->count++];
	memset(p, 0, sizeof(*p));
	p->pid = pid;
	p->uid = uid;
	p->count = n;
	p->objects = copy;
	p->actor_count = n_actors;
	p->actors = actor_copy;
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

/* Wire entry of @o; soname and path follow it with the lengths set here. */
static inline void registry_entry(const struct lota_rt_object_record *o,
				  struct lota_ipc_registry_entry *e)
{
	memset(e, 0, sizeof(*e));
	e->size = o->size;
	e->dev = makedev(o->entry.dev_major, o->entry.dev_minor);
	e->ino = o->entry.ino;
	e->road = registry_road(o);
	if (e->road != LOTA_IPC_REGISTRY_ROAD_NONE) {
		e->digest_len = (uint8_t)o->digest.len;
		memcpy(e->digest, o->digest.digest, o->digest.len);
	}
	e->soname_len =
		(uint16_t)strnlen(o->entry.soname, sizeof(o->entry.soname));
	e->path_len = (uint16_t)strnlen(o->entry.path, sizeof(o->entry.path));
	if (o->unmapped)
		e->flags |= LOTA_IPC_REGISTRY_ENTRY_UNMAPPED;
	if (o->history_flags & LOTA_EXEC_HISTORY_WRITABLE)
		e->flags |= LOTA_IPC_REGISTRY_ENTRY_WRITABLE;
	if (o->history_flags & LOTA_EXEC_HISTORY_MEMORY)
		e->flags |= LOTA_IPC_REGISTRY_ENTRY_MEMORY;
}

/*
 * The token's entry for a process whose list is @objs and @actors and flags
 * @flags, MEASURED included. Returns 0 or a negative errno.
 */
static inline int registry_digest(uint16_t flags,
				  const struct lota_rt_object_record *objs,
				  size_t n,
				  const struct lota_ipc_registry_actor *actors,
				  size_t n_actors, uint8_t out[32])
{
	EVP_MD_CTX *md;
	int ret;

	if (n > UINT32_MAX || (n > 0 && !objs) || n_actors > UINT32_MAX ||
	    (n_actors > 0 && !actors))
		return -EINVAL;
	md = EVP_MD_CTX_new();
	if (!md)
		return -ENOMEM;

	ret = lota_registry_digest_begin(md, flags, (uint32_t)n,
					 (uint32_t)n_actors);
	for (size_t i = 0; ret == 0 && i < n; i++) {
		struct lota_ipc_registry_entry e;

		registry_entry(&objs[i], &e);
		ret = lota_registry_digest_entry(md, &e, objs[i].entry.soname,
						 objs[i].entry.path);
	}
	for (size_t i = 0; ret == 0 && i < n_actors; i++)
		ret = lota_registry_digest_actor(md, &actors[i]);
	if (ret == 0)
		ret = lota_registry_digest_final(md, out);
	EVP_MD_CTX_free(md);
	return ret;
}

/*
 * Append to @objs, holding @n of @cap, every history item of the process
 * @tgid started at @start_ticks that the maps no longer show, and give the
 * objects still mapped the flags their history carries.
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
		for (size_t j = 0; j < mapped; j++) {
			if (objs[j].entry.dev_major == major &&
			    objs[j].entry.dev_minor == minor &&
			    objs[j].entry.ino == h->ino) {
				objs[j].history_flags |= v->flags;
				listed = 1;
			}
		}
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
		o->history_flags = v->flags;
		if (v->name[0] == '\0')
			memcpy(o->entry.soname, "?", 2);
		else
			snprintf(o->entry.soname, sizeof(o->entry.soname),
				 "%.*s", (int)sizeof(v->name), v->name);
	}
	return n;
}

_Static_assert(
	sizeof(((struct lota_ipc_registry_actor *)0)->comm) ==
			sizeof(((struct lota_instance_actor_val *)0)->comm) &&
		sizeof(((struct lota_ipc_registry_actor *)0)->owner_comm) ==
			sizeof(((struct lota_instance_actor_val *)0)
				       ->owner_comm),
	"the wire carries the kernel's task name");
_Static_assert((int)LOTA_INSTANCE_ACTOR_CONNECT ==
			       (int)LOTA_IPC_REGISTRY_ACTOR_CONNECT &&
		       (int)LOTA_INSTANCE_ACTOR_SEND ==
			       (int)LOTA_IPC_REGISTRY_ACTOR_SEND &&
		       (int)LOTA_INSTANCE_ACTOR_PTRACE_READ ==
			       (int)LOTA_IPC_REGISTRY_ACTOR_PTRACE_READ &&
		       (int)LOTA_INSTANCE_ACTOR_PTRACE_ATTACH ==
			       (int)LOTA_IPC_REGISTRY_ACTOR_PTRACE_ATTACH &&
		       (int)LOTA_INSTANCE_ACTOR_SIGNAL ==
			       (int)LOTA_IPC_REGISTRY_ACTOR_SIGNAL &&
		       (int)LOTA_INSTANCE_ACTOR_ANON_EXEC ==
			       (int)LOTA_IPC_REGISTRY_ACTOR_ANON_EXEC,
	       "the wire carries the kernel's actor kind");

/*
 * Copy into @out, holding @cap, every actor of the instance whose root
 * @tgid started at @start_ticks, as the wire carries it.
 * Returns the count; sets *@overflow when one did not fit.
 */
static inline size_t
registry_collect_actors(struct lota_ipc_registry_actor *out, size_t cap,
			const struct lota_instance_actor_key *keys,
			const struct lota_instance_actor_val *vals,
			size_t n_hist, uint32_t tgid, uint64_t start_ticks,
			int *overflow)
{
	size_t n = 0;

	for (size_t i = 0; i < n_hist; i++) {
		const struct lota_instance_actor_key *k = &keys[i];
		const struct lota_instance_actor_val *v = &vals[i];
		struct lota_ipc_registry_actor *p;

		if (k->root_tgid != tgid || k->root_start_ticks != start_ticks)
			continue;
		if (n >= cap) {
			*overflow = 1;
			break;
		}

		p = &out[n++];
		memset(p, 0, sizeof(*p));
		p->count = v->count;
		p->start_ticks = k->actor_start_ticks;
		p->exe_dev = makedev((unsigned int)LOTA_DEVT_MAJOR(v->exe_dev),
				     (unsigned int)LOTA_DEVT_MINOR(v->exe_dev));
		p->exe_ino = v->exe_ino;
		p->tgid = k->actor_tgid;
		p->uid = v->uid;
		p->owner_tgid = k->owner_tgid;
		p->kind = k->kind;
		memcpy(p->comm, v->comm, sizeof(p->comm) - 1);
		memcpy(p->owner_comm, v->owner_comm, sizeof(p->owner_comm) - 1);
	}
	return n;
}

/*
 * Encode the page of @p starting at entry @start into @buf: objects, then
 * actors.
 *
 * As many entries as fit in @cap follow the header.
 * Returns the number of entries written and sets *@len,
 * -ERANGE when @start is past the last entry,
 * or -ENOSPC when not even one entry fits.
 */
static inline int registry_encode_page(const struct registry_process *p,
				       uint64_t round, uint32_t start,
				       uint8_t *buf, size_t cap, size_t *len)
{
	struct lota_ipc_registry_page hdr;
	size_t total = p ? p->count + p->actor_count : 0;
	size_t off = sizeof(hdr);
	uint16_t count = 0;
	size_t i;

	if (!p || !buf || !len)
		return -EINVAL;
	if (start > total)
		return -ERANGE;
	if (cap < sizeof(hdr))
		return -ENOSPC;

	for (i = start; i < p->count && count < UINT16_MAX; i++) {
		const struct lota_rt_object_record *o = &p->objects[i];
		struct lota_ipc_registry_entry e;
		size_t slen;
		size_t plen;

		registry_entry(o, &e);
		slen = e.soname_len;
		plen = e.path_len;
		if (cap - off < sizeof(e) + slen + plen)
			break;

		memcpy(buf + off, &e, sizeof(e));
		off += sizeof(e);
		memcpy(buf + off, o->entry.soname, slen);
		off += slen;
		memcpy(buf + off, o->entry.path, plen);
		off += plen;
		count++;
	}

	/* actors only once every object before them is in */
	for (; i >= p->count && i < total && count < UINT16_MAX; i++) {
		const struct lota_ipc_registry_actor *actor =
			&p->actors[i - p->count];

		if (cap - off < sizeof(*actor))
			break;
		memcpy(buf + off, actor, sizeof(*actor));
		off += sizeof(*actor);
		count++;
	}

	if (count == 0 && start < total)
		return -ENOSPC;

	memset(&hdr, 0, sizeof(hdr));
	hdr.round = round;
	hdr.pid = p->pid;
	hdr.total = (uint32_t)p->count;
	hdr.actor_total = (uint32_t)p->actor_count;
	hdr.start = start;
	hdr.count = count;
	hdr.flags = p->flags;
	memcpy(hdr.image_digest, p->image_digest, sizeof(hdr.image_digest));
	memcpy(buf, &hdr, sizeof(hdr));

	*len = off;
	return count;
}

#endif /* LOTA_AGENT_REGISTRY_H */
