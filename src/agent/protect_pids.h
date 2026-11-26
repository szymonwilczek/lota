/* SPDX-License-Identifier: MIT */
/*
 * Keeps the agent's protected-PID set in step with the processes in it:
 * the ones gone from /proc leave, the ones that run in a protected instance
 * join. The runtime image measurement walks the set, and a token carries
 * the part of it protected for the connection's publisher.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */
#ifndef LOTA_AGENT_PROTECT_PIDS_H
#define LOTA_AGENT_PROTECT_PIDS_H

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "profile.h"

/* Whether @pid stays in the set; @ctx is the caller's */
typedef bool (*protect_pid_alive_fn)(uint32_t pid, void *ctx);

/**
 * protect_pids_reap() - Copy the set without the PIDs @alive drops.
 * @pids: The set.
 * @count: Its size.
 * @alive: Says whether a PID stays.
 * @ctx: Passed to @alive.
 * @out: Holds @count entries, in the order of @pids.
 * @out_count: Receives the number kept.
 *
 * Return: 1 when something was dropped, and the caller then bumps the
 * mutation epoch; 0 when nothing was; or -EINVAL.
 */
static inline int protect_pids_reap(const uint32_t *pids, int count,
				    protect_pid_alive_fn alive, void *ctx,
				    uint32_t *out, int *out_count)
{
	int kept = 0;

	if (!alive || !out || !out_count || count < 0)
		return -EINVAL;

	*out_count = 0;

	if (count == 0)
		return 0;

	if (!pids)
		return -EINVAL;

	for (int i = 0; i < count; i++) {
		if (alive(pids[i], ctx))
			out[kept++] = pids[i];
	}

	*out_count = kept;
	return kept == count ? 0 : 1;
}

/*
 * 1 when @pid runs in a protected instance and went into the kernel's map,
 * 0 when it is not a member, or a negative errno.
 */
typedef int (*protect_pid_adopt_fn)(uint32_t pid, void *ctx);

/**
 * protect_pids_adopt() - Copy the set and add what runs in its instances.
 * @pids: The set.
 * @count: Its size.
 * @cands: Candidate PIDs.
 * @cand_count: How many.
 * @adopt: Takes a candidate, or refuses it.
 * @ctx: Passed to @adopt.
 * @cap: Capacity of @out; adoption stops there.
 * @out: Receives the result.
 * @out_count: Receives its size.
 *
 * A candidate already in @pids is skipped, and so is one @adopt does not
 * take.
 *
 * Return: the number adopted, or -EINVAL. Above zero, the caller bumps the
 * mutation epoch.
 */
static inline int protect_pids_adopt(const uint32_t *pids, int count,
				     const uint32_t *cands, int cand_count,
				     protect_pid_adopt_fn adopt, void *ctx,
				     int cap, uint32_t *out, int *out_count)
{
	int added = 0;
	int n;

	if (!adopt || !out || !out_count || count < 0 || cand_count < 0 ||
	    count > cap)
		return -EINVAL;
	if ((count && !pids) || (cand_count && !cands))
		return -EINVAL;

	for (n = 0; n < count; n++)
		out[n] = pids[n];

	for (int i = 0; i < cand_count && n < cap; i++) {
		bool known = false;

		for (int j = 0; j < n; j++) {
			if (out[j] == cands[i]) {
				known = true;
				break;
			}
		}
		if (known || adopt(cands[i], ctx) <= 0)
			continue;

		out[n++] = cands[i];
		added++;
	}

	*out_count = n;
	return added;
}

/**
 * struct protect_owner - The publisher a process of the set is protected for.
 * @tgid: The process.
 * @start_ticks: Its start time, as /proc/<pid>/stat gives it.
 * @root_tgid: Root of the instance it was adopted from, @tgid when it was
 *             named itself.
 * @root_start_ticks: Start time of @root_tgid.
 * @publisher: Profile id of the connection that named it; "" when that
 *             connection named none, or the process was adopted.
 * @keep: Scratch for protect_owners_retain().
 * @keep_root: Scratch for protect_owners_retain().
 */
struct protect_owner {
	uint32_t tgid;
	uint32_t root_tgid;
	uint64_t start_ticks;
	uint64_t root_start_ticks;
	char publisher[LOTA_PROFILE_ID_LEN];
	bool keep;
	bool keep_root;
};

/**
 * struct protect_owners - Owners of the protected set.
 * @v: Entries, @cap of them.
 * @n: Entries in use.
 * @cap: Capacity of @v.
 */
struct protect_owners {
	struct protect_owner *v;
	size_t n;
	size_t cap;
};

static inline struct protect_owner *protect_owner_find(struct protect_owners *t,
						       uint32_t tgid,
						       uint64_t start_ticks)
{
	for (size_t i = 0; i < t->n; i++) {
		if (t->v[i].tgid == tgid && t->v[i].start_ticks == start_ticks)
			return &t->v[i];
	}
	return NULL;
}

/**
 * protect_owner_note() - Record who a process of the set is protected for.
 * @t: The owners.
 * @tgid: The process.
 * @start_ticks: Its start time.
 * @root_tgid: Root of its instance, @tgid for a process named itself.
 * @root_start_ticks: Start time of @root_tgid.
 * @publisher: Profile id, "" or NULL for none.
 *
 * A process already recorded under @start_ticks keeps its root and its
 * publisher, and takes @publisher only when it had none. An entry of an
 * earlier process on @tgid is replaced.
 *
 * Return: 0, -ENOSPC when @t is full, or -EINVAL.
 */
static inline int protect_owner_note(struct protect_owners *t, uint32_t tgid,
				     uint64_t start_ticks, uint32_t root_tgid,
				     uint64_t root_start_ticks,
				     const char *publisher)
{
	struct protect_owner *e = NULL;

	if (!t || !t->v || tgid == 0)
		return -EINVAL;
	if (!publisher)
		publisher = "";
	if (strlen(publisher) >= LOTA_PROFILE_ID_LEN)
		return -EINVAL;

	for (size_t i = 0; i < t->n; i++) {
		if (t->v[i].tgid == tgid) {
			e = &t->v[i];
			break;
		}
	}

	if (e && e->start_ticks == start_ticks) {
		if (!e->publisher[0])
			strcpy(e->publisher, publisher);
		return 0;
	}
	if (!e) {
		if (t->n >= t->cap)
			return -ENOSPC;
		e = &t->v[t->n++];
	}

	memset(e, 0, sizeof(*e));
	e->tgid = tgid;
	e->start_ticks = start_ticks;
	e->root_tgid = root_tgid;
	e->root_start_ticks = root_start_ticks;
	strcpy(e->publisher, publisher);
	return 0;
}

/**
 * protect_owner_publisher() - The publisher a process is protected for.
 * @t: The owners.
 * @tgid: The process.
 * @start_ticks: Its start time.
 *
 * A process with no publisher of its own takes the one of its instance root.
 *
 * Return: the profile id, "" when there is none.
 */
static inline const char *protect_owner_publisher(struct protect_owners *t,
						  uint32_t tgid,
						  uint64_t start_ticks)
{
	const struct protect_owner *e;

	e = protect_owner_find(t, tgid, start_ticks);
	if (!e)
		return "";
	if (e->publisher[0] || e->root_tgid == tgid)
		return e->publisher;

	e = protect_owner_find(t, e->root_tgid, e->root_start_ticks);
	return e ? e->publisher : "";
}

/**
 * protect_owners_retain() - Drop the owners nothing in the set needs.
 * @t: The owners.
 * @pids: The set.
 * @count: Its size.
 *
 * An entry stays while its process is in @pids, or while it is the root of
 * one that is: a member adopted later still finds the root's publisher.
 */
static inline void protect_owners_retain(struct protect_owners *t,
					 const uint32_t *pids, int count)
{
	size_t kept = 0;

	for (size_t i = 0; i < t->n; i++) {
		t->v[i].keep = false;
		for (int j = 0; j < count && !t->v[i].keep; j++)
			t->v[i].keep = t->v[i].tgid == pids[j];
	}

	for (size_t i = 0; i < t->n; i++) {
		struct protect_owner *root;

		if (!t->v[i].keep || t->v[i].root_tgid == t->v[i].tgid)
			continue;
		root = protect_owner_find(t, t->v[i].root_tgid,
					  t->v[i].root_start_ticks);
		if (root)
			root->keep_root = true;
	}

	for (size_t i = 0; i < t->n; i++) {
		if (t->v[i].keep || t->v[i].keep_root) {
			t->v[kept] = t->v[i];
			t->v[kept].keep_root = false;
			kept++;
		}
	}
	t->n = kept;
}

#endif /* LOTA_AGENT_PROTECT_PIDS_H */
