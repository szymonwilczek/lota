/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
#ifndef LOTA_SELFTEST_H
#define LOTA_SELFTEST_H

#include <errno.h>
#include <stddef.h>
#include <stdint.h>

int test_tpm(void);
int test_iommu(void);
void print_hex(const char *label, const uint8_t *data, size_t len);

/* What --test-tpm does about the attestation key it needs to quote with */
enum selftest_aik_plan {
	/* A key is already at the handle: quote with it and leave it there */
	SELFTEST_AIK_USE_EXISTING,
	/* The handle is free, or the TPM could not be asked.
	 * Creating a key here would outlive the probe and take a persistent
	 * object with it, so the quote test is skipped instead */
	SELFTEST_AIK_SKIP,
};

/*
 * @holds_object: tpm_handle_holds_object() for the AIK handle -- 1 when
 * the handle holds one, 0 when free, negative errno when the TPM could not be
 * asked.
 *
 * A diagnostic reports state; it does not create it. Anything but a key that
 * is already there means the probe quotes with nothing.
 */
static inline enum selftest_aik_plan selftest_aik_plan(int holds_object)
{
	return holds_object == 1 ? SELFTEST_AIK_USE_EXISTING :
				   SELFTEST_AIK_SKIP;
}

/*
 * What a probe learned about the things it tried.
 *
 * A probe runs several operations and reports each.
 * Whether the command as a whole succeeded is a question about all of them,
 * and a caller that gates on the exit status is asking exactly that
 * -- so the answer is kept.
 *
 * A section that could not be reached is not a failure: nothing about it was
 * learned, which is a different thing from learning that it does not work.
 */
struct selftest_tally {
	int passed;
	int failed;
	int skipped;
};

static inline void selftest_record(struct selftest_tally *t, int ret)
{
	if (ret < 0)
		t->failed++;
	else
		t->passed++;
}

static inline void selftest_skip(struct selftest_tally *t)
{
	t->skipped++;
}

/*
 * The exit status a probe leaves behind.
 *
 * A script gating on the command is asking whether this host can do what
 * the probe exercised, so the answer is built from the tally.
 */
static inline int selftest_verdict(const struct selftest_tally *t)
{
	return t->failed > 0 ? -EIO : 0;
}

/*
 * Operator/root one-shots: seal a secret read from stdin to the current
 * PCR state and write the blob to stdout, or unseal a blob from stdin and
 * write the secret to stdout. Never exposed over the agent IPC socket.
 */
int do_seal(const char *pcr_str);
int do_unseal(void);

/*
 * AIK-auth at-rest lifecycle one-shots (root): adopt sealing on an
 * already-enrolled host, or recover after a boot-state change rotated the
 * sealed auth out of reach.
 */
int do_seal_aik_auth(void);
int do_reprovision_aik(void);

/*
 * Seal storage-primary persistence one-shots (root): persist the
 * deterministic seal primary at its handle to skip per-op CreatePrimary, or
 * evict it. Sealed blobs stay valid across both.
 */
int do_seal_persist_primary(void);
int do_seal_evict_primary(void);

#endif /* LOTA_SELFTEST_H */
