// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
/*
 * Unit tests for tpm_classify_pcr14(), the rule that decides what
 * the PCR14 register observed at agent startup means.
 *
 * The register is the agent's boot commitment:
 * SHA-256 over the lock value the initramfs helper left, folded with
 * a digest of the agent binary and the TPM's resetCount and restartCount.
 * Every scenario below is built by deriving the register value the same
 * way the agent does, through tpm_derive_locked_pcr14(), so the states
 * under test are the states a real TPM produces.
 *
 * The case these tests exist for is a suspend/resume. A TPM that saves
 * and restores its state across S3 increments restartCount and leaves
 * resetCount and every PCR untouched, so the register still holds the
 * commitment the agent extended - derived with the restartCount that
 * was in effect then, not the one the next quote carries.
 */

#define LOTA_INTERNAL_TESTS 1

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../src/agent/tpm.h"

static int g_failures;
static const char *g_current_test;

#define TEST(name)                                 \
	do {                                       \
		g_current_test = name;             \
		printf("[ RUN      ] %s\n", name); \
	} while (0)

#define PASS()                                               \
	do {                                                 \
		printf("[       OK ] %s\n", g_current_test); \
	} while (0)

#define FAIL(fmt, ...)                                                        \
	do {                                                                  \
		fprintf(stderr, "[  FAILED  ] %s: " fmt "\n", g_current_test, \
			##__VA_ARGS__);                                       \
		g_failures++;                                                 \
		return;                                                       \
	} while (0)

/* A baseline shaped like what shim's MOK measurement leaves behind */
static const uint8_t k_baseline[LOTA_HASH_SIZE] = {
	0x17, 0xcd, 0xef, 0xd9, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
	0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x01, 0x02,
	0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
};

/*
 * Counters as a hardware TPM reports them through an AIK-signed quote:
 * large, and obfuscated per signing key, which is why nothing here
 * assumes a small resetCount.
 */
#define RESET_COUNT 43249437U
#define RESTART_AT_EXTEND 2393067179U

static void fill(uint8_t out[LOTA_HASH_SIZE], uint8_t seed)
{
	for (size_t i = 0; i < LOTA_HASH_SIZE; i++)
		out[i] = (uint8_t)(seed + i);
}

/*
 * Build the observation an agent instance makes when it starts while
 * PCR14 already holds a commitment extended earlier in this same boot.
 * @observed_restart is the restartCount the current quote carries.
 */
struct scenario {
	uint8_t current[LOTA_HASH_SIZE];
	uint8_t lock_value[LOTA_HASH_SIZE];
	uint8_t expected_locked[LOTA_HASH_SIZE];
	uint8_t self_hash[LOTA_HASH_SIZE];
	struct lota_clock_state prev;
	struct tpm_pcr14_observation obs;
};

static int build_committed_boot(struct scenario *s, uint32_t observed_restart)
{
	int ret;

	memset(s, 0, sizeof(*s));
	fill(s->self_hash, 0xA0);
	/* a lock value that is nothing else in the scenario */
	fill(s->lock_value, 0x40);

	/* What the agent extended, and what this instance derives now */
	ret = tpm_derive_locked_pcr14(s->self_hash, k_baseline, s->current);
	if (ret < 0)
		return ret;
	memcpy(s->expected_locked, s->current, LOTA_HASH_SIZE);

	s->prev.reset_count = RESET_COUNT;
	s->prev.restart_count = RESTART_AT_EXTEND;
	s->prev.saved_at = 1786228455;
	memcpy(s->prev.pcr14, s->current, LOTA_HASH_SIZE);
	memcpy(s->prev.self_hash, s->self_hash, LOTA_HASH_SIZE);

	s->obs.current = s->current;
	s->obs.baseline = k_baseline;
	s->obs.lock_value = s->lock_value;
	s->obs.expected_locked = s->expected_locked;
	s->obs.self_hash = s->self_hash;
	s->obs.reset_count = RESET_COUNT;
	s->obs.restart_count = observed_restart;
	s->obs.prev = &s->prev;
	return 0;
}

/*
 * A restart of the agent with nothing else changed is the warm case
 * the register already accounted for.
 */
static void test_warm_restart_is_committed(void)
{
	struct scenario s;

	TEST("an agent restart in an unchanged boot reads as committed");

	if (build_committed_boot(&s, RESTART_AT_EXTEND) < 0)
		FAIL("failed to derive the register value");

	if (tpm_classify_pcr14(&s.obs) != TPM_PCR14_ALREADY_COMMITTED)
		FAIL("a warm restart must read as already committed");
	PASS();
}

/*
 * The guard on the case above: a register somebody else really did extend
 * still has to be refused, whatever the counters say.
 * Without this, "stop calling a resume a mutation" could be satisfied by
 * never calling anything a mutation.
 */
static void test_foreign_extend_is_still_refused(void)
{
	struct scenario s;

	TEST("a register extended by another writer is still refused");

	if (build_committed_boot(&s, RESTART_AT_EXTEND) < 0)
		FAIL("failed to derive the register value");

	/* somebody extended PCR14; the snapshot still holds our value */
	fill(s.current, 0x77);

	if (tpm_classify_pcr14(&s.obs) != TPM_PCR14_MUTATED_IN_SESSION)
		FAIL("a foreign extend must read as a mutation");
	PASS();
}

/*
 * Second guard: a resume must not license a different binary.
 * The register belongs to the agent that extended it, and that
 * stays true across a TPM restart.
 */
static void test_resume_does_not_license_a_new_binary(void)
{
	struct scenario s;

	TEST("a resume does not admit a binary PCR14 never committed to");

	if (build_committed_boot(&s, RESTART_AT_EXTEND + 1) < 0)
		FAIL("failed to derive the register value");

	/*
	 * Different binary is running now, so what this instance derives is not
	 * what the register holds -- the register still carries the commitment
	 * of the binary that extended it
	 */
	fill(s.self_hash, 0xB0);
	if (tpm_derive_locked_pcr14(s.self_hash, k_baseline,
				    s.expected_locked) < 0)
		FAIL("failed to derive the register value");

	enum tpm_pcr14_state got = tpm_classify_pcr14(&s.obs);

	if (got == TPM_PCR14_ALREADY_COMMITTED)
		FAIL("a resume must not accept a different agent binary");
	if (got != TPM_PCR14_BINARY_CHANGED)
		FAIL("a changed binary must be named as such");
	PASS();
}

/*
 * A cold boot advances resetCount, and a register that is already dirty
 * at that point was written before the agent ran.
 * That path must not be confused with a restart, whose resetCount never moves.
 */
static void test_reset_count_advance_is_not_a_resume(void)
{
	struct scenario s;

	TEST("an advanced resetCount is not read as a resume");

	if (build_committed_boot(&s, RESTART_AT_EXTEND) < 0)
		FAIL("failed to derive the register value");

	/*
	 * Snapshot was written before the most recent hardware reset,
	 * so whatever the register carries now was extended before this
	 * boot's agent ran.
	 * Give it a value that is nothing this agent would have written,
	 * which is the case the counters used to produce on their own.
	 */
	fill(s.current, 0x21);
	memcpy(s.prev.pcr14, s.current, LOTA_HASH_SIZE);
	s.prev.reset_count = RESET_COUNT - 1;

	if (tpm_classify_pcr14(&s.obs) != TPM_PCR14_TAMPERED_BEFORE_START)
		FAIL("an advanced resetCount must read as pre-start tamper");
	PASS();
}

/*
 * Resume verdict is derived from the agent's own hash and the TPM's counters,
 * never read from the clock-state file. A local root who can rewrite that file
 * and who has extended PCR14 must not be able to dress the result up as
 * suspend/resume.
 */
static void test_forged_snapshot_cannot_fake_a_resume(void)
{
	struct scenario s;

	TEST("a forged clock-state snapshot cannot fake a resume");

	if (build_committed_boot(&s, RESTART_AT_EXTEND + 1) < 0)
		FAIL("failed to derive the register value");

	/* somebody extended PCR14 with a value of their choosing ... */
	fill(s.current, 0x5c);
	/* ... and wrote a snapshot that claims it is what we committed */
	memcpy(s.prev.pcr14, s.current, LOTA_HASH_SIZE);

	if (tpm_classify_pcr14(&s.obs) != TPM_PCR14_MUTATED_IN_SESSION)
		FAIL("a forged snapshot was allowed to explain the register");
	PASS();
}

/*
 * The commitment names the agent binary, and nothing else.
 * Binding it to the TPM's clock counters made the register different for every
 * publisher's AIK -- each key sees its own obfuscated counters -- so one PCR 14
 * could only ever be verified by one of them.
 */
static void test_commitment_does_not_bind_the_clock_counters(void)
{
	uint8_t self_hash[LOTA_HASH_SIZE];
	uint8_t a[LOTA_HASH_SIZE];
	uint8_t b[LOTA_HASH_SIZE];
	uint8_t c[LOTA_HASH_SIZE];

	TEST("the commitment does not bind the TPM clock counters");

	fill(self_hash, 0xA0);

	if (tpm_derive_locked_pcr14(self_hash, k_baseline, a) < 0)
		FAIL("failed to derive the register value");
	if (tpm_derive_locked_pcr14(self_hash, k_baseline, b) < 0)
		FAIL("failed to derive the register value");

	if (memcmp(a, b, LOTA_HASH_SIZE) != 0)
		FAIL("the derivation is not stable for one binary");

	/* binary is the only input that may move it */
	fill(self_hash, 0xB0);
	if (tpm_derive_locked_pcr14(self_hash, k_baseline, c) < 0)
		FAIL("failed to derive the register value");
	if (memcmp(a, c, LOTA_HASH_SIZE) == 0)
		FAIL("a different agent binary produced the same value");
	PASS();
}

/*
 * With the counters gone a resume needs no candidate scan:
 * the register still holds exactly what this agent extended,
 * so it reads as committed.
 */
static void test_resume_reads_as_committed(void)
{
	struct scenario s;

	TEST("a resume reads as committed without a candidate scan");

	if (build_committed_boot(&s, RESTART_AT_EXTEND + 1) < 0)
		FAIL("failed to derive the register value");

	if (tpm_classify_pcr14(&s.obs) != TPM_PCR14_ALREADY_COMMITTED)
		FAIL("a resume must read as already committed");
	PASS();
}

/*
 * What the counters used to catch implicitly, kept explicitly:
 * a cold boot has happened since the snapshot was written, so a register
 * that already carries this binary's commitment was extended by somebody
 * who ran before the agent did.
 * On an honest cold boot the register holds the initramfs lock value at
 * this point and nothing else.
 */
static void test_commitment_present_after_a_cold_boot_is_refused(void)
{
	struct scenario s;

	TEST("a commitment already present after a cold boot is refused");

	if (build_committed_boot(&s, RESTART_AT_EXTEND) < 0)
		FAIL("failed to derive the register value");

	/* snapshot was written before the most recent hardware reset */
	s.prev.reset_count = RESET_COUNT - 1;

	if (tpm_classify_pcr14(&s.obs) != TPM_PCR14_TAMPERED_BEFORE_START)
		FAIL("a commitment extended before the agent ran was accepted");
	PASS();
}

int main(void)
{
	test_warm_restart_is_committed();
	test_commitment_does_not_bind_the_clock_counters();
	test_resume_reads_as_committed();
	test_commitment_present_after_a_cold_boot_is_refused();
	test_forged_snapshot_cannot_fake_a_resume();
	test_foreign_extend_is_still_refused();
	test_resume_does_not_license_a_new_binary();
	test_reset_count_advance_is_not_a_resume();

	if (g_failures == 0) {
		printf("\nAll tests passed.\n");
		return 0;
	}
	fprintf(stderr, "\n%d test(s) failed.\n", g_failures);
	return 1;
}
