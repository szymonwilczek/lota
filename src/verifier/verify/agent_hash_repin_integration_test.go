// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek

package verify

import (
	"bytes"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/szymonwilczek/lota/verifier/store"
	"github.com/szymonwilczek/lota/verifier/types"
)

// baselineKey is the key a baseline row carries.
// VerifyReport rebinds the client identity to the AIK certificate's subject,
// so the row is keyed by the device pseudonym rather than by the label
// the caller passed in.
func baselineKey(clientID string) string {
	return testPseudonym(clientID)
}

// The build a client is standing on before the update, and the one the package
// manager moves it to.
const (
	repinOldBuild byte = 0xBB // fixtureAgentHash()
	repinNewBuild byte = 0xC7
)

// repinVerifier builds a verifier whose policy lists the given agent builds.
// Empty list is the enterprise profile: nobody has said which builds are trusted.
func repinVerifier(t *testing.T, allowedSeeds ...byte) *Verifier {
	t.Helper()

	cfg := DefaultConfig()
	cfg.NonceLifetime = 1 * time.Second
	cfg.RequireBootEnrollment = false

	verifier := NewVerifier(cfg, newCertStore(t))
	policy := DefaultPolicy()
	for _, seed := range allowedSeeds {
		h := fixtureAgentHashSeed(seed)
		policy.AgentHashes = append(policy.AgentHashes, hex.EncodeToString(h[:]))
	}
	if err := verifier.AddPolicy(policy); err != nil {
		t.Fatalf("AddPolicy: %v", err)
	}
	if err := verifier.SetActivePolicy("default"); err != nil {
		t.Fatalf("SetActivePolicy: %v", err)
	}
	return verifier
}

// attestAsBuild runs one full attestation for a client reporting the given
// agent build.
// PCR14 moves with the hash because the register content is derived from it.
func attestAsBuild(t *testing.T, v *Verifier, clientID string, seed byte) (*types.VerifyResult, error) {
	t.Helper()

	challenge, err := v.GenerateChallenge(clientID)
	if err != nil {
		t.Fatalf("GenerateChallenge: %v", err)
	}
	report := createValidReportWithAgentHash(t, clientID, challenge.Nonce,
		fixturePCR14Seed(seed), productionPCRMask, productionFlags,
		fixtureAgentHashSeed(seed))
	return v.VerifyReport(clientID, report)
}

// The path this whole feature exists for:
// package update moves the client to build the publisher already lists,
// and it keeps attesting.
func TestVerify_AgentUpdateRepinsToPolicyListedBuild(t *testing.T) {
	v := repinVerifier(t, repinOldBuild, repinNewBuild)
	const clientID = "agent-update-listed"

	if _, err := attestAsBuild(t, v, clientID, repinOldBuild); err != nil {
		t.Fatalf("first attestation (pins the baseline): %v", err)
	}

	result, err := attestAsBuild(t, v, clientID, repinNewBuild)
	if err != nil {
		t.Fatalf("attestation after the update was refused: %v", err)
	}
	if result.Result != types.VerifyOK {
		t.Fatalf("expected VerifyOK, got %d", result.Result)
	}

	// The pin moved rather than the mismatch being waved through:
	// the client now attests on the new build with no further re-pin,
	// and the old build is no longer what the row holds
	rs, ok := v.baselineStore.(AgentHashRepinStorer)
	if !ok {
		t.Fatal("store does not implement AgentHashRepinStorer")
	}
	if got := rs.GetAgentHashRepinState(baselineKey(clientID)).RepinCount; got != 1 {
		t.Fatalf("expected exactly one re-pin, got %d", got)
	}
}

// a build nobody blessed is the drift the pin exists to catch
func TestVerify_AgentUpdateRefusedWhenBuildNotListed(t *testing.T) {
	v := repinVerifier(t, repinOldBuild)
	const clientID = "agent-update-unlisted"

	if _, err := attestAsBuild(t, v, clientID, repinOldBuild); err != nil {
		t.Fatalf("first attestation: %v", err)
	}

	result, err := attestAsBuild(t, v, clientID, repinNewBuild)
	if err == nil {
		t.Fatal("expected refusal: the reported build is not on the allow-list")
	}

	// Policy gate refuses unlisted build before the baseline is consulted at all,
	// so the verdict is a policy failure rather than the integrity mismatch.
	// That ordering is the point: a build nobody blessed never reaches
	// the code that could move a pin.
	if result.Result != types.VerifyPCRFail {
		t.Fatalf("expected VerifyPCRFail from the policy gate, got %d (err=%v)",
			result.Result, err)
	}
	if !strings.Contains(err.Error(), "agent hash not in allowed list") {
		t.Fatalf("expected the policy-gate refusal, got: %v", err)
	}

	// Aaaand the pin did not move!
	rs, ok := v.baselineStore.(AgentHashRepinStorer)
	if !ok {
		t.Fatal("store does not implement AgentHashRepinStorer")
	}
	if got := rs.GetAgentHashRepinState(baselineKey(clientID)).RepinCount; got != 0 {
		t.Fatalf("an unlisted build moved the pin: count=%d", got)
	}
}

// Enterprise profile: with no allow-list there is no trust root to appeal to,
// so the TOFU pin stands and the operator decides.
func TestVerify_AgentUpdateRefusedWithoutAllowList(t *testing.T) {
	v := repinVerifier(t)
	const clientID = "agent-update-no-allowlist"

	if _, err := attestAsBuild(t, v, clientID, repinOldBuild); err != nil {
		t.Fatalf("first attestation: %v", err)
	}

	result, err := attestAsBuild(t, v, clientID, repinNewBuild)
	if err == nil {
		t.Fatal("expected refusal: no allow-list means no re-pin authority")
	}
	if result.Result != types.VerifyIntegrityMismatch {
		t.Fatalf("expected VerifyIntegrityMismatch, got %d", result.Result)
	}
	if !strings.Contains(err.Error(), "agent_hash changed from baseline") {
		t.Fatalf("expected the baseline refusal, got: %v", err)
	}
}

// One client may not flip builds repeatedly.
// Allow-list is the barrier; the interval is what makes oscillation visible.
func TestVerify_AgentUpdateRateLimitsSecondRepin(t *testing.T) {
	const thirdBuild byte = 0xD3
	v := repinVerifier(t, repinOldBuild, repinNewBuild, thirdBuild)
	const clientID = "agent-update-rate-limited"

	if _, err := attestAsBuild(t, v, clientID, repinOldBuild); err != nil {
		t.Fatalf("first attestation: %v", err)
	}
	if _, err := attestAsBuild(t, v, clientID, repinNewBuild); err != nil {
		t.Fatalf("first update: %v", err)
	}

	result, err := attestAsBuild(t, v, clientID, thirdBuild)
	if err == nil {
		t.Fatal("expected refusal: a second re-pin inside the interval")
	}
	if result.Result != types.VerifyIntegrityMismatch {
		t.Fatalf("expected VerifyIntegrityMismatch, got %d", result.Result)
	}

	rs, ok := v.baselineStore.(AgentHashRepinStorer)
	if !ok {
		t.Fatal("store does not implement AgentHashRepinStorer")
	}
	if got := rs.GetAgentHashRepinState(baselineKey(clientID)).RepinCount; got != 1 {
		t.Fatalf("the rate-limited attempt moved the pin: count=%d", got)
	}
}

// Client with no baseline row has no pin to move:
// establishing one is TOFU's job, and the re-pin path must not create it.
func TestAgentHashRepin_RefusesClientWithoutBaseline(t *testing.T) {
	bs := NewBaselineStore()

	err := bs.ArchiveAndRepinAgentHash(baselineKey("never-seen"),
		fixtureAgentHashSeed(repinNewBuild), fixturePCR14Seed(repinNewBuild),
		time.Now())
	if err == nil {
		t.Fatal("expected refusal for a client with no baseline row")
	}
}

// Store guard is authoritative, not the cheap-path check in the discriminator:
// caller that skips the decision still cannot re-pin twice inside the interval.
func TestAgentHashRepin_StoreGuardIsAuthoritative(t *testing.T) {
	bs := NewBaselineStore()
	const clientID = "store-guard"

	now := time.Now()
	outcome := bs.CheckAndUpdateAttestation(baselineKey(clientID),
		fixturePCR14Seed(repinOldBuild), fixtureAgentHashSeed(repinOldBuild), nil)
	if outcome.AgentHashResult != TOFUFirstUse {
		t.Fatalf("expected TOFUFirstUse, got %v", outcome.AgentHashResult)
	}

	if err := bs.ArchiveAndRepinAgentHash(baselineKey(clientID),
		fixtureAgentHashSeed(repinNewBuild), fixturePCR14Seed(repinNewBuild),
		now); err != nil {
		t.Fatalf("first re-pin: %v", err)
	}

	err := bs.ArchiveAndRepinAgentHash(baselineKey(clientID),
		fixtureAgentHashSeed(0xD3), fixturePCR14Seed(0xD3),
		now.Add(AgentHashRepinMinInterval-time.Minute))
	if err == nil {
		t.Fatal("expected ErrAgentHashRepinRateLimited")
	}

	// past the interval it goes through again
	if err := bs.ArchiveAndRepinAgentHash(baselineKey(clientID),
		fixtureAgentHashSeed(0xD3), fixturePCR14Seed(0xD3),
		now.Add(AgentHashRepinMinInterval+time.Minute)); err != nil {
		t.Fatalf("re-pin past the interval: %v", err)
	}
}

// Durable stores carry the same contract as the in-memory one, and their SQL
// is the part a unit test over the memory store cannot reach:
// the archive insert, the counter bump, and the rate-limit read that has to
// happen inside the transaction.
func TestAgentHashRepin_SQLitePersistsAndRateLimits(t *testing.T) {
	db, err := store.OpenDB(t.TempDir() + "/baselines.sqlite")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	bs := NewSQLiteBaselineStore(db)
	const clientID = "sqlite-repin"

	oldHash := fixtureAgentHashSeed(repinOldBuild)
	newHash := fixtureAgentHashSeed(repinNewBuild)
	outcome := bs.CheckAndUpdateAttestation(clientID,
		fixturePCR14Seed(repinOldBuild), oldHash, nil)
	if outcome.AgentHashResult != TOFUFirstUse {
		t.Fatalf("expected TOFUFirstUse, got %v", outcome.AgentHashResult)
	}

	now := time.Now()
	if err := bs.ArchiveAndRepinAgentHash(clientID, newHash,
		fixturePCR14Seed(repinNewBuild), now); err != nil {
		t.Fatalf("re-pin: %v", err)
	}

	st := bs.GetAgentHashRepinState(clientID)
	if !st.Present || st.RepinCount != 1 {
		t.Fatalf("expected one re-pin on a present row, got present=%v count=%d",
			st.Present, st.RepinCount)
	}

	// row now holds the new build, so the same report matches
	outcome = bs.CheckAndUpdateAttestation(clientID,
		fixturePCR14Seed(repinNewBuild), newHash, nil)
	if outcome.AgentHashResult != TOFUMatch {
		t.Fatalf("expected TOFUMatch after the re-pin, got %v", outcome.AgentHashResult)
	}

	// outgoing hash is archived rather than dropped
	var archived []byte
	if err := db.QueryRow(
		`SELECT agent_hash FROM baseline_archive
		   WHERE client_id = ? AND reason = 'agent-update'`,
		clientID,
	).Scan(&archived); err != nil {
		t.Fatalf("archive row: %v", err)
	}
	if !bytes.Equal(archived, oldHash[:]) {
		t.Fatalf("archived hash is not the outgoing build")
	}

	if err := bs.ArchiveAndRepinAgentHash(clientID, fixtureAgentHashSeed(0xD3),
		fixturePCR14Seed(0xD3), now.Add(AgentHashRepinMinInterval-time.Minute)); !errors.Is(err, ErrAgentHashRepinRateLimited) {
		t.Fatalf("expected ErrAgentHashRepinRateLimited, got %v", err)
	}
}
