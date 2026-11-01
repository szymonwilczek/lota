// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek

package verify

import (
	"bytes"
	"encoding/hex"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/szymonwilczek/lota/verifier/store"
	"github.com/szymonwilczek/lota/verifier/types"
)

func testAgentHash(seed byte) [types.HashSize]byte {
	var h [types.HashSize]byte
	for i := range h {
		h[i] = seed ^ byte(i)
	}
	return h
}

func testAgentHashHex(seed byte) string {
	h := testAgentHash(seed)
	return hex.EncodeToString(h[:])
}

// update case this whole path exists for:
// package upgrade moves the client to build the publisher already lists.
func TestAgentHashDecision_AllowsBlessedBuild(t *testing.T) {
	now := time.Now()
	allowed := []string{testAgentHashHex(0xAA), testAgentHashHex(0xBB)}

	got, _ := agentHashDecision(testAgentHash(0xBB), allowed, time.Time{}, now)
	if got != AgentHashRepin {
		t.Fatalf("expected %v, got %v", AgentHashRepin, got)
	}
}

// empty allow-list is the enterprise profile:
// nobody has said which agent builds are trusted,
// so the TOFU pin is the only such statement and it stands.
func TestAgentHashDecision_EscalatesWithoutAllowList(t *testing.T) {
	got, _ := agentHashDecision(testAgentHash(0xBB), nil, time.Time{}, time.Now())
	if got != AgentHashEscalate {
		t.Fatalf("expected %v, got %v", AgentHashEscalate, got)
	}

	got, _ = agentHashDecision(testAgentHash(0xBB), []string{}, time.Time{}, time.Now())
	if got != AgentHashEscalate {
		t.Fatalf("empty slice: expected %v, got %v", AgentHashEscalate, got)
	}
}

// hash nobody blessed is the drift the pin was built to catch
func TestAgentHashDecision_EscalatesUnlistedHash(t *testing.T) {
	allowed := []string{testAgentHashHex(0xAA)}

	got, _ := agentHashDecision(testAgentHash(0xCC), allowed, time.Time{}, time.Now())
	if got != AgentHashEscalate {
		t.Fatalf("expected %v, got %v", AgentHashEscalate, got)
	}
}

func TestAgentHashDecision_RateLimitsRepeatedRepins(t *testing.T) {
	now := time.Now()
	allowed := []string{testAgentHashHex(0xBB)}
	reported := testAgentHash(0xBB)

	recent := now.Add(-AgentHashRepinMinInterval + time.Minute)
	if got, _ := agentHashDecision(reported, allowed, recent, now); got != AgentHashEscalate {
		t.Fatalf("inside the window: expected %v, got %v", AgentHashEscalate, got)
	}

	elapsed := now.Add(-AgentHashRepinMinInterval - time.Minute)
	if got, _ := agentHashDecision(reported, allowed, elapsed, now); got != AgentHashRepin {
		t.Fatalf("past the window: expected %v, got %v", AgentHashRepin, got)
	}
}

// zero verdict must be the refusing one, so path that forgets to assign fails closed
func TestAgentHashDecision_ZeroVerdictIsEscalate(t *testing.T) {
	// a lookup that misses carries the same zero value a path that never
	// assigned one holds
	decided := map[string]AgentHashVerdict{}

	v := decided["client that never reported"]
	if v != AgentHashEscalate {
		t.Fatalf("zero value must be escalate, got %v", v)
	}
	if v.String() != "escalate" {
		t.Fatalf("zero value String(): got %q", v.String())
	}
}

// Policy gate and the re-pin discriminator must read the allow-list the same way.
// They share agentHashAllowed for that reason, so this pins the predicate's own
// contract: lower-case hex matches, anything else does not
func TestAgentHashAllowed_ComparesLowerCaseHex(t *testing.T) {
	reported := testAgentHash(0xBB)
	lower := hex.EncodeToString(reported[:])

	if !agentHashAllowed(reported, []string{"deadbeef", lower}) {
		t.Fatal("lower-case hex entry must match")
	}
	if agentHashAllowed(reported, []string{strings.ToUpper(lower)}) {
		t.Fatal("upper-case hex entry must not match")
	}
	if agentHashAllowed(reported, nil) {
		t.Fatal("empty list must not match")
	}

	// and the discriminator must inherit exactly that
	if got, _ := agentHashDecision(reported, []string{strings.ToUpper(lower)},
		time.Time{}, time.Now()); got != AgentHashEscalate {
		t.Fatal("discriminator accepted what the predicate rejects")
	}
}

// A verifier that keeps every line it logs, so a test can read what an operator
// would have read.
func repinVerifierWithLog(t *testing.T, buf *bytes.Buffer,
	allowedSeeds ...byte) *Verifier {
	t.Helper()

	cfg := DefaultConfig()
	cfg.NonceLifetime = 1 * time.Second
	cfg.RequireBootEnrollment = false
	cfg.Logger = slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))

	verifier := NewVerifier(cfg, newCertVerifier(t))
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

// The refusal an operator has to act on says which refusal it is.
//
// A client on a build the publisher lists, refused because it re-pinned
// less than AgentHashRepinMinInterval ago, is not the drift the pin exists
// to catch -- and the only difference visible from the outside is what
// the verifier says about it.
func TestVerify_RateLimitedRepinNamesTheInterval(t *testing.T) {
	const thirdBuild byte = 0xD3
	var logs bytes.Buffer

	v := repinVerifierWithLog(t, &logs, repinOldBuild, repinNewBuild, thirdBuild)
	const clientID = "repin-reason-rate-limited"

	if _, err := attestAsBuild(t, v, clientID, repinOldBuild); err != nil {
		t.Fatalf("first attestation: %v", err)
	}
	if _, err := attestAsBuild(t, v, clientID, repinNewBuild); err != nil {
		t.Fatalf("first update: %v", err)
	}

	logs.Reset()

	if _, err := attestAsBuild(t, v, clientID, thirdBuild); err == nil {
		t.Fatal("expected refusal: a second re-pin inside the interval")
	}

	line := logs.String()
	if !strings.Contains(line, "interval") {
		t.Fatalf("the refusal never names the interval that caused it:\n%s",
			line)
	}
	if !strings.Contains(line, "re-anchor") {
		t.Fatalf("the refusal names no way out:\n%s", line)
	}
}

// And the other refusal is not blamed on the interval.
//
// A build nobody listed is the case the pin exists for, so the interval
// must not appear in its refusal -- otherwise naming the interval would
// be a blanket sentence.
func TestVerify_UnlistedBuildIsNotBlamedOnTheInterval(t *testing.T) {
	var logs bytes.Buffer

	v := repinVerifierWithLog(t, &logs, repinOldBuild)
	const clientID = "repin-reason-unlisted"

	if _, err := attestAsBuild(t, v, clientID, repinOldBuild); err != nil {
		t.Fatalf("first attestation: %v", err)
	}

	logs.Reset()

	result, err := attestAsBuild(t, v, clientID, repinNewBuild)
	if err == nil {
		t.Fatal("expected refusal: the reported build is not listed")
	}

	// policy gate refuses an unlisted build before the pin is consulted,
	// and it already names the allow-list, so this case is not the silent one
	// the verdict is the one the agent binary owns either way: which gate saw
	// the build first is not something the host can act on.
	if result.Result != types.VerifyIntegrityMismatch {
		t.Fatalf("expected VerifyIntegrityMismatch from the policy gate, got %d",
			result.Result)
	}
	if !strings.Contains(err.Error(), "agent hash not in allowed list") {
		t.Fatalf("expected the policy-gate refusal, got: %v", err)
	}

	if strings.Contains(logs.String(), "interval") {
		t.Fatalf("an unlisted build is blamed on the interval:\n%s",
			logs.String())
	}
}

// An empty agent_hash only comes from an out-of-band PCR 14 pin; every
// attestation writes the column. Re-pin must refuse such a row, or it
// adopts the reported hash and replaces the operator's PCR 14 with it.

// Operator pins, then the device attests.
func TestVerify_OutOfBandPinIsNotAdoptedFromTheReport(t *testing.T) {
	v := repinVerifier(t, repinOldBuild, repinNewBuild)
	const clientID = "out-of-band-pin"
	key := baselineKey(clientID)

	operatorPCR14 := fixturePCR14Seed(repinOldBuild)
	if res, _ := v.baselineStore.CheckAndUpdate(key, operatorPCR14); res != TOFUFirstUse {
		t.Fatalf("out-of-band pin: expected TOFUFirstUse, got %v", res)
	}

	// Listed build, no prior re-pin: only the baseline check can refuse.
	result, err := attestAsBuild(t, v, clientID, repinNewBuild)
	if err == nil {
		t.Fatal("expected refusal: the row has no pinned agent hash to move")
	}
	if result.Result != types.VerifyIntegrityMismatch {
		t.Fatalf("expected VerifyIntegrityMismatch, got %d", result.Result)
	}
	if !strings.Contains(err.Error(), "no pinned agent_hash") {
		t.Fatalf("the refusal does not name the empty column: %v", err)
	}

	b := v.baselineStore.GetBaseline(key)
	if b == nil {
		t.Fatal("the baseline row is gone")
	}
	if b.PCR14 != operatorPCR14 {
		t.Fatalf("the operator's PCR 14 pin was replaced: %s",
			FormatPCR14(b.PCR14))
	}
	if b.AgentHash != ([types.HashSize]byte{}) {
		t.Fatalf("the reported agent hash was adopted into the empty column")
	}

	rs, ok := v.baselineStore.(AgentHashRepinStorer)
	if !ok {
		t.Fatal("store does not implement AgentHashRepinStorer")
	}
	if st := rs.GetAgentHashRepinState(key); st.RepinCount != 0 {
		t.Fatalf("the row was re-pinned: count=%d", st.RepinCount)
	}
}

// Store-level guard for callers that skip the re-pin decision.
func TestAgentHashRepin_RefusesRowWithNoPinnedHash(t *testing.T) {
	bs := NewBaselineStore()
	const clientID = "repin-unpinned"

	operatorPCR14 := fixturePCR14Seed(repinOldBuild)
	if res, _ := bs.CheckAndUpdate(clientID, operatorPCR14); res != TOFUFirstUse {
		t.Fatalf("out-of-band pin: expected TOFUFirstUse, got %v", res)
	}

	err := bs.ArchiveAndRepinAgentHash(clientID, fixtureAgentHashSeed(repinNewBuild),
		fixturePCR14Seed(repinNewBuild), time.Now())
	if err == nil {
		t.Fatal("expected a refusal: there is no pinned hash to replace")
	}
	if !strings.Contains(err.Error(), "no pinned agent_hash") {
		t.Fatalf("the refusal does not name the empty column: %v", err)
	}

	b := bs.GetBaseline(clientID)
	if b == nil || b.PCR14 != operatorPCR14 {
		t.Fatal("the operator's PCR 14 pin was replaced by the refused re-pin")
	}
}

// SQLite also writes the archive row; a refused re-pin must leave none.
func TestAgentHashRepin_SQLiteRefusesRowWithNoPinnedHash(t *testing.T) {
	db, err := store.OpenDB(t.TempDir() + "/baselines.sqlite")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	bs := NewSQLiteBaselineStore(db)
	const clientID = "sqlite-unpinned"

	operatorPCR14 := fixturePCR14Seed(repinOldBuild)
	if res, _ := bs.CheckAndUpdate(clientID, operatorPCR14); res != TOFUFirstUse {
		t.Fatalf("out-of-band pin: expected TOFUFirstUse, got %v", res)
	}

	err = bs.ArchiveAndRepinAgentHash(clientID, fixtureAgentHashSeed(repinNewBuild),
		fixturePCR14Seed(repinNewBuild), time.Now())
	if err == nil {
		t.Fatal("expected a refusal: there is no pinned hash to replace")
	}
	if !strings.Contains(err.Error(), "no pinned agent_hash") {
		t.Fatalf("the refusal does not name the empty column: %v", err)
	}

	var storedPCR14 []byte
	if err := db.QueryRow(
		`SELECT pcr14 FROM baselines WHERE client_id = ?`, clientID,
	).Scan(&storedPCR14); err != nil {
		t.Fatalf("read the row back: %v", err)
	}
	var got [types.HashSize]byte
	copy(got[:], storedPCR14)
	if got != operatorPCR14 {
		t.Fatalf("the operator's PCR 14 pin was replaced: %s", FormatPCR14(got))
	}

	var archived int
	if err := db.QueryRow(
		`SELECT COUNT(*) FROM baseline_archive WHERE client_id = ?`, clientID,
	).Scan(&archived); err != nil {
		t.Fatalf("read the archive: %v", err)
	}
	if archived != 0 {
		t.Fatalf("a refused re-pin left %d archive row(s) behind", archived)
	}
}
