// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek

package verify

import (
	"strings"
	"testing"
	"time"

	"github.com/szymonwilczek/lota/verifier/store"
	"github.com/szymonwilczek/lota/verifier/types"
)

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
