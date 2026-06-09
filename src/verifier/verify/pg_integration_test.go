// SPDX-License-Identifier: MIT
//go:build pg_integration

// Integration tests for the Postgres baseline and used-nonce backends.
// Gated behind the pg_integration build tag and LOTA_TEST_PG_DSN, same as
// the store package tests.
// See store/pg_integration_test.go for the local run recipe.

package verify

import (
	"os"
	"sync"
	"testing"
	"time"

	"github.com/szymonwilczek/lota/verifier/store"
	"github.com/szymonwilczek/lota/verifier/types"
)

func pgBaselineStore(t *testing.T) *PostgresBaselineStore {
	t.Helper()
	dsn := os.Getenv("LOTA_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("LOTA_TEST_PG_DSN not set; skipping Postgres integration test")
	}
	db, err := store.OpenPostgresDB(dsn)
	if err != nil {
		t.Fatalf("OpenPostgresDB: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if _, err := db.Exec("TRUNCATE baselines, used_nonces"); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	return NewPostgresBaselineStore(db)
}

func fill(b byte) [types.HashSize]byte {
	var x [types.HashSize]byte
	for i := range x {
		x[i] = b
	}
	return x
}

func TestPostgresBaselineAtomic(t *testing.T) {
	s := pgBaselineStore(t)
	pcr14, ah := fill(0x14), fill(0xA1)
	boot := &BootBaseline{PCR0: fill(0), PCR1: fill(1), PCR7: fill(7)}

	o := s.CheckAndUpdateAttestation("c1", pcr14, ah, boot)
	if o.AgentHashResult != TOFUFirstUse || o.BootResult != TOFUFirstUse {
		t.Fatalf("first use: agent=%v boot=%v", o.AgentHashResult, o.BootResult)
	}
	o = s.CheckAndUpdateAttestation("c1", pcr14, ah, boot)
	if o.AgentHashResult != TOFUMatch || o.BootResult != TOFUMatch {
		t.Fatalf("match: agent=%v boot=%v", o.AgentHashResult, o.BootResult)
	}
	if o.AgentHashBaseline.AttestCount != 2 {
		t.Fatalf("attest_count = %d, want 2", o.AgentHashBaseline.AttestCount)
	}
	// agent_hash drift leaves state unchanged
	if o = s.CheckAndUpdateAttestation("c1", pcr14, fill(0xBB), boot); o.AgentHashResult != TOFUMismatch {
		t.Fatalf("agent_hash drift: got %v", o.AgentHashResult)
	}
	// boot drift leaves state unchanged
	if o = s.CheckAndUpdateAttestation("c1", pcr14, ah,
		&BootBaseline{PCR0: fill(9), PCR1: fill(1), PCR7: fill(7)}); o.BootResult != TOFUMismatch {
		t.Fatalf("boot drift: got %v", o.BootResult)
	}
	if bb := s.GetBootBaseline("c1"); bb == nil || bb.PCR0 != fill(0) {
		t.Fatal("GetBootBaseline")
	}

	// legacy backfill: PCR14-only row then agent_hash pin
	if r, _ := s.CheckAndUpdate("leg", fill(0x14)); r != TOFUFirstUse {
		t.Fatal("PCR14 first use")
	}
	if r, _ := s.CheckAndUpdateAgentHash("leg", fill(0x14), fill(0xCC)); r != TOFULegacyBackfill {
		t.Fatalf("legacy backfill: got %v", r)
	}
}

// TestPostgresBaselineRace drives many concurrent attestations of one fresh
// client through one store.
// Per-client advisory lock plus the process mutex must yield exactly one
// first-use and no error
func TestPostgresBaselineRace(t *testing.T) {
	s := pgBaselineStore(t)
	const n = 24
	var wg sync.WaitGroup
	var mu sync.Mutex
	var firstUse, match, errs int
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			o := s.CheckAndUpdateAttestation("race", fill(0x33), fill(0x44), nil)
			mu.Lock()
			switch o.AgentHashResult {
			case TOFUFirstUse:
				firstUse++
			case TOFUMatch:
				match++
			default:
				errs++
			}
			mu.Unlock()
		}()
	}
	wg.Wait()
	if firstUse != 1 || match != n-1 || errs != 0 {
		t.Fatalf("race: firstUse=%d match=%d errs=%d", firstUse, match, errs)
	}
}

func TestPostgresSessionTokenCrossInstance(t *testing.T) {
	dsn := os.Getenv("LOTA_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("LOTA_TEST_PG_DSN not set; skipping Postgres integration test")
	}
	// two stores on independent pools standing in for two verifier instances
	dbA, err := store.OpenPostgresDB(dsn)
	if err != nil {
		t.Fatalf("open A: %v", err)
	}
	defer dbA.Close()
	if _, err := dbA.Exec("TRUNCATE session_tokens"); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	dbB, err := store.OpenPostgresDB(dsn)
	if err != nil {
		t.Fatalf("open B: %v", err)
	}
	defer dbB.Close()
	a := NewPostgresSessionTokenStore(dbA)
	b := NewPostgresSessionTokenStore(dbB)

	var tok [32]byte
	tok[0], tok[31] = 0x01, 0xFF
	rec := sessionTokenRecord{
		ClientID:   "client-1",
		ValidUntil: unixTimestamp(time.Now().Add(time.Hour)),
		ResultCode: 0,
		Flags:      0x5,
		PCRMask:    0x83,
	}
	rec.HardwareID[0] = 0xAB

	// instance A issues the token
	a.Remember(tok, rec)

	// instance B validates a token it never issued (the HA property)
	now := unixTimestamp(time.Now())
	st := b.Validate(tok, false, now)
	if !st.Exists || st.Expired || st.ClientID != "client-1" || st.HardwareID[0] != 0xAB {
		t.Fatalf("peer validate: %+v", st)
	}
	if st.Consumed {
		t.Fatal("token should not be consumed yet")
	}

	// instance B consumes; instance A then sees it consumed (global single-use)
	st = b.Validate(tok, true, now)
	if !st.Consumed {
		t.Fatal("consume on B should report consumed")
	}
	st = a.Validate(tok, false, now)
	if !st.Exists || !st.Consumed {
		t.Fatalf("A should see B's consume: %+v", st)
	}

	// expired token reports Exists=false and is pruned
	var tok2 [32]byte
	tok2[0] = 0x02
	expired := rec
	expired.ValidUntil = unixTimestamp(time.Now().Add(-time.Hour))
	a.Remember(tok2, expired)
	st = b.Validate(tok2, false, unixTimestamp(time.Now()))
	if st.Exists {
		t.Fatalf("expired token should not exist: %+v", st)
	}
}

func TestPostgresUsedNonce(t *testing.T) {
	dsn := os.Getenv("LOTA_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("LOTA_TEST_PG_DSN not set; skipping Postgres integration test")
	}
	db, err := store.OpenPostgresDB(dsn)
	if err != nil {
		t.Fatalf("OpenPostgresDB: %v", err)
	}
	defer db.Close()
	if _, err := db.Exec("TRUNCATE used_nonces"); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	b := NewPostgresUsedNonceBackend(db)
	if b.Contains("n1") {
		t.Fatal("nonce should be absent")
	}
	if err := b.Record("n1", time.Now()); err != nil {
		t.Fatalf("Record: %v", err)
	}
	if err := b.Record("n1", time.Now()); err != nil {
		t.Fatalf("Record idempotent: %v", err)
	}
	if !b.Contains("n1") {
		t.Fatal("nonce should be present")
	}
	if b.Count() != 1 {
		t.Fatalf("Count = %d, want 1", b.Count())
	}
	b.Record("old", time.Now().Add(-2*time.Hour))
	b.Cleanup(time.Now().Add(-1 * time.Hour))
	if b.Contains("old") {
		t.Fatal("stale nonce should be cleaned up")
	}
	if !b.Contains("n1") {
		t.Fatal("live nonce should survive cleanup")
	}
}
