// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
//go:build pg_integration

// Integration tests for the Postgres baseline and used-nonce backends.
// Gated behind the pg_integration build tag and LOTA_TEST_PG_DSN, same as
// the store package tests.
// See store/pg_integration_test.go for the local run recipe.

package verify

import (
	"bytes"
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

// TestPostgresBaselineInspection covers the monitoring-facing reads and
// the operator reset path: GetBaseline, ListClients, Stats, ClearBaseline.
func TestPostgresBaselineInspection(t *testing.T) {
	s := pgBaselineStore(t)

	if s.GetBaseline("absent") != nil {
		t.Fatal("GetBaseline on unknown client should be nil")
	}

	if r, _ := s.CheckAndUpdate("ins-a", fill(0x14)); r != TOFUFirstUse {
		t.Fatal("first use ins-a")
	}
	if r, _ := s.CheckAndUpdate("ins-b", fill(0x15)); r != TOFUFirstUse {
		t.Fatal("first use ins-b")
	}
	if r, _ := s.CheckAndUpdate("ins-a", fill(0x14)); r != TOFUMatch {
		t.Fatal("match ins-a")
	}

	b := s.GetBaseline("ins-a")
	if b == nil || b.PCR14 != fill(0x14) || b.AttestCount != 2 {
		t.Fatalf("GetBaseline ins-a: %+v", b)
	}
	if b.FirstSeen.IsZero() || b.LastSeen.Before(b.FirstSeen) {
		t.Fatalf("GetBaseline timestamps: %+v", b)
	}

	clients := s.ListClients()
	if len(clients) != 2 || clients[0] != "ins-a" || clients[1] != "ins-b" {
		t.Fatalf("ListClients: %v", clients)
	}

	st := s.Stats()
	if st.TotalClients != 2 || st.OldestBaseline.IsZero() || st.NewestBaseline.Before(st.OldestBaseline) {
		t.Fatalf("Stats: %+v", st)
	}

	s.ClearBaseline("ins-a")
	if s.GetBaseline("ins-a") != nil {
		t.Fatal("ClearBaseline left a row behind")
	}
	if got := s.ListClients(); len(got) != 1 || got[0] != "ins-b" {
		t.Fatalf("ListClients after clear: %v", got)
	}
}

// TestPostgresBootPCRsLegacyPath covers the standalone boot-PCR pin used by
// the non-FlagBootCommitment flow: first use, match, drift, and the
// backfill of a PCR14-only legacy row.
func TestPostgresBootPCRsLegacyPath(t *testing.T) {
	s := pgBaselineStore(t)
	boot := BootBaseline{PCR0: fill(0xA0), PCR1: fill(0xA1), PCR7: fill(0xA7)}

	// no PCR14 row yet: boot pin must fail closed, never auto-create
	if r, _ := s.CheckAndUpdateBootPCRs("boot-c", boot); r != TOFUError {
		t.Fatalf("boot pin without PCR14 row: got %v, want TOFUError", r)
	}

	if r, _ := s.CheckAndUpdate("boot-c", fill(0x14)); r != TOFUFirstUse {
		t.Fatal("PCR14 first use boot-c")
	}
	if r, _ := s.CheckAndUpdateBootPCRs("boot-c", boot); r != TOFUFirstUse {
		t.Fatal("boot first use")
	}
	if r, _ := s.CheckAndUpdateBootPCRs("boot-c", boot); r != TOFUMatch {
		t.Fatal("boot match")
	}

	drift := boot
	drift.PCR7 = fill(0xFF)
	r, stored := s.CheckAndUpdateBootPCRs("boot-c", drift)
	if r != TOFUMismatch {
		t.Fatalf("boot drift: got %v", r)
	}
	if stored == nil || stored.PCR7 != fill(0xA7) {
		t.Fatalf("drift must report the pinned baseline: %+v", stored)
	}

	// legacy PCR14-only row TOFU-establishes boot columns on next sight
	if r, _ := s.CheckAndUpdate("boot-leg", fill(0x14)); r != TOFUFirstUse {
		t.Fatal("legacy PCR14 first use")
	}
	if s.GetBootBaseline("boot-leg") != nil {
		t.Fatal("legacy row should have no boot baseline yet")
	}
	if r, _ := s.CheckAndUpdateBootPCRs("boot-leg", boot); r != TOFUFirstUse {
		t.Fatal("legacy boot backfill should be first use")
	}
}

// TestPostgresSessionTokenLifecycle covers the upsert and miss paths the
// cross-instance test does not reach.
func TestPostgresSessionTokenLifecycle(t *testing.T) {
	dsn := os.Getenv("LOTA_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("LOTA_TEST_PG_DSN not set; skipping Postgres integration test")
	}
	db, err := store.OpenPostgresDB(dsn)
	if err != nil {
		t.Fatalf("OpenPostgresDB: %v", err)
	}
	defer db.Close()
	if _, err := db.Exec("TRUNCATE session_tokens"); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	s := NewPostgresSessionTokenStore(db)
	now := unixTimestamp(time.Now())

	var miss [32]byte
	miss[5] = 0x99
	if st := s.Validate(miss, true, now); st.Exists {
		t.Fatalf("unknown token should not exist: %+v", st)
	}

	var tok [32]byte
	tok[1] = 0x42
	rec := sessionTokenRecord{
		ClientID:   "client-x",
		Tenant:     "acme",
		ValidUntil: unixTimestamp(time.Now().Add(time.Hour)),
		Flags:      0x1,
		PCRMask:    0x7F,
	}
	s.Remember(tok, rec)

	// re-attestation reissues the same token id: upsert refreshes the row
	rec.ValidUntil = unixTimestamp(time.Now().Add(2 * time.Hour))
	rec.Flags = 0x3
	s.Remember(tok, rec)

	st := s.Validate(tok, false, now)
	if !st.Exists || st.Flags != 0x3 || st.ValidUntil != rec.ValidUntil {
		t.Fatalf("upsert not visible: %+v", st)
	}
	if st.Tenant != "acme" {
		t.Fatalf("Tenant = %q, want acme", st.Tenant)
	}

	// consuming twice keeps reporting consumed without resurrecting state
	if st = s.Validate(tok, true, now); !st.Consumed {
		t.Fatalf("first consume: %+v", st)
	}
	if st = s.Validate(tok, true, now); !st.Exists || !st.Consumed {
		t.Fatalf("second consume: %+v", st)
	}
}

func TestPostgresReanchor(t *testing.T) {
	bs := pgBaselineStore(t)
	cid := "reanchor-pg"

	bs.CheckAndUpdate(cid, fill(0xDE))
	if r, _ := bs.CheckAndUpdateBootPCRs(cid, boot(0xB0, 0xB1, 0xB7)); r != TOFUFirstUse {
		t.Fatalf("boot first use expected, got %v", r)
	}

	st := bs.GetReanchorState(cid)
	if !st.Present || st.ReanchorCount != 0 || st.ESRTCapable {
		t.Fatalf("fresh re-anchor state wrong: %+v", st)
	}

	t0 := time.Now()
	if err := bs.ArchiveAndReanchor(cid, boot(0xC0, 0xC1, 0xB7),
		[]byte("evlog"), 785, true, false, "strong", t0); err != nil {
		t.Fatalf("ArchiveAndReanchor: %v", err)
	}
	st = bs.GetReanchorState(cid)
	if st.ReanchorCount != 1 || !st.ESRTCapable || st.ESRTVersion != 785 || st.LFA {
		t.Fatalf("after strong re-anchor: %+v", st)
	}
	if !bytes.Equal(st.EventLogBaseline, []byte("evlog")) {
		t.Error("event-log baseline not persisted")
	}
	if r, _ := bs.CheckAndUpdateBootPCRs(cid, boot(0xC0, 0xC1, 0xB7)); r != TOFUMatch {
		t.Errorf("re-anchored baseline should match, got %v", r)
	}

	// LFA re-anchor: esrt_capable stays sticky-true even though we pass false
	// past the LFA interval so this legitimate second re-anchor is admitted
	if err := bs.ArchiveAndReanchor(cid, boot(0xD0, 0xD1, 0xB7),
		[]byte("v2"), 0, false, true, "lfa",
		t0.Add(ReanchorMinIntervalLFA+time.Hour)); err != nil {
		t.Fatalf("ArchiveAndReanchor (lfa): %v", err)
	}
	st = bs.GetReanchorState(cid)
	if st.ReanchorCount != 2 || !st.ESRTCapable || !st.LFA {
		t.Fatalf("after lfa re-anchor: %+v", st)
	}

	// LFA re-anchor flagged the client for post-fact review
	pending := bs.ListLFAReviewPending()
	if len(pending) != 1 || pending[0] != cid {
		t.Fatalf("expected %q pending review, got %v", cid, pending)
	}
	if err := bs.AcknowledgeLFAReview(cid); err != nil {
		t.Fatalf("AcknowledgeLFAReview: %v", err)
	}
	if len(bs.ListLFAReviewPending()) != 0 {
		t.Error("review should be cleared after acknowledge (Postgres)")
	}
}

func TestPostgresTenantRoundTrip(t *testing.T) {
	s := pgBaselineStore(t)

	if err := s.SetClientTenant("ghost", "acme"); err == nil {
		t.Fatal("SetClientTenant stamped a client with no baseline row")
	}

	pcr14 := fill(0x14)
	if res, _ := s.CheckAndUpdate("c-tenant", pcr14); res != TOFUFirstUse {
		t.Fatal("CheckAndUpdate first use failed")
	}

	// freshly migrated row is in the default tenant
	if tenant, err := s.ClientTenant("c-tenant"); err != nil || tenant != DefaultTenant {
		t.Fatalf("ClientTenant before stamp = %q, %v; want default", tenant, err)
	}

	if err := s.SetClientTenant("c-tenant", "acme"); err != nil {
		t.Fatalf("SetClientTenant: %v", err)
	}
	if tenant, err := s.ClientTenant("c-tenant"); err != nil || tenant != "acme" {
		t.Fatalf("ClientTenant = %q, %v; want acme", tenant, err)
	}

	if err := s.ClearBaseline("c-tenant"); err != nil {
		t.Fatalf("ClearBaseline: %v", err)
	}
	if tenant, err := s.ClientTenant("c-tenant"); err != nil || tenant != DefaultTenant {
		t.Fatalf("ClientTenant after clear = %q, %v; want default", tenant, err)
	}
}
