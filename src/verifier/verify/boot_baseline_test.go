// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek

package verify

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/szymonwilczek/lota/verifier/logging"
	"github.com/szymonwilczek/lota/verifier/store"
	"github.com/szymonwilczek/lota/verifier/types"
)

// baselineOf reads the client's baseline; a store error fails the test.
func baselineOf(t *testing.T, s BaselineStorer, id string) *ClientBaseline {
	t.Helper()
	b, err := s.GetBaseline(id)
	if err != nil {
		t.Fatalf("GetBaseline(%s): %v", id, err)
	}
	return b
}

// bootBaselineOf reads the client's boot baseline; a store error fails
// the test.
func bootBaselineOf(t *testing.T, s BootBaselineReader,
	id string,
) *BootBaseline {
	t.Helper()
	b, err := s.GetBootBaseline(id)
	if err != nil {
		t.Fatalf("GetBootBaseline(%s): %v", id, err)
	}
	return b
}

// clientInfoOf reads the client's record; a store error fails the test.
func clientInfoOf(t *testing.T, v *Verifier, id string) (*ClientInfo, bool) {
	t.Helper()
	info, found, err := v.ClientInfo(id)
	if err != nil {
		t.Fatalf("ClientInfo(%s): %v", id, err)
	}
	return info, found
}

func boot(pcr0, pcr1, pcr7 byte) BootBaseline {
	var b BootBaseline
	for i := range b.PCR0 {
		b.PCR0[i] = pcr0
	}
	for i := range b.PCR1 {
		b.PCR1[i] = pcr1
	}
	for i := range b.PCR7 {
		b.PCR7[i] = pcr7
	}
	return b
}

func TestBootBaseline_MemoryFirstUseAndMatch(t *testing.T) {
	bs := NewBaselineStore()

	res, snap := bs.CheckAndUpdateBootPCRs("c1", boot(0xA0, 0xA1, 0xA7))
	if res != TOFUFirstUse {
		t.Fatalf("expected TOFUFirstUse, got %v", res)
	}
	if snap == nil || snap.PCR7[0] != 0xA7 {
		t.Fatalf("snapshot missing pinned values: %+v", snap)
	}

	res, snap = bs.CheckAndUpdateBootPCRs("c1", boot(0xA0, 0xA1, 0xA7))
	if res != TOFUMatch {
		t.Fatalf("expected TOFUMatch, got %v", res)
	}
	if snap == nil {
		t.Fatal("snapshot missing on match")
	}
}

func TestBootBaseline_MemoryDetectsMismatch(t *testing.T) {
	bs := NewBaselineStore()

	bs.CheckAndUpdateBootPCRs("c2", boot(0x10, 0x11, 0x17))

	res, snap := bs.CheckAndUpdateBootPCRs("c2", boot(0x10, 0x11, 0xFF /* SecureBoot changed */))
	if res != TOFUMismatch {
		t.Fatalf("expected TOFUMismatch on PCR7 drift, got %v", res)
	}
	if snap == nil || snap.PCR7[0] != 0x17 {
		t.Fatalf("snapshot should expose the pinned baseline, got %+v", snap)
	}
}

func TestBootBaseline_MemoryClearBaselineDropsAllState(t *testing.T) {
	bs := NewBaselineStore()

	pcr14 := [types.HashSize]byte{0x14}
	bs.CheckAndUpdate("c3", pcr14)
	bs.CheckAndUpdateBootPCRs("c3", boot(0x30, 0x31, 0x37))
	if err := bs.RecordBootEvidence("c3", []byte("event-log"), 7, true); err != nil {
		t.Fatalf("RecordBootEvidence failed: %v", err)
	}
	_, _, err := bs.RecordKernelHash("c3", [types.HashSize]byte{0x09})
	if err != nil {
		t.Fatalf("RecordKernelHash failed: %v", err)
	}

	if err := bs.ClearBaseline("c3"); err != nil {
		t.Fatalf("ClearBaseline failed: %v", err)
	}

	// SQL stores keep all client state in one row, so their DELETE drops
	// the PCR14 baseline, boot baseline and re-anchor bookkeeping together
	// in-memory store must match or forced re-anchor leaves stale boot pin behind
	if baselineOf(t, bs, "c3") != nil {
		t.Error("PCR14 baseline survived ClearBaseline")
	}
	if bootBaselineOf(t, bs, "c3") != nil {
		t.Error("boot baseline survived ClearBaseline")
	}
	if st := bs.GetReanchorState("c3"); st.Present {
		t.Errorf("re-anchor state survived ClearBaseline: %+v", st)
	}

	if res, _ := bs.CheckAndUpdateBootPCRs("c3", boot(0x40, 0x41, 0x47)); res != TOFUFirstUse {
		t.Fatalf("expected TOFUFirstUse after clear, got %v", res)
	}
	bs.CheckAndUpdate("c3", pcr14)
	prev, had, err := bs.RecordKernelHash("c3", [types.HashSize]byte{0x0a})
	if err != nil {
		t.Fatalf("RecordKernelHash failed: %v", err)
	}
	if had {
		t.Errorf("kernel hash %x survived ClearBaseline", prev)
	}
}

// client the in-memory store knows only through its boot baseline
// (no PCR14 row, no AIK registration) must still be valid target
// for the operator lifecycle actions, or forced re-anchor 404s while
// the stale boot pin stays behind.
func TestLifecycle_BootBaselineOnlyClient(t *testing.T) {
	bs := NewBaselineStore()
	cfg := DefaultConfig()
	cfg.BaselineStore = bs
	v := NewVerifier(cfg, nil)

	bs.CheckAndUpdateBootPCRs("c9", boot(0x50, 0x51, 0x57))
	if err := v.ForceReanchor("c9"); err != nil {
		t.Fatalf("ForceReanchor failed: %v", err)
	}
	if bootBaselineOf(t, bs, "c9") != nil {
		t.Error("boot baseline survived forced re-anchor")
	}

	bs.CheckAndUpdateBootPCRs("c9", boot(0x60, 0x61, 0x67))
	if err := v.DeleteClient("c9"); err != nil {
		t.Fatalf("DeleteClient failed: %v", err)
	}
	if bootBaselineOf(t, bs, "c9") != nil {
		t.Error("boot baseline survived delete")
	}
}

func TestBootBaseline_SQLitePersistsAcrossOpen(t *testing.T) {
	dir := t.TempDir()
	dbPath := dir + "/baselines.sqlite"

	db1, err := store.OpenDB(dbPath)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	bs1 := NewSQLiteBaselineStore(db1)

	// the boot baseline rides on top of a PCR14 row, so seed PCR14 first
	var pcr14 [types.HashSize]byte
	pcr14[0] = 0xDE
	if r, _ := bs1.CheckAndUpdate("client-x", pcr14); r != TOFUFirstUse {
		t.Fatalf("PCR14 seed expected TOFUFirstUse, got %v", r)
	}

	want := boot(0xB0, 0xB1, 0xB7)
	if r, _ := bs1.CheckAndUpdateBootPCRs("client-x", want); r != TOFUFirstUse {
		t.Fatalf("boot first use expected, got %v", r)
	}

	db1.Close()

	db2, err := store.OpenDB(dbPath)
	if err != nil {
		t.Fatalf("reopen db: %v", err)
	}
	defer db2.Close()
	bs2 := NewSQLiteBaselineStore(db2)

	r, snap := bs2.CheckAndUpdateBootPCRs("client-x", want)
	if r != TOFUMatch {
		t.Fatalf("post-reopen expected TOFUMatch, got %v", r)
	}
	if snap == nil {
		t.Fatal("post-reopen snapshot must be non-nil")
	}
	if !bytes.Equal(snap.PCR7[:], want.PCR7[:]) {
		t.Fatalf("post-reopen PCR7 mismatch: got %x want %x", snap.PCR7, want.PCR7)
	}
}

func TestBootBaseline_SQLiteRefusesWithoutPCR14Row(t *testing.T) {
	dir := t.TempDir()
	db, err := store.OpenDB(dir + "/baselines.sqlite")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer db.Close()
	bs := NewSQLiteBaselineStore(db)

	// no CheckAndUpdate() yet - PCR14 row absent
	r, snap := bs.CheckAndUpdateBootPCRs("ghost", boot(0xC0, 0xC1, 0xC7))
	if r != TOFUError {
		t.Fatalf("expected TOFUError when PCR14 row missing, got %v", r)
	}
	if snap != nil {
		t.Fatal("snapshot must be nil on error")
	}
}

func TestBootBaseline_SQLiteDetectsMismatch(t *testing.T) {
	dir := t.TempDir()
	db, err := store.OpenDB(dir + "/baselines.sqlite")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer db.Close()
	bs := NewSQLiteBaselineStore(db)

	var pcr14 [types.HashSize]byte
	pcr14[0] = 0xAA
	bs.CheckAndUpdate("drift", pcr14)

	bs.CheckAndUpdateBootPCRs("drift", boot(0x20, 0x21, 0x27))
	r, snap := bs.CheckAndUpdateBootPCRs("drift", boot(0x20, 0xEE, 0x27))
	if r != TOFUMismatch {
		t.Fatalf("expected TOFUMismatch on PCR1 drift, got %v", r)
	}
	if snap == nil || snap.PCR1[0] != 0x21 {
		t.Fatalf("snapshot must expose stored baseline, got %+v", snap)
	}
}

func TestBootBaseline_MemoryGetBootBaselineNilWhenUnpinned(t *testing.T) {
	bs := NewBaselineStore()
	if got := bootBaselineOf(t, bs, "never-seen"); got != nil {
		t.Fatalf("expected nil for unpinned client, got %+v", got)
	}

	bs.CheckAndUpdateBootPCRs("c1", boot(0x10, 0x11, 0x17))
	got := bootBaselineOf(t, bs, "c1")
	if got == nil {
		t.Fatal("expected populated baseline after first use")
	}
	if got.PCR0[0] != 0x10 || got.PCR1[0] != 0x11 || got.PCR7[0] != 0x17 {
		t.Fatalf("baseline values not preserved: %+v", got)
	}
}

func TestBootBaseline_SQLiteGetBootBaselineNilWhenUnpinned(t *testing.T) {
	dir := t.TempDir()
	db, err := store.OpenDB(dir + "/baselines.sqlite")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer db.Close()
	bs := NewSQLiteBaselineStore(db)

	if got := bootBaselineOf(t, bs, "never-seen"); got != nil {
		t.Fatalf("expected nil for unpinned client, got %+v", got)
	}

	var pcr14 [types.HashSize]byte
	pcr14[0] = 0xCC
	bs.CheckAndUpdate("c1", pcr14)
	// row exists but boot columns still NULL -> nil
	if got := bootBaselineOf(t, bs, "c1"); got != nil {
		t.Fatalf("expected nil while boot columns NULL, got %+v", got)
	}
	bs.CheckAndUpdateBootPCRs("c1", boot(0x30, 0x31, 0x37))
	got := bootBaselineOf(t, bs, "c1")
	if got == nil {
		t.Fatal("expected populated baseline after first use")
	}
	if got.PCR0[0] != 0x30 || got.PCR7[0] != 0x37 {
		t.Fatalf("baseline values not preserved: %+v", got)
	}
}

func TestPCRVerifier_PolicyDeclaresBootPCRsForTenant(t *testing.T) {
	if NewPCRVerifier().PolicyDeclaresBootPCRsForTenant("") {
		t.Fatal("expected false with no active policy")
	}

	for _, tc := range []struct {
		name string
		pcrs map[int]string
		want bool
	}{
		{"pin-all", map[int]string{0: "aa", 1: "bb", 7: "cc"}, true},
		{"pin-partial", map[int]string{0: "aa", 7: "cc"}, false},
		{"pin-none", map[int]string{14: "dd"}, false},
	} {
		v := NewPCRVerifier()
		policy := &PCRPolicy{Name: tc.name, PCRs: tc.pcrs, AgentHashes: []string{"de"}}
		if err := v.AddPolicy(policy); err != nil {
			t.Fatalf("AddPolicy: %v", err)
		}
		if got := v.PolicyDeclaresBootPCRsForTenant(""); got != tc.want {
			t.Fatalf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestPCRVerifier_PolicyRequiresSecureBootForTenant(t *testing.T) {
	if NewPCRVerifier().PolicyRequiresSecureBootForTenant("") {
		t.Fatal("expected false with no active policy")
	}

	for _, want := range []bool{true, false} {
		v := NewPCRVerifier()
		policy := &PCRPolicy{Name: "sb", RequireSecureBoot: want, AgentHashes: []string{"de"}}
		if err := v.AddPolicy(policy); err != nil {
			t.Fatalf("AddPolicy: %v", err)
		}
		if got := v.PolicyRequiresSecureBootForTenant(""); got != want {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

// Boot enrollment gate may treat a TOFU first-use as anchored only
// when every leg holds:
// PCR 7 replay-authenticated AND a SecureBoot measurement found AND enabled.
// Any missing leg must fail closed.
func TestSecureBootAnchored(t *testing.T) {
	cases := []struct {
		name  string
		facts *BootFacts
		want  bool
	}{
		{"nil facts", nil, false},
		{"trusted enabled", &BootFacts{
			SecureBoot:        SecureBootState{Found: true, Enabled: true},
			SecureBootTrusted: true,
		}, true},
		{"replay not authenticated", &BootFacts{
			SecureBoot:        SecureBootState{Found: true, Enabled: true},
			SecureBootTrusted: false,
		}, false},
		{"no SecureBoot measurement", &BootFacts{
			SecureBoot:        SecureBootState{Found: false, Enabled: false},
			SecureBootTrusted: true,
		}, false},
		{"SecureBoot disabled", &BootFacts{
			SecureBoot:        SecureBootState{Found: true, Enabled: false},
			SecureBootTrusted: true,
		}, false},
	}
	for _, tc := range cases {
		if got := SecureBootAnchored(tc.facts); got != tc.want {
			t.Errorf("%s: SecureBootAnchored = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestReanchor_MemoryStateAndArchive(t *testing.T) {
	bs := NewBaselineStore()

	// no baseline row -> not present
	if st := bs.GetReanchorState("dev"); st.Present {
		t.Fatal("no baseline -> Present should be false")
	}

	// pin the boot baseline first
	bs.CheckAndUpdateBootPCRs("dev", boot(0x10, 0x11, 0x17))
	st := bs.GetReanchorState("dev")
	if !st.Present {
		t.Fatal("after pin -> Present should be true")
	}
	if st.ReanchorCount != 0 || st.ESRTCapable || st.LFA {
		t.Errorf("fresh re-anchor state should be zero: %+v", st)
	}

	// strong re-anchor: records event log + ESRT version, sets capable
	t0 := time.Now()
	log1 := []byte("eventlog-v1")
	if err := bs.ArchiveAndReanchor("dev", boot(0x20, 0x21, 0x17), log1,
		785, true, false, "strong", t0); err != nil {
		t.Fatalf("ArchiveAndReanchor: %v", err)
	}
	st = bs.GetReanchorState("dev")
	if st.ReanchorCount != 1 {
		t.Errorf("ReanchorCount: got %d, want 1", st.ReanchorCount)
	}
	if !st.ESRTCapable || st.ESRTVersion != 785 || st.LFA {
		t.Errorf("strong re-anchor state wrong: %+v", st)
	}
	if !bytes.Equal(st.EventLogBaseline, log1) {
		t.Error("event-log baseline not stored")
	}
	if r, _ := bs.CheckAndUpdateBootPCRs("dev", boot(0x20, 0x21, 0x17)); r != TOFUMatch {
		t.Errorf("re-anchored baseline should match, got %v", r)
	}

	// LFA re-anchor: esrt_capable stays sticky-true, count bumps, LFA set
	// past the LFA interval so this legitimate second re-anchor is admitted
	if err := bs.ArchiveAndReanchor("dev", boot(0x30, 0x31, 0x17),
		[]byte("v2"), 0, false, true, "lfa",
		t0.Add(ReanchorMinIntervalLFA+time.Hour)); err != nil {
		t.Fatalf("ArchiveAndReanchor (lfa): %v", err)
	}
	st = bs.GetReanchorState("dev")
	if st.ReanchorCount != 2 {
		t.Errorf("ReanchorCount: got %d, want 2", st.ReanchorCount)
	}
	if !st.ESRTCapable {
		t.Error("esrt_capable must stay sticky true once set")
	}
	if !st.LFA {
		t.Error("LFA should be true after an lfa re-anchor")
	}
}

func TestReanchor_SQLitePersistsAndArchives(t *testing.T) {
	dir := t.TempDir()
	db, err := store.OpenDB(dir + "/b.sqlite")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer db.Close()
	bs := NewSQLiteBaselineStore(db)

	var pcr14 [types.HashSize]byte
	pcr14[0] = 0xDE
	bs.CheckAndUpdate("c", pcr14)
	bs.CheckAndUpdateBootPCRs("c", boot(0xB0, 0xB1, 0xB7))

	st := bs.GetReanchorState("c")
	if !st.Present || st.ReanchorCount != 0 || st.ESRTCapable {
		t.Fatalf("fresh re-anchor state wrong: %+v", st)
	}

	t0 := time.Now()
	log := []byte("evlog-baseline")
	if err := bs.ArchiveAndReanchor("c", boot(0xC0, 0xC1, 0xB7), log,
		785, true, false, "strong", t0); err != nil {
		t.Fatalf("ArchiveAndReanchor: %v", err)
	}
	st = bs.GetReanchorState("c")
	if st.ReanchorCount != 1 || !st.ESRTCapable || st.ESRTVersion != 785 || st.LFA {
		t.Fatalf("after strong re-anchor: %+v", st)
	}
	if !bytes.Equal(st.EventLogBaseline, log) {
		t.Error("event-log baseline not persisted")
	}
	if r, _ := bs.CheckAndUpdateBootPCRs("c", boot(0xC0, 0xC1, 0xB7)); r != TOFUMatch {
		t.Errorf("re-anchored baseline should match, got %v", r)
	}

	var n int
	if err := db.QueryRow(
		"SELECT COUNT(*) FROM baseline_archive WHERE client_id = 'c'").Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("archive rows after one re-anchor: got %d, want 1", n)
	}

	// LFA re-anchor: capability stays sticky, count bumps, second archive row
	// past the LFA interval so this legitimate second re-anchor is admitted
	if err := bs.ArchiveAndReanchor("c", boot(0xD0, 0xD1, 0xB7),
		[]byte("v2"), 0, false, true, "lfa",
		t0.Add(ReanchorMinIntervalLFA+time.Hour)); err != nil {
		t.Fatalf("ArchiveAndReanchor (lfa): %v", err)
	}
	st = bs.GetReanchorState("c")
	if st.ReanchorCount != 2 || !st.ESRTCapable || !st.LFA {
		t.Fatalf("after lfa re-anchor: %+v", st)
	}
	if err := db.QueryRow(
		"SELECT COUNT(*) FROM baseline_archive WHERE client_id = 'c'").Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Errorf("archive rows after two re-anchors: got %d, want 2", n)
	}
}

// TestArchiveAndReanchor_RateLimitAtomic pins the rate limit as an
// in-transaction invariant of the store rather than a cheap-path advisory
// in reanchorDecision.
// Two re-anchors for the same client inside the assurance-tier interval must
// leave exactly one re-anchor on record: the second is refused with
// ErrReanchorRateLimited and must not touch the baseline.
// Without the in-store guard, a burst of concurrent attestations could each
// pass the advisory gate and re-anchor repeatedly in one window.
func TestArchiveAndReanchor_RateLimitAtomic(t *testing.T) {
	t0 := time.Now()

	check := func(name string, rs ReanchorStorer) {
		// first strong re-anchor at t0 is admitted
		if err := rs.ArchiveAndReanchor("c", boot(0x20, 0x21, 0x17),
			[]byte("v1"), 785, true, false, "strong", t0); err != nil {
			t.Fatalf("%s: first re-anchor: %v", name, err)
		}
		// second re-anchor one second later is well inside the 30-day strong
		// interval and must be rate-limited
		err := rs.ArchiveAndReanchor("c", boot(0x30, 0x31, 0x17),
			[]byte("v2"), 900, true, false, "strong", t0.Add(time.Second))
		if !errors.Is(err, ErrReanchorRateLimited) {
			t.Fatalf("%s: second re-anchor: got %v, want ErrReanchorRateLimited",
				name, err)
		}
		// refused re-anchor left the row untouched:
		// count stays 1 and the event-log baseline is still v1
		st := rs.GetReanchorState("c")
		if st.ReanchorCount != 1 {
			t.Errorf("%s: ReanchorCount: got %d, want 1", name, st.ReanchorCount)
		}
		if !bytes.Equal(st.EventLogBaseline, []byte("v1")) {
			t.Errorf("%s: event-log baseline overwritten by rate-limited re-anchor",
				name)
		}
		// once the interval elapses the re-anchor is admitted again
		if err := rs.ArchiveAndReanchor("c", boot(0x40, 0x41, 0x17),
			[]byte("v3"), 1000, true, false, "strong",
			t0.Add(ReanchorMinIntervalStrong+time.Hour)); err != nil {
			t.Fatalf("%s: post-interval re-anchor: %v", name, err)
		}
		if st = rs.GetReanchorState("c"); st.ReanchorCount != 2 {
			t.Errorf("%s: ReanchorCount after interval: got %d, want 2",
				name, st.ReanchorCount)
		}
	}

	mem := NewBaselineStore()
	mem.CheckAndUpdateBootPCRs("c", boot(0x10, 0x11, 0x17))
	check("memory", mem)

	dir := t.TempDir()
	db, err := store.OpenDB(dir + "/rl.sqlite")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer db.Close()
	sq := NewSQLiteBaselineStore(db)
	var pcr14 [types.HashSize]byte
	pcr14[0] = 0xDE
	sq.CheckAndUpdate("c", pcr14)
	sq.CheckAndUpdateBootPCRs("c", boot(0x10, 0x11, 0x17))
	check("sqlite", sq)
}

func TestRecordBootEvidence_MemoryAndSQLite(t *testing.T) {
	// in-memory
	bs := NewBaselineStore()
	bs.CheckAndUpdateBootPCRs("c", boot(1, 2, 7))
	if err := bs.RecordBootEvidence("c", []byte("log"), 785, true); err != nil {
		t.Fatalf("RecordBootEvidence: %v", err)
	}
	st := bs.GetReanchorState("c")
	if !bytes.Equal(st.EventLogBaseline, []byte("log")) || st.ESRTVersion != 785 || !st.ESRTCapable {
		t.Fatalf("in-memory evidence: %+v", st)
	}
	// esrt_capable stays sticky even if a later record reports not-present
	if err := bs.RecordBootEvidence("c", []byte("log2"), 0, false); err != nil {
		t.Fatal(err)
	}
	if st = bs.GetReanchorState("c"); !st.ESRTCapable {
		t.Error("in-memory esrt_capable must stay sticky")
	}

	// SQLite
	dir := t.TempDir()
	db, err := store.OpenDB(dir + "/b.sqlite")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer db.Close()
	sq := NewSQLiteBaselineStore(db)
	var pcr14 [types.HashSize]byte
	pcr14[0] = 0xDE
	sq.CheckAndUpdate("c", pcr14)
	sq.CheckAndUpdateBootPCRs("c", boot(1, 2, 7))
	if err := sq.RecordBootEvidence("c", []byte("evlog"), 900, true); err != nil {
		t.Fatalf("sqlite RecordBootEvidence: %v", err)
	}
	st = sq.GetReanchorState("c")
	if !bytes.Equal(st.EventLogBaseline, []byte("evlog")) || st.ESRTVersion != 900 || !st.ESRTCapable {
		t.Fatalf("sqlite evidence: %+v", st)
	}
	// re-anchor count untouched by evidence recording
	if st.ReanchorCount != 0 {
		t.Errorf("RecordBootEvidence must not bump reanchor_count, got %d", st.ReanchorCount)
	}
}

func TestLFAReview_MemoryAndSQLite(t *testing.T) {
	// in-memory: an LFA re-anchor flags the client for review;
	// strong re-anchor clears it; acknowledge clears it too
	bs := NewBaselineStore()
	bs.CheckAndUpdateBootPCRs("c", boot(1, 2, 7))
	if len(bs.ListLFAReviewPending()) != 0 {
		t.Fatal("no review pending before any LFA re-anchor")
	}
	t0 := time.Now()
	if err := bs.ArchiveAndReanchor("c", boot(2, 2, 7), []byte("l"), 0, false, true, "lfa", t0); err != nil {
		t.Fatal(err)
	}
	if got := bs.ListLFAReviewPending(); len(got) != 1 || got[0] != "c" {
		t.Fatalf("expected c pending review, got %v", got)
	}
	if err := bs.AcknowledgeLFAReview("c"); err != nil {
		t.Fatal(err)
	}
	if len(bs.ListLFAReviewPending()) != 0 {
		t.Error("review should be cleared after acknowledge (in-memory)")
	}
	// an unacknowledged LFA re-anchor is cleared by a strong one
	// (each past the previous interval so it is admitted)
	t1 := t0.Add(ReanchorMinIntervalLFA + time.Hour)
	if err := bs.ArchiveAndReanchor("c", boot(3, 2, 7), []byte("l"),
		0, false, true, "lfa", t1); err != nil {
		t.Fatal(err)
	}
	if err := bs.ArchiveAndReanchor("c", boot(4, 2, 7), []byte("l"),
		800, true, false, "strong",
		t1.Add(ReanchorMinIntervalLFA+time.Hour)); err != nil {
		t.Fatal(err)
	}
	if len(bs.ListLFAReviewPending()) != 0 {
		t.Error("strong re-anchor must clear the review flag")
	}

	// SQLite: same contract
	dir := t.TempDir()
	db, err := store.OpenDB(dir + "/b.sqlite")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer db.Close()
	sq := NewSQLiteBaselineStore(db)
	var pcr14 [types.HashSize]byte
	pcr14[0] = 0xDE
	sq.CheckAndUpdate("c", pcr14)
	sq.CheckAndUpdateBootPCRs("c", boot(1, 2, 7))
	if err := sq.ArchiveAndReanchor("c", boot(2, 2, 7), []byte("l"), 0, false, true, "lfa", time.Now()); err != nil {
		t.Fatal(err)
	}
	if got := sq.ListLFAReviewPending(); len(got) != 1 || got[0] != "c" {
		t.Fatalf("sqlite: expected c pending, got %v", got)
	}
	if err := sq.AcknowledgeLFAReview("c"); err != nil {
		t.Fatal(err)
	}
	if len(sq.ListLFAReviewPending()) != 0 {
		t.Error("review should be cleared after acknowledge (SQLite)")
	}
}

// TestPinnedRegister_MemoryRefusesAMovedPCR14 and its SQLite twin cover the
// register itself.
// Nothing about the round changes except PCR 14: the same client, the same
// agent binary, the same firmware PCRs -- which is what a MOK enrollment
// or a shim update leaves behind, since both move the pre-lock baseline
// the boot commitment chains onto.
func TestPinnedRegister_MemoryRefusesAMovedPCR14(t *testing.T) {
	bs := NewBaselineStore()
	pcr14 := [types.HashSize]byte{0x14}
	agentHash := [types.HashSize]byte{0xA1}
	boot := &BootBaseline{PCR0: [types.HashSize]byte{0}, PCR1: [types.HashSize]byte{1}, PCR7: [types.HashSize]byte{7}}

	if o := bs.CheckAndUpdateAttestation("c", pcr14, agentHash, boot, false); o.PCR14Result != TOFUFirstUse {
		t.Fatalf("first use: pcr14 = %v", o.PCR14Result)
	}
	if o := bs.CheckAndUpdateAttestation("c", pcr14, agentHash, boot, false); o.PCR14Result != TOFUMatch {
		t.Fatalf("match: pcr14 = %v", o.PCR14Result)
	}

	moved := [types.HashSize]byte{0x15}
	o := bs.CheckAndUpdateAttestation("c", moved, agentHash, boot, false)
	if o.PCR14Result != TOFUMismatch {
		t.Fatalf("moved register: pcr14 = %v, want TOFUMismatch", o.PCR14Result)
	}
	if o.AgentHashBaseline == nil || o.AgentHashBaseline.PCR14 != pcr14 {
		t.Fatal("a refusal has to carry the register the client pinned")
	}
	if b := baselineOf(t, bs, "c"); b == nil || b.PCR14 != pcr14 ||
		b.AttestCount != 2 {
		t.Fatalf("refused round wrote state: %+v", b)
	}
}

func TestPinnedRegister_SQLiteRefusesAMovedPCR14(t *testing.T) {
	db, err := store.OpenDB(":memory:")
	if err != nil {
		t.Fatalf("OpenDB failed: %v", err)
	}
	defer db.Close()

	bs := NewSQLiteBaselineStore(db)
	pcr14 := [types.HashSize]byte{0x14}
	agentHash := [types.HashSize]byte{0xA1}
	boot := &BootBaseline{PCR0: [types.HashSize]byte{0}, PCR1: [types.HashSize]byte{1}, PCR7: [types.HashSize]byte{7}}

	if o := bs.CheckAndUpdateAttestation("c", pcr14, agentHash, boot, false); o.PCR14Result != TOFUFirstUse {
		t.Fatalf("first use: pcr14 = %v", o.PCR14Result)
	}
	if o := bs.CheckAndUpdateAttestation("c", pcr14, agentHash, boot, false); o.PCR14Result != TOFUMatch {
		t.Fatalf("match: pcr14 = %v", o.PCR14Result)
	}

	moved := [types.HashSize]byte{0x15}
	o := bs.CheckAndUpdateAttestation("c", moved, agentHash, boot, false)
	if o.PCR14Result != TOFUMismatch {
		t.Fatalf("moved register: pcr14 = %v, want TOFUMismatch", o.PCR14Result)
	}
	if o.AgentHashBaseline == nil || o.AgentHashBaseline.PCR14 != pcr14 {
		t.Fatal("a refusal has to carry the register the client pinned")
	}
	if b := baselineOf(t, bs, "c"); b == nil || b.PCR14 != pcr14 ||
		b.AttestCount != 2 {
		t.Fatalf("refused round wrote state: %+v", b)
	}
}

// Logs through logging.New, so lines carry level names (level=SECURITY),
// not slog's numeric fallback.
func acceptLogVerifier(t *testing.T, buf *bytes.Buffer, policy *PCRPolicy,
	requireBootEnrollment bool,
) *Verifier {
	t.Helper()

	cfg := DefaultConfig()
	cfg.NonceLifetime = 1 * time.Second
	cfg.RequireBootEnrollment = requireBootEnrollment
	cfg.Logger = logging.New(logging.Options{
		Level:  "debug",
		Format: "text",
		Output: buf,
	})

	v := NewVerifier(cfg, newCertVerifier(t))
	if err := v.AddPolicy(policy); err != nil {
		t.Fatalf("AddPolicy: %v", err)
	}
	return v
}

// Runs one first attestation, returns its first-use boot baseline line.
func firstUseBootAcceptLine(t *testing.T, v *Verifier, logs *bytes.Buffer,
	clientID string,
) string {
	t.Helper()

	challenge, err := v.GenerateChallenge(clientID)
	if err != nil {
		t.Fatalf("GenerateChallenge: %v", err)
	}
	report := createValidReport(t, clientID, challenge.Nonce, fixturePCR14())
	result, err := v.VerifyReportFrom(clientID, "", report)
	if err != nil {
		t.Fatalf("VerifyReport: %v", err)
	}
	if result.Result != types.VerifyOK {
		t.Fatalf("expected VerifyOK, got %d", result.Result)
	}

	for _, line := range strings.Split(logs.String(), "\n") {
		if strings.Contains(line, "boot baseline") &&
			strings.Contains(line, "first-use") {
			return line
		}
	}
	t.Fatalf("no first-use boot baseline record in the log:\n%s", logs.String())
	return ""
}

// A first-use pin under --allow-tofu-boot-baseline trusts unauthenticated
// firmware state; it logs at SECURITY like the anchored accept.
func TestVerify_UnanchoredBootPinIsLoggedAtSecurityLevel(t *testing.T) {
	var logs bytes.Buffer

	// no PCR0/1/7 pins, no require_secureboot: only the flag can pin
	v := acceptLogVerifier(t, &logs, DefaultPolicy(), false)

	line := firstUseBootAcceptLine(t, v, &logs, "tofu-accept-unanchored")

	if !strings.Contains(line, "level=SECURITY") {
		t.Fatalf("the unanchored pin is not a security event:\n%s", line)
	}
	if !strings.Contains(line, "allow-tofu-boot-baseline") {
		t.Fatalf("the accept does not name what allowed it:\n%s", line)
	}
}

// The anchored accept names its anchor; a field, not the level,
// tells the two apart.
func TestVerify_AnchoredBootPinNamesItsAnchor(t *testing.T) {
	var logs bytes.Buffer

	policy := DefaultPolicy()
	policy.Name = "anchored"
	policy.RequireSecureBoot = true

	v := acceptLogVerifier(t, &logs, policy, true)

	line := firstUseBootAcceptLine(t, v, &logs, "tofu-accept-anchored")

	if !strings.Contains(line, "level=SECURITY") {
		t.Fatalf("the anchored pin is not a security event:\n%s", line)
	}
	if !strings.Contains(line, "Secure Boot anchor") {
		t.Fatalf("the accept does not name the anchor that allowed it:\n%s",
			line)
	}
	if strings.Contains(line, "allow-tofu-boot-baseline") {
		t.Fatalf("an anchored accept is blamed on the flag:\n%s", line)
	}
}

// The pin road does not claim a signature: --policy-pubkey is optional.
func TestBootBaselineRoad_PolicyPinsClaimNoSignature(t *testing.T) {
	v := NewVerifier(DefaultConfig(), newCertVerifier(t))
	policy := &PCRPolicy{
		Name:        "pinned",
		PCRs:        map[int]string{0: "aa", 1: "bb", 7: "cc"},
		AgentHashes: []string{"de"},
	}
	if err := v.AddPolicy(policy); err != nil {
		t.Fatalf("AddPolicy: %v", err)
	}

	got := v.bootBaselineRoad("", nil).allowedBy
	if got != "policy PCR0/1/7 pins" {
		t.Fatalf("allowed_by = %q", got)
	}
}

func attestOnce(t *testing.T, v *Verifier, clientID string) uint32 {
	t.Helper()

	challenge, err := v.GenerateChallenge(clientID)
	if err != nil {
		t.Fatalf("GenerateChallenge: %v", err)
	}
	report := createValidReport(t, clientID, challenge.Nonce,
		fixturePCR14())
	result, _ := v.VerifyReportFrom(clientID, "", report)
	return result.Result
}

// Under RequireBootEnrollment a forced re-anchor lets the next attestation
// pin afresh once; a delete forgets the client.
func TestForceReanchor_ConsentsToOneFirstUsePin(t *testing.T) {
	var logs bytes.Buffer
	v := acceptLogVerifier(t, &logs, DefaultPolicy(), true)
	bs := v.baselineStore.(*BaselineStore)
	const id = "forced-client"
	stored := testPseudonym(id) // the store keys the AIK pseudonym

	if got := attestOnce(t, v, id); got != types.VerifyPolicyRequirement {
		t.Fatalf("unenrolled first use: %d", got)
	}
	if err := bs.MarkForcedReanchor(stored); err != nil {
		t.Fatal(err)
	}
	logs.Reset()
	line := firstUseBootAcceptLine(t, v, &logs, id)
	if !strings.Contains(line, "operator force-reanchor") {
		t.Fatalf("the pin does not name the consent:\n%s", line)
	}
	if got := attestOnce(t, v, id); got != types.VerifyOK {
		t.Fatalf("round on the new pin: %d", got)
	}

	if err := v.ForceReanchor(stored); err != nil {
		t.Fatalf("ForceReanchor: %v", err)
	}
	if got := attestOnce(t, v, id); got != types.VerifyOK {
		t.Fatalf("round after ForceReanchor: %d", got)
	}

	// the consent was spent by that round
	if err := bs.ClearBaseline(stored); err != nil {
		t.Fatal(err)
	}
	if got := attestOnce(t, v, id); got != types.VerifyPolicyRequirement {
		t.Fatalf("round on a spent consent: %d", got)
	}

	if err := bs.MarkForcedReanchor(stored); err != nil {
		t.Fatal(err)
	}
	bs.CheckAndUpdate(stored, fixturePCR14())
	if err := v.DeleteClient(stored); err != nil {
		t.Fatalf("DeleteClient: %v", err)
	}
	if got := attestOnce(t, v, id); got != types.VerifyPolicyRequirement {
		t.Fatalf("round after DeleteClient: %d", got)
	}
}

// A round whose pin does not commit keeps the consent for the next round.
func TestForceReanchor_FailedPinKeepsTheConsent(t *testing.T) {
	db, err := store.OpenDB(":memory:")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer db.Close()
	bs := NewSQLiteBaselineStore(db)

	cfg := DefaultConfig()
	cfg.NonceLifetime = 1 * time.Second
	cfg.RequireBootEnrollment = true
	cfg.BaselineStore = bs
	v := NewVerifier(cfg, newCertVerifier(t))
	if err := v.AddPolicy(DefaultPolicy()); err != nil {
		t.Fatalf("AddPolicy: %v", err)
	}
	const id = "forced-client"
	stored := testPseudonym(id)

	if err := bs.MarkForcedReanchor(stored); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TRIGGER refuse_pin BEFORE INSERT ON
		baselines BEGIN SELECT RAISE(ABORT, 'refused'); END`); err != nil {
		t.Fatal(err)
	}
	if got := attestOnce(t, v, id); got != types.VerifyInternalError {
		t.Fatalf("round on a failing store: %d", got)
	}
	if ok, err := bs.HasForcedReanchor(stored); err != nil || !ok {
		t.Fatalf("consent after the failed pin: %v, %v", ok, err)
	}

	if _, err := db.Exec("DROP TRIGGER refuse_pin"); err != nil {
		t.Fatal(err)
	}
	if got := attestOnce(t, v, id); got != types.VerifyOK {
		t.Fatalf("round after the store recovered: %d", got)
	}
	if ok, err := bs.HasForcedReanchor(stored); err != nil || ok {
		t.Fatalf("consent after the pin: %v, %v", ok, err)
	}
}

// The consent survives ClearBaseline and is taken once.
func TestForcedReanchor_MemoryAndSQLite(t *testing.T) {
	db, err := store.OpenDB(":memory:")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer db.Close()

	for name, fr := range map[string]forcedPinStore{
		"memory": NewBaselineStore(),
		"sqlite": NewSQLiteBaselineStore(db),
		"shard": NewShardedBaselineStore([]BaselineStorer{
			NewBaselineStore(), NewBaselineStore(),
		}),
	} {
		fr.CheckAndUpdate("c", [types.HashSize]byte{0x14})
		if err := fr.MarkForcedReanchor("c"); err != nil {
			t.Fatalf("%s: mark: %v", name, err)
		}
		if err := fr.MarkForcedReanchor("c"); err != nil {
			t.Fatalf("%s: mark twice: %v", name, err)
		}
		if err := fr.ClearBaseline("c"); err != nil {
			t.Fatalf("%s: clear: %v", name, err)
		}
		if ok, err := fr.TakeForcedReanchor("c"); err != nil || !ok {
			t.Fatalf("%s: take: %v, %v", name, ok, err)
		}
		if ok, err := fr.TakeForcedReanchor("c"); err != nil || ok {
			t.Fatalf("%s: second take: %v, %v", name, ok, err)
		}
		checkForcedReanchorPin(t, fr)
	}
}

type forcedPinStore interface {
	BaselineStorer
	BootBaselineReader
	AtomicBaselineStorer
	ForcedReanchorStorer
}

// The first boot pin of a consented round spends the consent in its own
// transaction: no consent left means no pin, and of two racing rounds one
// pins.
func checkForcedReanchorPin(t *testing.T, s forcedPinStore) {
	t.Helper()
	var pcr14, agentHash [types.HashSize]byte
	pcr14[0], agentHash[0] = 0x14, 0xA1
	bootA := &BootBaseline{PCR0: [types.HashSize]byte{0xA0}}
	bootB := &BootBaseline{PCR0: [types.HashSize]byte{0xB0}}

	o := s.CheckAndUpdateAttestation("no-consent", pcr14, agentHash, bootA, true)
	if o.AgentHashResult != TOFUError || o.BootResult != TOFUError {
		t.Fatalf("pin without a consent: %+v", o)
	}
	if b, err := s.GetBootBaseline("no-consent"); err != nil || b != nil {
		t.Fatalf("pin without a consent wrote %+v, %v", b, err)
	}

	if err := s.MarkForcedReanchor("racing"); err != nil {
		t.Fatal(err)
	}
	outs := make(chan AttestationOutcome, 2)
	for _, boot := range []*BootBaseline{bootA, bootB} {
		go func() {
			outs <- s.CheckAndUpdateAttestation("racing", pcr14,
				agentHash, boot, true)
		}()
	}
	pins := 0
	for range 2 {
		if o := <-outs; o.BootResult == TOFUFirstUse {
			pins++
		}
	}
	if pins != 1 {
		t.Fatalf("%d racing rounds pinned, want 1", pins)
	}
	if ok, err := s.HasForcedReanchor("racing"); err != nil || ok {
		t.Fatalf("consent after the pin: %v, %v", ok, err)
	}
}

type pcr14RepinStore interface {
	BaselineStorer
	BootBaselineStorer
	ReanchorStorer
	PCR14RepinStorer
}

func checkRepinPCR14(t *testing.T, bs pcr14RepinStore) {
	t.Helper()
	var from, to, other [types.HashSize]byte
	from[0], to[0], other[0] = 0xA1, 0xA2, 0xA3
	log := []byte("evlog-next")

	if bs.RepinPCR14("c", from, to, log, time.Now()) == nil {
		t.Fatal("re-pinned a client with no row")
	}
	bs.CheckAndUpdate("c", from)
	bs.CheckAndUpdateBootPCRs("c", boot(0xB0, 0xB1, 0xB7))

	if err := bs.RepinPCR14("c", other, to, log, time.Now()); !errors.Is(err, ErrPCR14RepinRaced) {
		t.Fatalf("stale register: got %v, want ErrPCR14RepinRaced", err)
	}
	if err := bs.RepinPCR14("c", from, to, log, time.Now()); err != nil {
		t.Fatalf("RepinPCR14: %v", err)
	}
	if got := baselineOf(t, bs, "c").PCR14; got != to {
		t.Fatalf("pin not moved: %x", got)
	}
	if st := bs.GetReanchorState("c"); !bytes.Equal(st.EventLogBaseline, log) {
		t.Fatal("boot evidence not moved")
	}
}

func TestRepinPCR14_Stores(t *testing.T) {
	db, err := store.OpenDB(t.TempDir() + "/b.sqlite")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer db.Close()

	sharded, _ := newShardedMemoryBaselines(2)
	for name, bs := range map[string]pcr14RepinStore{
		"memory":  NewBaselineStore(),
		"sqlite":  NewSQLiteBaselineStore(db),
		"sharded": sharded,
	} {
		t.Run(name, func(t *testing.T) { checkRepinPCR14(t, bs) })
	}
}
