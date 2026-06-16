// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
// LOTA Verifier - Boot baseline (PCR 0/1/7) TOFU tests

package verify

import (
	"bytes"
	"testing"

	"github.com/szymonwilczek/lota/verifier/store"
	"github.com/szymonwilczek/lota/verifier/types"
)

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
	if got := bs.GetBootBaseline("never-seen"); got != nil {
		t.Fatalf("expected nil for unpinned client, got %+v", got)
	}

	bs.CheckAndUpdateBootPCRs("c1", boot(0x10, 0x11, 0x17))
	got := bs.GetBootBaseline("c1")
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

	if got := bs.GetBootBaseline("never-seen"); got != nil {
		t.Fatalf("expected nil for unpinned client, got %+v", got)
	}

	var pcr14 [types.HashSize]byte
	pcr14[0] = 0xCC
	bs.CheckAndUpdate("c1", pcr14)
	// row exists but boot columns still NULL -> nil
	if got := bs.GetBootBaseline("c1"); got != nil {
		t.Fatalf("expected nil while boot columns NULL, got %+v", got)
	}
	bs.CheckAndUpdateBootPCRs("c1", boot(0x30, 0x31, 0x37))
	got := bs.GetBootBaseline("c1")
	if got == nil {
		t.Fatal("expected populated baseline after first use")
	}
	if got.PCR0[0] != 0x30 || got.PCR7[0] != 0x37 {
		t.Fatalf("baseline values not preserved: %+v", got)
	}
}

func TestPCRVerifier_ActivePolicyDeclaresBootPCRs(t *testing.T) {
	v := NewPCRVerifier()

	// no active policy
	if v.ActivePolicyDeclaresBootPCRs() {
		t.Fatal("expected false with no active policy")
	}

	pinAll := &PCRPolicy{
		Name: "pin-all",
		PCRs: map[int]string{
			0: "aa",
			1: "bb",
			7: "cc",
		},
		AgentHashes: []string{"de"},
	}
	if err := v.AddPolicy(pinAll); err != nil {
		t.Fatalf("AddPolicy: %v", err)
	}
	if err := v.SetActivePolicy("pin-all"); err != nil {
		t.Fatalf("SetActivePolicy: %v", err)
	}
	if !v.ActivePolicyDeclaresBootPCRs() {
		t.Fatal("expected true when PCR0/1/7 all pinned")
	}

	pinPartial := &PCRPolicy{
		Name: "pin-partial",
		PCRs: map[int]string{
			0: "aa",
			7: "cc",
		},
		AgentHashes: []string{"de"},
	}
	if err := v.AddPolicy(pinPartial); err != nil {
		t.Fatalf("AddPolicy: %v", err)
	}
	if err := v.SetActivePolicy("pin-partial"); err != nil {
		t.Fatalf("SetActivePolicy: %v", err)
	}
	if v.ActivePolicyDeclaresBootPCRs() {
		t.Fatal("expected false when PCR1 missing")
	}

	pinNone := &PCRPolicy{
		Name:        "pin-none",
		PCRs:        map[int]string{14: "dd"},
		AgentHashes: []string{"de"},
	}
	if err := v.AddPolicy(pinNone); err != nil {
		t.Fatalf("AddPolicy: %v", err)
	}
	if err := v.SetActivePolicy("pin-none"); err != nil {
		t.Fatalf("SetActivePolicy: %v", err)
	}
	if v.ActivePolicyDeclaresBootPCRs() {
		t.Fatal("expected false when no boot PCR is pinned")
	}
}

func TestPCRVerifier_ActivePolicyRequiresSecureBoot(t *testing.T) {
	v := NewPCRVerifier()

	// no active policy
	if v.ActivePolicyRequiresSecureBoot() {
		t.Fatal("expected false with no active policy")
	}

	sbOn := &PCRPolicy{
		Name:              "sb-on",
		RequireSecureBoot: true,
		AgentHashes:       []string{"de"},
	}
	if err := v.AddPolicy(sbOn); err != nil {
		t.Fatalf("AddPolicy: %v", err)
	}
	if err := v.SetActivePolicy("sb-on"); err != nil {
		t.Fatalf("SetActivePolicy: %v", err)
	}
	if !v.ActivePolicyRequiresSecureBoot() {
		t.Fatal("expected true when require_secureboot is set")
	}

	sbOff := &PCRPolicy{
		Name:        "sb-off",
		AgentHashes: []string{"de"},
	}
	if err := v.AddPolicy(sbOff); err != nil {
		t.Fatalf("AddPolicy: %v", err)
	}
	if err := v.SetActivePolicy("sb-off"); err != nil {
		t.Fatalf("SetActivePolicy: %v", err)
	}
	if v.ActivePolicyRequiresSecureBoot() {
		t.Fatal("expected false when require_secureboot is unset")
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
	log1 := []byte("eventlog-v1")
	if err := bs.ArchiveAndReanchor("dev", boot(0x20, 0x21, 0x17), log1,
		785, true, false, "strong"); err != nil {
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
	if err := bs.ArchiveAndReanchor("dev", boot(0x30, 0x31, 0x17),
		[]byte("v2"), 0, false, true, "lfa"); err != nil {
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

	log := []byte("evlog-baseline")
	if err := bs.ArchiveAndReanchor("c", boot(0xC0, 0xC1, 0xB7), log,
		785, true, false, "strong"); err != nil {
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
	if err := bs.ArchiveAndReanchor("c", boot(0xD0, 0xD1, 0xB7),
		[]byte("v2"), 0, false, true, "lfa"); err != nil {
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
	if err := bs.ArchiveAndReanchor("c", boot(2, 2, 7), []byte("l"), 0, false, true, "lfa"); err != nil {
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
	// strong re-anchor must not leave the client on the review list
	if err := bs.ArchiveAndReanchor("c", boot(3, 2, 7), []byte("l"), 800, true, false, "strong"); err != nil {
		t.Fatal(err)
	}
	if len(bs.ListLFAReviewPending()) != 0 {
		t.Error("strong re-anchor must not flag for review")
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
	if err := sq.ArchiveAndReanchor("c", boot(2, 2, 7), []byte("l"), 0, false, true, "lfa"); err != nil {
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
