// SPDX-License-Identifier: MIT
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
