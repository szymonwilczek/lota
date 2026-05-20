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
