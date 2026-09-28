// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
package store

import (
	"path/filepath"
	"testing"
)

// The kernel hash rides in the digest the TPM signs, so a recorded attestation
// holds attested evidence of which kernel image the agent measured.
// Keeping pcr14 and dropping that leaves an operator unable to answer the first
// question anyone asks about a Linux host: did its kernel change.
func TestAttestationLog_RecordsKernelHash(t *testing.T) {
	db, err := OpenDB(filepath.Join(t.TempDir(), "v.sqlite"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()

	log := NewSQLiteAttestationLog(db)
	if err := log.Record(AttestationRecord{
		ClientID:   "c1",
		Tenant:     "alpha",
		Result:     "ok",
		PCR14:      "aa",
		KernelHash: "1f2e3d4c",
	}); err != nil {
		t.Fatalf("record: %v", err)
	}

	got := log.QueryAttestations(1)
	if len(got) != 1 {
		t.Fatalf("want 1 record, got %d", len(got))
	}
	if got[0].KernelHash != "1f2e3d4c" {
		t.Errorf("kernel hash not stored: got %q, want %q",
			got[0].KernelHash, "1f2e3d4c")
	}
}

// A batched write is the production path, so the column has to survive it too,
// or the field is recorded only under a configuration nobody runs.
func TestAttestationLog_RecordsKernelHashInBatch(t *testing.T) {
	db, err := OpenDB(filepath.Join(t.TempDir(), "v.sqlite"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()

	log := NewSQLiteAttestationLog(db)
	if err := log.RecordBatch([]AttestationRecord{
		{ClientID: "c1", Result: "ok", KernelHash: "aaaa"},
		{ClientID: "c1", Result: "ok", KernelHash: "bbbb"},
	}); err != nil {
		t.Fatalf("batch: %v", err)
	}

	got := log.QueryAttestations(2)
	if len(got) != 2 {
		t.Fatalf("want 2 records, got %d", len(got))
	}
	for _, rec := range got {
		if rec.KernelHash == "" {
			t.Fatalf("a batched record lost its kernel hash: %+v", rec)
		}
	}
}
