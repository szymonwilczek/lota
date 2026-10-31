// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek

package store

import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"
)

func eventsTestDB(t *testing.T) *sql.DB {
	t.Helper()

	db, err := OpenDB(filepath.Join(t.TempDir(), "v.sqlite"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// a trusted round for one host
func trustedRound(at time.Time) AttestationRecord {
	return AttestationRecord{
		Timestamp:  at,
		Tenant:     "alpha",
		ClientID:   "c1",
		HardwareID: "aa11",
		Result:     "ok",
		PCR14:      "e9e239c2",
		KernelHash: "1f2e3d4c",
	}
}

// the row counts its rounds and keeps the last one's time
func TestSteadyAttestationHoldsOneRow(t *testing.T) {
	log := NewSQLiteAttestationLog(eventsTestDB(t))
	at := time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)

	for i := 0; i < 12; i++ {
		if err := log.Record(trustedRound(at.Add(time.Duration(i) * 5 * time.Minute))); err != nil {
			t.Fatalf("record %d: %v", i, err)
		}
	}

	got := log.QueryAttestations(0)
	if len(got) != 1 {
		t.Fatalf("an hour of steady attestation is one row, got %d", len(got))
	}
	if got[0].Rounds != 12 {
		t.Errorf("the row stands for 12 rounds, says %d", got[0].Rounds)
	}
	if !got[0].Timestamp.Equal(at) {
		t.Errorf("the row opened at %v, says %v", at, got[0].Timestamp)
	}
	if want := at.Add(55 * time.Minute); !got[0].LastSeen.Equal(want) {
		t.Errorf("the last round landed at %v, says %v", want, got[0].LastSeen)
	}
}

// the trusted rounds before a refusal survive it
func TestARefusalIsWrittenImmediately(t *testing.T) {
	log := NewSQLiteAttestationLog(eventsTestDB(t))
	at := time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)

	for i := 0; i < 3; i++ {
		if err := log.Record(trustedRound(at.Add(time.Duration(i) * 5 * time.Minute))); err != nil {
			t.Fatalf("record %d: %v", i, err)
		}
	}

	refused := trustedRound(at.Add(20 * time.Minute))
	refused.Result = "pcr_fail"
	refused.Details = "PCR 7 does not match the baseline"
	if err := log.Record(refused); err != nil {
		t.Fatalf("record refusal: %v", err)
	}

	got := log.QueryAttestations(0)
	if len(got) != 2 {
		t.Fatalf("three trusted rounds and a refusal are two rows, got %d", len(got))
	}
	if got[0].Result != "pcr_fail" {
		t.Errorf("the newest row is the refusal, got %q", got[0].Result)
	}
	if got[0].Rounds != 1 {
		t.Errorf("a refusal stands for itself alone, says %d", got[0].Rounds)
	}
	if got[1].Rounds != 3 {
		t.Errorf("the trusted row stands for its 3 rounds, says %d", got[1].Rounds)
	}
}

func TestRecoveryOpensItsOwnRow(t *testing.T) {
	log := NewSQLiteAttestationLog(eventsTestDB(t))
	at := time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)

	first := trustedRound(at)
	refused := trustedRound(at.Add(5 * time.Minute))
	refused.Result = "sig_fail"
	back := trustedRound(at.Add(10 * time.Minute))

	for i, r := range []AttestationRecord{first, refused, back} {
		if err := log.Record(r); err != nil {
			t.Fatalf("record %d: %v", i, err)
		}
	}

	got := log.QueryAttestations(0)
	if len(got) != 3 {
		t.Fatalf("trusted, refused and trusted again are three rows, got %d", len(got))
	}
	if !got[0].Timestamp.Equal(back.Timestamp) {
		t.Errorf("the newest row is the recovery, opened %v", got[0].Timestamp)
	}
}

func TestSubjectsDoNotShareARow(t *testing.T) {
	log := NewSQLiteAttestationLog(eventsTestDB(t))
	at := time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)

	for i := 0; i < 4; i++ {
		a := trustedRound(at.Add(time.Duration(i) * time.Minute))
		b := trustedRound(at.Add(time.Duration(i) * time.Minute))
		b.ClientID = "c2"
		if err := log.Record(a); err != nil {
			t.Fatalf("record a%d: %v", i, err)
		}
		if err := log.Record(b); err != nil {
			t.Fatalf("record b%d: %v", i, err)
		}
	}

	got := log.QueryAttestations(0)
	if len(got) != 2 {
		t.Fatalf("two hosts attesting are two rows, got %d", len(got))
	}
}

func TestABatchCollapsesLikeSingleRecords(t *testing.T) {
	log := NewSQLiteAttestationLog(eventsTestDB(t))
	at := time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)

	batch := make([]AttestationRecord, 0, 7)
	for i := 0; i < 6; i++ {
		batch = append(batch, trustedRound(at.Add(time.Duration(i)*time.Minute)))
	}
	refused := trustedRound(at.Add(6 * time.Minute))
	refused.Result = "revoked"
	batch = append(batch, refused)

	if err := log.RecordBatch(batch); err != nil {
		t.Fatalf("batch: %v", err)
	}

	got := log.QueryAttestations(0)
	if len(got) != 2 {
		t.Fatalf("six trusted rounds and a revocation are two rows, got %d", len(got))
	}
	if got[1].Rounds != 6 {
		t.Errorf("the trusted row stands for 6 rounds, says %d", got[1].Rounds)
	}
	if got[0].Result != "revoked" {
		t.Errorf("the revocation is its own row, got %q", got[0].Result)
	}
}

// 0, 30 and 60 min share the first row; 90 opens a second, 120 joins it
func TestTheWindowClosesTheRowInTheStore(t *testing.T) {
	log := NewSQLiteAttestationLog(eventsTestDB(t))
	at := time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)

	for i := 0; i < 5; i++ {
		if err := log.Record(trustedRound(at.Add(time.Duration(i) * 30 * time.Minute))); err != nil {
			t.Fatalf("record %d: %v", i, err)
		}
	}

	got := log.QueryAttestations(0)
	if len(got) != 2 {
		t.Fatalf("two hours of half-hourly rounds under an hour-long window are two rows, got %d", len(got))
	}
	if got[1].Rounds != 3 || got[0].Rounds != 2 {
		t.Errorf("the rows stand for 3 and 2 rounds, say %d and %d", got[1].Rounds, got[0].Rounds)
	}
	if want := at.Add(90 * time.Minute); !got[0].Timestamp.Equal(want) {
		t.Errorf("the second row opened at %v, says %v", want, got[0].Timestamp)
	}
}

func TestAZeroWindowRecordsEveryRound(t *testing.T) {
	log := NewSQLiteAttestationLogWindow(eventsTestDB(t), 0)
	at := time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)

	for i := 0; i < 5; i++ {
		if err := log.Record(trustedRound(at.Add(time.Duration(i) * time.Minute))); err != nil {
			t.Fatalf("record %d: %v", i, err)
		}
	}

	got := log.QueryAttestations(0)
	if len(got) != 5 {
		t.Fatalf("a zero window writes every round, got %d rows", len(got))
	}
	for i := range got {
		if got[i].Rounds != 1 {
			t.Errorf("row %d stands for %d rounds, want 1", i, got[i].Rounds)
		}
	}
}
