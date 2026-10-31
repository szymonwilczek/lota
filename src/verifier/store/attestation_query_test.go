// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
// LOTA Verifier - reading the decision log by what is being asked

package store

import (
	"testing"
	"time"
)

// c1 trusted 08:00-11:30, refused at 12:00; c2 trusted at 14:00
func populatedLog(t *testing.T) (*SQLiteAttestationLog, time.Time) {
	t.Helper()

	log := NewSQLiteAttestationLog(eventsTestDB(t))
	at := time.Date(2026, 9, 19, 8, 0, 0, 0, time.UTC)

	for i := 0; i < 8; i++ {
		r := trustedRound(at.Add(time.Duration(i) * 30 * time.Minute))
		if err := log.Record(r); err != nil {
			t.Fatalf("record %d: %v", i, err)
		}
	}

	refused := trustedRound(at.Add(4 * time.Hour))
	refused.Result = "pcr_fail"
	refused.Details = "PCR 7 does not match the baseline"
	if err := log.Record(refused); err != nil {
		t.Fatalf("record refusal: %v", err)
	}

	other := trustedRound(at.Add(6 * time.Hour))
	other.ClientID = "c2"
	if err := log.Record(other); err != nil {
		t.Fatalf("record other: %v", err)
	}
	return log, at
}

// a row opened before the window but overlapping it is returned
func TestAWindowReturnsTheRowsThatOverlapIt(t *testing.T) {
	log, at := populatedLog(t)

	got := log.QueryAttestationsFiltered(AttestationQuery{
		Since: at.Add(30 * time.Minute),
		Until: at.Add(90 * time.Minute),
	})
	if len(got) == 0 {
		t.Fatal("a window a host was attesting through returns the row standing for it")
	}
	for _, r := range got {
		if r.LastSeen.Before(at.Add(30*time.Minute)) || r.Timestamp.After(at.Add(90*time.Minute)) {
			t.Errorf("row %d does not overlap the window: %v..%v", r.ID, r.Timestamp, r.LastSeen)
		}
	}
}

// empty, not the newest rows
func TestAWindowBeforeAnythingIsEmpty(t *testing.T) {
	log, at := populatedLog(t)

	got := log.QueryAttestationsFiltered(AttestationQuery{
		Since: at.Add(-48 * time.Hour),
		Until: at.Add(-24 * time.Hour),
	})
	if len(got) != 0 {
		t.Fatalf("nothing was recorded in that window, got %d rows", len(got))
	}
}

func TestAResultFilterNarrowsToThatVerdict(t *testing.T) {
	log, _ := populatedLog(t)

	got := log.QueryAttestationsFiltered(AttestationQuery{Result: "pcr_fail"})
	if len(got) != 1 {
		t.Fatalf("one refusal was recorded, got %d", len(got))
	}
	if got[0].Result != "pcr_fail" {
		t.Errorf("got %q", got[0].Result)
	}
}

func TestEventsOnlyLeavesTheTrustedRoundsOut(t *testing.T) {
	log, _ := populatedLog(t)

	got := log.QueryAttestationsFiltered(AttestationQuery{EventsOnly: true})
	if len(got) != 1 {
		t.Fatalf("one round was not trusted, got %d", len(got))
	}
	if got[0].Result == "ok" {
		t.Error("a trusted round is not an event")
	}
}

func TestAClientFilterNarrowsToThatHost(t *testing.T) {
	log, _ := populatedLog(t)

	got := log.QueryAttestationsFiltered(AttestationQuery{ClientID: "c2"})
	if len(got) != 1 {
		t.Fatalf("the second host has one row, got %d", len(got))
	}
	if got[0].ClientID != "c2" {
		t.Errorf("got %q", got[0].ClientID)
	}
}

func TestTheFilteredReadIsStillBoundedAndNewestFirst(t *testing.T) {
	log, _ := populatedLog(t)

	got := log.QueryAttestationsFiltered(AttestationQuery{Limit: 2})
	if len(got) != 2 {
		t.Fatalf("a limit of 2 returns 2, got %d", len(got))
	}
	if got[0].ID < got[1].ID {
		t.Error("newest first")
	}
}

// same answer as the unfiltered read
func TestAnEmptyQueryReadsTheWholeLog(t *testing.T) {
	log, _ := populatedLog(t)

	plain := log.QueryAttestations(0)
	filtered := log.QueryAttestationsFiltered(AttestationQuery{})
	if len(plain) != len(filtered) {
		t.Fatalf("the two reads disagree: %d and %d rows", len(plain), len(filtered))
	}
}

// the batched writer must not hide the backend's capability
func TestTheBatchedWriterForwardsAFilteredRead(t *testing.T) {
	backend := NewSQLiteAttestationLog(eventsTestDB(t))
	bl := NewBatchedAttestationLog(backend, BatchedAttestationLogConfig{})
	defer bl.Close()

	at := time.Date(2026, 9, 19, 8, 0, 0, 0, time.UTC)
	refused := trustedRound(at)
	refused.Result = "banned"
	if err := bl.Record(refused); err != nil {
		t.Fatalf("record: %v", err)
	}
	if err := bl.Record(trustedRound(at.Add(time.Minute))); err != nil {
		t.Fatalf("record: %v", err)
	}
	bl.Flush()

	q, ok := any(bl).(AttestationQuerier)
	if !ok {
		t.Fatal("the batched writer has to offer the narrowed read its backend offers")
	}
	got := q.QueryAttestationsFiltered(AttestationQuery{EventsOnly: true})
	if len(got) != 1 || got[0].Result != "banned" {
		t.Fatalf("the filter did not reach the backend: %+v", got)
	}
}
