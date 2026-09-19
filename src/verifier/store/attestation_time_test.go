// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek

package store

import (
	"testing"
	"time"
)

// a window matches instants, whatever zone wrote the row or asks
func TestAttestationWindowIsAnInstantNotAClockReading(t *testing.T) {
	log := NewSQLiteAttestationLog(eventsTestDB(t))

	// one instant, stamped in UTC+5, asked in UTC
	east := time.FixedZone("UTC+5", 5*60*60)
	at := time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)

	if err := log.Record(trustedRound(at.In(east))); err != nil {
		t.Fatalf("record: %v", err)
	}

	got := log.QueryAttestationsFiltered(AttestationQuery{
		Since: at.Add(-time.Minute),
		Until: at.Add(time.Minute),
	})
	if len(got) != 1 {
		t.Fatalf("a window around the round the log holds returned %d rows, want 1", len(got))
	}
	if !got[0].Timestamp.Equal(at) {
		t.Errorf("the row reads %v, and the round was served at %v", got[0].Timestamp, at)
	}

	before := log.QueryAttestationsFiltered(AttestationQuery{
		Since: at.Add(-2 * time.Hour),
		Until: at.Add(-time.Hour),
	})
	if len(before) != 0 {
		t.Fatalf("a window ending an hour before the round returned %d rows, want none", len(before))
	}
}

// a window inside a row's span returns it
func TestAttestationWindowInsideAStandingRowReturnsIt(t *testing.T) {
	log := NewSQLiteAttestationLog(eventsTestDB(t))

	west := time.FixedZone("UTC-7", -7*60*60)
	at := time.Date(2026, 9, 19, 8, 0, 0, 0, time.UTC)

	for i := 0; i < 6; i++ {
		round := trustedRound(at.Add(time.Duration(i) * 5 * time.Minute).In(west))
		if err := log.Record(round); err != nil {
			t.Fatalf("record %d: %v", i, err)
		}
	}

	got := log.QueryAttestationsFiltered(AttestationQuery{
		Since: at.Add(10 * time.Minute),
		Until: at.Add(15 * time.Minute),
	})
	if len(got) != 1 {
		t.Fatalf("a window inside the standing row returned %d rows, want 1", len(got))
	}
	if got[0].Rounds != 6 {
		t.Errorf("the row stands for %d rounds, want 6", got[0].Rounds)
	}
}

// a round stamped east of UTC reads back as the same instant and still folds
func TestAttestationRowReadsBackAsTheInstantItHappened(t *testing.T) {
	log := NewSQLiteAttestationLog(eventsTestDB(t))

	east := time.FixedZone("UTC+2", 2*60*60)
	at := time.Date(2026, 9, 19, 6, 0, 0, 0, time.UTC)

	for i := 0; i < 3; i++ {
		round := trustedRound(at.Add(time.Duration(i) * time.Minute).In(east))
		if err := log.Record(round); err != nil {
			t.Fatalf("record %d: %v", i, err)
		}
	}

	got := log.QueryAttestations(0)
	if len(got) != 1 {
		t.Fatalf("three identical rounds are one row, got %d", len(got))
	}
	if !got[0].Timestamp.Equal(at) {
		t.Errorf("the row opened at %v, says %v", at, got[0].Timestamp)
	}
	if want := at.Add(2 * time.Minute); !got[0].LastSeen.Equal(want) {
		t.Errorf("the last round landed at %v, says %v", want, got[0].LastSeen)
	}
}
