// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek

//go:build pg_integration

// LOTA Verifier - Postgres and SQLite decision-log parity
//
// The collapse rule is shared; the stores can drift only in how they store
// times and compare bounds. Needs LOTA_TEST_PG_DSN.

package store

import (
	"testing"
	"time"
)

// trusted run, refusal, recovery: every shape a row can have
func parityRounds(at time.Time) []AttestationRecord {
	rounds := make([]AttestationRecord, 0, 9)
	for i := range 5 {
		rounds = append(rounds, trustedRound(at.Add(time.Duration(i)*time.Minute)))
	}
	refusal := trustedRound(at.Add(10 * time.Minute))
	refusal.Result = "integrity_mismatch"
	refusal.PCR14 = ""
	refusal.Details = "PCR 14 does not match the pinned baseline"
	rounds = append(rounds, refusal)
	for i := range 3 {
		rounds = append(rounds, trustedRound(at.Add(time.Duration(20+i)*time.Minute)))
	}
	return rounds
}

// timestamptz keeps microseconds, so rows compare at that resolution
func TestPostgresAndSQLiteAnswerTheSameQuestionTheSameWay(t *testing.T) {
	db := pgTestDB(t)
	// sub-microsecond on purpose
	at := time.Date(2026, 9, 19, 9, 0, 0, 123456789, time.UTC)

	pg := NewPostgresAttestationLogWindow(db, time.Hour)
	lite := NewSQLiteAttestationLogWindow(eventsTestDB(t), time.Hour)
	for i, r := range parityRounds(at) {
		if err := pg.Record(r); err != nil {
			t.Fatalf("postgres: record %d: %v", i, err)
		}
		if err := lite.Record(r); err != nil {
			t.Fatalf("sqlite: record %d: %v", i, err)
		}
	}

	queries := []AttestationQuery{
		{},
		{Since: at.Add(time.Minute), Until: at.Add(2 * time.Minute)},
		{Since: at.Add(4 * time.Minute), Until: at.Add(4 * time.Minute)},
		{Since: at.Add(5 * time.Minute), Until: at.Add(9 * time.Minute)},
		{Since: at.Add(9 * time.Minute), Until: at.Add(11 * time.Minute)},
		{Until: at.Add(10 * time.Minute)},
		{Since: at.Add(10 * time.Minute)},
		{EventsOnly: true},
		{Result: "ok"},
		{ClientID: "c1", Limit: 2},
		{Tenant: "alpha"},
		{Tenant: "beta"},
		{Since: at.Add(-48 * time.Hour), Until: at.Add(-24 * time.Hour)},
	}

	// Postgres keeps the input truncated to the microsecond
	whole := pg.QueryAttestations(0)
	if len(whole) == 0 {
		t.Fatal("postgres recorded nothing")
	}
	for i := range whole {
		if got := whole[i].Timestamp; !got.Equal(got.Truncate(time.Microsecond)) {
			t.Errorf("a postgres row reads %v, finer than the column holds", got)
		}
	}
	if got, want := whole[len(whole)-1].Timestamp, at.Truncate(time.Microsecond); !got.Equal(want) {
		t.Errorf("the row opened at %v, want the round's own instant %v", got, want)
	}

	for _, q := range queries {
		want := lite.QueryAttestationsFiltered(q)
		got := pg.QueryAttestationsFiltered(q)
		if len(got) != len(want) {
			t.Errorf("%+v: postgres returned %d rows, sqlite returned %d", q, len(got), len(want))
			continue
		}
		for i := range got {
			assertSameAttestation(t,
				"sqlite", truncateAttestationTimes(want[i]),
				"postgres", truncateAttestationTimes(got[i]))
		}
	}
}

// the resolution both stores keep
func truncateAttestationTimes(r AttestationRecord) AttestationRecord {
	r.Timestamp = r.Timestamp.Truncate(time.Microsecond)
	r.LastSeen = r.LastSeen.Truncate(time.Microsecond)
	return r
}

// a round stamped east of UTC reads back as the same instant and is
// covered by a window named in another zone
func TestPostgresHoldsTheInstantNotTheClockReading(t *testing.T) {
	db := pgTestDB(t)
	log := NewPostgresAttestationLogWindow(db, time.Hour)

	east := time.FixedZone("UTC+9", 9*60*60)
	at := time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)
	if err := log.Record(trustedRound(at.In(east))); err != nil {
		t.Fatalf("record: %v", err)
	}

	west := time.FixedZone("UTC-6", -6*60*60)
	got := log.QueryAttestationsFiltered(AttestationQuery{
		Since: at.Add(-time.Minute).In(west),
		Until: at.Add(time.Minute).In(west),
	})
	if len(got) != 1 {
		t.Fatalf("a window around the round returned %d rows, want 1", len(got))
	}
	if !got[0].Timestamp.Equal(at) {
		t.Errorf("the row reads %v, and the round was served at %v", got[0].Timestamp, at)
	}

	before := log.QueryAttestationsFiltered(AttestationQuery{
		Since: at.Add(-2 * time.Hour),
		Until: at.Add(-time.Hour),
	})
	if len(before) != 0 {
		t.Errorf("a window ending an hour before the round returned %d rows, want none", len(before))
	}
}

// refusals to fold, driven through the Postgres store
func TestPostgresWritesWhatItMayNotFold(t *testing.T) {
	at := time.Date(2026, 9, 19, 14, 0, 0, 0, time.UTC)

	cases := []struct {
		what   string
		change func(*AttestationRecord)
	}{
		{"a PCR 14 that moved", func(r *AttestationRecord) { r.PCR14 = "0badc0de" }},
		{"a kernel that changed", func(r *AttestationRecord) { r.KernelHash = "99887766" }},
		{"other hardware", func(r *AttestationRecord) { r.HardwareID = "bb22" }},
		{"another tenant", func(r *AttestationRecord) { r.Tenant = "beta" }},
		{"a detail on a trusted round", func(r *AttestationRecord) { r.Details = "certificate expires in 3 days" }},
		{"a refusal", func(r *AttestationRecord) { r.Result = "integrity_mismatch" }},
		{"a round behind the row", func(r *AttestationRecord) { r.Timestamp = at.Add(-time.Minute) }},
	}

	for _, c := range cases {
		t.Run(c.what, func(t *testing.T) {
			db := pgTestDB(t)
			log := NewPostgresAttestationLogWindow(db, time.Hour)

			for i := range 3 {
				if err := log.Record(trustedRound(at.Add(time.Duration(i) * time.Minute))); err != nil {
					t.Fatalf("record %d: %v", i, err)
				}
			}

			next := trustedRound(at.Add(3 * time.Minute))
			c.change(&next)
			if err := log.Record(next); err != nil {
				t.Fatalf("record the changed round: %v", err)
			}

			got := log.QueryAttestations(0)
			if len(got) != 2 {
				t.Fatalf("%s left %d rows, want 2", c.what, len(got))
			}
			standing := got[1]
			if standing.Rounds != 3 {
				t.Errorf("the row that stood before it counts %d rounds, want 3", standing.Rounds)
			}
		})
	}
}
