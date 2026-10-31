// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek

package store

import (
	"fmt"
	"testing"
	"time"
)

// one backend holding the fixture rounds
type windowBackend struct {
	name string
	log  interface {
		AttestationLog
		AttestationQuerier
	}
}

// standing row, one refusal, recovery; recorded into every backend
func windowFixture(t *testing.T, at time.Time) []windowBackend {
	t.Helper()

	rounds := make([]AttestationRecord, 0, 8)
	for i := 0; i < 5; i++ {
		rounds = append(rounds, trustedRound(at.Add(time.Duration(i)*time.Minute)))
	}
	refusal := trustedRound(at.Add(10 * time.Minute))
	refusal.Result = "integrity_mismatch"
	refusal.PCR14 = ""
	rounds = append(rounds, refusal)
	for i := 0; i < 3; i++ {
		rounds = append(rounds, trustedRound(at.Add(time.Duration(20+i)*time.Minute)))
	}

	backends := []windowBackend{
		{"memory", NewMemoryAttestationLogWindow(time.Hour)},
		{"sqlite", NewSQLiteAttestationLogWindow(eventsTestDB(t), time.Hour)},
	}
	for _, b := range backends {
		for i, r := range rounds {
			if err := b.log.Record(r); err != nil {
				t.Fatalf("%s: record %d: %v", b.name, i, err)
			}
		}
	}
	return backends
}

// a row's edges are inside the window; a nanosecond past either is not
func TestWindowEdgesAreInclusive(t *testing.T) {
	at := time.Date(2026, 9, 19, 9, 0, 0, 0, time.UTC)
	// rows: standing +0..+4m, refusal +10m, recovery +20..+22m
	standingOpen, standingLast := at, at.Add(4*time.Minute)

	cases := []struct {
		what  string
		q     AttestationQuery
		count int
	}{
		{
			"a window starting exactly at the standing row's last sighting",
			AttestationQuery{Since: standingLast, Until: standingLast},
			1,
		},
		{
			"a window starting a nanosecond after it",
			AttestationQuery{
				Since: standingLast.Add(time.Nanosecond),
				Until: standingLast.Add(time.Minute),
			},
			0,
		},
		{
			"a window ending exactly when the standing row opened",
			AttestationQuery{Since: at.Add(-time.Hour), Until: standingOpen},
			1,
		},
		{
			"a window ending a nanosecond before it opened",
			AttestationQuery{
				Since: at.Add(-time.Hour),
				Until: standingOpen.Add(-time.Nanosecond),
			},
			0,
		},
		{
			"a window wholly inside the standing row",
			AttestationQuery{Since: at.Add(time.Minute), Until: at.Add(2 * time.Minute)},
			1,
		},
		{
			"a window between the standing row and the refusal",
			AttestationQuery{Since: at.Add(5 * time.Minute), Until: at.Add(9 * time.Minute)},
			0,
		},
		{
			"a window over the refusal alone",
			AttestationQuery{Since: at.Add(9 * time.Minute), Until: at.Add(11 * time.Minute)},
			1,
		},
		{
			"a window over everything",
			AttestationQuery{Since: at.Add(-time.Hour), Until: at.Add(time.Hour)},
			3,
		},
		{
			"an open-ended window from the refusal on",
			AttestationQuery{Since: at.Add(10 * time.Minute)},
			2,
		},
		{
			"an open-ended window up to the refusal",
			AttestationQuery{Until: at.Add(10 * time.Minute)},
			2,
		},
	}

	for _, b := range windowFixture(t, at) {
		for _, c := range cases {
			t.Run(fmt.Sprintf("%s/%s", b.name, c.what), func(t *testing.T) {
				got := b.log.QueryAttestationsFiltered(c.q)
				if len(got) != c.count {
					t.Errorf("%d rows, want %d", len(got), c.count)
					for i := range got {
						t.Logf("  %v..%v %s rounds=%d",
							got[i].Timestamp, got[i].LastSeen, got[i].Result, got[i].Rounds)
					}
				}
			})
		}
	}
}

// a named verdict wins over events-only; an unknown subject reads empty
func TestNarrowedReadsAnswerWhatWasAsked(t *testing.T) {
	at := time.Date(2026, 9, 19, 9, 0, 0, 0, time.UTC)

	cases := []struct {
		what  string
		q     AttestationQuery
		count int
	}{
		{"events only", AttestationQuery{EventsOnly: true}, 1},
		{"one verdict by name", AttestationQuery{Result: "integrity_mismatch"}, 1},
		{
			"a verdict that is trusted, with events only also asked",
			AttestationQuery{Result: "ok", EventsOnly: true},
			2,
		},
		{"the host that attested here", AttestationQuery{ClientID: "c1"}, 3},
		{"a host that never did", AttestationQuery{ClientID: "c9"}, 0},
		{"the tenant that owns it", AttestationQuery{Tenant: "alpha"}, 3},
		{"another tenant", AttestationQuery{Tenant: "beta"}, 0},
		{"a limit below what is there", AttestationQuery{Limit: 2}, 2},
		{"events only, in a window that has none", AttestationQuery{
			Since: at.Add(20 * time.Minute), EventsOnly: true,
		}, 0},
	}

	for _, b := range windowFixture(t, at) {
		for _, c := range cases {
			t.Run(fmt.Sprintf("%s/%s", b.name, c.what), func(t *testing.T) {
				got := b.log.QueryAttestationsFiltered(c.q)
				if len(got) != c.count {
					t.Errorf("%d rows, want %d", len(got), c.count)
				}
			})
		}
	}
}

// same rounds, same query: rows match field for field across backends
func TestBackendsAnswerTheSameQuestionTheSameWay(t *testing.T) {
	at := time.Date(2026, 9, 19, 9, 0, 0, 0, time.UTC)
	backends := windowFixture(t, at)

	queries := []AttestationQuery{
		{},
		{Since: at.Add(time.Minute), Until: at.Add(2 * time.Minute)},
		{Since: at.Add(9 * time.Minute), Until: at.Add(21 * time.Minute)},
		{EventsOnly: true},
		{Result: "ok"},
		{ClientID: "c1", Limit: 2},
		{Tenant: "alpha", Since: at.Add(-time.Hour)},
	}

	for _, q := range queries {
		want := backends[0].log.QueryAttestationsFiltered(q)
		for _, b := range backends[1:] {
			got := b.log.QueryAttestationsFiltered(q)
			if len(got) != len(want) {
				t.Errorf("%+v: %s returned %d rows, %s returned %d",
					q, b.name, len(got), backends[0].name, len(want))
				continue
			}
			for i := range got {
				assertSameAttestation(t, backends[0].name, want[i], b.name, got[i])
			}
		}
	}
}

// reader-visible fields; the row id is the backend's own
func assertSameAttestation(t *testing.T, wantName string, want AttestationRecord, gotName string, got AttestationRecord) {
	t.Helper()

	if !want.Timestamp.Equal(got.Timestamp) || !want.LastSeen.Equal(got.LastSeen) {
		t.Errorf("%s says %v..%v, %s says %v..%v",
			wantName, want.Timestamp, want.LastSeen, gotName, got.Timestamp, got.LastSeen)
	}
	if want.Rounds != got.Rounds {
		t.Errorf("%s counts %d rounds, %s counts %d", wantName, want.Rounds, gotName, got.Rounds)
	}
	if want.Result != got.Result || want.ClientID != got.ClientID ||
		want.Tenant != got.Tenant || want.HardwareID != got.HardwareID ||
		want.PCR14 != got.PCR14 || want.KernelHash != got.KernelHash ||
		want.Details != got.Details {
		t.Errorf("%s says %+v, %s says %+v", wantName, want, gotName, got)
	}
}
