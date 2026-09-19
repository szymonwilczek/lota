// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek

package store

import (
	"testing"
	"time"
)

// rounds that arrive while a row is open yet must get their own row
func TestCollapseRefusesWhatItMayNotFold(t *testing.T) {
	at := time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)
	standing := trustedRound(at)
	standing.Rounds = 4
	standing.LastSeen = at.Add(2 * time.Minute)

	next := func(f func(*AttestationRecord)) AttestationRecord {
		r := trustedRound(at.Add(3 * time.Minute))
		f(&r)
		return r
	}

	cases := []struct {
		what  string
		round AttestationRecord
	}{
		{
			"a PCR 14 that moved under a trusted verdict",
			next(func(r *AttestationRecord) { r.PCR14 = "0badc0de" }),
		},
		{
			"a kernel hash that changed under an advisory pin",
			next(func(r *AttestationRecord) { r.KernelHash = "99887766" }),
		},
		{
			"the same client identity on different hardware",
			next(func(r *AttestationRecord) { r.HardwareID = "bb22" }),
		},
		{
			"the same client identifier under another tenant",
			next(func(r *AttestationRecord) { r.Tenant = "beta" }),
		},
		{
			"another host entirely",
			next(func(r *AttestationRecord) { r.ClientID = "c2" }),
		},
		{
			"a trusted round the verifier attached a detail to",
			next(func(r *AttestationRecord) { r.Details = "certificate expires in 3 days" }),
		},
		{
			"a refusal",
			next(func(r *AttestationRecord) { r.Result = "integrity_mismatch" }),
		},
		{
			"a round older than the row's last sighting",
			next(func(r *AttestationRecord) { r.Timestamp = at.Add(time.Minute) }),
		},
		{
			"a round past the window the row opened under",
			next(func(r *AttestationRecord) { r.Timestamp = at.Add(2 * time.Hour) }),
		},
	}

	for _, c := range cases {
		t.Run(c.what, func(t *testing.T) {
			if attestationCollapses(standing, c.round, time.Hour) {
				t.Errorf("a row stood for %s", c.what)
			}
		})
	}
}

// recovery opens a new row; nothing folds into a refusal
func TestCollapseRefusesEitherHalfOfAVerdictChange(t *testing.T) {
	at := time.Date(2026, 9, 19, 11, 0, 0, 0, time.UTC)

	refused := trustedRound(at)
	refused.Result = "integrity_mismatch"
	refused.Rounds = 1
	refused.LastSeen = at

	recovery := trustedRound(at.Add(time.Minute))
	if attestationCollapses(refused, recovery, time.Hour) {
		t.Error("a recovery folded into the refusal above it")
	}

	trusted := trustedRound(at)
	trusted.Rounds = 3
	trusted.LastSeen = at.Add(time.Minute)

	again := trustedRound(at.Add(2 * time.Minute))
	again.Result = "integrity_mismatch"
	if attestationCollapses(trusted, again, time.Hour) {
		t.Error("a refusal folded into the trusted row above it")
	}
}

// interleaved rounds of two hosts keep two rows and two counts
func TestTwoHostsDoNotShareARow(t *testing.T) {
	log := NewSQLiteAttestationLog(eventsTestDB(t))
	at := time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)

	for i := 0; i < 5; i++ {
		first := trustedRound(at.Add(time.Duration(i) * time.Minute))
		second := trustedRound(at.Add(time.Duration(i)*time.Minute + 30*time.Second))
		second.ClientID = "c2"
		second.HardwareID = "bb22"
		if err := log.Record(first); err != nil {
			t.Fatalf("record c1 %d: %v", i, err)
		}
		if err := log.Record(second); err != nil {
			t.Fatalf("record c2 %d: %v", i, err)
		}
	}

	got := log.QueryAttestations(0)
	if len(got) != 2 {
		t.Fatalf("two hosts are two rows, got %d", len(got))
	}
	for i := range got {
		if got[i].Rounds != 5 {
			t.Errorf("%s stands for %d rounds, want 5", got[i].ClientID, got[i].Rounds)
		}
	}
}

// a round behind the last sighting (reordered, or clock stepped back) gets
// its own row, so the anomaly shows instead of hiding in a count
func TestARoundOlderThanTheRowIsWrittenNotFolded(t *testing.T) {
	log := NewSQLiteAttestationLog(eventsTestDB(t))
	at := time.Date(2026, 9, 19, 13, 0, 0, 0, time.UTC)

	for i := 0; i < 4; i++ {
		if err := log.Record(trustedRound(at.Add(time.Duration(i) * time.Minute))); err != nil {
			t.Fatalf("record %d: %v", i, err)
		}
	}
	// behind the last sighting, at +3m
	stepped := trustedRound(at.Add(90 * time.Second))
	if err := log.Record(stepped); err != nil {
		t.Fatalf("record stepped: %v", err)
	}

	// newest first: the stepped round
	got := log.QueryAttestations(0)
	if len(got) != 2 {
		t.Fatalf("a round behind the row's last sighting is its own row, got %d rows", len(got))
	}
	if want := at.Add(3 * time.Minute); !got[1].LastSeen.Equal(want) {
		t.Errorf("the standing row's last sighting moved to %v, want %v", got[1].LastSeen, want)
	}
	if got[1].Rounds != 4 {
		t.Errorf("the standing row stands for %d rounds, want 4", got[1].Rounds)
	}
	if !got[0].Timestamp.Equal(stepped.Timestamp) {
		t.Errorf("the stepped round reads %v, want %v", got[0].Timestamp, stepped.Timestamp)
	}
	if got[0].Rounds != 1 {
		t.Errorf("the stepped round stands for %d rounds, want 1", got[0].Rounds)
	}
}

// window runs from the row's opening; its edge is inside, one past is not
func TestTheWindowsOwnEdge(t *testing.T) {
	at := time.Date(2026, 9, 19, 14, 0, 0, 0, time.UTC)
	standing := trustedRound(at)
	standing.Rounds = 2
	standing.LastSeen = at.Add(time.Minute)

	onTheEdge := trustedRound(at.Add(time.Hour))
	if !attestationCollapses(standing, onTheEdge, time.Hour) {
		t.Error("the round landing exactly on the window's edge opened a new row")
	}

	pastIt := trustedRound(at.Add(time.Hour + time.Nanosecond))
	if attestationCollapses(standing, pastIt, time.Hour) {
		t.Error("a round past the window extended the row")
	}
}

// a round equal to the last sighting is not behind it: it folds
func TestARoundOnTheLastSightingFolds(t *testing.T) {
	at := time.Date(2026, 9, 19, 15, 0, 0, 0, time.UTC)
	standing := trustedRound(at)
	standing.Rounds = 2
	standing.LastSeen = at.Add(time.Minute)

	if !attestationCollapses(standing, trustedRound(at.Add(time.Minute)), time.Hour) {
		t.Error("a round on the row's last sighting was not folded")
	}
}
