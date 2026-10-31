// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek

package store

import (
	"testing"
	"time"

	// zone rules ship with the test, not the host
	_ "time/tzdata"
)

// A verifier clock falling back an hour: rounds still extend one row.
// Stored clock readings would make a later round look older and two rounds
// an hour apart look simultaneous.
func TestTheHourAClockRepeatsIsStillAnHour(t *testing.T) {
	warsaw, err := time.LoadLocation("Europe/Warsaw")
	if err != nil {
		t.Fatalf("load the verifier host's zone: %v", err)
	}

	// 01:00 UTC: Warsaw falls back from 03:00 CEST to 02:00 CET
	change := time.Date(2026, 10, 25, 0, 30, 0, 0, time.UTC)
	log := NewSQLiteAttestationLogWindow(eventsTestDB(t), 2*time.Hour)

	const rounds = 5
	for i := range rounds {
		at := change.Add(time.Duration(i) * 15 * time.Minute)
		if err := log.Record(trustedRound(at.In(warsaw))); err != nil {
			t.Fatalf("record %d: %v", i, err)
		}
	}

	// local readings, for the failure message
	first := change.In(warsaw).Format("15:04 MST")
	last := change.Add((rounds - 1) * 15 * time.Minute).In(warsaw).Format("15:04 MST")
	t.Logf("the verifier's clock read %s for the first round and %s for the last", first, last)

	got := log.QueryAttestations(0)
	if len(got) != 1 {
		t.Fatalf("a host attesting across the change left %d rows, want 1", len(got))
	}
	if got[0].Rounds != rounds {
		t.Errorf("the row stands for %d rounds, want %d", got[0].Rounds, rounds)
	}
	if want := change.Add((rounds - 1) * 15 * time.Minute); !got[0].LastSeen.Equal(want) {
		t.Errorf("the row's last sighting is %v, want %v", got[0].LastSeen, want)
	}

	// the repeated hour still reads as an hour
	window := log.QueryAttestationsFiltered(AttestationQuery{
		Since: change.Add(30 * time.Minute),
		Until: change.Add(45 * time.Minute),
	})
	if len(window) != 1 {
		t.Errorf("a window inside the repeated hour returned %d rows, want 1", len(window))
	}
}
