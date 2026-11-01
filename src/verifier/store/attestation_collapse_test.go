// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek

package store

import (
	"testing"
	"time"
)

// trusted round, host unchanged
func standingOK(at time.Time) AttestationRecord {
	return AttestationRecord{
		Timestamp:  at,
		LastSeen:   at,
		Rounds:     1,
		Tenant:     "acme",
		ClientID:   "client-1",
		HardwareID: "aa11",
		Result:     "ok",
		PCR14:      "e9e239c2",
		KernelHash: "5f5f5f",
	}
}

func TestIdenticalTrustedRoundExtendsTheStandingRow(t *testing.T) {
	at := time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)
	standing := standingOK(at)
	next := standingOK(at.Add(5 * time.Minute))

	if !attestationCollapses(standing, next, time.Hour) {
		t.Fatal("a trusted round identical to the standing row has to extend it")
	}
}

// per-day retention still keeps per-day evidence
func TestTheWindowClosesAStandingRow(t *testing.T) {
	at := time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)
	standing := standingOK(at)

	inside := standingOK(at.Add(59 * time.Minute))
	if !attestationCollapses(standing, inside, time.Hour) {
		t.Fatal("a round inside the window extends the standing row")
	}

	outside := standingOK(at.Add(time.Hour + time.Second))
	if attestationCollapses(standing, outside, time.Hour) {
		t.Fatal("a round past the window opens a new one")
	}
}

// else a host that never stops attesting holds one row forever
func TestTheWindowRunsFromWhenTheRowOpened(t *testing.T) {
	at := time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)
	standing := standingOK(at)
	standing.LastSeen = at.Add(55 * time.Minute)
	standing.Rounds = 11

	next := standingOK(at.Add(time.Hour + time.Minute))
	if attestationCollapses(standing, next, time.Hour) {
		t.Fatal("the window is spent an hour after the row opened, whatever it absorbed since")
	}
}

func TestTheFirstSightingIsAnEvent(t *testing.T) {
	at := time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)

	if attestationCollapses(AttestationRecord{}, standingOK(at), time.Hour) {
		t.Fatal("a client with no standing row is arriving, which is an event")
	}
}
