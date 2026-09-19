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

func TestRefusalNeverCollapses(t *testing.T) {
	at := time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)
	standing := standingOK(at)

	for _, result := range []string{"nonce_fail", "sig_fail", "pcr_fail", "integrity_mismatch", "revoked", "banned", "parse_error"} {
		next := standingOK(at.Add(time.Minute))
		next.Result = result
		if attestationCollapses(standing, next, time.Hour) {
			t.Fatalf("%s is an event and must have its own row", result)
		}
	}
}

func TestRecoveryAfterARefusalIsItsOwnRow(t *testing.T) {
	at := time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)
	standing := standingOK(at)
	standing.Result = "pcr_fail"
	next := standingOK(at.Add(time.Minute))

	if attestationCollapses(standing, next, time.Hour) {
		t.Fatal("a verdict change back to trusted has to be recorded")
	}
}

func TestChangedEvidenceIsNotTheSameRound(t *testing.T) {
	at := time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)

	for _, tc := range []struct {
		what string
		edit func(*AttestationRecord)
	}{
		{"pcr14", func(r *AttestationRecord) { r.PCR14 = "ffffffff" }},
		{"kernel hash", func(r *AttestationRecord) { r.KernelHash = "aaaaaa" }},
		{"hardware id", func(r *AttestationRecord) { r.HardwareID = "bb22" }},
		{"detail", func(r *AttestationRecord) { r.Details = "re-anchored" }},
	} {
		standing := standingOK(at)
		next := standingOK(at.Add(time.Minute))
		tc.edit(&next)
		if attestationCollapses(standing, next, time.Hour) {
			t.Fatalf("a changed %s is a new row", tc.what)
		}
	}
}

// another publisher, or another host of the same one
func TestAnotherSubjectNeverCollapses(t *testing.T) {
	at := time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)

	standing := standingOK(at)
	other := standingOK(at.Add(time.Minute))
	other.ClientID = "client-2"
	if attestationCollapses(standing, other, time.Hour) {
		t.Fatal("a different client is a different row")
	}

	otherTenant := standingOK(at.Add(time.Minute))
	otherTenant.Tenant = "globex"
	if attestationCollapses(standing, otherTenant, time.Hour) {
		t.Fatal("a different tenant is a different row")
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

func TestAZeroWindowCollapsesNothing(t *testing.T) {
	at := time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)
	standing := standingOK(at)
	next := standingOK(at.Add(time.Second))

	if attestationCollapses(standing, next, 0) {
		t.Fatal("a zero window records every round")
	}
}

// an out-of-order batch would move last_seen backwards
func TestARoundOlderThanTheStandingRowDoesNotExtendIt(t *testing.T) {
	at := time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)
	standing := standingOK(at)
	standing.LastSeen = at.Add(10 * time.Minute)

	next := standingOK(at.Add(5 * time.Minute))
	if attestationCollapses(standing, next, time.Hour) {
		t.Fatal("a round older than the row's last sighting does not extend it")
	}
}

func TestTheFirstSightingIsAnEvent(t *testing.T) {
	at := time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)

	if attestationCollapses(AttestationRecord{}, standingOK(at), time.Hour) {
		t.Fatal("a client with no standing row is arriving, which is an event")
	}
}
