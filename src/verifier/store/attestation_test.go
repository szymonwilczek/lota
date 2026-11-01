// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek

package store

import (
	"bytes"
	"database/sql"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	// zone rules ship with the test, not the host
	_ "time/tzdata"
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

// loss counts by kind
type kindLossSpy struct {
	records atomic.Int64
	events  atomic.Int64
	failed  atomic.Int64
}

func (s *kindLossSpy) AttestationRecordsDropped(n int64) { s.records.Add(n) }
func (s *kindLossSpy) AttestationEventsLost(n int64)     { s.events.Add(n) }
func (s *kindLossSpy) AttestationRecordsFailed(n int64)  { s.failed.Add(n) }

// stalled backend, flood of trusted rounds: heartbeats shed, no event lost
func TestSheddingHeartbeatsLosesNoEvents(t *testing.T) {
	backend := &blockingLog{entered: make(chan struct{}), release: make(chan struct{})}
	loss := &kindLossSpy{}
	cfg := BatchedAttestationLogConfig{
		MaxBatch:      8,
		MaxBuffer:     16,
		FlushInterval: time.Hour,
		Loss:          loss,
	}
	bl := NewBatchedAttestationLog(backend, cfg)

	for range cfg.MaxBatch {
		if err := bl.Record(AttestationRecord{Result: "ok", ClientID: "c1"}); err != nil {
			t.Fatalf("Record: %v", err)
		}
	}
	<-backend.entered

	for range cfg.MaxBuffer * 4 {
		_ = bl.Record(AttestationRecord{Result: "ok", ClientID: "c1"})
	}

	close(backend.release)
	bl.Close()

	if loss.records.Load() == 0 {
		t.Fatal("a flood past the buffer bound dropped nothing")
	}
	if got := loss.events.Load(); got != 0 {
		t.Errorf("shedding trusted rounds reported %d lost events, want none", got)
	}
}

// with no heartbeats left, events go too, counted on their own
func TestSheddingEventsIsCountedApart(t *testing.T) {
	backend := &blockingLog{entered: make(chan struct{}), release: make(chan struct{})}
	loss := &kindLossSpy{}
	cfg := BatchedAttestationLogConfig{
		MaxBatch:      8,
		MaxBuffer:     16,
		FlushInterval: time.Hour,
		Loss:          loss,
	}
	bl := NewBatchedAttestationLog(backend, cfg)

	for range cfg.MaxBatch {
		if err := bl.Record(AttestationRecord{Result: "ok", ClientID: "c1"}); err != nil {
			t.Fatalf("Record: %v", err)
		}
	}
	<-backend.entered

	// refusals only: nothing left to shed but events
	for range cfg.MaxBuffer * 4 {
		_ = bl.Record(AttestationRecord{Result: "integrity_mismatch", ClientID: "c1"})
	}

	close(backend.release)
	bl.Close()

	dropped, events := loss.records.Load(), loss.events.Load()
	if dropped == 0 {
		t.Fatal("a flood of refusals past the buffer bound dropped nothing")
	}
	if events == 0 {
		t.Fatalf("%d records were dropped and every one of them was an event, "+
			"but the deployment was told of no lost events", dropped)
	}
	if events > dropped {
		t.Errorf("%d lost events out of %d dropped records", events, dropped)
	}
}

// @n rounds, every fourth a refusal
func mixedBuffer(n int) []AttestationRecord {
	buf := make([]AttestationRecord, 0, n)
	at := time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)
	for i := 0; i < n; i++ {
		r := AttestationRecord{
			Timestamp: at.Add(time.Duration(i) * time.Second),
			ClientID:  "c1",
			Result:    "ok",
		}
		if i%4 == 3 {
			r.Result = "pcr_fail"
		}
		buf = append(buf, r)
	}
	return buf
}

// heartbeats go first; a refusal is what the log is read for
func TestSheddingTakesHeartbeatsFirst(t *testing.T) {
	buf := mixedBuffer(40) // 30 trusted, 10 refusals
	kept, _ := shedOldest(buf, 12)

	if len(kept) != 28 {
		t.Fatalf("shedding 12 of 40 leaves 28, got %d", len(kept))
	}
	events := 0
	for _, r := range kept {
		if r.Result != "ok" {
			events++
		}
	}
	if events != 10 {
		t.Errorf("all 10 refusals survive a shed that had trusted rounds to take, got %d", events)
	}
}

// oldest heartbeats first: a stall costs the start of a quiet period
func TestSheddingTakesTheOldestHeartbeats(t *testing.T) {
	buf := mixedBuffer(40)
	// read before the shed: it reuses the buffer it is handed
	at := buf[0].Timestamp
	kept, _ := shedOldest(buf, 6)

	for _, r := range kept {
		if r.Result != "ok" {
			continue
		}

		// six oldest trusted: 0-2s, 4-6s
		if !r.Timestamp.After(at.Add(6 * time.Second)) {
			t.Fatalf("a trusted round from %v survived a shed of the six oldest", r.Timestamp)
		}
		break
	}
}

// with only events left, events go too
func TestSheddingFallsBackToEvents(t *testing.T) {
	buf := make([]AttestationRecord, 0, 10)
	at := time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)
	for i := 0; i < 10; i++ {
		buf = append(buf, AttestationRecord{
			Timestamp: at.Add(time.Duration(i) * time.Second),
			Result:    "sig_fail",
		})
	}

	kept, _ := shedOldest(buf, 4)
	if len(kept) != 6 {
		t.Fatalf("shedding 4 of 10 leaves 6, got %d", len(kept))
	}
	if !kept[0].Timestamp.Equal(at.Add(4 * time.Second)) {
		t.Errorf("the four oldest events went, the fifth stands: %v", kept[0].Timestamp)
	}
}

// the flush writes in buffer order; reordered rows open out of sequence
func TestSheddingKeepsOrder(t *testing.T) {
	kept, _ := shedOldest(mixedBuffer(40), 9)

	for i := 1; i < len(kept); i++ {
		if kept[i].Timestamp.Before(kept[i-1].Timestamp) {
			t.Fatalf("record %d is older than the one before it", i)
		}
	}
}

func TestSheddingBounds(t *testing.T) {
	if got, _ := shedOldest(mixedBuffer(8), 99); len(got) != 0 {
		t.Errorf("shedding more than the buffer holds empties it, got %d", len(got))
	}
	if got, _ := shedOldest(mixedBuffer(8), 0); len(got) != 8 {
		t.Errorf("shedding nothing keeps everything, got %d", len(got))
	}
}

// a refusal recorded into an overflowing buffer still reaches the backend
func TestTheWriterShedsHeartbeatsBeforeARefusal(t *testing.T) {
	backend := &blockingLog{entered: make(chan struct{}), release: make(chan struct{})}
	cfg := BatchedAttestationLogConfig{
		MaxBatch:      8,
		MaxBuffer:     32,
		FlushInterval: 10 * time.Millisecond,
	}
	bl := NewBatchedAttestationLog(backend, cfg)

	// the worker takes the first batch and blocks inside the backend
	for range cfg.MaxBatch {
		if err := bl.Record(AttestationRecord{Result: "ok", ClientID: "c1"}); err != nil {
			t.Fatalf("Record: %v", err)
		}
	}
	<-backend.entered

	// overflow the buffer, one refusal mid-flood
	for i := range cfg.MaxBuffer * 3 {
		r := AttestationRecord{Result: "ok", ClientID: "c1"}
		if i == cfg.MaxBuffer {
			r = AttestationRecord{Result: "banned", ClientID: "c1", Details: "hardware ban"}
		}
		_ = bl.Record(r)
	}

	close(backend.release)
	bl.Close()

	for _, r := range backend.all() {
		if r.Result == "banned" {
			return
		}
	}
	t.Fatal("the ban was dropped to make room for heartbeats")
}

// syncBuffer collects log output from the writer's own goroutines.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

// stallAndOverflow stalls the backend, floods past MaxBuffer,
// and hands back the writer and everything it logged.
func stallAndOverflow(t *testing.T, cfg BatchedAttestationLogConfig) (*BatchedAttestationLog, *syncBuffer) {
	t.Helper()

	out := &syncBuffer{}
	cfg.Logger = slog.New(slog.NewTextHandler(out, &slog.HandlerOptions{Level: slog.LevelDebug}))

	backend := &blockingLog{entered: make(chan struct{}), release: make(chan struct{})}
	bl := NewBatchedAttestationLog(backend, cfg)
	t.Cleanup(func() { close(backend.release); bl.Close() })

	// fill one batch: the worker takes it and blocks inside the backend
	for range cfg.MaxBatch {
		if err := bl.Record(AttestationRecord{Result: "ok"}); err != nil {
			t.Fatalf("Record: %v", err)
		}
	}
	<-backend.entered

	// refill to MaxBuffer, then push it over
	for range cfg.MaxBuffer + 50 {
		_ = bl.Record(AttestationRecord{Result: "ok"})
	}
	return bl, out
}

// The decision log is what answers "did we lose records during that incident?",
// and the incident is exactly when the buffer overflows.
// A drop that is only counted into a field nothing reads cannot answer it.
func TestBufferOverflowIsReported(t *testing.T) {
	bl, out := stallAndOverflow(t, BatchedAttestationLogConfig{
		MaxBatch:      10,
		MaxBuffer:     10,
		FlushInterval: time.Hour,
	})

	if bl.DroppedCount() == 0 {
		t.Fatal("nothing was dropped; this test needs an overflow")
	}

	logged := out.String()
	if !strings.Contains(logged, "dropped") && !strings.Contains(logged, "drop") {
		t.Errorf("%d records were dropped and the log says nothing:\n%s",
			bl.DroppedCount(), logged)
	}
}

// A stalled backend drops on nearly every Record, so the report has to be
// rate-limited: the loss is an incident, not a line per lost record.
func TestOverflowReportIsRateLimited(t *testing.T) {
	bl, out := stallAndOverflow(t, BatchedAttestationLogConfig{
		MaxBatch:      10,
		MaxBuffer:     10,
		FlushInterval: time.Hour,
	})

	lines := strings.Count(out.String(), "\n")
	if lines > 4 {
		t.Errorf("%d log lines for %d dropped records, want a rate-limited report:\n%s",
			lines, bl.DroppedCount(), out.String())
	}
}

// countingLoss stands for whatever a deployment reads its loss off.
type countingLoss struct {
	dropped    atomic.Int64
	failed     atomic.Int64
	eventsLost atomic.Int64
}

func (c *countingLoss) AttestationRecordsDropped(n int64) { c.dropped.Add(n) }
func (c *countingLoss) AttestationRecordsFailed(n int64)  { c.failed.Add(n) }
func (c *countingLoss) AttestationEventsLost(n int64)     { c.eventsLost.Add(n) }

// The loss has to reach a counter a dashboard can plot,
// not only a log line somebody has to be reading at the time.
func TestBufferOverflowReachesTheLossCounter(t *testing.T) {
	loss := &countingLoss{}
	bl, _ := stallAndOverflow(t, BatchedAttestationLogConfig{
		MaxBatch:      10,
		MaxBuffer:     10,
		FlushInterval: time.Hour,
		Loss:          loss,
	})

	if got, want := loss.dropped.Load(), bl.DroppedCount(); got != want {
		t.Errorf("loss counter read %d dropped records, the writer counted %d", got, want)
	}
	if loss.dropped.Load() == 0 {
		t.Error("nothing reached the loss counter")
	}
}

// A write that does not land is the other way the decision log goes
// incomplete, and it is counted the same way.
func TestFailedFlushReachesTheLossCounter(t *testing.T) {
	loss := &countingLoss{}
	spy := &spyLog{failBatch: true}
	bl := NewBatchedAttestationLog(spy, BatchedAttestationLogConfig{
		MaxBatch:      8,
		FlushInterval: time.Hour,
		Logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		Loss:          loss,
	})

	for range 8 {
		if err := bl.Record(AttestationRecord{Result: "ok"}); err != nil {
			t.Fatalf("Record: %v", err)
		}
	}
	if err := bl.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if got, want := loss.failed.Load(), bl.FailedCount(); got != want || got != 8 {
		t.Errorf("loss counter read %d failed records, the writer counted %d, want 8", got, want)
	}
}

// Close on a stalled backend returns an error and counts the unwritten tail
// as failed instead of blocking.
func TestCloseDoesNotWaitForeverOnAStalledBackend(t *testing.T) {
	backend := &blockingLog{entered: make(chan struct{}), release: make(chan struct{})}
	out := &syncBuffer{}
	loss := &countingLoss{}
	bl := NewBatchedAttestationLog(backend, BatchedAttestationLogConfig{
		MaxBatch:      10,
		MaxBuffer:     100,
		FlushInterval: time.Hour,
		Logger:        slog.New(slog.NewTextHandler(out, nil)),
		Loss:          loss,
	})
	t.Cleanup(func() { close(backend.release) })

	// one batch takes the worker into the stalled backend
	for range 10 {
		if err := bl.Record(AttestationRecord{Result: "ok"}); err != nil {
			t.Fatalf("Record: %v", err)
		}
	}
	<-backend.entered

	// and these stay buffered behind it
	for range 5 {
		_ = bl.Record(AttestationRecord{Result: "ok"})
	}

	done := make(chan error, 1)
	start := time.Now()
	go func() { done <- bl.Close() }()

	select {
	case err := <-done:
		if err == nil {
			t.Error("Close reported success while the tail was never written")
		}
		if waited := time.Since(start); waited > 10*time.Second {
			t.Errorf("Close waited %s on a stalled backend", waited)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("Close is still waiting on a stalled backend")
	}

	if loss.failed.Load() == 0 {
		t.Error("the records left buffered at shutdown were not counted as lost")
	}
	if !strings.Contains(out.String(), "shutdown") {
		t.Errorf("the loss at shutdown was not reported:\n%s", out.String())
	}
}
