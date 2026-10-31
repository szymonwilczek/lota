// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek

package store

import (
	"database/sql"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// a log whose database outlives the process
func restartableLog(t *testing.T, path string) (*SQLiteAttestationLog, *sql.DB) {
	t.Helper()

	db, err := OpenDB(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	return NewSQLiteAttestationLog(db), db
}

// the standing row lives in the database: rounds after a restart extend it
func TestARestartDoesNotOpenASecondRow(t *testing.T) {
	path := filepath.Join(t.TempDir(), "v.sqlite")
	at := time.Date(2026, 9, 19, 16, 0, 0, 0, time.UTC)

	log, db := restartableLog(t, path)
	for i := range 4 {
		if err := log.Record(trustedRound(at.Add(time.Duration(i) * time.Minute))); err != nil {
			t.Fatalf("record %d: %v", i, err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	log, db = restartableLog(t, path)
	defer db.Close()
	for i := 4; i < 8; i++ {
		if err := log.Record(trustedRound(at.Add(time.Duration(i) * time.Minute))); err != nil {
			t.Fatalf("record %d after the restart: %v", i, err)
		}
	}

	got := log.QueryAttestations(0)
	if len(got) != 1 {
		t.Fatalf("a restart mid-row left %d rows, want 1", len(got))
	}
	if got[0].Rounds != 8 {
		t.Errorf("the row stands for %d rounds, want the 8 that were served", got[0].Rounds)
	}
	if want := at.Add(7 * time.Minute); !got[0].LastSeen.Equal(want) {
		t.Errorf("the row's last sighting is %v, want %v", got[0].LastSeen, want)
	}
}

// a row with unreadable times is left alone; the round gets its own row
func TestARowWhoseTimesDoNotReadBackIsNotExtended(t *testing.T) {
	db := eventsTestDB(t)
	log := NewSQLiteAttestationLog(db)
	at := time.Date(2026, 9, 19, 17, 0, 0, 0, time.UTC)

	for i := range 3 {
		if err := log.Record(trustedRound(at.Add(time.Duration(i) * time.Minute))); err != nil {
			t.Fatalf("record %d: %v", i, err)
		}
	}

	// unreadable last sighting
	if _, err := db.Exec(
		"UPDATE attestation_log SET last_seen = ? WHERE id = 1", "not a time at all",
	); err != nil {
		t.Fatalf("damage the row: %v", err)
	}

	if err := log.Record(trustedRound(at.Add(3 * time.Minute))); err != nil {
		t.Fatalf("record after the damage: %v", err)
	}

	var rows int
	if err := db.QueryRow("SELECT count(*) FROM attestation_log").Scan(&rows); err != nil {
		t.Fatalf("count: %v", err)
	}
	if rows != 2 {
		t.Fatalf("the round after an unreadable row left %d rows, want 2", rows)
	}

	var (
		rounds   int64
		lastSeen string
	)
	if err := db.QueryRow(
		"SELECT rounds, last_seen FROM attestation_log WHERE id = 1",
	).Scan(&rounds, &lastSeen); err != nil {
		t.Fatalf("read the damaged row: %v", err)
	}
	if rounds != 3 || lastSeen != "not a time at all" {
		t.Errorf("the unreadable row now says rounds=%d last_seen=%q; it was not the one to change",
			rounds, lastSeen)
	}
}

// concurrent rounds for one host: each counted exactly once
func TestConcurrentRoundsForOneHostAreAllCounted(t *testing.T) {
	log := NewSQLiteAttestationLog(eventsTestDB(t))
	at := time.Date(2026, 9, 19, 18, 0, 0, 0, time.UTC)

	const rounds = 24
	var wg sync.WaitGroup
	errs := make(chan error, rounds)
	for i := range rounds {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := log.Record(trustedRound(at.Add(time.Duration(i) * time.Second))); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("record: %v", err)
	}

	got := log.QueryAttestations(0)
	var total int64
	for i := range got {
		total += got[i].Rounds
	}
	if total != rounds {
		t.Errorf("%d rounds were served and the log stands for %d", rounds, total)
	}
}
