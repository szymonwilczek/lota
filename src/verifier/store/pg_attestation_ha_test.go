// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek

//go:build pg_integration

// LOTA Verifier - the decision log under several instances
//
// Instances racing on one host must reach what they would one after another.
//
// Needs a live database: LOTA_TEST_PG_DSN.

package store

import (
	"sync"
	"testing"
	"time"
)

// fixed timestamp: the instances race, not the clock
func haRound(clientID string, at time.Time) AttestationRecord {
	return AttestationRecord{
		Timestamp:  at,
		Tenant:     "default",
		ClientID:   clientID,
		HardwareID: "aabb",
		Result:     "ok",
		PCR14:      "cc",
		KernelHash: "dd",
	}
}

// a second instance waits while the first decides about the same host
func TestPostgresAttestationLogOneInstanceDecidesPerSubject(t *testing.T) {
	db := pgTestDB(t)
	first := NewPostgresAttestationLog(db)
	second := NewPostgresAttestationLog(db)

	at := time.Now().UTC().Truncate(time.Millisecond)
	round := haRound("ha-subject", at)

	// first instance mid-decision: transaction open from read to commit
	tx, err := db.Begin()
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	// an open transaction would stall the next test's TRUNCATE
	defer func() { _ = tx.Rollback() }()
	if err := first.record(tx, round, at); err != nil {
		t.Fatalf("record: %v", err)
	}

	done := make(chan error, 1)
	go func() { done <- second.Record(round) }()

	select {
	case err := <-done:
		t.Fatalf("a second instance decided about the same host while the first was still deciding (Record returned %v); the round it wrote cannot have seen the row the first one is opening", err)
	case <-time.After(500 * time.Millisecond):
	}

	if err := tx.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("Record: %v", err)
	}

	rows := first.QueryAttestationsFiltered(AttestationQuery{ClientID: "ha-subject"})
	if len(rows) != 1 {
		t.Fatalf("two instances recorded one host's arrival and left %d rows, want 1", len(rows))
	}
	if rows[0].Rounds != 2 {
		t.Fatalf("the standing row stands for %d rounds, want 2", rows[0].Rounds)
	}
}

// different hosts do not wait on each other
func TestPostgresAttestationLogSubjectsDoNotBlockEachOther(t *testing.T) {
	db := pgTestDB(t)
	first := NewPostgresAttestationLog(db)
	second := NewPostgresAttestationLog(db)

	at := time.Now().UTC().Truncate(time.Millisecond)

	tx, err := db.Begin()
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	// an open transaction would stall the next test's TRUNCATE
	defer func() { _ = tx.Rollback() }()
	if err := first.record(tx, haRound("ha-one", at), at); err != nil {
		t.Fatalf("record: %v", err)
	}

	done := make(chan error, 1)
	go func() { done <- second.Record(haRound("ha-two", at)) }()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Record: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a round for one host waited on a decision about another")
	}

	if err := tx.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	rows := first.QueryAttestationsFiltered(AttestationQuery{})
	if len(rows) != 2 {
		t.Fatalf("two hosts arrived and left %d rows, want one each", len(rows))
	}
}

// every round counted, whichever instance served it
func TestPostgresAttestationLogConcurrentRoundsAreAllCounted(t *testing.T) {
	db := pgTestDB(t)

	const (
		instances = 4
		rounds    = 25
	)
	logs := make([]*PostgresAttestationLog, instances)
	for i := range logs {
		logs[i] = NewPostgresAttestationLog(db)
	}

	at := time.Now().UTC().Truncate(time.Millisecond)
	round := haRound("ha-steady", at)

	start := make(chan struct{})
	errs := make(chan error, instances)
	var wg sync.WaitGroup
	for i := range logs {
		wg.Add(1)
		go func(l *PostgresAttestationLog) {
			defer wg.Done()
			<-start
			for r := 0; r < rounds; r++ {
				if err := l.Record(round); err != nil {
					errs <- err
					return
				}
			}
		}(logs[i])
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("Record: %v", err)
	}

	got := logs[0].QueryAttestationsFiltered(AttestationQuery{ClientID: "ha-steady"})
	if len(got) != 1 {
		t.Fatalf("%d instances served %d rounds each and left %d rows, want 1",
			instances, rounds, len(got))
	}
	if want := int64(instances * rounds); got[0].Rounds != want {
		t.Fatalf("the standing row stands for %d rounds, want %d", got[0].Rounds, want)
	}
}
