// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek

package store

import (
	"sync/atomic"
	"testing"
	"time"
)

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
