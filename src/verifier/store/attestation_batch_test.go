// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek

package store

import (
	"errors"
	"sync"
	"testing"
	"time"
)

// spyLog is an AttestationLog+BatchRecorder that counts how the batched writer reaches it:
// total records persisted and how many flush calls that took.
// failBatch forces RecordBatch to error.
type spyLog struct {
	mu         sync.Mutex
	records    []AttestationRecord
	batchCalls int
	failBatch  bool
}

func (s *spyLog) Record(entry AttestationRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records = append(s.records, entry)
	return nil
}

func (s *spyLog) RecordBatch(entries []AttestationRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failBatch {
		return errors.New("forced flush failure")
	}
	s.batchCalls++
	s.records = append(s.records, entries...)
	return nil
}

func (s *spyLog) QueryAttestations(limit int) []AttestationRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := len(s.records)
	if limit > 0 && limit < n {
		n = limit
	}
	out := make([]AttestationRecord, n)
	copy(out, s.records[len(s.records)-n:])
	return out
}

func (s *spyLog) counts() (records, calls int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.records), s.batchCalls
}

// burst of Record calls must persist every record but reach
// the backend in far fewer batch flushes than there were records.
func TestBatchedAttestationLogCoalesces(t *testing.T) {
	spy := &spyLog{}
	// long interval so only the size trigger and Close flush fire,
	// which keeps the coalescing assertion independent of wall-clock timing
	bl := NewBatchedAttestationLog(spy, BatchedAttestationLogConfig{
		MaxBatch:      256,
		FlushInterval: time.Hour,
	})

	const n = 1000
	for i := range n {
		if err := bl.Record(AttestationRecord{ClientID: string(rune('a' + i%26)), Result: "ok"}); err != nil {
			t.Fatalf("Record: %v", err)
		}
	}
	if err := bl.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	records, calls := spy.counts()
	if records != n {
		t.Fatalf("persisted %d records, want %d (Close must flush the tail)", records, n)
	}
	if calls == 0 {
		t.Fatal("no batch flushes reached the backend")
	}
	// whole point: many records, few commits
	if calls >= n {
		t.Fatalf("%d batch flushes for %d records: no coalescing", calls, n)
	}
	// with MaxBatch=256 1000-record burst needs at most ceil(1000/256)+1
	// flushes even if the worker services every wake individually
	if calls > 5 {
		t.Fatalf("%d batch flushes, want <= 5 for 1000 records at MaxBatch=256", calls)
	}
}

// QueryAttestations must expose records that are still only buffered.
func TestBatchedAttestationLogReadYourWrites(t *testing.T) {
	spy := &spyLog{}
	bl := NewBatchedAttestationLog(spy, BatchedAttestationLogConfig{FlushInterval: time.Hour})
	defer bl.Close()

	if err := bl.Record(AttestationRecord{ClientID: "c1", Result: "ok"}); err != nil {
		t.Fatalf("Record: %v", err)
	}
	// nothing flushed yet on its own
	// query must force it
	if got := bl.QueryAttestations(10); len(got) != 1 || got[0].ClientID != "c1" {
		t.Fatalf("QueryAttestations = %+v, want the buffered record", got)
	}
}

// blockingLog stalls the very first flush so a test can drive the buffer
// into its overflow path while the worker is stuck writing.
type blockingLog struct {
	entered chan struct{}
	release chan struct{}
	once    sync.Once
	mu      sync.Mutex
	records []AttestationRecord
}

func (b *blockingLog) Record(e AttestationRecord) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.records = append(b.records, e)
	return nil
}

func (b *blockingLog) RecordBatch(e []AttestationRecord) error {
	b.once.Do(func() { close(b.entered) })
	<-b.release
	b.mu.Lock()
	defer b.mu.Unlock()
	b.records = append(b.records, e...)
	return nil
}

func (b *blockingLog) QueryAttestations(int) []AttestationRecord { return nil }

// Past MaxBuffer the oldest records drop and the buffer stays bounded,
// rather than growing without limit while the backend is stalled
func TestBatchedAttestationLogDropsUnderPressure(t *testing.T) {
	backend := &blockingLog{entered: make(chan struct{}), release: make(chan struct{})}
	bl := NewBatchedAttestationLog(backend, BatchedAttestationLogConfig{
		MaxBatch:      10,
		MaxBuffer:     10,
		FlushInterval: time.Hour,
	})
	t.Cleanup(func() { close(backend.release); bl.Close() })

	// first 10 fill batch and trigger flush;
	// worker enters RecordBatch and blocks there, draining the buffer to empty
	for range 10 {
		if err := bl.Record(AttestationRecord{Result: "ok"}); err != nil {
			t.Fatalf("Record: %v", err)
		}
	}
	<-backend.entered

	// with the worker stuck, refill to MaxBuffer, then overflow:
	// every further record drops the oldest to keep the buffer bounded
	for range 10 {
		_ = bl.Record(AttestationRecord{Result: "ok"})
	}
	for range 50 {
		_ = bl.Record(AttestationRecord{Result: "ok"})
	}

	if d := bl.DroppedCount(); d != 50 {
		t.Fatalf("DroppedCount = %d, want 50 (50 records past a full 10-slot buffer)", d)
	}
}

// failing backend must not wedge the writer:
// records are counted as failed and the verify path never sees the error
func TestBatchedAttestationLogFlushFailureIsBounded(t *testing.T) {
	spy := &spyLog{failBatch: true}
	bl := NewBatchedAttestationLog(spy, BatchedAttestationLogConfig{
		MaxBatch:      8,
		FlushInterval: time.Hour,
	})

	for i := range 8 {
		if err := bl.Record(AttestationRecord{ClientID: string(rune(i))}); err != nil {
			t.Fatalf("Record returned an error to the hot path: %v", err)
		}
	}
	if err := bl.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if f := bl.FailedCount(); f != 8 {
		t.Fatalf("FailedCount = %d, want 8", f)
	}
}

// partialFailLog persists every record but one, so the per-record fallback
// path loses strictly less than the batch it was flushing
type partialFailLog struct {
	mu        sync.Mutex
	seen      int
	failNth   int
	persisted int
}

func (p *partialFailLog) Record(AttestationRecord) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.seen++
	if p.seen == p.failNth {
		return errors.New("transient backend failure")
	}
	p.persisted++
	return nil
}

func (p *partialFailLog) QueryAttestations(int) []AttestationRecord { return nil }

func (p *partialFailLog) count() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.persisted
}

// FailedCount must report records actually lost, not the size of the batch they
// were flushed in.
// Operators alert on it, so counting a whole batch for one failed row turns single
// lost record into an apparent audit-trail outage
func TestBatchedAttestationLogFailedCountMatchesLoss(t *testing.T) {
	backend := &partialFailLog{failNth: 3}
	bl := NewBatchedAttestationLog(backend, BatchedAttestationLogConfig{
		MaxBatch:      8,
		FlushInterval: time.Hour,
	})

	const n = 8
	for range n {
		if err := bl.Record(AttestationRecord{Result: "ok"}); err != nil {
			t.Fatalf("Record: %v", err)
		}
	}
	if err := bl.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	persisted := backend.count()
	if persisted != n-1 {
		t.Fatalf("backend persisted %d of %d, want %d", persisted, n, n-1)
	}
	if got := bl.FailedCount(); got != int64(n-persisted) {
		t.Errorf("FailedCount = %d, want %d (only one record was lost)", got, n-persisted)
	}
}

// Close is idempotent.
func TestBatchedAttestationLogCloseIdempotent(t *testing.T) {
	bl := NewBatchedAttestationLog(&spyLog{}, BatchedAttestationLogConfig{})
	if err := bl.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := bl.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

// Backend that cannot batch still works through the per-record fallback.
// It wraps MemoryAttestationLog as named field so RecordBatch is not promoted
// and the type is deliberately not a BatchRecorder.
type recordOnlyLog struct{ inner *MemoryAttestationLog }

func (r *recordOnlyLog) Record(e AttestationRecord) error { return r.inner.Record(e) }
func (r *recordOnlyLog) QueryAttestations(limit int) []AttestationRecord {
	return r.inner.QueryAttestations(limit)
}

func TestBatchedAttestationLogFallbackWithoutBatcher(t *testing.T) {
	backend := &recordOnlyLog{inner: NewMemoryAttestationLog()}
	if _, isBatcher := any(backend).(BatchRecorder); isBatcher {
		t.Fatal("test backend must not satisfy BatchRecorder")
	}
	bl := NewBatchedAttestationLog(backend, BatchedAttestationLogConfig{FlushInterval: time.Hour})

	for i := range 5 {
		if err := bl.Record(AttestationRecord{ClientID: string(rune('a' + i))}); err != nil {
			t.Fatalf("Record: %v", err)
		}
	}
	if err := bl.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if got := backend.QueryAttestations(0); len(got) != 5 {
		t.Fatalf("fallback persisted %d records, want 5", len(got))
	}
}
