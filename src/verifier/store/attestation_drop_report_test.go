// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
// LOTA Verifier - the batched decision log reports what it loses

package store

import (
	"bytes"
	"io"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

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
	dropped atomic.Int64
	failed  atomic.Int64
}

func (c *countingLoss) AttestationRecordsDropped(n int64) { c.dropped.Add(n) }
func (c *countingLoss) AttestationRecordsFailed(n int64)  { c.failed.Add(n) }

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
