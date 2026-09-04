// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
// LOTA Verifier - the batched decision log reports what it loses

package store

import (
	"bytes"
	"log/slog"
	"strings"
	"sync"
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
