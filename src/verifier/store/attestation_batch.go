// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
// LOTA Verifier - Batched attestation log writer
//
// BatchedAttestationLog moves the attestation audit write off the verification hot path.
// Record only buffers; background worker flushes the buffer as single batch on timer
// or once it fills, so the N per-report audit writes that would each cost WAL commit
// fsync collapse into one commit per flush.
// Audit log is append-only and never gates attestation, so crash may lose at most
// the records buffered since the last flush - bounded by the flush interval.

package store

import (
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

// BatchedAttestationLogConfig tunes the batched writer.
// Zero fields take their defaults.
type BatchedAttestationLogConfig struct {
	// MaxBatch flushes the buffer once this many records accumulate.
	MaxBatch int
	// FlushInterval bounds how long a record waits before it is durable
	// (and thus the worst-case audit loss on a crash).
	FlushInterval time.Duration
	// MaxBuffer caps buffered records;
	// Past it the oldest records drop so stalled database cannot grow
	// the buffer without bound.
	MaxBuffer int
	// Logger receives flush-failure and drop warnings.
	// Defaults to the slog default logger.
	Logger *slog.Logger
}

const (
	defaultBatchMaxBatch      = 256
	defaultBatchFlushInterval = time.Second
	// hard cap defaults to a multiple of the batch size:
	// enough slack to ride out brief database stall,
	// bounded enough to protect memory
	defaultBatchMaxBufferMul = 16
)

// BatchedAttestationLog wraps an AttestationLog with an asynchronous, batching writer.
// It satisfies AttestationLog and is safe for concurrent Record callers.
type BatchedAttestationLog struct {
	backend AttestationLog
	batcher BatchRecorder // non-nil when backend can batch; else Record loop

	maxBatch      int
	maxBuffer     int
	flushInterval time.Duration

	mu  sync.Mutex
	buf []AttestationRecord

	wake    chan struct{}
	closeCh chan struct{}
	done    chan struct{}
	closed  atomic.Bool

	dropped atomic.Int64
	failed  atomic.Int64
	log     *slog.Logger
}

// NewBatchedAttestationLog wraps backend with an asynchronous batching writer
// and starts its background flush worker.
// Close stops the worker and flushes what remains.
func NewBatchedAttestationLog(backend AttestationLog, cfg BatchedAttestationLogConfig) *BatchedAttestationLog {
	if cfg.MaxBatch <= 0 {
		cfg.MaxBatch = defaultBatchMaxBatch
	}
	if cfg.FlushInterval <= 0 {
		cfg.FlushInterval = defaultBatchFlushInterval
	}
	if cfg.MaxBuffer <= 0 {
		cfg.MaxBuffer = cfg.MaxBatch * defaultBatchMaxBufferMul
	}
	if cfg.MaxBuffer < cfg.MaxBatch {
		cfg.MaxBuffer = cfg.MaxBatch
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	l := &BatchedAttestationLog{
		backend:       backend,
		maxBatch:      cfg.MaxBatch,
		maxBuffer:     cfg.MaxBuffer,
		flushInterval: cfg.FlushInterval,
		buf:           make([]AttestationRecord, 0, cfg.MaxBatch),
		wake:          make(chan struct{}, 1),
		closeCh:       make(chan struct{}),
		done:          make(chan struct{}),
		log:           cfg.Logger,
	}
	if br, ok := backend.(BatchRecorder); ok {
		l.batcher = br
	}

	go l.worker()
	return l
}

// Record buffers entry and returns immediately;
// it never performs database write on the caller's goroutine.
func (l *BatchedAttestationLog) Record(entry AttestationRecord) error {
	// stamp the enqueue time so the audit record reflects when
	// the attestation happened, not when the batch was flushed
	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now().UTC()
	}

	l.mu.Lock()
	overflow := len(l.buf) >= l.maxBuffer
	if overflow {
		// bound memory by dropping the oldest records;
		// liveness of the verify path beats completeness
		// of best-effort audit trail.
		// Whole batch goes at once so the shift costs O(maxBuffer) every
		// maxBatch records rather than on every Record -- a per-record
		// shift makes this path O(maxBuffer) under the mutex, which
		// re-serializes the hot path exactly when the backend is stalled
		drop := min(l.maxBatch, len(l.buf))
		l.buf = append(l.buf[:0], l.buf[drop:]...)
		l.dropped.Add(int64(drop))
	}
	l.buf = append(l.buf, entry)
	full := overflow || len(l.buf) >= l.maxBatch
	l.mu.Unlock()

	if full {
		l.signal()
	}
	return nil
}

// QueryAttestations flushes any buffered records first so the monitoring surface
// reads its own recent writes, then delegates to the backend
func (l *BatchedAttestationLog) QueryAttestations(limit int) []AttestationRecord {
	l.flush()
	return l.backend.QueryAttestations(limit)
}

// Flush drains the buffer synchronously.
// Safe to call concurrently with Record.
func (l *BatchedAttestationLog) Flush() {
	l.flush()
}

// Close stops the background worker and flushes remaining records.
// It is idempotent; after Close the worker no longer drains,
// so callers must stop issuing Record first.
func (l *BatchedAttestationLog) Close() error {
	if l.closed.Swap(true) {
		return nil
	}
	close(l.closeCh)
	<-l.done
	return nil
}

// DroppedCount returns the number of records dropped under buffer pressure.
// FailedCount returns the number lost to flush errors.
func (l *BatchedAttestationLog) DroppedCount() int64 { return l.dropped.Load() }
func (l *BatchedAttestationLog) FailedCount() int64  { return l.failed.Load() }

func (l *BatchedAttestationLog) signal() {
	select {
	case l.wake <- struct{}{}:
	default:
	}
}

func (l *BatchedAttestationLog) worker() {
	defer close(l.done)

	t := time.NewTicker(l.flushInterval)
	defer t.Stop()

	for {
		select {
		case <-l.closeCh:
			l.flush()
			return
		case <-t.C:
			l.flush()
		case <-l.wake:
			l.flush()
		}
	}
}

func (l *BatchedAttestationLog) flush() {
	l.mu.Lock()
	if len(l.buf) == 0 {
		l.mu.Unlock()
		return
	}
	batch := l.buf
	l.buf = make([]AttestationRecord, 0, l.maxBatch)
	l.mu.Unlock()

	// count what was actually lost, not the batch it happened in:
	// RecordBatch is all-or-nothing, but the per-record fallback can lose
	// one entry and persist the rest
	var (
		err  error
		lost int
	)
	if l.batcher != nil {
		if err = l.batcher.RecordBatch(batch); err != nil {
			lost = len(batch)
		}
	} else {
		for i := range batch {
			if e := l.backend.Record(batch[i]); e != nil {
				err = e
				lost++
			}
		}
	}
	if lost > 0 {
		l.failed.Add(int64(lost))
		l.log.Warn("attestation-log flush failed; records dropped",
			"records", lost, "batch", len(batch), "error", err)
	}
}
