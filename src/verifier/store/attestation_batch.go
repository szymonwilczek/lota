// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
// LOTA Verifier - Batched attestation log writer
//
// Record only buffers. The worker writes the buffer as one batch on a timer
// or once it fills; Flush and QueryAttestations write it on the caller's
// goroutine. A failed write never changes a verdict, and a crash loses
// what is still buffered.

package store

import (
	"errors"
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
	// FlushInterval is the period of the timed flush.
	FlushInterval time.Duration
	// MaxBuffer caps buffered records; past it Record sheds a batch,
	// see shedOldest.
	MaxBuffer int
	// Logger receives flush-failure and drop warnings.
	Logger *slog.Logger

	// Loss receives dropped and failed record counts.
	Loss AttestationLogLoss

	// CloseTimeout bounds the final flush in Close;
	// past it the buffered records count as failed.
	CloseTimeout time.Duration
}

// AttestationLogLoss counts records dropped on a full buffer or lost to a
// failed write, and the events among them.
type AttestationLogLoss interface {
	AttestationRecordsDropped(n int64)
	AttestationRecordsFailed(n int64)
	AttestationEventsLost(n int64)
}

const (
	defaultBatchMaxBatch      = 256
	defaultBatchFlushInterval = time.Second
	// MaxBuffer defaults to this many batches
	defaultBatchMaxBufferMul = 16

	defaultCloseTimeout = 5 * time.Second

	// a stalled backend drops on nearly every record; warn at most this often
	dropReportInterval = 30 * time.Second
)

// BatchedAttestationLog is an AttestationLog that batches writes to its
// backend. Record is safe for concurrent use.
type BatchedAttestationLog struct {
	backend AttestationLog
	batcher BatchRecorder // non-nil when backend can batch; else Record loop

	maxBatch      int
	maxBuffer     int
	flushInterval time.Duration
	closeTimeout  time.Duration

	mu  sync.Mutex
	buf []AttestationRecord
	// records and events taken by flushes still writing;
	// abandoned once a timed-out Close has counted them lost
	inflight       int
	inflightEvents int
	abandoned      bool

	wake    chan struct{}
	closeCh chan struct{}
	done    chan struct{}
	closed  atomic.Bool

	dropped    atomic.Int64
	failed     atomic.Int64
	eventsLost atomic.Int64

	lastDropReport atomic.Int64
	loss           AttestationLogLoss
	log            *slog.Logger
}

// NewBatchedAttestationLog wraps backend and starts the flush worker.
// Zero config fields take their defaults.
func NewBatchedAttestationLog(backend AttestationLog, cfg BatchedAttestationLogConfig) *BatchedAttestationLog {
	if cfg.CloseTimeout <= 0 {
		cfg.CloseTimeout = defaultCloseTimeout
	}
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
		closeTimeout:  cfg.CloseTimeout,
		loss:          cfg.Loss,
		log:           cfg.Logger,
	}
	if br, ok := backend.(BatchRecorder); ok {
		l.batcher = br
	}

	go l.worker()
	return l
}

// shedOldest drops n records from buf, the oldest heartbeats first and then
// the oldest events. It reuses buf's storage and returns the kept records and
// the number of events dropped.
func shedOldest(buf []AttestationRecord, n int) (kept []AttestationRecord, events int) {
	if n <= 0 {
		return buf, 0
	}
	if n >= len(buf) {
		return buf[:0], countAttestationEvents(buf)
	}

	heartbeats := 0
	for i := range buf {
		if !attestationIsEvent(buf[i]) {
			heartbeats++
		}
	}

	dropHeartbeats := min(n, heartbeats)
	dropEvents := n - dropHeartbeats
	events = dropEvents

	kept = buf[:0]
	for i := range buf {
		if attestationIsEvent(buf[i]) {
			if dropEvents > 0 {
				dropEvents--
				continue
			}
		} else if dropHeartbeats > 0 {
			dropHeartbeats--
			continue
		}
		kept = append(kept, buf[i])
	}
	return kept, events
}

// countAttestationEvents counts the records in buf that are events.
func countAttestationEvents(buf []AttestationRecord) int {
	n := 0
	for i := range buf {
		if attestationIsEvent(buf[i]) {
			n++
		}
	}
	return n
}

// Record buffers entry and returns nil; it never writes to the backend on the
// caller's goroutine.
func (l *BatchedAttestationLog) Record(entry AttestationRecord) error {
	// the attestation time, not the flush time
	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now().UTC()
	}

	drop := 0
	shedEvents := 0
	l.mu.Lock()
	overflow := len(l.buf) >= l.maxBuffer
	if overflow {
		// a whole batch at once, so the O(maxBuffer) shift under the
		// mutex runs once per maxBatch records
		drop = min(l.maxBatch, len(l.buf))
		l.buf, shedEvents = shedOldest(l.buf, drop)
		l.dropped.Add(int64(drop))
		if shedEvents > 0 {
			l.eventsLost.Add(int64(shedEvents))
		}
	}
	l.buf = append(l.buf, entry)
	full := overflow || len(l.buf) >= l.maxBatch
	l.mu.Unlock()

	if drop > 0 {
		if l.loss != nil {
			l.loss.AttestationRecordsDropped(int64(drop))
			if shedEvents > 0 {
				l.loss.AttestationEventsLost(int64(shedEvents))
			}
		}
		l.reportDrop()
	}

	if full {
		l.signal()
	}
	return nil
}

// reportDrop warns of buffer overflow with the running drop total,
// at most once per dropReportInterval.
func (l *BatchedAttestationLog) reportDrop() {
	now := time.Now()
	last := l.lastDropReport.Load()
	if last != 0 && now.Sub(time.Unix(0, last)) < dropReportInterval {
		return
	}
	if !l.lastDropReport.CompareAndSwap(last, now.UnixNano()) {
		return
	}
	events := l.EventsLostCount()
	hint := "the decision log backend is not keeping up; trusted rounds are shed first, so what is lost is how long a quiet host stayed quiet"
	if events > 0 {
		hint = "the decision log backend is not keeping up and the buffer has run out of trusted rounds to shed: refusals and bans are being lost"
	}
	l.log.Warn("attestation-log buffer full; decision records shed",
		"dropped_total", l.DroppedCount(),
		"events_lost_total", events,
		"buffer", l.maxBuffer,
		"hint", hint)
}

// QueryAttestations flushes the buffer and queries the backend.
func (l *BatchedAttestationLog) QueryAttestations(q AttestationQuery) []AttestationRecord {
	l.flush()
	return l.backend.QueryAttestations(q)
}

// Flush drains the buffer synchronously.
// Safe to call concurrently with Record.
func (l *BatchedAttestationLog) Flush() {
	l.flush()
}

// Close stops the worker after a final flush. Records after Close stay in the
// buffer. Past closeTimeout it counts the buffer and the records still being
// written as failed and returns ErrCloseTimedOut. Later calls return nil.
func (l *BatchedAttestationLog) Close() error {
	if l.closed.Swap(true) {
		return nil
	}
	close(l.closeCh)

	timer := time.NewTimer(l.closeTimeout)
	defer timer.Stop()

	select {
	case <-l.done:
		return nil
	case <-timer.C:
	}

	l.mu.Lock()
	pending := len(l.buf) + l.inflight
	pendingEvents := countAttestationEvents(l.buf) + l.inflightEvents
	l.abandoned = true
	l.mu.Unlock()

	lost := int64(pending)
	l.failed.Add(lost)
	l.eventsLost.Add(int64(pendingEvents))
	if l.loss != nil {
		l.loss.AttestationRecordsFailed(lost)
		if pendingEvents > 0 {
			l.loss.AttestationEventsLost(int64(pendingEvents))
		}
	}
	l.log.Warn("attestation-log did not flush before shutdown deadline; buffered decision records lost",
		"records", lost, "deadline", l.closeTimeout,
		"hint", "the decision log backend stopped answering; enforcement state is unaffected")
	return ErrCloseTimedOut
}

// ErrCloseTimedOut is returned by Close when the final flush missed the
// deadline.
var ErrCloseTimedOut = errors.New("attestation log did not flush before the shutdown deadline")

// DroppedCount returns the number of records dropped under buffer pressure.
// FailedCount returns the number lost to flush errors.
func (l *BatchedAttestationLog) DroppedCount() int64 { return l.dropped.Load() }
func (l *BatchedAttestationLog) FailedCount() int64  { return l.failed.Load() }

// EventsLostCount returns how many of the lost records were events.
func (l *BatchedAttestationLog) EventsLostCount() int64 { return l.eventsLost.Load() }

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
	batchEvents := countAttestationEvents(batch)
	l.buf = make([]AttestationRecord, 0, l.maxBatch)
	l.inflight += len(batch)
	l.inflightEvents += batchEvents
	l.mu.Unlock()

	// the per-record fallback can lose some records and write the rest
	var (
		err        error
		lost       int
		lostEvents int
	)
	if l.batcher != nil {
		if err = l.batcher.RecordBatch(batch); err != nil {
			lost = len(batch)
			lostEvents = batchEvents
		}
	} else {
		for i := range batch {
			if e := l.backend.Record(batch[i]); e != nil {
				err = e
				lost++
				if attestationIsEvent(batch[i]) {
					lostEvents++
				}
			}
		}
	}

	l.mu.Lock()
	l.inflight -= len(batch)
	l.inflightEvents -= batchEvents
	abandoned := l.abandoned
	l.mu.Unlock()
	if abandoned {
		// the timed-out Close counted this batch lost
		return
	}
	if lost > 0 {
		l.failed.Add(int64(lost))
		l.eventsLost.Add(int64(lostEvents))
		if l.loss != nil {
			l.loss.AttestationRecordsFailed(int64(lost))
			if lostEvents > 0 {
				l.loss.AttestationEventsLost(int64(lostEvents))
			}
		}
		l.log.Warn("attestation-log flush failed; records dropped",
			"records", lost, "events", lostEvents, "batch", len(batch), "error", err)
	}
}
