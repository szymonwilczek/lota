// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
// LOTA Verifier - what a full buffer gives up first

package store

import (
	"testing"
	"time"
)

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
