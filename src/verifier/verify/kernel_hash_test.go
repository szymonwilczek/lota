// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
package verify

import (
	"path/filepath"
	"testing"

	"github.com/szymonwilczek/lota/verifier/store"
	"github.com/szymonwilczek/lota/verifier/types"
)

func kernelHash(b byte) [types.HashSize]byte {
	var h [types.HashSize]byte
	h[0] = b
	return h
}

// Recording the value is half of it.
// Naming the change is what an operator reads, and that needs the value
// it replaced -- and a first attestation has to read as a first attestation.
func TestRecordKernelHash_ReturnsWhatItReplaced(t *testing.T) {
	db, err := store.OpenDB(filepath.Join(t.TempDir(), "v.sqlite"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()

	bs := NewSQLiteBaselineStore(db)
	first, second := kernelHash(0xA1), kernelHash(0xB2)

	// no baseline row yet: nothing this verifier agreed to remember
	if _, had, err := bs.RecordKernelHash("c1", first); err != nil {
		t.Fatalf("unknown client: %v", err)
	} else if had {
		t.Error("a client with no baseline reported a previous kernel")
	}

	bs.CheckAndUpdate("c1", kernelHash(0x14))

	if _, had, err := bs.RecordKernelHash("c1", first); err != nil {
		t.Fatalf("first record: %v", err)
	} else if had {
		t.Error("a first attestation was reported as a kernel change")
	}

	prev, had, err := bs.RecordKernelHash("c1", second)
	if err != nil {
		t.Fatalf("second record: %v", err)
	}
	if !had {
		t.Fatal("the previous kernel hash was not returned")
	}
	if prev != first {
		t.Errorf("wrong previous value: got %x, want %x", prev, first)
	}

	// reporting the same kernel again is not a change
	prev, had, err = bs.RecordKernelHash("c1", second)
	if err != nil || !had || prev != second {
		t.Errorf("the stored value did not settle: %x had=%v err=%v", prev, had, err)
	}
}

// The in-memory store is what the default configuration and most tests run
// on, so the capability has to be there too or the log line never appears
// outside a database-backed deployment.
func TestRecordKernelHash_MemoryStore(t *testing.T) {
	bs := NewBaselineStore()
	var _ KernelHashRecorder = bs

	if _, had, _ := bs.RecordKernelHash("c1", kernelHash(0x01)); had {
		t.Error("an unknown client reported a previous kernel")
	}

	bs.CheckAndUpdate("c1", kernelHash(0x14))
	if _, had, _ := bs.RecordKernelHash("c1", kernelHash(0x01)); had {
		t.Error("a first attestation was reported as a kernel change")
	}
	prev, had, _ := bs.RecordKernelHash("c1", kernelHash(0x02))
	if !had || prev != kernelHash(0x01) {
		t.Errorf("previous value not returned: %x had=%v", prev, had)
	}
}
