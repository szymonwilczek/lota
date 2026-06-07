// SPDX-License-Identifier: MIT
// LOTA Verifier - Fuzz tests for TCG event log parser and PCR replay

package verify

import (
	"crypto/sha256"
	"testing"

	"github.com/szymonwilczek/lota/verifier/types"
)

func FuzzParseEventLog(f *testing.F) {
	// seed: single-entry SHA-256 event log
	d1 := sha256.Sum256([]byte("firmware"))
	log1 := buildTestEventLog([]EventLogEntry{
		{
			PCRIndex:  0,
			EventType: 0x00000001,
			Digests:   map[uint16][]byte{AlgSHA256: d1[:]},
			EventData: []byte("POST CODE"),
		},
	})
	f.Add(log1)

	// seed: multi-entry log
	d2 := sha256.Sum256([]byte("bootloader"))
	d3 := sha256.Sum256([]byte("secureboot"))
	log2 := buildTestEventLog([]EventLogEntry{
		{PCRIndex: 0, EventType: 0x00000001, Digests: map[uint16][]byte{AlgSHA256: d1[:]}, EventData: []byte("fw")},
		{PCRIndex: 4, EventType: EvAction, Digests: map[uint16][]byte{AlgSHA256: d2[:]}, EventData: []byte("bl")},
		{PCRIndex: 7, EventType: EvEFIVarBoot, Digests: map[uint16][]byte{AlgSHA256: d3[:]}, EventData: []byte("sb")},
	})
	f.Add(log2)

	// seed: minimal truncated (too short)
	f.Add([]byte{0x00, 0x01, 0x02, 0x03})

	f.Fuzz(func(t *testing.T, data []byte) {
		parsed, err := ParseEventLog(data)
		if err != nil {
			if parsed != nil {
				t.Fatal("ParseEventLog returned non-nil result with error")
			}
			return
		}
		if parsed == nil {
			t.Fatal("ParseEventLog returned nil without error")
		}
		for _, entry := range parsed.Entries {
			if entry.PCRIndex >= types.PCRCount {
				// parser should accept any index; replay skips out-of-range
			}
			for algID, digest := range entry.Digests {
				expected := algDigestSize(algID)
				if expected != 0 && len(digest) != expected {
					t.Fatalf("digest length %d for alg 0x%04x, expected %d", len(digest), algID, expected)
				}
			}
		}
	})
}

func FuzzReplayEventLog(f *testing.F) {
	d1 := sha256.Sum256([]byte("measurement"))
	log1 := buildTestEventLog([]EventLogEntry{
		{PCRIndex: 0, EventType: 0x00000001, Digests: map[uint16][]byte{AlgSHA256: d1[:]}},
	})
	f.Add(log1)

	d2 := sha256.Sum256([]byte("first"))
	d3 := sha256.Sum256([]byte("second"))
	log2 := buildTestEventLog([]EventLogEntry{
		{PCRIndex: 7, EventType: EvEFIVarBoot, Digests: map[uint16][]byte{AlgSHA256: d2[:]}},
		{PCRIndex: 7, EventType: EvEFIBootService, Digests: map[uint16][]byte{AlgSHA256: d3[:]}},
	})
	f.Add(log2)

	f.Fuzz(func(t *testing.T, data []byte) {
		parsed, err := ParseEventLog(data)
		if err != nil || parsed == nil {
			return
		}
		result, err := ReplayEventLog(parsed)
		if err != nil {
			return
		}
		if result == nil {
			t.Fatal("ReplayEventLog returned nil without error")
		}
		if result.TotalEntries != len(parsed.Entries) {
			t.Fatalf("TotalEntries=%d, parsed entries=%d", result.TotalEntries, len(parsed.Entries))
		}
	})
}
