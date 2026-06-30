// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
// LOTA Verifier - Fuzz tests for TCG event log parser and PCR replay

package verify

import (
	"crypto/sha256"
	"testing"
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
		{PCRIndex: 7, EventType: EvEFIVariableDriverConfig, Digests: map[uint16][]byte{AlgSHA256: d3[:]}, EventData: []byte("sb")},
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
			for algID, digest := range entry.Digests {
				expected := algDigestSize(algID)
				if expected != 0 && len(digest) != expected {
					t.Fatalf("digest length %d for alg 0x%04x, expected %d", len(digest), algID, expected)
				}
			}
		}
		// determinism: parsing the same bytes must yield the same entry count
		again, err2 := ParseEventLog(data)
		if err2 != nil || again == nil {
			t.Fatal("ParseEventLog nondeterministic: second parse failed")
		}
		if len(again.Entries) != len(parsed.Entries) {
			t.Fatalf("ParseEventLog nondeterministic: %d then %d entries", len(parsed.Entries), len(again.Entries))
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
		{PCRIndex: 7, EventType: EvEFIVariableDriverConfig, Digests: map[uint16][]byte{AlgSHA256: d2[:]}},
		{PCRIndex: 7, EventType: EvEFIVariableBoot, Digests: map[uint16][]byte{AlgSHA256: d3[:]}},
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
		// replay is a pure function of the parsed log:
		// second replay must reconstruct the identical PCR bank
		result2, err := ReplayEventLog(parsed)
		if err != nil || result2 == nil {
			t.Fatal("ReplayEventLog nondeterministic: second replay failed")
		}
		if result2.PCRValues != result.PCRValues {
			t.Fatal("ReplayEventLog reconstructed different PCRs for the same log")
		}
	})
}

func FuzzParseUEFIVariableData(f *testing.F) {
	f.Add(encodeUEFIVariableData(efiGlobalVariableGUID, "SecureBoot", []byte{0x01}))
	f.Add(encodeUEFIVariableData([16]byte{}, "", nil))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		v, err := parseUEFIVariableData(data)
		if err != nil {
			return
		}
		if v == nil {
			t.Fatal("nil result without error")
		}
		if len(v.VariableData) > len(data) {
			t.Fatalf("variable data longer than input: %d > %d", len(v.VariableData), len(data))
		}
	})
}
