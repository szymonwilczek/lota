// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
// LOTA Verifier - event log replay against firmware that starts the TPM
// above locality 0

package verify

import (
	"bytes"
	"crypto/sha256"
	"testing"
)

// startupLocalityEvent is the EV_NO_ACTION record firmware writes to say which
// locality it started the TPM at: the signature, its NUL, then one byte.
func startupLocalityEvent(locality byte) EventLogEntry {
	return EventLogEntry{
		PCRIndex:  0,
		EventType: EvNoAction,
		// EV_NO_ACTION carries a zero digest -- there is nothing to measure
		Digests:   map[uint16][]byte{AlgSHA256: make([]byte, 32)},
		EventData: append([]byte("StartupLocality\x00"), locality),
	}
}

func measurement(pcr uint32, b byte) EventLogEntry {
	d := bytes.Repeat([]byte{b}, 32)
	return EventLogEntry{
		PCRIndex:  pcr,
		EventType: 0x80000008, // EV_EFI_PLATFORM_FIRMWARE_BLOB
		Digests:   map[uint16][]byte{AlgSHA256: d},
	}
}

// extendFrom is the PCR arithmetic the TPM does, so a test states the expected value
func extendFrom(start []byte, digests ...[]byte) []byte {
	cur := make([]byte, 32)
	copy(cur, start)
	for _, d := range digests {
		h := sha256.New()
		h.Write(cur)
		h.Write(d)
		cur = h.Sum(nil)
	}
	return cur
}

// Firmware that measures a static root of trust starts the TPM at locality 3 --
// Intel Boot Guard does this on every recent platform -- and PCR 0 then begins
// at 31 zero bytes followed by the locality, not at zero. The log says so in an
// EV_NO_ACTION record, which is informational: the TPM never extended it, so
// neither may the replay.
func TestReplayEventLogHonoursStartupLocality(t *testing.T) {
	log := buildTestEventLog([]EventLogEntry{
		startupLocalityEvent(3),
		measurement(0, 0xAA),
		measurement(0, 0xBB),
	})

	parsed, err := ParseEventLog(log)
	if err != nil {
		t.Fatalf("ParseEventLog: %v", err)
	}
	replay, err := ReplayEventLog(parsed)
	if err != nil {
		t.Fatalf("ReplayEventLog: %v", err)
	}

	want := extendFrom(append(make([]byte, 31), 3),
		bytes.Repeat([]byte{0xAA}, 32), bytes.Repeat([]byte{0xBB}, 32))
	if !bytes.Equal(replay.PCRValues[0][:], want) {
		t.Errorf("PCR 0 = %x, want %x", replay.PCRValues[0][:], want)
	}
	if replay.ExtendCounts[0] != 2 {
		t.Errorf("PCR 0 extend count = %d, want 2 -- EV_NO_ACTION is not an extend",
			replay.ExtendCounts[0])
	}
}

// A log with no StartupLocality event describes a TPM started at locality 0.
// That is OVMF, every platform without a measured static root, and every log
// the project has replayed until now: it must keep replaying identically.
func TestReplayEventLogWithoutStartupLocality(t *testing.T) {
	log := buildTestEventLog([]EventLogEntry{
		measurement(0, 0xAA),
		measurement(0, 0xBB),
	})

	parsed, err := ParseEventLog(log)
	if err != nil {
		t.Fatalf("ParseEventLog: %v", err)
	}
	replay, err := ReplayEventLog(parsed)
	if err != nil {
		t.Fatalf("ReplayEventLog: %v", err)
	}

	want := extendFrom(make([]byte, 32),
		bytes.Repeat([]byte{0xAA}, 32), bytes.Repeat([]byte{0xBB}, 32))
	if !bytes.Equal(replay.PCRValues[0][:], want) {
		t.Errorf("PCR 0 = %x, want %x", replay.PCRValues[0][:], want)
	}
}

// EV_NO_ACTION is informational wherever it appears and on whatever PCR:
// the spec-ID header, a locality record, a vendor note.
// None of them was extended into a PCR, so none of them may move the replay.
func TestReplayEventLogNeverExtendsNoAction(t *testing.T) {
	noise := EventLogEntry{
		PCRIndex:  1,
		EventType: EvNoAction,
		Digests:   map[uint16][]byte{AlgSHA256: bytes.Repeat([]byte{0xCC}, 32)},
		EventData: []byte("vendor note"),
	}
	log := buildTestEventLog([]EventLogEntry{noise, measurement(1, 0xDD)})

	parsed, err := ParseEventLog(log)
	if err != nil {
		t.Fatalf("ParseEventLog: %v", err)
	}
	replay, err := ReplayEventLog(parsed)
	if err != nil {
		t.Fatalf("ReplayEventLog: %v", err)
	}

	want := extendFrom(make([]byte, 32), bytes.Repeat([]byte{0xDD}, 32))
	if !bytes.Equal(replay.PCRValues[1][:], want) {
		t.Errorf("PCR 1 = %x, want %x -- a non-zero EV_NO_ACTION digest was extended",
			replay.PCRValues[1][:], want)
	}
	if replay.ExtendCounts[1] != 1 {
		t.Errorf("PCR 1 extend count = %d, want 1", replay.ExtendCounts[1])
	}
}

// A locality record that arrives after PCR 0 has already been measured into
// describes nothing that can be true, so it is ignored rather than allowed to
// reset the accumulator a real measurement is already in.
func TestReplayEventLogIgnoresLateStartupLocality(t *testing.T) {
	log := buildTestEventLog([]EventLogEntry{
		measurement(0, 0xAA),
		startupLocalityEvent(3),
		measurement(0, 0xBB),
	})

	parsed, err := ParseEventLog(log)
	if err != nil {
		t.Fatalf("ParseEventLog: %v", err)
	}
	replay, err := ReplayEventLog(parsed)
	if err != nil {
		t.Fatalf("ReplayEventLog: %v", err)
	}

	want := extendFrom(make([]byte, 32),
		bytes.Repeat([]byte{0xAA}, 32), bytes.Repeat([]byte{0xBB}, 32))
	if !bytes.Equal(replay.PCRValues[0][:], want) {
		t.Errorf("PCR 0 = %x, want %x", replay.PCRValues[0][:], want)
	}
}

// A truncated or over-long locality record is firmware data the verifier does
// not control, so it is ignored
func TestReplayEventLogRejectsMalformedStartupLocality(t *testing.T) {
	short := EventLogEntry{
		PCRIndex:  0,
		EventType: EvNoAction,
		Digests:   map[uint16][]byte{AlgSHA256: make([]byte, 32)},
		EventData: []byte("StartupLocality\x00"), // signature, no locality byte
	}
	log := buildTestEventLog([]EventLogEntry{short, measurement(0, 0xAA)})

	parsed, err := ParseEventLog(log)
	if err != nil {
		t.Fatalf("ParseEventLog: %v", err)
	}
	replay, err := ReplayEventLog(parsed)
	if err != nil {
		t.Fatalf("ReplayEventLog: %v", err)
	}

	want := extendFrom(make([]byte, 32), bytes.Repeat([]byte{0xAA}, 32))
	if !bytes.Equal(replay.PCRValues[0][:], want) {
		t.Errorf("PCR 0 = %x, want %x", replay.PCRValues[0][:], want)
	}
}
