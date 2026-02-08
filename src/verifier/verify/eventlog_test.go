// SPDX-License-Identifier: MIT
// LOTA Verifier - Event Log Tests

package verify

import (
	"crypto/sha256"
	"encoding/binary"
	"testing"

	"github.com/szymonwilczek/lota/verifier/types"
)

// builds a minimal valid TCG event log with Spec ID Event header
// and a set of crypto-agile PCR_EVENT2 entries (SHA-256 only)
func buildTestEventLog(entries []EventLogEntry) []byte {
	var buf []byte

	// legacy header: TCG_PCR_EVENT
	// pcr_index=0, event_type=EV_NO_ACTION, sha1_digest=zeros(20)
	header := make([]byte, 32)
	binary.LittleEndian.PutUint32(header[0:4], 0)          // pcr_index
	binary.LittleEndian.PutUint32(header[4:8], EvNoAction) // event_type

	// build Spec ID Event data
	specData := buildSpecIDEvent([]uint16{AlgSHA256})
	binary.LittleEndian.PutUint32(header[28:32], uint32(len(specData)))
	buf = append(buf, header...)
	buf = append(buf, specData...)

	// append PCR_EVENT2 entries
	for _, entry := range entries {
		buf = append(buf, encodePCREvent2(&entry)...)
	}

	return buf
}

func buildSpecIDEvent(algs []uint16) []byte {
	// signature (16)
	sig := []byte("Spec ID Event03\x00")
	// platformClass (4) + specVersionMinor (1) + specVersionMajor (1) + specErrata (1) + uintnSize (1)
	meta := make([]byte, 8)
	// numberOfAlgorithms (4)
	numAlgs := make([]byte, 4)
	binary.LittleEndian.PutUint32(numAlgs, uint32(len(algs)))
	// digestSizes: algorithmId(2) + digestSize(2) per alg
	var digestSizes []byte
	for _, alg := range algs {
		entry := make([]byte, 4)
		binary.LittleEndian.PutUint16(entry[0:2], alg)
		binary.LittleEndian.PutUint16(entry[2:4], uint16(algDigestSize(alg)))
		digestSizes = append(digestSizes, entry...)
	}
	// vendorInfoSize (1) = 0
	vendorInfo := []byte{0}

	var buf []byte
	buf = append(buf, sig...)
	buf = append(buf, meta...)
	buf = append(buf, numAlgs...)
	buf = append(buf, digestSizes...)
	buf = append(buf, vendorInfo...)
	return buf
}

func encodePCREvent2(entry *EventLogEntry) []byte {
	var buf []byte

	// pcr_index (4) + event_type (4)
	hdr := make([]byte, 8)
	binary.LittleEndian.PutUint32(hdr[0:4], entry.PCRIndex)
	binary.LittleEndian.PutUint32(hdr[4:8], entry.EventType)
	buf = append(buf, hdr...)

	// TPML_DIGEST_VALUES: count (4)
	count := make([]byte, 4)
	binary.LittleEndian.PutUint32(count, uint32(len(entry.Digests)))
	buf = append(buf, count...)

	// digests: algID (2) + digest bytes
	for algID, digest := range entry.Digests {
		algBuf := make([]byte, 2)
		binary.LittleEndian.PutUint16(algBuf, algID)
		buf = append(buf, algBuf...)
		buf = append(buf, digest...)
	}

	// event data size (4) + data
	eventSize := make([]byte, 4)
	binary.LittleEndian.PutUint32(eventSize, uint32(len(entry.EventData)))
	buf = append(buf, eventSize...)
	buf = append(buf, entry.EventData...)

	return buf
}

func TestParseEventLog_ValidLog(t *testing.T) {
	t.Log("TEST: Parse valid TCG event log")

	digest := sha256.Sum256([]byte("test firmware measurement"))
	entries := []EventLogEntry{
		{
			PCRIndex:  0,
			EventType: 0x00000001, // EV_POST_CODE
			Digests:   map[uint16][]byte{AlgSHA256: digest[:]},
			EventData: []byte("POST CODE"),
		},
	}

	logData := buildTestEventLog(entries)
	parsed, err := ParseEventLog(logData)
	if err != nil {
		t.Fatalf("ParseEventLog failed: %v", err)
	}

	if len(parsed.Entries) != 1 {
		t.Fatalf("Expected 1 entry, got %d", len(parsed.Entries))
	}

	if parsed.Entries[0].PCRIndex != 0 {
		t.Errorf("Expected PCR 0, got %d", parsed.Entries[0].PCRIndex)
	}

	sha256Digest, ok := parsed.Entries[0].Digests[AlgSHA256]
	if !ok {
		t.Fatal("Missing SHA-256 digest")
	}
	if len(sha256Digest) != 32 {
		t.Errorf("Expected 32-byte digest, got %d", len(sha256Digest))
	}

	t.Log("Event log parsed correctly")
}

func TestParseEventLog_MultipleEntries(t *testing.T) {
	t.Log("TEST: Parse event log with multiple entries")

	digest1 := sha256.Sum256([]byte("firmware"))
	digest2 := sha256.Sum256([]byte("bootloader"))
	digest3 := sha256.Sum256([]byte("secure boot state"))

	entries := []EventLogEntry{
		{
			PCRIndex:  0,
			EventType: 0x00000001,
			Digests:   map[uint16][]byte{AlgSHA256: digest1[:]},
			EventData: []byte("firmware"),
		},
		{
			PCRIndex:  4,
			EventType: 0x00000005,
			Digests:   map[uint16][]byte{AlgSHA256: digest2[:]},
			EventData: []byte("bootloader"),
		},
		{
			PCRIndex:  7,
			EventType: 0x80000001,
			Digests:   map[uint16][]byte{AlgSHA256: digest3[:]},
			EventData: []byte("secureboot"),
		},
	}

	logData := buildTestEventLog(entries)
	parsed, err := ParseEventLog(logData)
	if err != nil {
		t.Fatalf("ParseEventLog failed: %v", err)
	}

	if len(parsed.Entries) != 3 {
		t.Fatalf("Expected 3 entries, got %d", len(parsed.Entries))
	}

	t.Log("Multiple entries parsed correctly")
}

func TestParseEventLog_TooShort(t *testing.T) {
	t.Log("TEST: Reject truncated event log")

	_, err := ParseEventLog([]byte{0x01, 0x02})
	if err == nil {
		t.Error("Expected error for truncated log")
	}

	t.Logf("Truncated log rejected: %v", err)
}

func TestParseEventLog_EmptyLog(t *testing.T) {
	t.Log("TEST: Handle empty event log")

	_, err := ParseEventLog(nil)
	if err == nil {
		t.Error("Expected error for nil event log")
	}

	t.Log("Empty event log correctly rejected")
}

func TestReplayEventLog_SingleExtend(t *testing.T) {
	t.Log("TEST: Replay single PCR extend operation")

	digest := sha256.Sum256([]byte("measurement"))
	parsed := &ParsedEventLog{
		Entries: []EventLogEntry{
			{
				PCRIndex:  0,
				EventType: 0x00000001,
				Digests:   map[uint16][]byte{AlgSHA256: digest[:]},
			},
		},
	}

	result, err := ReplayEventLog(parsed)
	if err != nil {
		t.Fatalf("Replay failed: %v", err)
	}

	// expected: SHA256(zeros(32) || digest)
	h := sha256.New()
	var zeros [32]byte
	h.Write(zeros[:])
	h.Write(digest[:])
	expected := h.Sum(nil)

	for i := 0; i < 32; i++ {
		if result.PCRValues[0][i] != expected[i] {
			t.Fatalf("PCR 0 mismatch at byte %d", i)
		}
	}

	if result.ExtendCounts[0] != 1 {
		t.Errorf("Expected 1 extend, got %d", result.ExtendCounts[0])
	}

	t.Log("Single extend replayed correctly")
}

func TestReplayEventLog_MultipleExtends(t *testing.T) {
	t.Log("TEST: Replay multiple extends into same PCR")

	d1 := sha256.Sum256([]byte("first"))
	d2 := sha256.Sum256([]byte("second"))

	parsed := &ParsedEventLog{
		Entries: []EventLogEntry{
			{
				PCRIndex:  7,
				EventType: 0x80000001,
				Digests:   map[uint16][]byte{AlgSHA256: d1[:]},
			},
			{
				PCRIndex:  7,
				EventType: 0x80000002,
				Digests:   map[uint16][]byte{AlgSHA256: d2[:]},
			},
		},
	}

	result, err := ReplayEventLog(parsed)
	if err != nil {
		t.Fatalf("Replay failed: %v", err)
	}

	// manual calculation
	var pcr7 [32]byte
	h := sha256.New()
	h.Write(pcr7[:])
	h.Write(d1[:])
	copy(pcr7[:], h.Sum(nil))

	h.Reset()
	h.Write(pcr7[:])
	h.Write(d2[:])
	copy(pcr7[:], h.Sum(nil))

	if result.PCRValues[7] != pcr7 {
		t.Error("PCR 7 does not match manual calculation")
	}

	if result.ExtendCounts[7] != 2 {
		t.Errorf("Expected 2 extends for PCR 7, got %d", result.ExtendCounts[7])
	}

	t.Log("Multiple extends replayed correctly")
}

func TestReplayEventLog_Nil(t *testing.T) {
	t.Log("TEST: Replay nil event log")

	_, err := ReplayEventLog(nil)
	if err == nil {
		t.Error("Expected error for nil event log")
	}

	t.Log("Nil event log correctly rejected")
}

func TestVerifyEventLogConsistency_Match(t *testing.T) {
	t.Log("SECURITY TEST: Event log matches reported PCR values")

	d1 := sha256.Sum256([]byte("firmware"))

	parsed := &ParsedEventLog{
		Entries: []EventLogEntry{
			{
				PCRIndex:  0,
				EventType: 0x00000001,
				Digests:   map[uint16][]byte{AlgSHA256: d1[:]},
			},
		},
	}

	replay, err := ReplayEventLog(parsed)
	if err != nil {
		t.Fatalf("Replay failed: %v", err)
	}

	report := &types.AttestationReport{}
	report.TPM.PCRValues[0] = replay.PCRValues[0] // match

	mismatches := VerifyEventLogConsistency(report, replay, nil)
	if len(mismatches) != 0 {
		t.Errorf("Expected no mismatches, got: %v", mismatches)
	}

	t.Log("Matching PCR values correctly verified")
}

func TestVerifyEventLogConsistency_Mismatch(t *testing.T) {
	t.Log("SECURITY TEST: Detect PCR tampering via event log")

	d1 := sha256.Sum256([]byte("firmware"))

	parsed := &ParsedEventLog{
		Entries: []EventLogEntry{
			{
				PCRIndex:  0,
				EventType: 0x00000001,
				Digests:   map[uint16][]byte{AlgSHA256: d1[:]},
			},
		},
	}

	replay, err := ReplayEventLog(parsed)
	if err != nil {
		t.Fatalf("Replay failed: %v", err)
	}

	report := &types.AttestationReport{}
	// set a different PCR 0 value
	for i := 0; i < 32; i++ {
		report.TPM.PCRValues[0][i] = 0xFF
	}

	mismatches := VerifyEventLogConsistency(report, replay, nil)
	if len(mismatches) != 1 {
		t.Errorf("Expected 1 mismatch, got %d", len(mismatches))
	}

	t.Logf("PCR tampering detected: %v", mismatches)
}

func TestVerifyEventLogConsistency_SkipPCRs(t *testing.T) {
	t.Log("TEST: Skip PCR 14 in event log verification")

	d1 := sha256.Sum256([]byte("self-measurement"))

	parsed := &ParsedEventLog{
		Entries: []EventLogEntry{
			{
				PCRIndex:  14,
				EventType: 0x0000000D,
				Digests:   map[uint16][]byte{AlgSHA256: d1[:]},
			},
		},
	}

	replay, err := ReplayEventLog(parsed)
	if err != nil {
		t.Fatalf("Replay failed: %v", err)
	}

	report := &types.AttestationReport{}
	// PCR 14 intentionally differs (runtime extension)

	skip := map[int]bool{14: true}
	mismatches := VerifyEventLogConsistency(report, replay, skip)
	if len(mismatches) != 0 {
		t.Errorf("Expected no mismatches with skip, got: %v", mismatches)
	}

	t.Log("PCR 14 correctly skipped in verification")
}

func TestVerifyEventLog_EmptyLog(t *testing.T) {
	t.Log("TEST: VerifyEventLog rejects empty event log")

	report := &types.AttestationReport{}

	err := VerifyEventLog(report)
	if err == nil {
		t.Error("Empty event log should produce error")
	}

	t.Log("Empty event log correctly rejected")
}

func TestVerifyEventLog_FullPipeline(t *testing.T) {
	t.Log("SECURITY TEST: Full event log pipeline - parse, replay, verify")

	d1 := sha256.Sum256([]byte("SRTM firmware"))
	d2 := sha256.Sum256([]byte("boot config"))

	entries := []EventLogEntry{
		{
			PCRIndex:  0,
			EventType: 0x00000001,
			Digests:   map[uint16][]byte{AlgSHA256: d1[:]},
			EventData: []byte("firmware"),
		},
		{
			PCRIndex:  1,
			EventType: 0x00000001,
			Digests:   map[uint16][]byte{AlgSHA256: d2[:]},
			EventData: []byte("config"),
		},
	}

	logData := buildTestEventLog(entries)

	// calculate expected PCR values
	h0 := sha256.New()
	var zeros [32]byte
	h0.Write(zeros[:])
	h0.Write(d1[:])
	expectedPCR0 := h0.Sum(nil)

	h1 := sha256.New()
	h1.Write(zeros[:])
	h1.Write(d2[:])
	expectedPCR1 := h1.Sum(nil)

	// build report with correct PCR values
	report := &types.AttestationReport{}
	copy(report.TPM.PCRValues[0][:], expectedPCR0)
	copy(report.TPM.PCRValues[1][:], expectedPCR1)
	report.EventLog = logData

	err := VerifyEventLog(report)
	if err != nil {
		t.Errorf("Full pipeline verification should pass: %v", err)
	}

	t.Log("Full event log pipeline verified successfully")
}

func TestParseReport_WithEventLog(t *testing.T) {
	t.Log("TEST: ParseReport handles variable-length event log")

	// minimal fixed report
	buf := make([]byte, types.FixedReportSize)
	binary.LittleEndian.PutUint32(buf[0:], types.ReportMagic)
	binary.LittleEndian.PutUint32(buf[4:], types.ReportVersion)

	// event_count = 0
	eventCountBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(eventCountBuf, 0)
	buf = append(buf, eventCountBuf...)

	// event_log_size = 5, data = "hello"
	eventLogSizeBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(eventLogSizeBuf, 5)
	buf = append(buf, eventLogSizeBuf...)
	buf = append(buf, []byte("hello")...)

	// update report_size header
	binary.LittleEndian.PutUint32(buf[24:28], uint32(len(buf)))

	report, err := types.ParseReport(buf)
	if err != nil {
		t.Fatalf("ParseReport failed: %v", err)
	}

	if len(report.EventLog) != 5 {
		t.Fatalf("Expected 5-byte event log, got %d", len(report.EventLog))
	}

	if string(report.EventLog) != "hello" {
		t.Errorf("Event log content mismatch: got %q", string(report.EventLog))
	}

	t.Log("ParseReport correctly extracts event log from variable sections")
}
