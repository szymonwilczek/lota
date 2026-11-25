// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
// LOTA Verifier - TPM Event Log Parser and PCR Replay

package verify

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"unicode/utf16"

	"github.com/szymonwilczek/lota/verifier/types"
)

// TCG event types
const (
	EvNoAction                uint32 = 0x00000003
	EvSeparator               uint32 = 0x00000004
	EvAction                  uint32 = 0x00000005
	EvIPL                     uint32 = 0x0000000D
	EvEFIVariableDriverConfig uint32 = 0x80000001
	EvEFIVariableBoot         uint32 = 0x80000002
	EvEFIGPTEvent             uint32 = 0x80000006
	EvEFIAction               uint32 = 0x80000007
)

// TCG hash algorithm IDs
const (
	AlgSHA1   uint16 = 0x0004
	AlgSHA256 uint16 = 0x000B
	AlgSHA384 uint16 = 0x000C
	AlgSHA512 uint16 = 0x000D
)

// untrusted size caps
const (
	maxTCGHeaderDataSize uint32 = 1 << 20
	maxTCGEventDataSize  uint32 = 1 << 20
	maxTCGDigestCount    uint32 = 16
	maxUEFIVarNameUnits  uint64 = 1 << 10 // UTF-16 code units
)

// EventLogEntry is one TCG_PCR_EVENT2 entry of the event log.
type EventLogEntry struct {
	PCRIndex  uint32
	EventType uint32
	Digests   map[uint16][]byte // algorithm ID -> digest
	EventData []byte
}

// ParsedEventLog is a parsed event log.
type ParsedEventLog struct {
	Entries       []EventLogEntry
	AlgorithmList []uint16 // from the Spec ID Event
}

// ReplayResult holds the SHA-256 bank a replay reconstructs.
type ReplayResult struct {
	PCRValues    [types.PCRCount][types.HashSize]byte
	ExtendCounts [types.PCRCount]int
	TotalEntries int
}

// ParseEventLog parses a TCG crypto-agile binary event log: a TCG_PCR_EVENT
// header carrying the Spec ID Event, then TCG_PCR_EVENT2 entries.
func ParseEventLog(data []byte) (*ParsedEventLog, error) {
	if len(data) < 32 {
		return nil, errors.New("event log too short")
	}

	result := &ParsedEventLog{}
	offset := 0

	// pcr_index (4) + event_type (4) + sha1_digest (20) + event_data_size (4) + event_data
	if len(data) < offset+32 {
		return nil, errors.New("event log truncated at header")
	}

	headerPCR := binary.LittleEndian.Uint32(data[offset:])
	offset += 4
	headerType := binary.LittleEndian.Uint32(data[offset:])
	offset += 4
	offset += 20
	headerDataSize := binary.LittleEndian.Uint32(data[offset:])
	offset += 4

	if headerPCR != 0 || headerType != EvNoAction {
		return nil, fmt.Errorf("invalid event log header: pcr=%d type=0x%x", headerPCR, headerType)
	}

	if headerDataSize > maxTCGHeaderDataSize {
		return nil, fmt.Errorf("event log header data too large: %d", headerDataSize)
	}
	remaining := len(data) - offset
	if remaining < 0 || uint64(headerDataSize) > uint64(remaining) {
		return nil, errors.New("event log truncated at header data")
	}
	headerSize := int(headerDataSize)

	specData := data[offset : offset+headerSize]
	algList, err := parseSpecIDEvent(specData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse Spec ID Event: %w", err)
	}
	result.AlgorithmList = algList
	offset += headerSize

	for offset < len(data) {
		entry, consumed, err := parsePCREvent2(data[offset:])
		if err != nil {
			return nil, fmt.Errorf("event log truncated or malformed at offset %d: %w", offset, err)
		}
		if consumed == 0 {
			return nil, fmt.Errorf("event log parser consumed zero bytes at offset %d", offset)
		}
		result.Entries = append(result.Entries, *entry)
		offset += consumed
	}

	return result, nil
}

func parseSpecIDEvent(data []byte) ([]uint16, error) {
	// signature (16 bytes): "Spec ID Event03\0"
	// platformClass (4)
	// specVersionMinor (1)
	// specVersionMajor (1)
	// specErrata (1)
	// uintnSize (1)
	// numberOfAlgorithms (4)
	// digestSizes[]: algorithmId(2) + digestSize(2)

	if len(data) < 28 {
		return nil, errors.New("spec ID event too short")
	}

	offset := 16 + 4 + 1 + 1 + 1 + 1
	numAlgs := binary.LittleEndian.Uint32(data[offset:])
	offset += 4

	if numAlgs == 0 || numAlgs > 8 {
		return nil, fmt.Errorf("invalid algorithm count: %d", numAlgs)
	}

	var algs []uint16
	for i := uint32(0); i < numAlgs; i++ {
		if len(data) < offset+4 {
			return nil, errors.New("truncated algorithm list")
		}
		algID := binary.LittleEndian.Uint16(data[offset:])
		offset += 4
		algs = append(algs, algID)
	}

	return algs, nil
}

func parsePCREvent2(data []byte) (*EventLogEntry, int, error) {
	if len(data) < 8 {
		return nil, 0, io.ErrUnexpectedEOF
	}

	offset := 0

	entry := &EventLogEntry{
		Digests: make(map[uint16][]byte),
	}

	entry.PCRIndex = binary.LittleEndian.Uint32(data[offset:])
	offset += 4
	entry.EventType = binary.LittleEndian.Uint32(data[offset:])
	offset += 4

	// TPML_DIGEST_VALUES: count (4) + digests
	if len(data) < offset+4 {
		return nil, 0, io.ErrUnexpectedEOF
	}
	digestCount := binary.LittleEndian.Uint32(data[offset:])
	offset += 4
	if digestCount > maxTCGDigestCount {
		return nil, 0, fmt.Errorf("digest count too large: %d", digestCount)
	}

	for i := uint32(0); i < digestCount; i++ {
		if len(data) < offset+2 {
			return nil, 0, io.ErrUnexpectedEOF
		}
		algID := binary.LittleEndian.Uint16(data[offset:])
		offset += 2

		digestSize := algDigestSize(algID)
		if digestSize == 0 {
			return nil, 0, fmt.Errorf("unknown digest algorithm: 0x%04x", algID)
		}

		if len(data) < offset+digestSize {
			return nil, 0, io.ErrUnexpectedEOF
		}
		digest := make([]byte, digestSize)
		copy(digest, data[offset:offset+digestSize])
		entry.Digests[algID] = digest
		offset += digestSize
	}

	if len(data) < offset+4 {
		return nil, 0, io.ErrUnexpectedEOF
	}
	eventDataSize := binary.LittleEndian.Uint32(data[offset:])
	offset += 4
	if eventDataSize > maxTCGEventDataSize {
		return nil, 0, fmt.Errorf("event data too large: %d", eventDataSize)
	}
	remaining := len(data) - offset
	if remaining < 0 || uint64(eventDataSize) > uint64(remaining) {
		return nil, 0, io.ErrUnexpectedEOF
	}
	eventSize := int(eventDataSize)
	entry.EventData = make([]byte, eventSize)
	copy(entry.EventData, data[offset:offset+eventSize])
	offset += eventSize

	return entry, offset, nil
}

// EFI global variable namespace GUID 8be4df61-93ca-11d2-aa0d-00e098032b8c
// in the on-disk mixed-endian layout (first three fields little-endian)
var efiGlobalVariableGUID = [16]byte{
	0x61, 0xdf, 0xe4, 0x8b, 0xca, 0x93, 0xd2, 0x11,
	0xaa, 0x0d, 0x00, 0xe0, 0x98, 0x03, 0x2b, 0x8c,
}

// UEFIVariableData is the decoded UEFI_VARIABLE_DATA of an EV_EFI_VARIABLE_*
// event.
type UEFIVariableData struct {
	VariableName [16]byte // EFI_GUID, on-disk mixed-endian layout
	UnicodeName  string
	VariableData []byte
}

// UEFI_VARIABLE_DATA layout:
//
//	VariableName       EFI_GUID (16)
//	UnicodeNameLength  u64 (UTF-16 code units)
//	VariableDataLength u64
//	UnicodeName        UTF-16LE[UnicodeNameLength]
//	VariableData       u8[VariableDataLength]
func parseUEFIVariableData(data []byte) (*UEFIVariableData, error) {
	if len(data) < 32 {
		return nil, errors.New("UEFI variable data too short")
	}

	out := &UEFIVariableData{}
	copy(out.VariableName[:], data[:16])

	nameUnits := binary.LittleEndian.Uint64(data[16:])
	varLen := binary.LittleEndian.Uint64(data[24:])

	if nameUnits > maxUEFIVarNameUnits {
		return nil, fmt.Errorf("UEFI variable name too long: %d units", nameUnits)
	}
	avail := uint64(len(data)) - 32
	nameBytes := nameUnits * 2
	if nameBytes > avail || varLen > avail-nameBytes {
		return nil, errors.New("UEFI variable data truncated")
	}

	name := make([]uint16, nameUnits)
	for i := range name {
		name[i] = binary.LittleEndian.Uint16(data[32+2*i:])
	}
	out.UnicodeName = string(utf16.Decode(name))

	out.VariableData = make([]byte, varLen)
	copy(out.VariableData, data[32+nameBytes:32+nameBytes+varLen])

	return out, nil
}

func parseIPLEventString(data []byte) string {
	if i := bytes.IndexByte(data, 0); i >= 0 {
		data = data[:i]
	}
	return string(data)
}

func algDigestSize(algID uint16) int {
	switch algID {
	case AlgSHA1:
		return 20
	case AlgSHA256:
		return 32
	case AlgSHA384:
		return 48
	case AlgSHA512:
		return 64
	default:
		return 0
	}
}

// startupLocalitySignature starts the EV_NO_ACTION record of the locality the
// firmware started the TPM at; one byte of locality follows it.
var startupLocalitySignature = []byte("StartupLocality\x00")

func startupLocality(entry *EventLogEntry) (byte, bool) {
	if entry.EventType != EvNoAction {
		return 0, false
	}
	if len(entry.EventData) != len(startupLocalitySignature)+1 {
		return 0, false
	}
	if !bytes.Equal(entry.EventData[:len(startupLocalitySignature)], startupLocalitySignature) {
		return 0, false
	}
	return entry.EventData[len(startupLocalitySignature)], true
}

// ReplayEventLog extends the SHA-256 digests of the log into zeroed PCRs.
// A StartupLocality record ahead of the first PCR 0 extend starts PCR 0 at
// 31 zero bytes and the locality. EV_NO_ACTION entries, entries without a
// SHA-256 digest and entries past the last PCR are not extended.
func ReplayEventLog(parsed *ParsedEventLog) (*ReplayResult, error) {
	if parsed == nil {
		return nil, errors.New("nil event log")
	}

	result := &ReplayResult{}
	for _, entry := range parsed.Entries {
		if entry.PCRIndex >= types.PCRCount {
			continue
		}

		if entry.EventType == EvNoAction {
			if locality, ok := startupLocality(&entry); ok &&
				result.ExtendCounts[0] == 0 {
				result.PCRValues[0] = [types.HashSize]byte{}
				result.PCRValues[0][types.HashSize-1] = locality
			}
			continue
		}

		sha256Digest, ok := entry.Digests[AlgSHA256]
		if !ok {
			continue
		}

		h := sha256.New()
		h.Write(result.PCRValues[entry.PCRIndex][:])
		h.Write(sha256Digest)
		copy(result.PCRValues[entry.PCRIndex][:], h.Sum(nil))

		result.ExtendCounts[entry.PCRIndex]++
	}

	result.TotalEntries = len(parsed.Entries)
	return result, nil
}

// VerifyEventLogConsistency returns a mismatch for each PCR outside skipPCRs
// that the replay extended and the report quoted with another value.
func VerifyEventLogConsistency(report *types.AttestationReport, replay *ReplayResult, skipPCRs map[int]bool) []string {
	var mismatches []string

	for i := 0; i < types.PCRCount; i++ {
		if replay.ExtendCounts[i] == 0 {
			continue
		}
		if report.TPM.PCRMask&(1<<uint(i)) == 0 {
			continue
		}
		if skipPCRs != nil && skipPCRs[i] {
			continue
		}

		reported := report.TPM.PCRValues[i]
		replayed := replay.PCRValues[i]

		if reported != replayed {
			mismatches = append(mismatches, fmt.Sprintf(
				"PCR %d: reported=%s replayed=%s (extends=%d)",
				i,
				hex.EncodeToString(reported[:]),
				hex.EncodeToString(replayed[:]),
				replay.ExtendCounts[i]))
		}
	}

	return mismatches
}

// VerifyEventLogWithPolicy parses and replays the report's event log, fails
// on a mismatch with a quoted PCR the log extends, other than 8, 9 and 14, and
// returns the boot facts. enforcePCR8 adds PCR 8 to the check.
func VerifyEventLogWithPolicy(report *types.AttestationReport, enforcePCR8 bool) (*BootFacts, error) {
	if len(report.EventLog) == 0 {
		return nil, errors.New("TPM event log missing from report")
	}

	parsed, err := ParseEventLog(report.EventLog)
	if err != nil {
		return nil, fmt.Errorf("event log parse failed: %w", err)
	}

	replay, err := ReplayEventLog(parsed)
	if err != nil {
		return nil, fmt.Errorf("event log replay failed: %w", err)
	}

	if err := verifyVariableEventDigests(parsed); err != nil {
		return nil, fmt.Errorf("event log verification: %w", err)
	}

	skipPCRs := map[int]bool{
		9: true, 14: true,
	}
	if !enforcePCR8 {
		skipPCRs[8] = true
	}

	mismatches := VerifyEventLogConsistency(report, replay, skipPCRs)
	if len(mismatches) > 0 {
		for _, m := range mismatches {
			slog.Warn("event log PCR mismatch", "detail", m)
		}
		return nil, fmt.Errorf("event log verification: %d PCR mismatches detected", len(mismatches))
	}

	facts, err := ExtractBootFacts(report, parsed, replay)
	if err != nil {
		return nil, fmt.Errorf("event log semantic extraction failed: %w", err)
	}
	facts.Parsed = parsed

	slog.Info("event log verified",
		"entries", replay.TotalEntries,
		"pcrs_replayed", countNonZero(replay.ExtendCounts[:]))

	return facts, nil
}

// verifyVariableEventDigests refuses a PCR 7 EV_EFI_VARIABLE_DRIVER_CONFIG
// event whose data does not hash to its SHA-256 digest. The replay extends the
// digest alone, so uncovered data could name any value while PCR 7 matches.
func verifyVariableEventDigests(parsed *ParsedEventLog) error {
	for i := range parsed.Entries {
		e := &parsed.Entries[i]
		if e.PCRIndex != 7 || e.EventType != EvEFIVariableDriverConfig {
			continue
		}
		sum := sha256.Sum256(e.EventData)
		if !bytes.Equal(e.Digests[AlgSHA256], sum[:]) {
			return fmt.Errorf("PCR 7 variable event %d does not match its digest", i)
		}
	}
	return nil
}

func countNonZero(counts []int) int {
	n := 0
	for _, c := range counts {
		if c > 0 {
			n++
		}
	}
	return n
}
