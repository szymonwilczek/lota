// SPDX-License-Identifier: MIT
// LOTA Verifier - TPM Event Log Parser and PCR Replay
//
// Parses the TCG binary event log (binary_bios_measurements) and replays
// PCR extend operations to independently verify that reported PCR values
// are consistent with the firmware/bootloader measurement chain.
//
// Event log format:
//	- Legacy header event (TCG_PCR_EVENT format, pcr_index=0, event_type=EV_NO_ACTION)
// 		Contains Spec ID Event with digest algorithm info
//  - TCG_PCR_EVENT2 entries (crypto-agile format with per-algorithm digests)

package verify

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"

	"github.com/szymonwilczek/lota/verifier/types"
)

// TCG event types
const (
	EvNoAction       uint32 = 0x00000003
	EvSeparator      uint32 = 0x00000004
	EvAction         uint32 = 0x00000005
	EvEFIAction      uint32 = 0x80000007
	EvEFIVarBoot     uint32 = 0x80000001
	EvEFIBootService uint32 = 0x80000002
	EvEFIGPTEvent    uint32 = 0x80000006
)

// TCG hash algorithm IDs
const (
	AlgSHA1   uint16 = 0x0004
	AlgSHA256 uint16 = 0x000B
	AlgSHA384 uint16 = 0x000C
	AlgSHA512 uint16 = 0x000D
)

// single measurement entry from the event log
type EventLogEntry struct {
	PCRIndex  uint32
	EventType uint32
	Digests   map[uint16][]byte // algorithm ID -> digest
	EventData []byte
}

// result of event log parsing
type ParsedEventLog struct {
	Entries       []EventLogEntry
	AlgorithmList []uint16 // algorithms present in log
}

// result of PCR replay
type ReplayResult struct {
	// reconstructed PCR values per algorithm (IMPORTANT NOTE: currently SHA-256 only)
	PCRValues [types.PCRCount][types.HashSize]byte

	// number of extend operations per PCR
	ExtendCounts [types.PCRCount]int

	// total entries processed
	TotalEntries int
}

// parses a TCG binary event log (binary_bios_measurements format)
func ParseEventLog(data []byte) (*ParsedEventLog, error) {
	if len(data) < 32 {
		return nil, errors.New("event log too short")
	}

	result := &ParsedEventLog{}
	offset := 0

	// first entry is the legacy header (TCG_PCR_EVENT format)
	// pcr_index (4) + event_type (4) + sha1_digest (20) + event_data_size (4) + event_data
	if len(data) < offset+32 {
		return nil, errors.New("event log truncated at header")
	}

	headerPCR := binary.LittleEndian.Uint32(data[offset:])
	offset += 4
	headerType := binary.LittleEndian.Uint32(data[offset:])
	offset += 4
	offset += 20 // skip SHA-1 digest
	headerDataSize := binary.LittleEndian.Uint32(data[offset:])
	offset += 4

	if headerPCR != 0 || headerType != EvNoAction {
		return nil, fmt.Errorf("invalid event log header: pcr=%d type=0x%x", headerPCR, headerType)
	}

	if len(data) < offset+int(headerDataSize) {
		return nil, errors.New("event log truncated at header data")
	}

	// parse Spec ID Event to get algorithm list
	specData := data[offset : offset+int(headerDataSize)]
	algList, err := parseSpecIDEvent(specData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse Spec ID Event: %w", err)
	}
	result.AlgorithmList = algList
	offset += int(headerDataSize)

	// parse remaining entries as TCG_PCR_EVENT2
	for offset < len(data) {
		entry, consumed, err := parsePCREvent2(data[offset:], algList)
		if err != nil {
			if errors.Is(err, io.ErrUnexpectedEOF) {
				break // truncated log is acceptable
			}
			break // stop on parse errors, use what we have
		}
		if consumed == 0 {
			break
		}
		result.Entries = append(result.Entries, *entry)
		offset += consumed
	}

	return result, nil
}

// extracts algorithm list from Spec ID Event header
func parseSpecIDEvent(data []byte) ([]uint16, error) {
	// spec ID Event structure:
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

	// skip to numberOfAlgorithms at offset 24
	offset := 16 + 4 + 1 + 1 + 1 + 1 // = 24
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
		// digestSize := binary.LittleEndian.Uint16(data[offset+2:])
		offset += 4
		algs = append(algs, algID)
	}

	return algs, nil
}

// parses a single TCG_PCR_EVENT2 entry
func parsePCREvent2(data []byte, algList []uint16) (*EventLogEntry, int, error) {
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

	for i := uint32(0); i < digestCount; i++ {
		if len(data) < offset+2 {
			return nil, 0, io.ErrUnexpectedEOF
		}
		algID := binary.LittleEndian.Uint16(data[offset:])
		offset += 2

		digestSize := algDigestSize(algID)
		if digestSize == 0 {
			// unknown algorithm, try to find size from algList
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

	// event data
	if len(data) < offset+4 {
		return nil, 0, io.ErrUnexpectedEOF
	}
	eventDataSize := binary.LittleEndian.Uint32(data[offset:])
	offset += 4

	if len(data) < offset+int(eventDataSize) {
		return nil, 0, io.ErrUnexpectedEOF
	}
	entry.EventData = make([]byte, eventDataSize)
	copy(entry.EventData, data[offset:offset+int(eventDataSize)])
	offset += int(eventDataSize)

	return entry, offset, nil
}

// returns digest size in bytes for a given TCG algorithm ID
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

// replays the event log to reconstruct PCR values
// starts from all-zero PCRs and applies each extend operation
func ReplayEventLog(parsed *ParsedEventLog) (*ReplayResult, error) {
	if parsed == nil {
		return nil, errors.New("nil event log")
	}

	result := &ReplayResult{}
	for _, entry := range parsed.Entries {
		if entry.PCRIndex >= types.PCRCount {
			continue
		}

		sha256Digest, ok := entry.Digests[AlgSHA256]
		if !ok {
			continue // skip entries without SHA-256 digest
		}

		// PCR extend: new_value = SHA256(old_value || digest)
		h := sha256.New()
		h.Write(result.PCRValues[entry.PCRIndex][:])
		h.Write(sha256Digest)
		copy(result.PCRValues[entry.PCRIndex][:], h.Sum(nil))

		result.ExtendCounts[entry.PCRIndex]++
	}

	result.TotalEntries = len(parsed.Entries)
	return result, nil
}
