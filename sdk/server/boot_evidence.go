// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek

package server

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
)

// Boot evidence wire format constants (see: include/lota_token.h)
const BootEvidenceVersion uint16 = 0x0001

const (
	BootEvidenceHeaderSize = 8
	BootEvidenceEventSize  = 34 // digest + data_size
	BootEvidenceMaxSize    = 8192
)

const (
	pcrCount         = 24
	pcrSecureBoot    = 7
	efiVariableHdr   = 16 + 8 + 8 // GUID, name length, data length
	secureBootNameSz = 20
)

// EFI global variable namespace 8be4df61-93ca-11d2-aa0d-00e098032b8c
var efiGlobalGUID = []byte{
	0x61, 0xdf, 0xe4, 0x8b, 0xca, 0x93, 0xd2, 0x11,
	0xaa, 0x0d, 0x00, 0xe0, 0x98, 0x03, 0x2b, 0x8c,
}

// "SecureBoot" in UTF-16LE
var secureBootName = []byte{
	'S', 0, 'e', 0, 'c', 0, 'u', 0, 'r', 0,
	'e', 0, 'B', 0, 'o', 0, 'o', 0, 't', 0,
}

// secureBootVote reads a UEFI_VARIABLE_DATA event: 1 for SecureBoot=1,
// 0 for any other SecureBoot value, -1 for any other variable.
func secureBootVote(data []byte) int {
	if len(data) < efiVariableHdr+secureBootNameSz {
		return -1
	}
	if !bytes.Equal(data[:16], efiGlobalGUID) {
		return -1
	}
	nameLen := binary.LittleEndian.Uint64(data[16:])
	valueLen := binary.LittleEndian.Uint64(data[24:])
	if nameLen != secureBootNameSz/2 ||
		!bytes.Equal(data[efiVariableHdr:efiVariableHdr+secureBootNameSz], secureBootName) {
		return -1
	}

	value := data[efiVariableHdr+secureBootNameSz:]
	if valueLen != uint64(len(value)) {
		return 0
	}
	if valueLen == 1 && value[0] == 1 {
		return 1
	}
	return 0
}

// VerifyBootEvidence reads Secure Boot from the PCRs a verified token quotes.
//
// Parameters:
//   - claims: Claims VerifyToken returned for the token; ParseToken claims
//     prove nothing
//   - evidence: bytes the agent returned next to the token
//
// Accepts the evidence only when its PCR values hash to the signed PCR
// digest and its PCR 7 events replay to the PCR 7 value, so a host cannot
// rewrite it. A SecureBoot measurement that is absent, carries any value but
// 1 or comes after the firmware's separator reads as off, as does evidence
// with no separator.
//
// Returns ErrInvalidArg for nil claims and ErrBadEvidence for evidence that
// is malformed or describes another boot; secureBoot is false on any error.
func VerifyBootEvidence(claims *Claims, evidence []byte) (secureBoot bool, err error) {
	if claims == nil {
		return false, ErrInvalidArg
	}
	if len(evidence) < BootEvidenceHeaderSize ||
		binary.LittleEndian.Uint16(evidence) != BootEvidenceVersion {
		return false, ErrBadEvidence
	}
	count := binary.LittleEndian.Uint16(evidence[2:])
	mask := binary.LittleEndian.Uint32(evidence[4:])
	if mask != claims.PCRMask || len(claims.PCRDigest) != sha256.Size ||
		mask&(1<<pcrSecureBoot) == 0 || mask>>pcrCount != 0 {
		return false, ErrBadEvidence
	}
	p := evidence[BootEvidenceHeaderSize:]

	// the PCR values, checked against the digest the TPM signed
	var pcr7 []byte
	h := sha256.New()
	for i := 0; i < pcrCount; i++ {
		if mask&(1<<i) == 0 {
			continue
		}
		if len(p) < sha256.Size {
			return false, ErrBadEvidence
		}
		h.Write(p[:sha256.Size])
		if i == pcrSecureBoot {
			pcr7 = p[:sha256.Size]
		}
		p = p[sha256.Size:]
	}
	if subtle.ConstantTimeCompare(h.Sum(nil), claims.PCRDigest) != 1 {
		return false, ErrBadEvidence
	}

	// The events, replayed to the PCR 7 value. Event types are labels
	// the log carries outside the digest, so only digests and data count:
	// the separator is the first event that extends SHA-256 of four zero
	// bytes, and only a SecureBoot measurement before it is the firmware's.
	separator := sha256.Sum256(make([]byte, 4))
	var chain [2 * sha256.Size]byte
	votesOn, votesOff, beforeSeparator := 0, 0, true
	for i := 0; i < int(count); i++ {
		if len(p) < BootEvidenceEventSize {
			return false, ErrBadEvidence
		}
		digest := p[:sha256.Size]
		dataSize := int(binary.LittleEndian.Uint16(p[sha256.Size:]))
		p = p[BootEvidenceEventSize:]
		if len(p) < dataSize {
			return false, ErrBadEvidence
		}

		if dataSize > 0 {
			sum := sha256.Sum256(p[:dataSize])
			if subtle.ConstantTimeCompare(sum[:], digest) != 1 {
				return false, ErrBadEvidence
			}
			vote := secureBootVote(p[:dataSize])
			if beforeSeparator && vote == 1 {
				votesOn++
			} else if beforeSeparator && vote == 0 {
				votesOff++
			}
		}
		if bytes.Equal(digest, separator[:]) {
			beforeSeparator = false
		}

		copy(chain[sha256.Size:], digest)
		next := sha256.Sum256(chain[:])
		copy(chain[:sha256.Size], next[:])
		p = p[dataSize:]
	}
	if len(p) != 0 || subtle.ConstantTimeCompare(chain[:sha256.Size], pcr7) != 1 {
		return false, ErrBadEvidence
	}

	return !beforeSeparator && votesOn > 0 && votesOff == 0, nil
}
