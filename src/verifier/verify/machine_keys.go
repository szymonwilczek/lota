// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek

package verify

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
)

// MOK list states.
const (
	// MOKListed means the list hashes to the first PCR 14 event,
	// named MokList.
	MOKListed = "listed"
	// MOKNotMeasured means the log has no PCR 14 event.
	MOKNotMeasured = "not_measured"
	// MOKUnproven means there is no log, or its first PCR 14 event is not
	// a MokList the list hashes to.
	MOKUnproven = "unproven"
)

// signature types of an EFI_SIGNATURE_LIST, in on-disk GUID byte order
var (
	efiCertX509GUID = [16]byte{
		0xa1, 0x59, 0xc0, 0xa5, 0xe4, 0x94, 0xa7, 0x4a,
		0x87, 0xb5, 0xab, 0x15, 0x5c, 0x2b, 0xf0, 0x72,
	}
	efiCertSHA256GUID = [16]byte{
		0x26, 0x16, 0xc4, 0xc1, 0x4c, 0x50, 0x92, 0x40,
		0xac, 0xa9, 0x41, 0xf9, 0x36, 0x93, 0x43, 0x28,
	}
)

// MachineKey is one signature database entry.
type MachineKey struct {
	Type    string `json:"type"`              // x509, sha256 or the type's GUID
	SHA256  string `json:"sha256"`            // certificate fingerprint or the hash itself
	Subject string `json:"subject,omitempty"` // certificate subject, when it parses
}

// MachineKeys lists the keys a machine trusts at boot and for its modules.
// DB is read from a PCR 7 event whose digest is the hash of its data;
// MOK holds the agent's list only when it is MOKListed.
type MachineKeys struct {
	DB       []MachineKey `json:"db"`
	MOK      []MachineKey `json:"mok"`
	MOKState string       `json:"mok_state"`
}

// ExtractMachineKeys reads the keys out of a quote-authenticated log and the
// MOK list the agent sent.
func ExtractMachineKeys(parsed *ParsedEventLog, mokList []byte) *MachineKeys {
	keys := &MachineKeys{
		DB:       parseSignatureLists(pcr7Variables(parsed)["db"]),
		MOK:      []MachineKey{},
		MOKState: mokListState(parsed, mokList),
	}
	if keys.MOKState == MOKListed {
		keys.MOK = parseSignatureLists(mokList)
	}
	return keys
}

// mokListState checks mokList against the first PCR 14 event alone: event
// data is outside the digest, so only the event's position binds its name.
func mokListState(parsed *ParsedEventLog, mokList []byte) string {
	if parsed == nil {
		return MOKUnproven
	}
	for i := range parsed.Entries {
		e := &parsed.Entries[i]
		if e.PCRIndex != pcr14Index || e.EventType == EvNoAction {
			continue
		}
		sum := sha256.Sum256(mokList)
		if string(bytes.TrimRight(e.EventData, "\x00")) == "MokList" &&
			bytes.Equal(e.Digests[AlgSHA256], sum[:]) {
			return MOKListed
		}
		return MOKUnproven
	}
	return MOKNotMeasured
}

// parseSignatureLists walks EFI_SIGNATURE_LIST records.
// A malformed record ends the walk, and the keys before it are returned.
func parseSignatureLists(data []byte) []MachineKey {
	const (
		listHeaderSize = 28 // SignatureType, ListSize, HeaderSize, SignatureSize
		ownerSize      = 16 // SignatureOwner in front of each entry
	)

	keys := []MachineKey{}
	for len(data) >= listHeaderSize {
		listSize := uint64(binary.LittleEndian.Uint32(data[16:]))
		headerSize := uint64(binary.LittleEndian.Uint32(data[20:]))
		sigSize := uint64(binary.LittleEndian.Uint32(data[24:]))
		if listSize > uint64(len(data)) || sigSize <= ownerSize ||
			listSize < listHeaderSize+headerSize {
			break
		}

		var sigType [16]byte
		copy(sigType[:], data)
		for sigs := data[listHeaderSize+headerSize : listSize]; uint64(len(sigs)) >= sigSize; sigs = sigs[sigSize:] {
			keys = append(keys, machineKey(sigType, sigs[ownerSize:sigSize]))
		}
		data = data[listSize:]
	}
	return keys
}

func machineKey(sigType [16]byte, sig []byte) MachineKey {
	sum := sha256.Sum256(sig)
	key := MachineKey{Type: hex.EncodeToString(sigType[:]), SHA256: hex.EncodeToString(sum[:])}

	switch sigType {
	case efiCertX509GUID:
		key.Type = "x509"
		key.Subject = certSubject(sig)
	case efiCertSHA256GUID:
		key.Type = "sha256"
		key.SHA256 = hex.EncodeToString(sig)
	}
	return key
}

// certSubject reads the subject alone, since x509.ParseCertificate refuses
// firmware certificates with a negative serial. asn1 ignores the later fields.
func certSubject(der []byte) string {
	var cert struct {
		TBS struct {
			Version  asn1.RawValue `asn1:"optional,explicit,tag:0"`
			Serial   asn1.RawValue
			SigAlg   asn1.RawValue
			Issuer   asn1.RawValue
			Validity asn1.RawValue
			Subject  pkix.RDNSequence
		}
	}
	if _, err := asn1.Unmarshal(der, &cert); err != nil {
		return ""
	}
	var name pkix.Name
	name.FillFromRDNSequence(&cert.TBS.Subject)
	return name.String()
}
