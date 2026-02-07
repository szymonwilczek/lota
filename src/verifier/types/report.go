// SPDX-License-Identifier: MIT
// LOTA Verifier - Wire format types
// Go equivalents of include/attestation.h

package types

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// protocol constants
const (
	ReportMagic   uint32 = 0x41544F4C // "LOTA" little-endian
	ReportVersion uint32 = 0x00010000 // 1.0.0

	HashSize        = 32   // SHA-256
	NonceSize       = 32   // Challenge nonce
	HardwareIDSize  = 32   // SHA-256 of EK public key
	MaxSigSize      = 512  // RSA-4096 signature
	MaxAttestSize   = 1024 // TPMS_ATTEST blob
	MaxAIKPubSize   = 512  // AIK public key (DER SPKI)
	MaxAIKCertSize  = 2048 // AIK certificate (DER X.509)
	MaxEKCertSize   = 2048 // EK certificate (DER X.509)
	PCRCount        = 24   // TPM PCR bank size
	MaxKernelPath   = 256
	CmdlineParamMax = 64
)

// report flags (see: include/attestation.h)
const (
	FlagIOMMUOK      uint32 = 1 << 0 // IOMMU verification passed
	FlagTPMQuoteOK   uint32 = 1 << 1 // TPM quote succeeded
	FlagKernelHashOK uint32 = 1 << 2 // Kernel hash computed
	FlagBPFActive    uint32 = 1 << 3 // eBPF LSM is loaded
	FlagModuleSig    uint32 = 1 << 4 // Kernel enforces module sigs
	FlagLockdown     uint32 = 1 << 5 // Kernel lockdown active
	FlagSecureBoot   uint32 = 1 << 6 // Secure Boot enabled
	FlagEnforce      uint32 = 1 << 7 // LSM enforce mode active
)

// verification result codes
const (
	VerifyOK                uint32 = 0
	VerifyNonceFail         uint32 = 1
	VerifySigFail           uint32 = 2
	VerifyPCRFail           uint32 = 3
	VerifyIOMMUFail         uint32 = 4
	VerifyOldVersion        uint32 = 5
	VerifyIntegrityMismatch uint32 = 6
	VerifyRevoked           uint32 = 7 // AIK revoked by administrator
	VerifyBanned            uint32 = 8 // hardware ID banned
)

// struct lota_report_header (see: include/attestation.h)
type ReportHeader struct {
	Magic       uint32 // offset 0
	Version     uint32 // offset 4
	Timestamp   uint64 // offset 8
	TimestampNs uint64 // offset 16
	ReportSize  uint32 // offset 24
	Flags       uint32 // offset 28
}

// struct lota_tpm_evidence (see: include/attestation.h)
//
//	pcr_values[24][32]     768 bytes
//	pcr_mask                 4 bytes
//	quote_signature[512]   512 bytes
//	quote_sig_size           2 bytes
//	attest_data[1024]     1024 bytes
//	attest_size              2 bytes
//	aik_public[512]        512 bytes
//	aik_public_size          2 bytes
//	aik_certificate[2048] 2048 bytes
//	aik_cert_size            2 bytes
//	ek_certificate[2048]  2048 bytes
//	ek_cert_size             2 bytes
//	nonce[32]               32 bytes
//	hardware_id[32]         32 bytes
//	reserved[2]              2 bytes
//	TOTAL:                6992 bytes
type TPMEvidence struct {
	PCRValues      [PCRCount][HashSize]byte // 768 bytes
	PCRMask        uint32                   // 4 bytes
	QuoteSignature [MaxSigSize]byte         // 512 bytes
	QuoteSigSize   uint16                   // 2 bytes
	AttestData     [MaxAttestSize]byte      // 1024 bytes
	AttestSize     uint16                   // 2 bytes
	AIKPublic      [MaxAIKPubSize]byte      // 512 bytes
	AIKPublicSize  uint16                   // 2 bytes
	AIKCertificate [MaxAIKCertSize]byte     // 2048 bytes
	AIKCertSize    uint16                   // 2 bytes
	EKCertificate  [MaxEKCertSize]byte      // 2048 bytes
	EKCertSize     uint16                   // 2 bytes
	Nonce          [NonceSize]byte          // 32 bytes
	HardwareID     [HardwareIDSize]byte     // 32 bytes
	Reserved       [2]byte                  // 2 bytes alignment
}

// struct iommu_status (see: include/iommu_types.h)
type IOMMUStatus struct {
	Vendor       uint32
	Flags        uint32
	UnitCount    uint32
	CmdlineParam [CmdlineParamMax]byte // 64 bytes
}

// struct lota_system_measurement (see: include/attestation.h)
type SystemMeasurement struct {
	KernelHash [HashSize]byte      // 32 bytes
	AgentHash  [HashSize]byte      // 32 bytes
	KernelPath [MaxKernelPath]byte // 256 bytes
	IOMMU      IOMMUStatus         // 76 bytes
}

// struct lota_bpf_summary (see: include/attestation.h)
type BPFSummary struct {
	TotalExecEvents uint32 // 4 bytes
	UniqueBinaries  uint32 // 4 bytes
	FirstEventTS    uint64 // 8 bytes
	LastEventTS     uint64 // 8 bytes
}

// struct lota_attestation_report (see: include/attestation.h)
type AttestationReport struct {
	Header ReportHeader      // 32 bytes
	TPM    TPMEvidence       // 2860 bytes
	System SystemMeasurement // 396 bytes (364 + 32 for agent_hash)
	BPF    BPFSummary        // 24 bytes
}

// Challenge for attestation protocol (48 bytes)
type Challenge struct {
	Magic   uint32
	Version uint32
	Nonce   [NonceSize]byte
	PCRMask uint32
	Flags   uint32
}

// VerifyResult returned to agent (56 bytes)
type VerifyResult struct {
	Magic        uint32
	Version      uint32
	Result       uint32
	Flags        uint32
	ValidUntil   uint64
	SessionToken [32]byte
}

// errors
var (
	ErrInvalidMagic   = errors.New("invalid report magic")
	ErrInvalidVersion = errors.New("unsupported protocol version")
	ErrInvalidSize    = errors.New("invalid report size")
)

// expected binary size of AttestationReport
// Header(32) + TPM(6992) + System(396) + BPF(24) = 7444
const ExpectedReportSize = 7444

// deserializes a binary attestation report
func ParseReport(data []byte) (*AttestationReport, error) {
	if len(data) < ExpectedReportSize {
		return nil, fmt.Errorf("%w: got %d, expected %d", ErrInvalidSize, len(data), ExpectedReportSize)
	}

	report := &AttestationReport{}
	offset := 0

	// header (32 bytes)
	report.Header.Magic = binary.LittleEndian.Uint32(data[offset:])
	offset += 4
	if report.Header.Magic != ReportMagic {
		return nil, fmt.Errorf("%w: got 0x%08X, expected 0x%08X", ErrInvalidMagic, report.Header.Magic, ReportMagic)
	}

	report.Header.Version = binary.LittleEndian.Uint32(data[offset:])
	offset += 4
	if report.Header.Version != ReportVersion {
		return nil, fmt.Errorf("%w: got 0x%08X, expected 0x%08X",
			ErrInvalidVersion, report.Header.Version, ReportVersion)
	}

	report.Header.Timestamp = binary.LittleEndian.Uint64(data[offset:])
	offset += 8
	report.Header.TimestampNs = binary.LittleEndian.Uint64(data[offset:])
	offset += 8
	report.Header.ReportSize = binary.LittleEndian.Uint32(data[offset:])
	offset += 4
	report.Header.Flags = binary.LittleEndian.Uint32(data[offset:])
	offset += 4

	// tpm evidence (6992 bytes)
	// pcr values: 24 * 32 = 768 bytes
	for i := 0; i < PCRCount; i++ {
		copy(report.TPM.PCRValues[i][:], data[offset:offset+HashSize])
		offset += HashSize
	}
	report.TPM.PCRMask = binary.LittleEndian.Uint32(data[offset:])
	offset += 4
	copy(report.TPM.QuoteSignature[:], data[offset:offset+MaxSigSize])
	offset += MaxSigSize
	report.TPM.QuoteSigSize = binary.LittleEndian.Uint16(data[offset:])
	offset += 2
	copy(report.TPM.AttestData[:], data[offset:offset+MaxAttestSize])
	offset += MaxAttestSize
	report.TPM.AttestSize = binary.LittleEndian.Uint16(data[offset:])
	offset += 2
	copy(report.TPM.AIKPublic[:], data[offset:offset+MaxAIKPubSize])
	offset += MaxAIKPubSize
	report.TPM.AIKPublicSize = binary.LittleEndian.Uint16(data[offset:])
	offset += 2
	copy(report.TPM.AIKCertificate[:], data[offset:offset+MaxAIKCertSize])
	offset += MaxAIKCertSize
	report.TPM.AIKCertSize = binary.LittleEndian.Uint16(data[offset:])
	offset += 2
	copy(report.TPM.EKCertificate[:], data[offset:offset+MaxEKCertSize])
	offset += MaxEKCertSize
	report.TPM.EKCertSize = binary.LittleEndian.Uint16(data[offset:])
	offset += 2
	copy(report.TPM.Nonce[:], data[offset:offset+NonceSize])
	offset += NonceSize
	copy(report.TPM.HardwareID[:], data[offset:offset+HardwareIDSize])
	offset += HardwareIDSize
	offset += 2 // reserved

	// system measurement (396 bytes)
	copy(report.System.KernelHash[:], data[offset:offset+HashSize])
	offset += HashSize
	copy(report.System.AgentHash[:], data[offset:offset+HashSize])
	offset += HashSize
	copy(report.System.KernelPath[:], data[offset:offset+MaxKernelPath])
	offset += MaxKernelPath

	// iommu status (76 bytes)
	report.System.IOMMU.Vendor = binary.LittleEndian.Uint32(data[offset:])
	offset += 4
	report.System.IOMMU.Flags = binary.LittleEndian.Uint32(data[offset:])
	offset += 4
	report.System.IOMMU.UnitCount = binary.LittleEndian.Uint32(data[offset:])
	offset += 4
	copy(report.System.IOMMU.CmdlineParam[:], data[offset:offset+CmdlineParamMax])
	offset += CmdlineParamMax

	// bpf summary (24 bytes)
	report.BPF.TotalExecEvents = binary.LittleEndian.Uint32(data[offset:])
	offset += 4
	report.BPF.UniqueBinaries = binary.LittleEndian.Uint32(data[offset:])
	offset += 4
	report.BPF.FirstEventTS = binary.LittleEndian.Uint64(data[offset:])
	offset += 8
	report.BPF.LastEventTS = binary.LittleEndian.Uint64(data[offset:])

	return report, nil
}

// creates binary challenge for agent
func (c *Challenge) Serialize() []byte {
	data := make([]byte, 48) // 4+4+32+4+4
	binary.LittleEndian.PutUint32(data[0:4], c.Magic)
	binary.LittleEndian.PutUint32(data[4:8], c.Version)
	copy(data[8:40], c.Nonce[:])
	binary.LittleEndian.PutUint32(data[40:44], c.PCRMask)
	binary.LittleEndian.PutUint32(data[44:48], c.Flags)
	return data
}

// creates binary result for agent
func (r *VerifyResult) Serialize() []byte {
	data := make([]byte, 56) // 4+4+4+4+8+32
	binary.LittleEndian.PutUint32(data[0:4], r.Magic)
	binary.LittleEndian.PutUint32(data[4:8], r.Version)
	binary.LittleEndian.PutUint32(data[8:12], r.Result)
	binary.LittleEndian.PutUint32(data[12:16], r.Flags)
	binary.LittleEndian.PutUint64(data[16:24], r.ValidUntil)
	copy(data[24:56], r.SessionToken[:])
	return data
}

// returns null-terminated kernel path as string
func (s *SystemMeasurement) GetKernelPath() string {
	for i, b := range s.KernelPath {
		if b == 0 {
			return string(s.KernelPath[:i])
		}
	}
	return string(s.KernelPath[:])
}
