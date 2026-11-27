// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
// LOTA Verifier - Wire format types
// Go equivalents of include/attestation.h

package types

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	ReportMagic uint32 = 0x41544F4C // "LOTA" little-endian
	// ReportVersion is LOTA_REPORT_VERSION of include/lota.h; ParseReport
	// accepts no other.
	ReportVersion uint32 = 0x00010000 // 1.0.0

	HashSize        = 32 // SHA-256
	NonceSize       = 32
	HardwareIDSize  = 32
	MaxSigSize      = 512
	MaxAttestSize   = 1024
	MaxAIKPubSize   = 512
	MaxAIKCertSize  = 2048
	PCRCount        = 24
	MaxKernelPath   = 256
	CmdlineParamMax = 64
)

// report flags (see: include/attestation.h)
const (
	FlagIOMMUOK      uint32 = 1 << 0
	FlagTPMQuoteOK   uint32 = 1 << 1
	FlagKernelHashOK uint32 = 1 << 2
	FlagBPFActive    uint32 = 1 << 3
	FlagModuleSig    uint32 = 1 << 4
	FlagLockdown     uint32 = 1 << 5
	FlagSecureBoot   uint32 = 1 << 6
	FlagEnforce      uint32 = 1 << 7

	// FlagBootCommitmentV1 and FlagInitramfsLockV1 name the one PCR 14
	// derivation the verifier rederives; a report without both is refused.
	FlagBootCommitmentV1 uint32 = 1 << 8
	FlagInitramfsLockV1  uint32 = 1 << 9

	// FlagIMAAppraisal is clear on a stock host; a policy may require it.
	FlagIMAAppraisal uint32 = 1 << 10

	FlagBench uint32 = 1 << 11

	// The policy keys the daemon applies, set with FlagEnforce only.
	// Logged, not a verdict.
	FlagStrictMmap    uint32 = 1 << 12
	FlagStrictExec    uint32 = 1 << 13
	FlagStrictModules uint32 = 1 << 14
	FlagBlockAnonExec uint32 = 1 << 15
	FlagBlockPtrace   uint32 = 1 << 16

	// FlagEventsLost: the kernel left events out of the daemon's log.
	// Logged, not a verdict.
	FlagEventsLost uint32 = 1 << 17
)

// challenge capability flags (see: include/attestation.h)
const (
	// ChallengeFlagBootCommitmentV1 names the PCR 14 derivation the
	// verifier validates; every challenge carries it.
	ChallengeFlagBootCommitmentV1 uint32 = 1 << 0
)

const (
	VerifyOK                uint32 = 0
	VerifyNonceFail         uint32 = 1
	VerifySigFail           uint32 = 2
	VerifyPCRFail           uint32 = 3
	VerifyIOMMUFail         uint32 = 4
	VerifyOldVersion        uint32 = 5
	VerifyIntegrityMismatch uint32 = 6
	VerifyRevoked           uint32 = 7
	VerifyBanned            uint32 = 8
	VerifyInternalError     uint32 = 9 // also VerifyReportFrom's default

	// VerifyIdentityFail: the AIK certificate names another key, or its
	// pseudonym or tenant is invalid; checked before the quote signature.
	// Re-enrolling fixes it, unlike VerifySigFail.
	VerifyIdentityFail uint32 = 10

	// a policy requirement with no code below; the fix is not in the boot
	// chain, unlike VerifyPCRFail
	VerifyPolicyRequirement uint32 = 11

	// the AIK certificate has expired or is not yet valid
	VerifyCertificateValidity uint32 = 12

	VerifyCertificateMissing uint32 = 13

	VerifySecureBootRequired   uint32 = 14
	VerifyLockdownRequired     uint32 = 15
	VerifyModuleSigRequired    uint32 = 16
	VerifyEnforceRequired      uint32 = 17
	VerifyIMAAppraisalRequired uint32 = 18
	VerifyKernelImageRequired  uint32 = 19
	VerifyCmdlineRequired      uint32 = 20

	// unparsable for a reason other than the version field; an upgrade does
	// not fix it, unlike VerifyOldVersion
	VerifyReportMalformed uint32 = 21
)

// PolicyKeys names the policy keys a report header says the daemon applies,
// in the order of their bits. A key outside enforce mode is not reported.
func PolicyKeys(flags uint32) []string {
	if flags&FlagEnforce == 0 {
		return nil
	}

	keys := []struct {
		flag uint32
		name string
	}{
		{FlagStrictMmap, "strict_mmap"},
		{FlagStrictExec, "strict_exec"},
		{FlagStrictModules, "strict_modules"},
		{FlagBlockAnonExec, "block_anon_exec"},
		{FlagBlockPtrace, "block_ptrace"},
	}
	var names []string
	for _, k := range keys {
		if flags&k.flag != 0 {
			names = append(names, k.name)
		}
	}
	return names
}

// VerifyResultString returns the exported name of a result code.
func VerifyResultString(code uint32) string {
	switch code {
	case VerifyOK:
		return "ok"
	case VerifyNonceFail:
		return "nonce_fail"
	case VerifySigFail:
		return "sig_fail"
	case VerifyPCRFail:
		return "pcr_fail"
	case VerifyIOMMUFail:
		return "iommu_fail"
	case VerifyOldVersion:
		return "old_version"
	case VerifyIntegrityMismatch:
		return "integrity_mismatch"
	case VerifyRevoked:
		return "revoked"
	case VerifyBanned:
		return "banned"
	case VerifyInternalError:
		return "internal_error"
	case VerifyIdentityFail:
		return "identity_fail"
	case VerifyPolicyRequirement:
		return "policy_requirement"
	case VerifyCertificateValidity:
		return "certificate_validity"
	case VerifyCertificateMissing:
		return "certificate_missing"
	case VerifySecureBootRequired:
		return "secureboot_required"
	case VerifyLockdownRequired:
		return "lockdown_required"
	case VerifyModuleSigRequired:
		return "module_sig_required"
	case VerifyEnforceRequired:
		return "enforce_required"
	case VerifyIMAAppraisalRequired:
		return "ima_appraisal_required"
	case VerifyKernelImageRequired:
		return "kernel_image_required"
	case VerifyCmdlineRequired:
		return "cmdline_required"
	case VerifyReportMalformed:
		return "report_malformed"
	default:
		return fmt.Sprintf("unknown_%d", code)
	}
}

// RejectionReasons returns the exported name of every refusing verdict.
func RejectionReasons() []string {
	return []string{
		VerifyResultString(VerifyNonceFail),
		VerifyResultString(VerifySigFail),
		VerifyResultString(VerifyPCRFail),
		VerifyResultString(VerifyIOMMUFail),
		VerifyResultString(VerifyOldVersion),
		VerifyResultString(VerifyIntegrityMismatch),
		VerifyResultString(VerifyRevoked),
		VerifyResultString(VerifyBanned),
		VerifyResultString(VerifyInternalError),
		VerifyResultString(VerifyIdentityFail),
		VerifyResultString(VerifyPolicyRequirement),
		VerifyResultString(VerifyCertificateValidity),
		VerifyResultString(VerifyCertificateMissing),
		VerifyResultString(VerifySecureBootRequired),
		VerifyResultString(VerifyLockdownRequired),
		VerifyResultString(VerifyModuleSigRequired),
		VerifyResultString(VerifyEnforceRequired),
		VerifyResultString(VerifyIMAAppraisalRequired),
		VerifyResultString(VerifyKernelImageRequired),
		VerifyResultString(VerifyCmdlineRequired),
		VerifyResultString(VerifyReportMalformed),
	}
}

// ReportHeader is struct lota_report_header (include/attestation.h).
type ReportHeader struct {
	Magic      uint32 // offset 0
	Version    uint32 // offset 4
	ReportSize uint32 // offset 8
	Flags      uint32 // offset 12
}

// TPMEvidence is struct lota_tpm_evidence (include/attestation.h),
// 4912 bytes on the wire.
type TPMEvidence struct {
	PCRValues       [PCRCount][HashSize]byte
	PCRMask         uint32
	QuoteSignature  [MaxSigSize]byte
	QuoteSigSize    uint16
	AttestData      [MaxAttestSize]byte
	AttestSize      uint16
	AIKPublic       [MaxAIKPubSize]byte
	AIKPublicSize   uint16
	AIKCertificate  [MaxAIKCertSize]byte
	AIKCertSize     uint16
	Nonce           [NonceSize]byte
	QuoteSigAlg     uint16
	QuoteSigHashAlg uint16
}

// IOMMUStatus is struct iommu_status (include/iommu_types.h).
type IOMMUStatus struct {
	Vendor       uint32
	Flags        uint32
	UnitCount    uint32
	CmdlineParam [CmdlineParamMax]byte
}

// SystemMeasurement is struct lota_system_measurement (include/attestation.h),
// 396 bytes on the wire.
type SystemMeasurement struct {
	KernelHash [HashSize]byte
	AgentHash  [HashSize]byte
	KernelPath [MaxKernelPath]byte
	IOMMU      IOMMUStatus
}

// AttestationReport is struct lota_attestation_report (include/attestation.h)
// followed by the variable-length sections.
type AttestationReport struct {
	Header ReportHeader
	TPM    TPMEvidence
	System SystemMeasurement

	EventLog []byte // TCG binary event log

	// ESRT is always set by ParseReport. Present == false means the
	// platform exposed no ESRT System Firmware entry, not that the section
	// was missing.
	ESRT *ESRTInfo

	// MokList is the agent's copy of MokListRT, unverified until compared with
	// the MokList event of the quote-authenticated log. Empty when not sent.
	MokList []byte
}

// ESRTInfo is struct lota_esrt (include/attestation.h): the platform's ESRT
// System Firmware version, the firmware rollback signal of self-service
// re-anchor.
type ESRTInfo struct {
	Present         bool
	FWVersion       uint32
	LowestSupported uint32
	FWClass         [16]byte
}

// ESRTWireSize is the fixed serialized length of the ESRT section.
const ESRTWireSize = 28

// MokListSizeLen is the length prefix of the MOK list section.
const MokListSizeLen = 4

// Challenge is the 48-byte challenge the verifier sends.
type Challenge struct {
	Magic   uint32
	Version uint32
	Nonce   [NonceSize]byte
	PCRMask uint32
	Flags   uint32
}

// VerifyResult is the 24-byte result the verifier sends.
type VerifyResult struct {
	Magic      uint32
	Version    uint32
	Result     uint32
	Flags      uint32
	ValidUntil uint64
}

var (
	ErrInvalidMagic   = errors.New("invalid report magic")
	ErrInvalidVersion = errors.New("unsupported protocol version")
	ErrInvalidSize    = errors.New("invalid report size")
)

// MinReportSize is a report with empty variable sections: Header(16) +
// TPM(4912) + System(396) + event_log_size(4) + ESRT(28) + mok_list_size(4).
const MinReportSize = 5360

// MaxEventLogSize is the largest event log section;
// the agent reads at most TPM_MAX_EVENT_LOG_SIZE (src/agent/tpm.h).
const MaxEventLogSize = 512 * 1024

// MaxMokListSize is the largest MOK list section;
// the agent reads at most MOK_LIST_MAX (src/agent/moklist.h).
const MaxMokListSize = 32 * 1024

// MaxReportWireSize caps a report before the verifier allocates for it:
// the fixed part with both variable sections at their limits.
const MaxReportWireSize = FixedReportSize + 4 + MaxEventLogSize +
	ESRTWireSize + MokListSizeLen + MaxMokListSize

// FixedReportSize is Header(16) + TPM(4912) + System(396).
const FixedReportSize = 5324

// ParseReport parses a wire report, refusing any version but ReportVersion.
func ParseReport(data []byte) (*AttestationReport, error) {
	if len(data) < MinReportSize {
		return nil, fmt.Errorf("%w: got %d, minimum %d", ErrInvalidSize, len(data), MinReportSize)
	}

	report := &AttestationReport{}
	offset := 0

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

	report.Header.ReportSize = binary.LittleEndian.Uint32(data[offset:])
	offset += 4
	report.Header.Flags = binary.LittleEndian.Uint32(data[offset:])
	offset += 4

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
	if report.TPM.QuoteSigSize > MaxSigSize {
		return nil, fmt.Errorf("%w: quote_sig_size %d exceeds max %d", ErrInvalidSize, report.TPM.QuoteSigSize, MaxSigSize)
	}
	copy(report.TPM.AttestData[:], data[offset:offset+MaxAttestSize])
	offset += MaxAttestSize
	report.TPM.AttestSize = binary.LittleEndian.Uint16(data[offset:])
	offset += 2
	if report.TPM.AttestSize > MaxAttestSize {
		return nil, fmt.Errorf("%w: attest_size %d exceeds max %d", ErrInvalidSize, report.TPM.AttestSize, MaxAttestSize)
	}
	copy(report.TPM.AIKPublic[:], data[offset:offset+MaxAIKPubSize])
	offset += MaxAIKPubSize
	report.TPM.AIKPublicSize = binary.LittleEndian.Uint16(data[offset:])
	offset += 2
	if report.TPM.AIKPublicSize > MaxAIKPubSize {
		return nil, fmt.Errorf("%w: aik_public_size %d exceeds max %d", ErrInvalidSize, report.TPM.AIKPublicSize, MaxAIKPubSize)
	}
	copy(report.TPM.AIKCertificate[:], data[offset:offset+MaxAIKCertSize])
	offset += MaxAIKCertSize
	report.TPM.AIKCertSize = binary.LittleEndian.Uint16(data[offset:])
	offset += 2
	if report.TPM.AIKCertSize > MaxAIKCertSize {
		return nil, fmt.Errorf("%w: aik_cert_size %d exceeds max %d", ErrInvalidSize, report.TPM.AIKCertSize, MaxAIKCertSize)
	}
	copy(report.TPM.Nonce[:], data[offset:offset+NonceSize])
	offset += NonceSize
	report.TPM.QuoteSigAlg = binary.LittleEndian.Uint16(data[offset:])
	offset += 2
	report.TPM.QuoteSigHashAlg = binary.LittleEndian.Uint16(data[offset:])
	offset += 2

	copy(report.System.KernelHash[:], data[offset:offset+HashSize])
	offset += HashSize
	copy(report.System.AgentHash[:], data[offset:offset+HashSize])
	offset += HashSize
	copy(report.System.KernelPath[:], data[offset:offset+MaxKernelPath])
	offset += MaxKernelPath

	report.System.IOMMU.Vendor = binary.LittleEndian.Uint32(data[offset:])
	offset += 4
	report.System.IOMMU.Flags = binary.LittleEndian.Uint32(data[offset:])
	offset += 4
	report.System.IOMMU.UnitCount = binary.LittleEndian.Uint32(data[offset:])
	offset += 4
	copy(report.System.IOMMU.CmdlineParam[:], data[offset:offset+CmdlineParamMax])
	offset += CmdlineParamMax

	if len(data) < offset+4 {
		return nil, fmt.Errorf("%w: truncated at event_log_size", ErrInvalidSize)
	}
	eventLogSize := binary.LittleEndian.Uint32(data[offset:])
	offset += 4
	if eventLogSize > MaxEventLogSize {
		return nil, fmt.Errorf("%w: event_log_size %d exceeds max %d",
			ErrInvalidSize, eventLogSize, MaxEventLogSize)
	}
	if len(data) < offset+int(eventLogSize) {
		return nil, fmt.Errorf("%w: truncated at event_log (need %d, have %d)",
			ErrInvalidSize, eventLogSize, len(data)-offset)
	}
	if eventLogSize > 0 {
		report.EventLog = make([]byte, eventLogSize)
		copy(report.EventLog, data[offset:offset+int(eventLogSize)])
	}
	offset += int(eventLogSize)

	if len(data) < offset+ESRTWireSize {
		return nil, fmt.Errorf("%w: report ends before the ESRT section (need %d more bytes)",
			ErrInvalidSize, offset+ESRTWireSize-len(data))
	}
	esrt := &ESRTInfo{}
	esrt.Present = binary.LittleEndian.Uint32(data[offset:]) != 0
	offset += 4
	esrt.FWVersion = binary.LittleEndian.Uint32(data[offset:])
	offset += 4
	esrt.LowestSupported = binary.LittleEndian.Uint32(data[offset:])
	offset += 4
	copy(esrt.FWClass[:], data[offset:offset+16])
	offset += 16
	report.ESRT = esrt

	if len(data) < offset+MokListSizeLen {
		return nil, fmt.Errorf("%w: report ends before the MOK list section", ErrInvalidSize)
	}
	mokListSize := binary.LittleEndian.Uint32(data[offset:])
	offset += MokListSizeLen
	if mokListSize > MaxMokListSize {
		return nil, fmt.Errorf("%w: mok_list_size %d exceeds max %d",
			ErrInvalidSize, mokListSize, MaxMokListSize)
	}
	if len(data) < offset+int(mokListSize) {
		return nil, fmt.Errorf("%w: truncated at MOK list (need %d, have %d)",
			ErrInvalidSize, mokListSize, len(data)-offset)
	}
	if mokListSize > 0 {
		report.MokList = make([]byte, mokListSize)
		copy(report.MokList, data[offset:offset+int(mokListSize)])
	}

	return report, nil
}

// Serialize encodes c for the wire.
func (c *Challenge) Serialize() []byte {
	data := make([]byte, 48)
	binary.LittleEndian.PutUint32(data[0:4], c.Magic)
	binary.LittleEndian.PutUint32(data[4:8], c.Version)
	copy(data[8:40], c.Nonce[:])
	binary.LittleEndian.PutUint32(data[40:44], c.PCRMask)
	binary.LittleEndian.PutUint32(data[44:48], c.Flags)
	return data
}

// Serialize encodes r for the wire.
func (r *VerifyResult) Serialize() []byte {
	data := make([]byte, 24)
	binary.LittleEndian.PutUint32(data[0:4], r.Magic)
	binary.LittleEndian.PutUint32(data[4:8], r.Version)
	binary.LittleEndian.PutUint32(data[8:12], r.Result)
	binary.LittleEndian.PutUint32(data[12:16], r.Flags)
	binary.LittleEndian.PutUint64(data[16:24], r.ValidUntil)
	return data
}
