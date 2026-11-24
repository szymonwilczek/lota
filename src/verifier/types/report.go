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

// protocol constants
const (
	ReportMagic uint32 = 0x41544F4C // "LOTA" little-endian
	// ReportVersion is the attestation report wire version,
	// matching LOTA_REPORT_VERSION in include/lota.h
	//
	// Verifier accepts exactly this one:
	// breaking layout change bumps the major and is a flag-day.
	ReportVersion uint32 = 0x00010000 // 1.0.0

	HashSize        = 32   // SHA-256
	NonceSize       = 32   // Challenge nonce
	HardwareIDSize  = 32   // SHA-256 of EK public key
	MaxSigSize      = 512  // RSA-4096 signature
	MaxAttestSize   = 1024 // TPMS_ATTEST blob
	MaxAIKPubSize   = 512  // AIK public key (DER SPKI)
	MaxAIKCertSize  = 2048 // AIK certificate (DER X.509)
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

	// FlagBootCommitmentV1 indicates the agent extended PCR14 with
	// SHA256(tag || agent_hash), chained onto the value the initramfs lock
	// helper left. The verifier rederives that chain from the reported agent
	// hash and the pre-lock baseline the report's event log replays to,
	// and compares the result against the register the quote signed and against
	// the one the client pinned.
	// The register is per-binary, not per-boot.
	// Every agent sets it and the verifier requires it:
	// the bit names the v1 wire contract specifically, so a future
	// derivation gets its own flag rather than reusing this one.
	FlagBootCommitmentV1 uint32 = 1 << 8

	// FlagInitramfsLockV1 is set when the agent observed that an
	// initramfs-time helper (lota-pcr14-lock, shipped under the
	// 90lota dracut module) extended PCR14 with the domain-separated
	// digest
	//     SHA256("LOTA-PCR14-INITRAMFS-LOCK-v1")
	// before the agent ran. The agent then extends with the
	// boot-commitment value on top, so the final PCR14 reflects a
	// two-hop chain:
	//     pcr14_lock  = SHA256(0^32 || initramfs_lock_commit)
	//     pcr14_final = SHA256(pcr14_lock || boot_commitment)
	// Verifier mirrors that two-hop derivation and has no other one:
	// report without this bit alongside FlagBootCommitmentV1 carries
	// a PCR14 the verifier cannot interpret and is rejected.
	FlagInitramfsLockV1 uint32 = 1 << 9

	// FlagIMAAppraisal is set when the kernel appraises the executables
	// on the host: IMA in a blocking mode over a loaded policy carrying
	// an appraise rule that reaches an exec. Clear is the ordinary state
	// of a stock distribution host, whose packages carry no IMA signatures,
	// and it says nothing about the agent's own binding -- fs-verity and the
	// PCR 14 commitment in this report cover that.
	// Telemetry with a policy knob (RequireIMAAppraisal), not a verdict.
	FlagIMAAppraisal uint32 = 1 << 10

	// FlagBench is set when the daemon runs with --bench and writes what it
	// costs. Its policy is the same as without it. Logged, not a verdict.
	FlagBench uint32 = 1 << 11

	// The policy keys the daemon applies, set with FlagEnforce only.
	// Logged, not a verdict: whether a host needs one is the relying
	// party's call.
	FlagStrictMmap    uint32 = 1 << 12
	FlagStrictExec    uint32 = 1 << 13
	FlagStrictModules uint32 = 1 << 14
	FlagBlockAnonExec uint32 = 1 << 15
	FlagBlockPtrace   uint32 = 1 << 16

	// FlagEventsLost is set when the kernel left events out of the daemon's
	// log. Enforcement is unaffected. Logged, not a verdict.
	FlagEventsLost uint32 = 1 << 17
)

// challenge capability flags (see: include/attestation.h)
const (
	// ChallengeFlagBootCommitmentV1 names the PCR14 derivation the verifier
	// validates. Every challenge carries it, because v1 is the only construction
	// the verifier accepts.
	// It stays on the wire so future v2 derivation has capability bit to differ from.
	ChallengeFlagBootCommitmentV1 uint32 = 1 << 0
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
	VerifyInternalError     uint32 = 9 // verifier internal error / unset failure path

	// VerifyIdentityFail: the quote's signature verified, but the AIK
	// certificate names another key. Kept apart from VerifySigFail
	// because only this one is fixed by re-enrolling.
	VerifyIdentityFail uint32 = 10

	// policy requirement with no code below; not VerifyPCRFail,
	// the fix is not in the boot chain
	VerifyPolicyRequirement uint32 = 11

	// the AIK certificate has expired or is not yet valid (host clock behind).
	// Kept apart from VerifySigFail: the fix is re-enrolment, not distrust.
	VerifyCertificateValidity uint32 = 12

	// no AIK certificate in the report: unfinished enrolment
	VerifyCertificateMissing uint32 = 13

	// one per policy requirement, each with its own remedy
	VerifySecureBootRequired   uint32 = 14
	VerifyLockdownRequired     uint32 = 15
	VerifyModuleSigRequired    uint32 = 16
	VerifyEnforceRequired      uint32 = 17
	VerifyIMAAppraisalRequired uint32 = 18
	VerifyKernelImageRequired  uint32 = 19
	VerifyCmdlineRequired      uint32 = 20

	// unparsable for a reason other than the version field (truncated,
	// foreign magic). Not VerifyOldVersion: an upgrade does not fix it
	VerifyReportMalformed uint32 = 21
)

// returns a deterministic string for a result code
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

// RejectionReasons returns every refusing verdict by its exported name.
// The exporter seeds a zero series for each, so alerts read 0.
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

// struct lota_report_header (see: include/attestation.h)
type ReportHeader struct {
	Magic      uint32 // offset 0
	Version    uint32 // offset 4
	ReportSize uint32 // offset 8
	Flags      uint32 // offset 12
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
//	nonce[32]               32 bytes
//	hardware_id[32]         32 bytes
//	aik_generation           8 bytes
//	prev_aik_public[512]   512 bytes
//	prev_aik_public_size     2 bytes
//	quote_sig_alg            2 bytes
//	quote_sig_hash_alg       2 bytes
//	TOTAL:                5466 bytes
type TPMEvidence struct {
	PCRValues       [PCRCount][HashSize]byte // 768 bytes
	PCRMask         uint32                   // 4 bytes
	QuoteSignature  [MaxSigSize]byte         // 512 bytes
	QuoteSigSize    uint16                   // 2 bytes
	AttestData      [MaxAttestSize]byte      // 1024 bytes
	AttestSize      uint16                   // 2 bytes
	AIKPublic       [MaxAIKPubSize]byte      // 512 bytes
	AIKPublicSize   uint16                   // 2 bytes
	AIKCertificate  [MaxAIKCertSize]byte     // 2048 bytes
	AIKCertSize     uint16                   // 2 bytes
	Nonce           [NonceSize]byte          // 32 bytes
	HardwareID      [HardwareIDSize]byte     // 32 bytes
	AIKGeneration   uint64                   // 8 bytes
	PrevAIKPublic   [MaxAIKPubSize]byte      // 512 bytes
	PrevAIKSize     uint16                   // 2 bytes
	QuoteSigAlg     uint16                   // 2 bytes (TPM2_ALG_RSASSA or TPM2_ALG_RSAPSS)
	QuoteSigHashAlg uint16                   // 2 bytes (TPM2_ALG_SHA256/SHA384/SHA512)
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

// struct lota_attestation_report (see: include/attestation.h)
type AttestationReport struct {
	Header ReportHeader      // 32 bytes
	TPM    TPMEvidence       // 5466 bytes
	System SystemMeasurement // 396 bytes (364 + 32 for agent_hash)

	// variable-length sections (not part of fixed wire format)
	EventLog []byte // raw TCG binary event log from agent

	// ESRT is always set by ParseReport: the section is mandatory.
	// Present == false means the platform exposed no ESRT System Firmware entry
	// (the Low-Firmware-Assurance path), not that the agent omitted the section.
	ESRT *ESRTInfo

	// MokList is the agent's copy of MokListRT, unverified until compared with
	// the MokList event of the quote-authenticated log. Empty when not sent.
	MokList []byte
}

// ESRTInfo mirrors struct lota_esrt (include/attestation.h):
// platform's ESRT System Firmware version, used by the verifier as a firmware
// anti-rollback signal for self-service re-anchor.
// Wire size of 28 bytes.
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

// Challenge for attestation protocol (48 bytes)
type Challenge struct {
	Magic   uint32
	Version uint32
	Nonce   [NonceSize]byte
	PCRMask uint32
	Flags   uint32
}

// VerifyResult returned to agent (24 bytes)
type VerifyResult struct {
	Magic      uint32
	Version    uint32
	Result     uint32
	Flags      uint32
	ValidUntil uint64
}

// errors
var (
	ErrInvalidMagic   = errors.New("invalid report magic")
	ErrInvalidVersion = errors.New("unsupported protocol version")
	ErrInvalidSize    = errors.New("invalid report size")
)

// minimum binary size of a serialized report on the wire.
// Header(16) + TPM(5466) + System(396) + event_log_size(4) + ESRT(28) +
// mok_list_size(4) = 5914.
//
// ESRT and MOK list sections are mandatory, so they count toward the minimum:
// report that stops before one is truncated.
// src/agent/report.c pins the C-side sizes with static asserts
const MinReportSize = 5914

// MaxReportWireSize caps a report before the verifier allocates for it.
// A firmware event log takes most of it, and dbx grows over a machine's life.
const MaxReportWireSize = 256 * 1024

// fixed struct portion (without variable-length sections)
// Header(16) + TPM(5466) + System(396) = 5878
const FixedReportSize = 5878

// deserializes a binary attestation report
func ParseReport(data []byte) (*AttestationReport, error) {
	if len(data) < MinReportSize {
		return nil, fmt.Errorf("%w: got %d, minimum %d", ErrInvalidSize, len(data), MinReportSize)
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
	copy(report.TPM.HardwareID[:], data[offset:offset+HardwareIDSize])
	offset += HardwareIDSize
	report.TPM.AIKGeneration = binary.LittleEndian.Uint64(data[offset:])
	offset += 8
	copy(report.TPM.PrevAIKPublic[:], data[offset:offset+MaxAIKPubSize])
	offset += MaxAIKPubSize
	report.TPM.PrevAIKSize = binary.LittleEndian.Uint16(data[offset:])
	offset += 2
	if report.TPM.PrevAIKSize > MaxAIKPubSize {
		return nil, fmt.Errorf("%w: prev_aik_public_size %d exceeds max %d", ErrInvalidSize, report.TPM.PrevAIKSize, MaxAIKPubSize)
	}
	report.TPM.QuoteSigAlg = binary.LittleEndian.Uint16(data[offset:])
	offset += 2
	report.TPM.QuoteSigHashAlg = binary.LittleEndian.Uint16(data[offset:])
	offset += 2

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

	// TPM event log section
	if len(data) < offset+4 {
		return nil, fmt.Errorf("%w: truncated at event_log_size", ErrInvalidSize)
	}
	eventLogSize := binary.LittleEndian.Uint32(data[offset:])
	offset += 4
	if len(data) < offset+int(eventLogSize) {
		return nil, fmt.Errorf("%w: truncated at event_log (need %d, have %d)",
			ErrInvalidSize, eventLogSize, len(data)-offset)
	}
	if eventLogSize > 0 {
		report.EventLog = make([]byte, eventLogSize)
		copy(report.EventLog, data[offset:offset+int(eventLogSize)])
	}
	offset += int(eventLogSize)

	// Mandatory ESRT section (28 bytes)
	// Agent always emits it and reports Present == false where the platform
	// exposes no ESRT System Firmware entry, so report that stops short
	// is truncated
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

	// Mandatory MOK list section: length prefix, then the variable's data
	if len(data) < offset+MokListSizeLen {
		return nil, fmt.Errorf("%w: report ends before the MOK list section", ErrInvalidSize)
	}
	mokListSize := binary.LittleEndian.Uint32(data[offset:])
	offset += MokListSizeLen
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
	data := make([]byte, 24) // 4+4+4+4+8
	binary.LittleEndian.PutUint32(data[0:4], r.Magic)
	binary.LittleEndian.PutUint32(data[4:8], r.Version)
	binary.LittleEndian.PutUint32(data[8:12], r.Result)
	binary.LittleEndian.PutUint32(data[12:16], r.Flags)
	binary.LittleEndian.PutUint64(data[16:24], r.ValidUntil)
	return data
}
