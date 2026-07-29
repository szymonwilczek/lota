// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
// LOTA Load Generator - Attestation report synthesis
//
// Serializes the exact wire layout types.ParseReport consumes
// (the Go mirror of include/attestation.h)
// and signs the quote so the report passes the production verification path:
// binding nonce, PCR digest, PCR14 boot-commitment derivation (initramfs lock
// + boot commitment over zero baseline, the legacy/BIOS event-log shape),
// and the AIK certificate chain.

package synth

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"math"

	"github.com/szymonwilczek/lota/verifier/types"
	"github.com/szymonwilczek/lota/verifier/verify"
)

// narrow16/narrow32/narrow8 bound a length before narrowing it for the wire.
// Every input is already checked against its wire maximum, so out-of-range
// value is builder bug, not runtime condition
func narrow16(n int) uint16 {
	if n < 0 || n > math.MaxUint16 {
		panic(fmt.Sprintf("wire length %d out of uint16 range", n))
	}
	return uint16(n)
}

func narrow32(n int) uint32 {
	if n < 0 || n > math.MaxUint32 {
		panic(fmt.Sprintf("wire length %d out of uint32 range", n))
	}
	return uint32(n)
}

func narrow8(n int) byte {
	if n < 0 || n > math.MaxUint8 {
		panic(fmt.Sprintf("wire length %d out of byte range", n))
	}
	return byte(n)
}

// ReportPCRMask selects PCR 0, 1, 7 (boot pins) and 14 (boot commitment),
// the minimum production verifier accepts with RequireBootPCRs and the boot-commitment path
const ReportPCRMask uint32 = 1<<0 | 1<<1 | 1<<7 | 1<<14

// reportFlags mirrors a healthy enforcing agent
// FlagBootCommitmentV1 + FlagInitramfsLockV1 select the locked two-hop PCR14 derivation
const reportFlags = types.FlagTPMQuoteOK | types.FlagKernelHashOK |
	types.FlagBPFActive | types.FlagModuleSig | types.FlagLockdown |
	types.FlagEnforce | types.FlagBootCommitmentV1 | types.FlagInitramfsLockV1

// quote ClockInfo counters
// PCR14 derivation folds them, so the TPMS_ATTEST below carries the same values
const (
	quoteResetCount   uint32 = 1
	quoteRestartCount uint32 = 0
)

// synthetic IOMMU block
// hashed into the binding nonce, so the serialized report
// and the binding mirror share these constants
const (
	iommuVendor  uint32 = 0x8086
	iommuFlags   uint32 = 0x07
	iommuUnits   uint32 = 2
	iommuCmdline        = "intel_iommu=on"
)

// PCR14 returns the fleet's boot-commitment PCR14:
// initramfs lock and agent boot commitment chained over zero baseline
// (nothing measures PCR14 before userspace in the synthetic event log)
func (f *Fleet) PCR14() [types.HashSize]byte {
	var zeroBaseline [types.HashSize]byte
	return verify.DeriveLockedBootCommitmentPCR14(
		zeroBaseline, f.AgentHash, quoteResetCount, quoteRestartCount)
}

// BuildReport assembles and signs full attestation report for agent answering challengeNonce
func (f *Fleet) BuildReport(a *Agent, challengeNonce [types.NonceSize]byte) ([]byte, error) {
	aikPub, err := x509.MarshalPKIXPublicKey(&a.Key.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("marshal AIK public key: %w", err)
	}
	if len(aikPub) > types.MaxAIKPubSize {
		return nil, fmt.Errorf("AIK public key %d bytes exceeds wire max %d",
			len(aikPub), types.MaxAIKPubSize)
	}

	pcrs := f.PCRs
	pcrs[14] = f.PCR14()

	// binding nonce covers hardware_id, flags, kernel/agent hash
	// and the IOMMU block
	// mirror struct must match the serialized bytes below field for field
	binding := &types.AttestationReport{}
	binding.Header.Flags = reportFlags
	binding.TPM.HardwareID = a.HardwareID
	binding.System.KernelHash = f.KernelHash
	binding.System.AgentHash = f.AgentHash
	binding.System.IOMMU.Vendor = iommuVendor
	binding.System.IOMMU.Flags = iommuFlags
	binding.System.IOMMU.UnitCount = iommuUnits
	copy(binding.System.IOMMU.CmdlineParam[:], iommuCmdline)
	bindingNonce := verify.ComputeAttestationBindingNonce(challengeNonce, binding)

	attestData := buildTPMSAttest(bindingNonce[:], pcrDigest(&pcrs, ReportPCRMask))
	digest := sha256.Sum256(attestData)
	signature, err := rsa.SignPKCS1v15(rand.Reader, a.Key, crypto.SHA256, digest[:])
	if err != nil {
		return nil, fmt.Errorf("sign quote: %w", err)
	}

	eventLog := minimalEventLog()

	buf := make([]byte, types.FixedReportSize, types.MinReportSize+len(eventLog))
	off := 0

	// header
	binary.LittleEndian.PutUint32(buf[off:], types.ReportMagic)
	off += 4
	binary.LittleEndian.PutUint32(buf[off:], types.ReportVersion)
	off += 4
	off += 4 // report_size backfilled once total length is known
	binary.LittleEndian.PutUint32(buf[off:], reportFlags)
	off += 4

	// TPM evidence
	for i := range pcrs {
		copy(buf[off:], pcrs[i][:])
		off += types.HashSize
	}
	binary.LittleEndian.PutUint32(buf[off:], ReportPCRMask)
	off += 4
	copy(buf[off:], signature)
	off += types.MaxSigSize
	binary.LittleEndian.PutUint16(buf[off:], narrow16(len(signature)))
	off += 2
	copy(buf[off:], attestData)
	off += types.MaxAttestSize
	binary.LittleEndian.PutUint16(buf[off:], narrow16(len(attestData)))
	off += 2
	copy(buf[off:], aikPub)
	off += types.MaxAIKPubSize
	binary.LittleEndian.PutUint16(buf[off:], narrow16(len(aikPub)))
	off += 2
	copy(buf[off:], a.CertDER)
	off += types.MaxAIKCertSize
	binary.LittleEndian.PutUint16(buf[off:], narrow16(len(a.CertDER)))
	off += 2
	off += types.MaxEKCertSize // no EK certificate
	binary.LittleEndian.PutUint16(buf[off:], 0)
	off += 2
	copy(buf[off:], challengeNonce[:])
	off += types.NonceSize
	copy(buf[off:], a.HardwareID[:])
	off += types.HardwareIDSize
	binary.LittleEndian.PutUint64(buf[off:], 1) // aik_generation
	off += 8
	off += types.MaxAIKPubSize // no prev AIK
	binary.LittleEndian.PutUint16(buf[off:], 0)
	off += 2
	binary.LittleEndian.PutUint16(buf[off:], types.TPMAlgRSASSA)
	off += 2
	binary.LittleEndian.PutUint16(buf[off:], types.TPMAlgSHA256)
	off += 2

	// system measurement
	copy(buf[off:], f.KernelHash[:])
	off += types.HashSize
	copy(buf[off:], f.AgentHash[:])
	off += types.HashSize
	copy(buf[off:], "/boot/vmlinuz-lota-loadgen")
	off += types.MaxKernelPath
	binary.LittleEndian.PutUint32(buf[off:], iommuVendor)
	off += 4
	binary.LittleEndian.PutUint32(buf[off:], iommuFlags)
	off += 4
	binary.LittleEndian.PutUint32(buf[off:], iommuUnits)
	off += 4
	copy(buf[off:], iommuCmdline)
	off += types.CmdlineParamMax

	// BPF summary
	binary.LittleEndian.PutUint32(buf[off:], 0)
	off += 4
	binary.LittleEndian.PutUint32(buf[off:], 0)
	off += 4
	binary.LittleEndian.PutUint64(buf[off:], 0)
	off += 8
	binary.LittleEndian.PutUint64(buf[off:], 0)
	off += 8

	if off != types.FixedReportSize {
		return nil, fmt.Errorf("fixed section is %d bytes, want %d", off, types.FixedReportSize)
	}

	// variable sections: BPF event count, then the TCG event log
	var tail [8]byte
	binary.LittleEndian.PutUint32(tail[0:4], 0) // bpf event_count
	binary.LittleEndian.PutUint32(tail[4:8], narrow32(len(eventLog)))
	buf = append(buf, tail[:]...)
	buf = append(buf, eventLog...)

	binary.LittleEndian.PutUint32(buf[8:12], narrow32(len(buf)))
	return buf, nil
}

// pcrDigest is the SHA-256 over the selected PCR values in ascending index order,
// the digest TPM2_Quote signs
func pcrDigest(pcrs *[types.PCRCount][types.HashSize]byte, mask uint32) []byte {
	h := sha256.New()
	for i := range types.PCRCount {
		if mask&(1<<uint(i)) != 0 {
			h.Write(pcrs[i][:])
		}
	}
	return h.Sum(nil)
}

// buildTPMSAttest emits minimal TPMS_ATTEST(QUOTE) blob:
// correct magic/type, the binding nonce as extraData, ClockInfo counters
// the PCR14 derivation expects, and signed PCR selection/digest
func buildTPMSAttest(nonce, digest []byte) []byte {
	buf := make([]byte, 0, 128)

	buf = append(buf,
		0xff, 0x54, 0x43, 0x47, // TPM_GENERATED_VALUE
		0x80, 0x18, // TPM_ST_ATTEST_QUOTE
		0x00, 0x02, 0x00, 0x00, // qualifiedSigner: minimal TPM2B_NAME
		0x00, narrow8(len(nonce))) // extraData: TPM2B_DATA
	buf = append(buf, nonce...)

	// ClockInfo: clock(8) + resetCount(4) + restartCount(4) + safe(1)
	buf = append(buf, make([]byte, 8)...)
	buf = binary.BigEndian.AppendUint32(buf, quoteResetCount)
	buf = binary.BigEndian.AppendUint32(buf, quoteRestartCount)
	buf = append(buf, 0x01)

	buf = append(buf, make([]byte, 8)...) // firmwareVersion

	// TPMS_QUOTE_INFO: one SHA-256 selection over ReportPCRMask
	buf = append(buf,
		0x00, 0x00, 0x00, 0x01, // selection count
		0x00, 0x0b, // TPM_ALG_SHA256
		0x03,             // sizeofSelect
		0x83, 0x40, 0x00, // PCR 0,1,7 | PCR 14
		0x00, 0x20) // digest size
	buf = append(buf, digest[:32]...)

	return buf
}

// minimalEventLog is valid TCG log holding only the Spec ID header:
// no PCR14 events, so the verifier reconstructs zero PCR14 baseline
// (the legacy/BIOS shape) and no Secure Boot variables
func minimalEventLog() []byte {
	specData := specIDEvent()

	header := make([]byte, 32)
	binary.LittleEndian.PutUint32(header[0:4], 0)                         // pcr_index
	binary.LittleEndian.PutUint32(header[4:8], verify.EvNoAction)         // event_type
	binary.LittleEndian.PutUint32(header[28:32], narrow32(len(specData))) // event_data_size

	return append(header, specData...)
}

// specIDEvent encodes SHA-256-only "Spec ID Event03" block
func specIDEvent() []byte {
	var buf []byte
	buf = append(buf, []byte("Spec ID Event03\x00")...)
	buf = append(buf, make([]byte, 8)...) // platformClass, version, errata, uintnSize
	buf = binary.LittleEndian.AppendUint32(buf, 1)
	buf = binary.LittleEndian.AppendUint16(buf, verify.AlgSHA256)
	buf = binary.LittleEndian.AppendUint16(buf, sha256.Size)
	buf = append(buf, 0) // vendorInfoSize
	return buf
}
