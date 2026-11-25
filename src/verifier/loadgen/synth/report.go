// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
// LOTA Load Generator - Attestation report synthesis

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

// narrow16, narrow32 and narrow8 panic on a length out of range,
// which is a builder bug.
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

// ReportPCRMask selects PCR 0, 1 and 7, which the verifier requires, PCR 9,
// where the kernel image is measured, and PCR 14, the boot commitment.
const ReportPCRMask uint32 = 1<<0 | 1<<1 | 1<<7 | 1<<9 | 1<<14

// reportFlags are those of an enforcing agent; FlagBootCommitmentV1 and
// FlagInitramfsLockV1 select the locked PCR 14 derivation.
const reportFlags = types.FlagTPMQuoteOK | types.FlagKernelHashOK |
	types.FlagBPFActive | types.FlagModuleSig | types.FlagLockdown |
	types.FlagEnforce | types.FlagBootCommitmentV1 | types.FlagInitramfsLockV1

const (
	quoteResetCount   uint32 = 1
	quoteRestartCount uint32 = 0
)

// the binding nonce covers the IOMMU block, so the report and the binding
// mirror in BuildReport share these values
const (
	iommuVendor  uint32 = 0x8086
	iommuFlags   uint32 = 0x07
	iommuUnits   uint32 = 2
	iommuCmdline        = "intel_iommu=on"
)

// secureBootVariableEvent is the UEFI_VARIABLE_DATA payload measuring the EFI
// global SecureBoot variable as enabled. The verifier reads it as the UEFI
// boot anchor.
func secureBootVariableEvent() []byte {
	const name = "SecureBoot"

	buf := make([]byte, 0, 32+2*len(name)+1)
	buf = append(buf, efiGlobalVariableGUID[:]...)
	buf = binary.LittleEndian.AppendUint64(buf, uint64(len(name)))
	buf = binary.LittleEndian.AppendUint64(buf, 1)
	// name is ASCII, so each byte widens into one UTF-16 code unit
	for i := 0; i < len(name); i++ {
		buf = binary.LittleEndian.AppendUint16(buf, uint16(name[i]))
	}
	return append(buf, 0x01)
}

// separatorEvent is the EV_SEPARATOR data that ends the firmware's PCR 7
// measurements; the verifier reads SecureBoot only before it.
var separatorEvent = []byte{0, 0, 0, 0}

// PCR7 returns the value the fleet's event log replays into PCR 7: the
// SecureBoot variable measurement and the separator over a zero register.
func (f *Fleet) PCR7() [types.HashSize]byte {
	var pcr7 [types.HashSize]byte
	for _, data := range [][]byte{secureBootVariableEvent(), separatorEvent} {
		digest := sha256.Sum256(data)
		h := sha256.New()
		h.Write(pcr7[:])
		h.Write(digest[:])
		copy(pcr7[:], h.Sum(nil))
	}
	return pcr7
}

// KernelImagePath is the GRUB path the PCR 9 event names.
const KernelImagePath = "(hd0,gpt2)/vmlinuz-6.19.4-200.fc44.x86_64"

// PCR9 returns a zero register extended with KernelHash, the digest the event
// log's PCR 9 event carries.
func (f *Fleet) PCR9() [types.HashSize]byte {
	var pcr9 [types.HashSize]byte

	h := sha256.New()
	h.Write(pcr9[:])
	h.Write(f.KernelHash[:])
	copy(pcr9[:], h.Sum(nil))
	return pcr9
}

// PCR14 returns the initramfs lock and the boot commitment over a zero
// baseline; the event log has no PCR 14 event.
func (f *Fleet) PCR14() [types.HashSize]byte {
	var zeroBaseline [types.HashSize]byte
	return verify.DeriveLockedBootCommitmentPCR14(zeroBaseline, f.AgentHash)
}

// BuildReport returns a's signed report answering challengeNonce.
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
	pcrs[7] = f.PCR7()
	pcrs[9] = f.PCR9()
	pcrs[14] = f.PCR14()

	// the binding nonce covers these fields; they must equal the bytes
	// serialized below
	binding := &types.AttestationReport{}
	binding.Header.Flags = reportFlags
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

	eventLog := f.uefiEventLog()

	buf := make([]byte, types.FixedReportSize, types.MinReportSize+len(eventLog))
	off := 0

	binary.LittleEndian.PutUint32(buf[off:], types.ReportMagic)
	off += 4
	binary.LittleEndian.PutUint32(buf[off:], types.ReportVersion)
	off += 4
	off += 4 // report_size backfilled once total length is known
	binary.LittleEndian.PutUint32(buf[off:], reportFlags)
	off += 4

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
	copy(buf[off:], challengeNonce[:])
	off += types.NonceSize
	binary.LittleEndian.PutUint16(buf[off:], types.TPMAlgRSASSA)
	off += 2
	binary.LittleEndian.PutUint16(buf[off:], types.TPMAlgSHA256)
	off += 2

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

	if off != types.FixedReportSize {
		return nil, fmt.Errorf("fixed section is %d bytes, want %d", off, types.FixedReportSize)
	}

	buf = binary.LittleEndian.AppendUint32(buf, narrow32(len(eventLog)))
	buf = append(buf, eventLog...)

	// ESRT with present == 0 and an empty MOK list: no ESRT firmware
	// entry, no shim
	buf = append(buf, make([]byte, types.ESRTWireSize+types.MokListSizeLen)...)

	binary.LittleEndian.PutUint32(buf[8:12], narrow32(len(buf)))
	return buf, nil
}

// pcrDigest returns the SHA-256 of the masked PCR values in index order.
func pcrDigest(pcrs *[types.PCRCount][types.HashSize]byte, mask uint32) []byte {
	h := sha256.New()
	for i := range types.PCRCount {
		if mask&(1<<uint(i)) != 0 {
			h.Write(pcrs[i][:])
		}
	}
	return h.Sum(nil)
}

// buildTPMSAttest returns a minimal TPMS_ATTEST quote with nonce as extraData
// and digest as the PCR digest. Its selection names PCR 0, 1, 7 and 14 only.
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

	// TPMS_QUOTE_INFO: one SHA-256 selection
	buf = append(buf,
		0x00, 0x00, 0x00, 0x01, // selection count
		0x00, 0x0b, // TPM_ALG_SHA256
		0x03,             // sizeofSelect
		0x83, 0x40, 0x00, // PCR 0,1,7 | PCR 14
		0x00, 0x20) // digest size
	buf = append(buf, digest[:32]...)

	return buf
}

// efiGlobalVariableGUID is EFI_GLOBAL_VARIABLE, the GUID the firmware stamps
// on the SecureBoot variable measurement.
var efiGlobalVariableGUID = [16]byte{
	0x61, 0xdf, 0xe4, 0x8b, 0xca, 0x93, 0xd2, 0x11,
	0xaa, 0x0d, 0x00, 0xe0, 0x98, 0x03, 0x2b, 0x8c,
}

// uefiEventLog returns the Spec ID header, the PCR 7 SecureBoot measurement
// and separator, and the PCR 9 EV_IPL event naming KernelImagePath.
func (f *Fleet) uefiEventLog() []byte {
	payload := secureBootVariableEvent()
	digest := sha256.Sum256(payload)
	separator := sha256.Sum256(separatorEvent)

	log := minimalEventLog()
	log = append(log, eventEntry(7, verify.EvEFIVariableDriverConfig,
		digest[:], payload)...)
	log = append(log, eventEntry(7, verify.EvSeparator, separator[:],
		separatorEvent)...)
	log = append(log, eventEntry(9, verify.EvIPL, f.KernelHash[:],
		[]byte(KernelImagePath+"\x00"))...)
	return log
}

// eventEntry encodes one crypto-agile TCG record with a single SHA-256 digest.
func eventEntry(pcr, eventType uint32, digest, payload []byte) []byte {
	entry := make([]byte, 0, 64+len(payload))
	entry = binary.LittleEndian.AppendUint32(entry, pcr)
	entry = binary.LittleEndian.AppendUint32(entry, eventType)
	entry = binary.LittleEndian.AppendUint32(entry, 1) // digest count
	entry = binary.LittleEndian.AppendUint16(entry, verify.AlgSHA256)
	entry = append(entry, digest...)
	entry = binary.LittleEndian.AppendUint32(entry, narrow32(len(payload)))
	return append(entry, payload...)
}

// minimalEventLog returns a TCG log holding only the Spec ID header.
func minimalEventLog() []byte {
	specData := specIDEvent()

	header := make([]byte, 32)
	binary.LittleEndian.PutUint32(header[0:4], 0)                         // pcr_index
	binary.LittleEndian.PutUint32(header[4:8], verify.EvNoAction)         // event_type
	binary.LittleEndian.PutUint32(header[28:32], narrow32(len(specData))) // event_data_size

	return append(header, specData...)
}

// specIDEvent encodes a SHA-256-only "Spec ID Event03" block.
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
