// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
// LOTA Verifier - Wire Format Unit Tests
//
// Tests for binary report parsing and encoding.
// Verifies alignment, padding, and endianness handling between
// C structs (agent) and Go structs (verifier).

package types

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

// Test report matching C struct layout
// IMPORTANT: Any misalignment causes verification failures
func createTestReportBytes() []byte {
	// fixed struct plus the two variable-section length prefixes;
	// mandatory ESRT section is appended at the end
	buf := make([]byte, FixedReportSize+8)
	offset := 0

	// Header (32 bytes)
	binary.LittleEndian.PutUint32(buf[offset:], ReportMagic) // magic
	offset += 4
	binary.LittleEndian.PutUint32(buf[offset:], ReportVersion) // version
	offset += 4
	binary.LittleEndian.PutUint32(buf[offset:], MinReportSize) // report_size
	offset += 4
	binary.LittleEndian.PutUint32(buf[offset:], FlagTPMQuoteOK|FlagModuleSig) // flags
	offset += 4

	// TPM Evidence (2860 bytes)
	for i := 0; i < PCRCount; i++ {
		for j := 0; j < HashSize; j++ {
			buf[offset+j] = byte(i ^ j)
		}
		offset += HashSize
	}
	// pcr_mask
	binary.LittleEndian.PutUint32(buf[offset:], 0x00004003) // PCR 0,1,14
	offset += 4
	// quote_signature (512 bytes)
	for i := 0; i < MaxSigSize; i++ {
		buf[offset+i] = byte(i % 256)
	}
	offset += MaxSigSize
	// quote_sig_size
	binary.LittleEndian.PutUint16(buf[offset:], 256)
	offset += 2
	// attest_data (1024 bytes)
	copy(buf[offset:], []byte("ATTEST_DATA_PLACEHOLDER"))
	offset += MaxAttestSize
	// attest_size
	binary.LittleEndian.PutUint16(buf[offset:], 145)
	offset += 2
	// aik_public (512 bytes)
	copy(buf[offset:], []byte("AIK_PUBLIC_KEY"))
	offset += MaxAIKPubSize
	// aik_public_size
	binary.LittleEndian.PutUint16(buf[offset:], 294)
	offset += 2
	// aik_certificate (2048 bytes, optional - leave empty)
	offset += MaxAIKCertSize
	// aik_cert_size
	binary.LittleEndian.PutUint16(buf[offset:], 0)
	offset += 2
	// nonce (32 bytes)
	for i := 0; i < NonceSize; i++ {
		buf[offset+i] = byte(0xAA ^ i)
	}
	offset += NonceSize
	// hardware_id (32 bytes) - SHA-256 of EK public key
	for i := 0; i < HardwareIDSize; i++ {
		buf[offset+i] = byte(0xDD ^ i)
	}
	offset += HardwareIDSize
	// aik_generation (8)
	binary.LittleEndian.PutUint64(buf[offset:], 1)
	offset += 8
	// prev_aik_public (512) + size
	copy(buf[offset:], []byte("PREV_AIK_PUBLIC_KEY"))
	offset += MaxAIKPubSize
	binary.LittleEndian.PutUint16(buf[offset:], 0)
	offset += 2
	// quote_sig_alg (2 bytes)
	binary.LittleEndian.PutUint16(buf[offset:], 0x0014) // TPM2_ALG_RSASSA
	offset += 2
	// quote_sig_hash_alg (2 bytes)
	binary.LittleEndian.PutUint16(buf[offset:], TPMAlgSHA256)
	offset += 2

	// System Measurement (396 bytes)
	// kernel_hash (32 bytes)
	for i := 0; i < HashSize; i++ {
		buf[offset+i] = byte(0xBB ^ i)
	}
	offset += HashSize
	// agent_hash (32 bytes)
	for i := 0; i < HashSize; i++ {
		buf[offset+i] = byte(0xCC ^ i)
	}
	offset += HashSize
	// kernel_path (256 bytes)
	copy(buf[offset:], "/boot/vmlinuz-6.12.0")
	offset += MaxKernelPath
	// IOMMU status (76 bytes)
	binary.LittleEndian.PutUint32(buf[offset:], 0x8086) // vendor
	offset += 4
	binary.LittleEndian.PutUint32(buf[offset:], 0x07) // flags
	offset += 4
	binary.LittleEndian.PutUint32(buf[offset:], 2) // unit_count
	offset += 4
	copy(buf[offset:], "intel_iommu=on") // cmdline
	offset += CmdlineParamMax

	// BPF Summary (24 bytes)
	binary.LittleEndian.PutUint32(buf[offset:], 100) // total_exec_events
	offset += 4
	binary.LittleEndian.PutUint32(buf[offset:], 50) // unique_binaries
	offset += 4
	binary.LittleEndian.PutUint64(buf[offset:], 1699999000) // first_event_ts
	offset += 8
	binary.LittleEndian.PutUint64(buf[offset:], 1700000000) // last_event_ts

	// mandatory trailing ESRT section
	// all-zero means present == false
	buf = append(buf, make([]byte, ESRTWireSize)...)
	binary.LittleEndian.PutUint32(buf[8:12], uint32(len(buf))) // report_size

	return buf
}

// TestParseReport_OversizedEventCountRejected pins the BPF event_count bound.
// event_count is attacker-controlled u32; parser must reject count whose byte
// span cannot fit the buffer without overflowing the size computation.
//
// createTestReportBytes() lays event_count as the u32 right after the fixed struct,
// followed by event_log_size and the mandatory ESRT section, all zero in the valid baseline.
func TestParseReport_OversizedEventCountRejected(t *testing.T) {
	data := createTestReportBytes()
	binary.LittleEndian.PutUint32(data[FixedReportSize:], 0xFFFFFFFF)

	report, err := ParseReport(data)
	if err == nil {
		t.Fatalf("oversized event_count accepted: report=%+v", report)
	}
	if !errors.Is(err, ErrInvalidSize) {
		t.Fatalf("oversized event_count: got %v, want ErrInvalidSize", err)
	}
	if report != nil {
		t.Fatal("ParseReport returned non-nil report with error")
	}
}

func TestParseReport_ValidReport(t *testing.T) {
	t.Log("TEST: Parsing valid attestation report")
	t.Log("Verifies C struct layout matches Go parsing")

	data := createTestReportBytes()

	report, err := ParseReport(data)
	if err != nil {
		t.Fatalf("Failed to parse valid report: %v", err)
	}

	t.Run("Header", func(t *testing.T) {
		if report.Header.Magic != ReportMagic {
			t.Errorf("Magic: got 0x%08X, want 0x%08X", report.Header.Magic, ReportMagic)
		}
		if report.Header.Version != ReportVersion {
			t.Errorf("Version: got 0x%08X, want 0x%08X", report.Header.Version, ReportVersion)
		}
		if report.Header.ReportSize != MinReportSize {
			t.Errorf("ReportSize: got %d, want %d", report.Header.ReportSize, MinReportSize)
		}
		if report.Header.Flags != (FlagTPMQuoteOK | FlagModuleSig) {
			t.Errorf("Flags: got 0x%08X, want 0x%08X",
				report.Header.Flags, FlagTPMQuoteOK|FlagModuleSig)
		}
		t.Log("✓ Header parsed correctly")
	})

	t.Run("TPMEvidence", func(t *testing.T) {
		for i := 0; i < PCRCount; i++ {
			for j := 0; j < HashSize; j++ {
				expected := byte(i ^ j)
				if report.TPM.PCRValues[i][j] != expected {
					t.Errorf("PCR[%d][%d]: got 0x%02X, want 0x%02X",
						i, j, report.TPM.PCRValues[i][j], expected)
				}
			}
		}
		if report.TPM.PCRMask != 0x00004003 {
			t.Errorf("PCRMask: got 0x%08X, want 0x00004003", report.TPM.PCRMask)
		}
		if report.TPM.QuoteSigSize != 256 {
			t.Errorf("QuoteSigSize: got %d, want 256", report.TPM.QuoteSigSize)
		}
		if report.TPM.AttestSize != 145 {
			t.Errorf("AttestSize: got %d, want 145", report.TPM.AttestSize)
		}
		if report.TPM.AIKPublicSize != 294 {
			t.Errorf("AIKPublicSize: got %d, want 294", report.TPM.AIKPublicSize)
		}
		for i := 0; i < NonceSize; i++ {
			expected := byte(0xAA ^ i)
			if report.TPM.Nonce[i] != expected {
				t.Errorf("Nonce[%d]: got 0x%02X, want 0x%02X",
					i, report.TPM.Nonce[i], expected)
			}
		}
		t.Log("✓ TPM evidence parsed correctly")
	})

	t.Run("SystemMeasurement", func(t *testing.T) {
		for i := 0; i < HashSize; i++ {
			expected := byte(0xBB ^ i)
			if report.System.KernelHash[i] != expected {
				t.Errorf("KernelHash[%d]: got 0x%02X, want 0x%02X",
					i, report.System.KernelHash[i], expected)
			}
		}
		for i := 0; i < HashSize; i++ {
			expected := byte(0xCC ^ i)
			if report.System.AgentHash[i] != expected {
				t.Errorf("AgentHash[%d]: got 0x%02X, want 0x%02X",
					i, report.System.AgentHash[i], expected)
			}
		}
		if report.System.IOMMU.Vendor != 0x8086 {
			t.Errorf("IOMMU.Vendor: got 0x%04X, want 0x8086", report.System.IOMMU.Vendor)
		}
		if report.System.IOMMU.Flags != 0x07 {
			t.Errorf("IOMMU.Flags: got 0x%02X, want 0x07", report.System.IOMMU.Flags)
		}
		t.Log("✓ System measurement parsed correctly")
	})

	t.Run("BPFSummary", func(t *testing.T) {
		if report.BPF.TotalExecEvents != 100 {
			t.Errorf("TotalExecEvents: got %d, want 100", report.BPF.TotalExecEvents)
		}
		if report.BPF.UniqueBinaries != 50 {
			t.Errorf("UniqueBinaries: got %d, want 50", report.BPF.UniqueBinaries)
		}
		t.Log("✓ BPF summary parsed correctly")
	})
}

func TestParseReport_InvalidMagic(t *testing.T) {
	t.Log("SECURITY TEST: Rejecting report with invalid magic")

	data := createTestReportBytes()
	binary.LittleEndian.PutUint32(data[0:], 0xDEADBEEF) // corrrupted magic

	_, err := ParseReport(data)
	if err == nil {
		t.Fatal("Expected error for invalid magic")
	}

	t.Logf("✓ Correctly rejected invalid magic: %v", err)
}

func TestParseReport_InvalidVersion(t *testing.T) {
	t.Log("SECURITY TEST: Rejecting report with incompatible version")

	data := createTestReportBytes()
	binary.LittleEndian.PutUint32(data[4:], 0x00630000) // incompatible version

	_, err := ParseReport(data)
	if err == nil {
		t.Fatal("Expected error for invalid version")
	}

	t.Logf("✓ Correctly rejected incompatible version: %v", err)
}

func TestParseReport_TruncatedData(t *testing.T) {
	t.Log("SECURITY TEST: Rejecting truncated report")

	testCases := []struct {
		name   string
		length int
	}{
		{"Empty", 0},
		{"OnlyMagic", 4},
		{"OnlyHeader", 32},
		{"HalfTPM", 32 + 1000},
		{"AlmostComplete", MinReportSize - 1},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			data := createTestReportBytes()[:tc.length]

			_, err := ParseReport(data)
			if err == nil {
				t.Errorf("Expected error for %d-byte report", tc.length)
			} else {
				t.Logf("✓ Correctly rejected %d-byte truncated report", tc.length)
			}
		})
	}
}

// TestParseReport_FieldOffsetsMatchCLayout proves the Go parser walks
// the same byte layout the C serializer writes.
//
// Nothing links the two languages at build time:
// src/agent/report.c memcpy's the packed C struct onto the wire and ParseReport
// re-reads it from hand-computed offsets.
// C side pins its own sizes with static asserts; this is the Go side of the same contract.
//
// Check is positive, not bounds test: unique marker is written at each expected offset
// and the parsed report must expose that marker in the matching field.
// Field that moved -- because one was added, removed or reordered on either side
// -- lands the marker somewhere else and fails here instead of silently misreading
// production reports.
func TestParseReport_FieldOffsetsMatchCLayout(t *testing.T) {
	// Offsets derived from struct lota_tpm_evidence in include/attestation.h
	// Report version 2 carries no ek_certificate
	const (
		tpmBase          = 16
		offPCRValues     = tpmBase
		offPCRMask       = offPCRValues + PCRCount*HashSize
		offQuoteSig      = offPCRMask + 4
		offQuoteSigSize  = offQuoteSig + MaxSigSize
		offAttestData    = offQuoteSigSize + 2
		offAttestSize    = offAttestData + MaxAttestSize
		offAIKPublic     = offAttestSize + 2
		offAIKPublicSize = offAIKPublic + MaxAIKPubSize
		offAIKCert       = offAIKPublicSize + 2
		offAIKCertSize   = offAIKCert + MaxAIKCertSize
		offNonce         = offAIKCertSize + 2
		offHardwareID    = offNonce + NonceSize
		offAIKGeneration = offHardwareID + HardwareIDSize
		offPrevAIKPublic = offAIKGeneration + 8
		offPrevAIKSize   = offPrevAIKPublic + MaxAIKPubSize
		offQuoteSigAlg   = offPrevAIKSize + 2
		offQuoteHashAlg  = offQuoteSigAlg + 2
		tpmEnd           = offQuoteHashAlg + 2

		offKernelHash = tpmEnd
		offAgentHash  = offKernelHash + HashSize
		offKernelPath = offAgentHash + HashSize
		offIOMMU      = offKernelPath + MaxKernelPath
		offBPFTotal   = offIOMMU + 4 + 4 + 4 + CmdlineParamMax
	)

	// layout must close exactly on the published constants
	assertEqual := func(got, want int, msg string) {
		t.Helper()
		if got != want {
			t.Fatalf("%s: got %d, want %d", msg, got, want)
		}
	}
	assertEqual(tpmEnd-tpmBase, 5466, "TPM evidence section")
	assertEqual(offBPFTotal+24, FixedReportSize, "fixed section")

	// byte-slice fields: write a marker, parse, require it in the field
	sliceCases := []struct {
		name   string
		offset int
		size   int
		get    func(*AttestationReport) []byte
	}{
		{"TPM.PCRValues[0]", offPCRValues, HashSize, func(r *AttestationReport) []byte { return r.TPM.PCRValues[0][:] }},
		{"TPM.QuoteSignature", offQuoteSig, 16, func(r *AttestationReport) []byte { return r.TPM.QuoteSignature[:16] }},
		{"TPM.AttestData", offAttestData, 16, func(r *AttestationReport) []byte { return r.TPM.AttestData[:16] }},
		{"TPM.AIKPublic", offAIKPublic, 16, func(r *AttestationReport) []byte { return r.TPM.AIKPublic[:16] }},
		{"TPM.AIKCertificate", offAIKCert, 16, func(r *AttestationReport) []byte { return r.TPM.AIKCertificate[:16] }},
		{"TPM.Nonce", offNonce, NonceSize, func(r *AttestationReport) []byte { return r.TPM.Nonce[:] }},
		{"TPM.HardwareID", offHardwareID, HardwareIDSize, func(r *AttestationReport) []byte { return r.TPM.HardwareID[:] }},
		{"TPM.PrevAIKPublic", offPrevAIKPublic, 16, func(r *AttestationReport) []byte { return r.TPM.PrevAIKPublic[:16] }},
		{"System.KernelHash", offKernelHash, HashSize, func(r *AttestationReport) []byte { return r.System.KernelHash[:] }},
		{"System.AgentHash", offAgentHash, HashSize, func(r *AttestationReport) []byte { return r.System.AgentHash[:] }},
		{"System.KernelPath", offKernelPath, 8, func(r *AttestationReport) []byte { return r.System.KernelPath[:8] }},
	}

	for i, tc := range sliceCases {
		t.Run(tc.name, func(t *testing.T) {
			data := createTestReportBytes()
			marker := make([]byte, tc.size)
			for j := range marker {
				// distinct per field and per byte, and never all-zero
				marker[j] = byte(0x40 + i)
				marker[j] ^= byte(j)
			}
			copy(data[tc.offset:], marker)

			report, err := ParseReport(data)
			if err != nil {
				t.Fatalf("ParseReport: %v", err)
			}
			if got := tc.get(report); !bytes.Equal(got, marker) {
				t.Fatalf("%s: field holds %x, marker written at offset %d was %x",
					tc.name, got, tc.offset, marker)
			}
		})
	}

	// scalar fields: same idea with distinct values
	t.Run("scalars", func(t *testing.T) {
		data := createTestReportBytes()
		binary.LittleEndian.PutUint32(data[offPCRMask:], 0x0BADF00D)
		binary.LittleEndian.PutUint16(data[offQuoteSigSize:], 0x0101)
		binary.LittleEndian.PutUint16(data[offAttestSize:], 0x0202)
		binary.LittleEndian.PutUint16(data[offAIKPublicSize:], 499)
		binary.LittleEndian.PutUint16(data[offAIKCertSize:], 0x0404)
		binary.LittleEndian.PutUint64(data[offAIKGeneration:], 0x0505050505050505)
		binary.LittleEndian.PutUint16(data[offPrevAIKSize:], 0x0006)
		binary.LittleEndian.PutUint16(data[offQuoteSigAlg:], TPMAlgRSASSA)
		binary.LittleEndian.PutUint16(data[offQuoteHashAlg:], TPMAlgSHA256)
		binary.LittleEndian.PutUint32(data[offBPFTotal:], 0x07070707)

		report, err := ParseReport(data)
		if err != nil {
			t.Fatalf("ParseReport: %v", err)
		}
		checks := []struct {
			name string
			got  uint64
			want uint64
		}{
			{"TPM.PCRMask", uint64(report.TPM.PCRMask), 0x0BADF00D},
			{"TPM.QuoteSigSize", uint64(report.TPM.QuoteSigSize), 0x0101},
			{"TPM.AttestSize", uint64(report.TPM.AttestSize), 0x0202},
			{"TPM.AIKPublicSize", uint64(report.TPM.AIKPublicSize), 499},
			{"TPM.AIKCertSize", uint64(report.TPM.AIKCertSize), 0x0404},
			{"TPM.AIKGeneration", report.TPM.AIKGeneration, 0x0505050505050505},
			{"TPM.PrevAIKSize", uint64(report.TPM.PrevAIKSize), 0x0006},
			{"TPM.QuoteSigAlg", uint64(report.TPM.QuoteSigAlg), uint64(TPMAlgRSASSA)},
			{"TPM.QuoteSigHashAlg", uint64(report.TPM.QuoteSigHashAlg), uint64(TPMAlgSHA256)},
			{"BPF.TotalExecEvents", uint64(report.BPF.TotalExecEvents), 0x07070707},
		}
		for _, c := range checks {
			if c.got != c.want {
				t.Errorf("%s: got %#x, want %#x", c.name, c.got, c.want)
			}
		}
	})
}

func TestChallenge_Serialize(t *testing.T) {
	t.Log("TEST: Challenge serialization")

	challenge := &Challenge{
		Magic:   ReportMagic,
		Version: ReportVersion,
		PCRMask: 0x00004003,
		Flags:   ChallengeFlagBootCommitmentV1,
	}
	for i := range challenge.Nonce {
		challenge.Nonce[i] = byte(i)
	}

	data := challenge.Serialize()

	if len(data) != 48 {
		t.Errorf("Challenge size: got %d, want 48", len(data))
	}

	magic := binary.LittleEndian.Uint32(data[0:4])
	if magic != ReportMagic {
		t.Errorf("Magic: got 0x%08X, want 0x%08X", magic, ReportMagic)
	}

	nonce := data[8:40]
	for i := 0; i < 32; i++ {
		if nonce[i] != byte(i) {
			t.Errorf("Nonce[%d]: got %d, want %d", i, nonce[i], i)
		}
	}

	pcrMask := binary.LittleEndian.Uint32(data[40:44])
	if pcrMask != 0x00004003 {
		t.Errorf("PCRMask: got 0x%08X, want 0x00004003", pcrMask)
	}

	flags := binary.LittleEndian.Uint32(data[44:48])
	if flags != ChallengeFlagBootCommitmentV1 {
		t.Errorf("Flags: got 0x%08X, want 0x%08X",
			flags, ChallengeFlagBootCommitmentV1)
	}

	t.Log("✓ Challenge serialization correct")
}

func TestVerifyResult_Serialize(t *testing.T) {
	t.Log("TEST: VerifyResult serialization")

	result := &VerifyResult{
		Magic:      ReportMagic,
		Version:    ReportVersion,
		Result:     VerifyOK,
		Flags:      0,
		ValidUntil: 1700003600,
	}
	for i := range result.SessionToken {
		result.SessionToken[i] = byte(0xFF - i)
	}

	data := result.Serialize()

	if len(data) != 56 {
		t.Errorf("Result size: got %d, want 56", len(data))
	}

	resultCode := binary.LittleEndian.Uint32(data[8:12])
	if resultCode != VerifyOK {
		t.Errorf("Result: got %d, want %d", resultCode, VerifyOK)
	}

	validUntil := binary.LittleEndian.Uint64(data[16:24])
	if validUntil != 1700003600 {
		t.Errorf("ValidUntil: got %d, want 1700003600", validUntil)
	}

	t.Log("✓ VerifyResult serialization correct")
}

// Table-driven tests for flags
func TestReportFlags(t *testing.T) {
	testCases := []struct {
		name       string
		flags      uint32
		iommuOK    bool
		tpmOK      bool
		moduleSig  bool
		lockdown   bool
		secureBoot bool
	}{
		{"AllOff", 0, false, false, false, false, false},
		{"IOMMUOnly", FlagIOMMUOK, true, false, false, false, false},
		{"AllSecurityOn", FlagModuleSig | FlagLockdown | FlagSecureBoot, false, false, true, true, true},
		{
			"Production", FlagIOMMUOK | FlagTPMQuoteOK | FlagModuleSig | FlagLockdown | FlagSecureBoot,
			true, true, true, true, true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if (tc.flags&FlagIOMMUOK != 0) != tc.iommuOK {
				t.Errorf("IOMMU flag mismatch")
			}
			if (tc.flags&FlagTPMQuoteOK != 0) != tc.tpmOK {
				t.Errorf("TPM flag mismatch")
			}
			if (tc.flags&FlagModuleSig != 0) != tc.moduleSig {
				t.Errorf("ModuleSig flag mismatch")
			}
			if (tc.flags&FlagLockdown != 0) != tc.lockdown {
				t.Errorf("Lockdown flag mismatch")
			}
			if (tc.flags&FlagSecureBoot != 0) != tc.secureBoot {
				t.Errorf("SecureBoot flag mismatch")
			}
		})
	}

	t.Log("✓ All flag combinations verified")
}

// Endianness test
func TestEndianness(t *testing.T) {
	t.Log("TEST: Little-endian encoding verification")
	t.Log("C agent uses little-endian, Go must match")

	buf := make([]byte, 8)

	// uint32
	binary.LittleEndian.PutUint32(buf, 0x41544F4C) // "LOTA"
	if buf[0] != 0x4C || buf[1] != 0x4F || buf[2] != 0x54 || buf[3] != 0x41 {
		t.Error("uint32 endianness incorrect")
	}

	// uint64
	binary.LittleEndian.PutUint64(buf, 0x0123456789ABCDEF)
	expected := []byte{0xEF, 0xCD, 0xAB, 0x89, 0x67, 0x45, 0x23, 0x01}
	if !bytes.Equal(buf, expected) {
		t.Errorf("uint64 endianness:\n  got:  %x\n  want: %x", buf, expected)
	}

	t.Log("✓ Little-endian encoding correct")
}

// Benchmark parsing
func BenchmarkParseReport(b *testing.B) {
	data := createTestReportBytes()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ParseReport(data)
	}
}

// ESRT section is mandatory: agent always emits it and reports Present == false
// where the platform exposes no System Firmware entry, so report that stops
// before the section is truncated, not an older agent
func TestParseReport_RejectsMissingESRT(t *testing.T) {
	full := createTestReportBytes()
	truncated := full[:len(full)-ESRTWireSize]
	binary.LittleEndian.PutUint32(truncated[8:12], uint32(len(truncated)))

	report, err := ParseReport(truncated)
	if err == nil {
		t.Fatalf("report without the ESRT section accepted: %+v", report)
	}
	if !errors.Is(err, ErrInvalidSize) {
		t.Fatalf("missing ESRT: got %v, want ErrInvalidSize", err)
	}

	// one byte short of the section is refused just the same
	short := full[:len(full)-1]
	binary.LittleEndian.PutUint32(short[8:12], uint32(len(short)))
	if _, err := ParseReport(short); !errors.Is(err, ErrInvalidSize) {
		t.Fatalf("report one byte short of the ESRT section: got %v, want ErrInvalidSize", err)
	}
}

// report with the trailing 28-byte ESRT section round-trips into ESRTInfo
func TestParseReport_ESRT(t *testing.T) {
	esrt := make([]byte, ESRTWireSize)
	binary.LittleEndian.PutUint32(esrt[0:], 1)   // present
	binary.LittleEndian.PutUint32(esrt[4:], 785) // fw_version
	binary.LittleEndian.PutUint32(esrt[8:], 700) // lowest_supported
	esrt[12] = 0xb5                              // fw_class[0]
	esrt[13] = 0x3e                              // fw_class[1]

	// createTestReportBytes() already carries all-zero ESRT section
	// overwrite it rather than appending second one
	data := createTestReportBytes()
	copy(data[len(data)-ESRTWireSize:], esrt)

	report, err := ParseReport(data)
	if err != nil {
		t.Fatalf("ParseReport failed: %v", err)
	}
	if report.ESRT == nil {
		t.Fatal("expected ESRT non-nil")
	}
	if !report.ESRT.Present {
		t.Error("expected ESRT.Present true")
	}
	if report.ESRT.FWVersion != 785 {
		t.Errorf("FWVersion: got %d, want 785", report.ESRT.FWVersion)
	}
	if report.ESRT.LowestSupported != 700 {
		t.Errorf("LowestSupported: got %d, want 700", report.ESRT.LowestSupported)
	}
	if report.ESRT.FWClass[0] != 0xb5 || report.ESRT.FWClass[1] != 0x3e {
		t.Errorf("FWClass prefix: got %x %x, want b5 3e",
			report.ESRT.FWClass[0], report.ESRT.FWClass[1])
	}
}

// agent that ran but found no ESRT entry sends present=0
// ESRT is non-nil (the section was sent) but Present is false
// -> Low-Firmware-Assurance path
func TestParseReport_ESRT_NotPresent(t *testing.T) {
	esrt := make([]byte, ESRTWireSize) // all zero -> present=0

	// createTestReportBytes() already carries all-zero ESRT section
	// overwrite it rather than appending second one
	data := createTestReportBytes()
	copy(data[len(data)-ESRTWireSize:], esrt)

	report, err := ParseReport(data)
	if err != nil {
		t.Fatalf("ParseReport failed: %v", err)
	}
	if report.ESRT == nil {
		t.Fatal("expected ESRT non-nil (section was sent)")
	}
	if report.ESRT.Present {
		t.Error("expected ESRT.Present false")
	}
}
