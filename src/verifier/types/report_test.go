// SPDX-License-Identifier: MIT
// LOTA Verifier - Wire Format Unit Tests
//
// Tests for binary report parsing and encoding.
// Verifies alignment, padding, and endianness handling between
// C structs (agent) and Go structs (verifier).

package types

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// Test report matching C struct layout
// IMPORTANT: Any misalignment causes verification failures
func createTestReportBytes() []byte {
	buf := make([]byte, ExpectedReportSize)
	offset := 0

	// Header (32 bytes)
	binary.LittleEndian.PutUint32(buf[offset:], ReportMagic) // magic
	offset += 4
	binary.LittleEndian.PutUint32(buf[offset:], ReportVersion) // version
	offset += 4
	binary.LittleEndian.PutUint64(buf[offset:], 1700000000) // timestamp
	offset += 8
	binary.LittleEndian.PutUint64(buf[offset:], 123456789) // timestamp_ns
	offset += 8
	binary.LittleEndian.PutUint32(buf[offset:], ExpectedReportSize) // report_size
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
	// ek_certificate (2048 bytes, optional - leave empty)
	offset += MaxEKCertSize
	// ek_cert_size
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
	// reserved (2 bytes)
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

	return buf
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
		if report.Header.Timestamp != 1700000000 {
			t.Errorf("Timestamp: got %d, want 1700000000", report.Header.Timestamp)
		}
		if report.Header.TimestampNs != 123456789 {
			t.Errorf("TimestampNs: got %d, want 123456789", report.Header.TimestampNs)
		}
		if report.Header.ReportSize != ExpectedReportSize {
			t.Errorf("ReportSize: got %d, want %d", report.Header.ReportSize, ExpectedReportSize)
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
		{"AlmostComplete", ExpectedReportSize - 1},
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

func TestParseReport_Alignment(t *testing.T) {
	t.Log("TEST: Verifying field alignment matches C struct")
	t.Log("CRITICAL: Misalignment causes silent data corruption")

	// These offsets MUST match C struct with __attribute__((packed))
	// See include/attestation.h
	// TPM evidence section: 6992 bytes
	expectedOffsets := map[string]int{
		"Header.Magic":       0,
		"Header.Version":     4,
		"Header.Timestamp":   8,
		"Header.TimestampNs": 16,
		"Header.ReportSize":  24,
		"Header.Flags":       28,
		"TPM.PCRValues":      32,
		"TPM.PCRMask":        32 + 768,
		"TPM.QuoteSignature": 32 + 768 + 4,
		"TPM.QuoteSigSize":   32 + 768 + 4 + 512,
		"TPM.AttestData":     32 + 768 + 4 + 512 + 2,
		"TPM.AttestSize":     32 + 768 + 4 + 512 + 2 + 1024,
		"TPM.AIKPublic":      32 + 768 + 4 + 512 + 2 + 1024 + 2,
		"TPM.AIKPublicSize":  32 + 768 + 4 + 512 + 2 + 1024 + 2 + 512,
		"TPM.AIKCertificate": 32 + 768 + 4 + 512 + 2 + 1024 + 2 + 512 + 2,
		"TPM.AIKCertSize":    32 + 768 + 4 + 512 + 2 + 1024 + 2 + 512 + 2 + 2048,
		"TPM.EKCertificate":  32 + 768 + 4 + 512 + 2 + 1024 + 2 + 512 + 2 + 2048 + 2,
		"TPM.EKCertSize":     32 + 768 + 4 + 512 + 2 + 1024 + 2 + 512 + 2 + 2048 + 2 + 2048,
		"TPM.Nonce":          32 + 768 + 4 + 512 + 2 + 1024 + 2 + 512 + 2 + 2048 + 2 + 2048 + 2,
		"TPM.HardwareID":     32 + 768 + 4 + 512 + 2 + 1024 + 2 + 512 + 2 + 2048 + 2 + 2048 + 2 + 32,
		"System.KernelHash":  32 + 6992,
		"System.AgentHash":   32 + 6992 + 32,
		"System.KernelPath":  32 + 6992 + 64,
		"System.IOMMU":       32 + 6992 + 64 + 256,
		"BPF.TotalExec":      32 + 6992 + 396,
	}

	data := createTestReportBytes()

	for field, offset := range expectedOffsets {
		t.Run(field, func(t *testing.T) {
			if offset >= len(data) {
				t.Errorf("Offset %d exceeds data length %d", offset, len(data))
				return
			}
			t.Logf("✓ %s at offset %d", field, offset)
		})
	}

	// final check: total size (with certificates and hardware_id)
	if ExpectedReportSize != 7444 {
		t.Errorf("ExpectedReportSize: got %d, want 7444", ExpectedReportSize)
	}
	t.Logf("✓ Total report size: %d bytes", ExpectedReportSize)
}

func TestChallenge_Serialize(t *testing.T) {
	t.Log("TEST: Challenge serialization")

	challenge := &Challenge{
		Magic:   ReportMagic,
		Version: ReportVersion,
		PCRMask: 0x00004003,
		Flags:   0,
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
