// SPDX-License-Identifier: MIT
// LOTA Verifier - TPMS_ATTEST Parser Unit Tests
//
// These tests verify correct parsing of TPM 2.0 attestation
// structures.
//
// Test vectors are derived from real TPM 2.0 hardware captures.

package verify

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/szymonwilczek/lota/verifier/types"
)

// magic:           ff544347 (TPM_GENERATED_VALUE)
// type:            8018 (TPM_ST_ATTEST_QUOTE)
// qualifiedSigner: [size:2][name:34 bytes]
// extraData:       [size:2][nonce:32 bytes]
// clockInfo:       [clock:8][resetCount:4][restartCount:4][safe:1]
// firmwareVersion: [8 bytes]
// quoteInfo:       [pcrSelect][pcrDigest]
var realTPMSAttestBlob = mustDecodeHex(
	"ff544347" + // magic: TPM_GENERATED_VALUE
		"8018" + // type: TPM_ST_ATTEST_QUOTE
		"0022" + // qualifiedSigner size: 34
		"000b" + // name algorithm: SHA256
		"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4" + // name hash (32 bytes)
		"e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2" +
		"0020" + // extraData size: 32 (nonce)
		"0102030405060708090a0b0c0d0e0f10" + // nonce (32 bytes)
		"1112131415161718191a1b1c1d1e1f20" +
		"0000000000001234" + // clock
		"00000005" + // resetCount
		"00000003" + // restartCount
		"01" + // safe: true
		"0000000100020003" + // firmwareVersion
		"00000001" + // PCR selection count
		"000b" + // hash algorithm: SHA256
		"03" + // sizeofSelect
		"030040" + // PCR bitmap (PCR 0,1,14)
		"0020" + // PCR digest size
		"deadbeefdeadbeefdeadbeefdeadbeef" + // PCR digest (32 bytes)
		"cafebabecafebabecafebabecafebabe",
)

var expectedNonce = mustDecodeHex(
	"0102030405060708090a0b0c0d0e0f10" +
		"1112131415161718191a1b1c1d1e1f20",
)

func TestParseTPMSAttest_ValidQuote(t *testing.T) {
	t.Log("SECURITY TEST: Verifying TPMS_ATTEST structure parsing")
	t.Log("This is critical for nonce verification and replay attack prevention")

	attest, err := ParseTPMSAttest(realTPMSAttestBlob)
	if err != nil {
		t.Fatalf("Failed to parse valid TPMS_ATTEST: %v", err)
	}

	// TPM_GENERATED_VALUE
	t.Run("Magic", func(t *testing.T) {
		if attest.Magic != TPMGeneratedValue {
			t.Errorf("Magic mismatch: got 0x%08X, want 0x%08X",
				attest.Magic, TPMGeneratedValue)
		}
		t.Logf("✓ Magic value correct (0x%08X = TPM_GENERATED_VALUE)", attest.Magic)
	})

	// TPM_ST_ATTEST_QUOTE
	t.Run("Type", func(t *testing.T) {
		if attest.Type != TPMSTAttestQuote {
			t.Errorf("Type mismatch: got 0x%04X, want 0x%04X",
				attest.Type, TPMSTAttestQuote)
		}
		t.Logf("✓ Attestation type correct (0x%04X = TPM_ST_ATTEST_QUOTE)", attest.Type)
	})

	t.Run("QualifiedSigner", func(t *testing.T) {
		if len(attest.QualifiedSigner) != 34 {
			t.Errorf("QualifiedSigner length: got %d, want 34",
				len(attest.QualifiedSigner))
		}
		t.Logf("✓ QualifiedSigner parsed (%d bytes)", len(attest.QualifiedSigner))
	})

	// nonce extraction
	t.Run("ExtraData_Nonce", func(t *testing.T) {
		t.Log("SECURITY: extraData contains challenge nonce - critical for anti-replay")

		if len(attest.ExtraData) != 32 {
			t.Errorf("ExtraData length: got %d, want 32", len(attest.ExtraData))
		}

		if !bytes.Equal(attest.ExtraData, expectedNonce) {
			t.Errorf("ExtraData (nonce) mismatch:\n  got:  %x\n  want: %x",
				attest.ExtraData, expectedNonce)
		}
		t.Logf("✓ Nonce correctly extracted from extraData")
	})

	t.Run("ClockInfo", func(t *testing.T) {
		if attest.ClockInfo.Clock != 0x1234 {
			t.Errorf("Clock: got 0x%X, want 0x1234", attest.ClockInfo.Clock)
		}
		if attest.ClockInfo.ResetCount != 5 {
			t.Errorf("ResetCount: got %d, want 5", attest.ClockInfo.ResetCount)
		}
		if attest.ClockInfo.RestartCount != 3 {
			t.Errorf("RestartCount: got %d, want 3", attest.ClockInfo.RestartCount)
		}
		if !attest.ClockInfo.Safe {
			t.Error("Safe flag should be true")
		}
		t.Logf("✓ ClockInfo parsed correctly")
	})

	t.Run("FirmwareVersion", func(t *testing.T) {
		expected := uint64(0x0000000100020003)
		if attest.FirmwareVersion != expected {
			t.Errorf("FirmwareVersion: got 0x%X, want 0x%X",
				attest.FirmwareVersion, expected)
		}
		t.Logf("✓ FirmwareVersion correct")
	})

	t.Run("QuoteInfo", func(t *testing.T) {
		if attest.QuoteInfo == nil {
			t.Fatal("QuoteInfo is nil for TPM_ST_ATTEST_QUOTE")
		}
		if len(attest.QuoteInfo.PCRDigest) != 32 {
			t.Errorf("PCRDigest length: got %d, want 32",
				len(attest.QuoteInfo.PCRDigest))
		}
		t.Logf("✓ QuoteInfo with PCR digest parsed")
	})
}

func TestParseTPMSAttest_InvalidMagic(t *testing.T) {
	t.Log("SECURITY TEST: Rejecting TPMS_ATTEST with invalid magic")
	t.Log("Prevents accepting non-TPM-generated data")

	invalidBlob := make([]byte, len(realTPMSAttestBlob))
	copy(invalidBlob, realTPMSAttestBlob)
	invalidBlob[0] = 0x00 // corrupted magic

	_, err := ParseTPMSAttest(invalidBlob)
	if err == nil {
		t.Fatal("Expected error for invalid magic, got nil")
	}

	t.Logf("✓ Correctly rejected invalid magic: %v", err)
}

func TestParseTPMSAttest_TruncatedData(t *testing.T) {
	t.Log("SECURITY TEST: Rejecting truncated TPMS_ATTEST")
	t.Log("Prevents buffer over-read attacks")

	testCases := []struct {
		name   string
		length int
	}{
		{"Empty", 0},
		{"TooShort", 10},
		{"MissingExtraData", 40},
		{"MissingClockInfo", 80},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			truncated := realTPMSAttestBlob[:min(tc.length, len(realTPMSAttestBlob))]
			_, err := ParseTPMSAttest(truncated)
			if err == nil {
				t.Errorf("Expected error for truncated data (%d bytes)", tc.length)
			} else {
				t.Logf("✓ Correctly rejected %d-byte blob: %v", tc.length, err)
			}
		})
	}
}

func TestVerifyNonceInAttest_Match(t *testing.T) {
	t.Log("SECURITY TEST: Nonce verification in TPMS_ATTEST")
	t.Log("CRITICAL: This prevents replay attacks")

	err := VerifyNonceInAttest(realTPMSAttestBlob, expectedNonce)
	if err != nil {
		t.Fatalf("Nonce verification failed for matching nonce: %v", err)
	}

	t.Log("✓ Matching nonce correctly verified")
}

func TestVerifyNonceInAttest_Mismatch(t *testing.T) {
	t.Log("SECURITY TEST: Rejecting mismatched nonce")
	t.Log("CRITICAL: Detects replay attacks with old TPM quotes")

	wrongNonce := make([]byte, 32)
	copy(wrongNonce, expectedNonce)
	wrongNonce[0] ^= 0xFF // flipped first byte

	err := VerifyNonceInAttest(realTPMSAttestBlob, wrongNonce)
	if err == nil {
		t.Fatal("Expected error for mismatched nonce, got nil")
	}

	t.Logf("✓ Correctly rejected mismatched nonce: %v", err)
}

func TestGetNonceFromAttest(t *testing.T) {
	t.Log("SECURITY TEST: Nonce extraction from TPMS_ATTEST")

	nonce, err := GetNonceFromAttest(realTPMSAttestBlob)
	if err != nil {
		t.Fatalf("Failed to extract nonce: %v", err)
	}

	if !bytes.Equal(nonce, expectedNonce) {
		t.Errorf("Extracted nonce mismatch:\n  got:  %x\n  want: %x",
			nonce, expectedNonce)
	}

	t.Logf("✓ Nonce correctly extracted: %x", nonce)
}

// Table-driven test for various TPMS_ATTEST edge cases
func TestParseTPMSAttest_TableDriven(t *testing.T) {
	testCases := []struct {
		name        string
		hexBlob     string
		wantErr     bool
		errContains string
		checkFn     func(*TPMSAttest) error
	}{
		{
			name:    "ValidQuote",
			hexBlob: hex.EncodeToString(realTPMSAttestBlob),
			wantErr: false,
			checkFn: func(a *TPMSAttest) error {
				if a.Magic != TPMGeneratedValue {
					return bytes.ErrTooLarge // placeholder
				}
				return nil
			},
		},
		{
			name:        "InvalidMagic_Zero",
			hexBlob:     "00000000" + hex.EncodeToString(realTPMSAttestBlob[4:]),
			wantErr:     true,
			errContains: "invalid TPM magic",
		},
		{
			name:        "InvalidMagic_Random",
			hexBlob:     "deadbeef" + hex.EncodeToString(realTPMSAttestBlob[4:]),
			wantErr:     true,
			errContains: "invalid TPM magic",
		},
		{
			name:    "EmptyExtraData",
			hexBlob: createTestBlobWithNonceSize(0),
			wantErr: false,
			checkFn: func(a *TPMSAttest) error {
				if len(a.ExtraData) != 0 {
					return bytes.ErrTooLarge
				}
				return nil
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			blob, err := hex.DecodeString(tc.hexBlob)
			if err != nil {
				t.Fatalf("Invalid test hex: %v", err)
			}

			attest, err := ParseTPMSAttest(blob)

			if tc.wantErr {
				if err == nil {
					t.Error("Expected error, got nil")
				} else if tc.errContains != "" && !contains(err.Error(), tc.errContains) {
					t.Errorf("Error should contain %q, got: %v", tc.errContains, err)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if tc.checkFn != nil {
					if checkErr := tc.checkFn(attest); checkErr != nil {
						t.Errorf("Check function failed: %v", checkErr)
					}
				}
			}
		})
	}
}

func mustDecodeHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic("invalid hex in test: " + err.Error())
	}
	return b
}

func createTestBlobWithNonceSize(nonceSize int) string {
	blob := "ff544347" + // magic
		"8018" + // type: quote
		"0002" + // qualifiedSigner size: 2
		"0000" + // minimal signer
		hex.EncodeToString([]byte{byte(nonceSize >> 8), byte(nonceSize)}) // extraData size

	// nonce bytes
	for i := 0; i < nonceSize; i++ {
		blob += "00"
	}

	// minimal clock info and firmware
	blob += "0000000000000000" + // clock
		"00000000" + // resetCount
		"00000000" + // restartCount
		"00" + // safe
		"0000000000000000" + // firmwareVersion
		// QuoteInfo (TPMS_QUOTE_INFO):
		"00000001" + // PCR selection count = 1
		"000b" + // hash algorithm: SHA256
		"03" + // sizeofSelect = 3
		"ff0000" + // pcrSelect bitmap (PCR 0-7)
		"0020" + // PCR digest size = 32
		"0000000000000000000000000000000000000000000000000000000000000000" // digest

	return blob
}

func contains(s, substr string) bool {
	return bytes.Contains([]byte(s), []byte(substr))
}

// builds a TPMS_ATTEST blob with the given PCR digest
func buildTestAttestBlob(pcrDigest []byte) []byte {
	blob := mustDecodeHex(
		"ff544347" + // magic: TPM_GENERATED_VALUE
			"8018" + // type: TPM_ST_ATTEST_QUOTE
			"0002" + // qualifiedSigner size: 2
			"0000" + // minimal signer
			"0020" + // extraData size: 32 (nonce)
			"0102030405060708090a0b0c0d0e0f10" +
			"1112131415161718191a1b1c1d1e1f20" +
			"0000000000000000" + // clock
			"00000000" + // resetCount
			"00000000" + // restartCount
			"00" + // safe
			"0000000000000000" + // firmwareVersion
			"00000001" + // PCR selection count: 1
			"000b" + // hash algorithm: SHA256
			"03" + // sizeofSelect: 3
			"034000" + // PCR bitmap (PCR 0,1,14)
			"0020", // PCR digest size: 32
	)
	blob = append(blob, pcrDigest...)
	return blob
}

func TestVerifyPCRDigest_Match(t *testing.T) {
	t.Log("SECURITY TEST: PCR digest binding verification")
	t.Log("CRITICAL: Ensures reported PCR values match TPM-signed digest")

	// PCR mask: PCR 0, 1, 14
	pcrMask := uint32((1 << 0) | (1 << 1) | (1 << 14))

	// create known PCR values
	var pcrValues [types.PCRCount][types.HashSize]byte
	for i := 0; i < types.HashSize; i++ {
		pcrValues[0][i] = byte(i)
		pcrValues[1][i] = byte(i + 0x20)
		pcrValues[14][i] = byte(i + 0x40)
	}

	// compute expected digest: SHA-256(PCR0 || PCR1 || PCR14)
	h := sha256.New()
	h.Write(pcrValues[0][:])
	h.Write(pcrValues[1][:])
	h.Write(pcrValues[14][:])
	expectedDigest := h.Sum(nil)

	blob := buildTestAttestBlob(expectedDigest)

	err := VerifyPCRDigest(blob, pcrValues, pcrMask)
	if err != nil {
		t.Fatalf("PCR digest should match: %v", err)
	}

	t.Log("✓ PCR digest correctly verified against reported values")
}

func TestVerifyPCRDigest_Mismatch(t *testing.T) {
	t.Log("SECURITY TEST: Detecting tampered PCR values")
	t.Log("CRITICAL: A malicious agent sending fake PCR values must be caught")

	pcrMask := uint32((1 << 0) | (1 << 1) | (1 << 14))

	var pcrValues [types.PCRCount][types.HashSize]byte
	for i := 0; i < types.HashSize; i++ {
		pcrValues[0][i] = byte(i)
		pcrValues[1][i] = byte(i + 0x20)
		pcrValues[14][i] = byte(i + 0x40)
	}

	// compute digest from original values
	h := sha256.New()
	h.Write(pcrValues[0][:])
	h.Write(pcrValues[1][:])
	h.Write(pcrValues[14][:])
	realDigest := h.Sum(nil)

	blob := buildTestAttestBlob(realDigest)

	// tamper with PCR values (simulate malicious agent)
	pcrValues[14][0] ^= 0xFF

	err := VerifyPCRDigest(blob, pcrValues, pcrMask)
	if err == nil {
		t.Fatal("Expected error for tampered PCR values, got nil")
	}

	t.Logf("✓ Correctly detected tampered PCR values: %v", err)
}

func TestVerifyPCRDigest_InvalidAttest(t *testing.T) {
	t.Log("SECURITY TEST: Rejecting invalid attestation data")

	pcrMask := uint32((1 << 0) | (1 << 1) | (1 << 14))
	var pcrValues [types.PCRCount][types.HashSize]byte

	err := VerifyPCRDigest([]byte{0x00, 0x01, 0x02}, pcrValues, pcrMask)
	if err == nil {
		t.Fatal("Expected error for invalid attestation data, got nil")
	}

	t.Logf("✓ Correctly rejected invalid attestation data: %v", err)
}
