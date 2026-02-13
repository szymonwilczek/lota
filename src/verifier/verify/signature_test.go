// SPDX-License-Identifier: MIT
// LOTA Verifier - Signature Verification Unit Tests
//
// Tests for TPM quote signature verification using real RSA keys.

package verify

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"testing"

	"github.com/szymonwilczek/lota/verifier/types"
)

var testKeyPair *rsa.PrivateKey

func init() {
	var err error
	testKeyPair, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic("failed to generate test key: " + err.Error())
	}
}

func TestRSASSAVerifier_ValidSignature(t *testing.T) {
	t.Log("SECURITY TEST: RSASSA-PKCS1-v1_5 signature verification")
	t.Log("This verifies TPM quote signatures over TPMS_ATTEST")

	verifier := NewRSASSAVerifier()

	attestData := []byte("test attestation data for LOTA verification")

	// simulating TPM signature
	hash := sha256.Sum256(attestData)
	signature, err := rsa.SignPKCS1v15(rand.Reader, testKeyPair, crypto.SHA256, hash[:])
	if err != nil {
		t.Fatalf("Failed to create test signature: %v", err)
	}

	err = verifier.VerifyQuoteSignature(attestData, signature, &testKeyPair.PublicKey)
	if err != nil {
		t.Fatalf("Signature verification failed: %v", err)
	}

	t.Log("✓ Valid RSASSA signature correctly verified")
}

func TestRSASSAVerifier_InvalidSignature(t *testing.T) {
	t.Log("SECURITY TEST: Rejecting invalid RSASSA signatures")
	t.Log("CRITICAL: Prevents accepting forged attestation data")

	verifier := NewRSASSAVerifier()

	attestData := []byte("test attestation data")

	// valid signature
	hash := sha256.Sum256(attestData)
	signature, _ := rsa.SignPKCS1v15(rand.Reader, testKeyPair, crypto.SHA256, hash[:])

	// corrupt signature
	signature[0] ^= 0xFF

	err := verifier.VerifyQuoteSignature(attestData, signature, &testKeyPair.PublicKey)
	if err == nil {
		t.Fatal("SECURITY VIOLATION: Invalid signature was accepted!")
	}

	t.Logf("✓ Correctly rejected corrupted signature: %v", err)
}

func TestRSASSAVerifier_WrongKey(t *testing.T) {
	t.Log("SECURITY TEST: Rejecting signatures from wrong key")
	t.Log("Ensures only registered AIK can sign valid attestations")

	verifier := NewRSASSAVerifier()

	// different key
	wrongKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	attestData := []byte("test attestation data")

	// sign with test key
	hash := sha256.Sum256(attestData)
	signature, _ := rsa.SignPKCS1v15(rand.Reader, testKeyPair, crypto.SHA256, hash[:])

	// verify with wrong key
	err := verifier.VerifyQuoteSignature(attestData, signature, &wrongKey.PublicKey)
	if err == nil {
		t.Fatal("SECURITY VIOLATION: Signature verified with wrong key!")
	}

	t.Logf("✓ Correctly rejected signature from wrong AIK: %v", err)
}

func TestRSASSAVerifier_ModifiedAttestData(t *testing.T) {
	t.Log("SECURITY TEST: Detecting modified attestation data")
	t.Log("CRITICAL: Ensures integrity of TPM quote")

	verifier := NewRSASSAVerifier()

	attestData := []byte("original attestation data")

	// sign original data
	hash := sha256.Sum256(attestData)
	signature, _ := rsa.SignPKCS1v15(rand.Reader, testKeyPair, crypto.SHA256, hash[:])

	// modify the attestation data
	modifiedData := []byte("MODIFIED attestation data")

	err := verifier.VerifyQuoteSignature(modifiedData, signature, &testKeyPair.PublicKey)
	if err == nil {
		t.Fatal("SECURITY VIOLATION: Modified data accepted with original signature!")
	}

	t.Logf("✓ Correctly detected data modification: %v", err)
}

func TestRSASSAVerifier_NilKey(t *testing.T) {
	t.Log("TEST: Nil key handling")

	verifier := NewRSASSAVerifier()

	err := verifier.VerifyQuoteSignature([]byte("data"), []byte("sig"), nil)
	if err == nil {
		t.Error("Expected error for nil key")
	}

	t.Logf("✓ Correctly handled nil key: %v", err)
}

func TestRSAPSSVerifier_ValidSignature(t *testing.T) {
	t.Log("SECURITY TEST: RSASSA-PSS signature verification")
	t.Log("Alternative signature scheme supported by TPM 2.0")

	verifier := NewRSAPSSVerifier()

	attestData := []byte("test attestation data for PSS verification")

	// sign with PSS
	hash := sha256.Sum256(attestData)
	opts := &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
		Hash:       crypto.SHA256,
	}
	signature, err := rsa.SignPSS(rand.Reader, testKeyPair, crypto.SHA256, hash[:], opts)
	if err != nil {
		t.Fatalf("Failed to create PSS signature: %v", err)
	}

	// verify
	err = verifier.VerifyQuoteSignature(attestData, signature, &testKeyPair.PublicKey)
	if err != nil {
		t.Fatalf("PSS signature verification failed: %v", err)
	}

	t.Log("✓ Valid RSASSA-PSS signature correctly verified")
}

func TestRSAPSSVerifier_InvalidSignature(t *testing.T) {
	t.Log("SECURITY TEST: Rejecting invalid PSS signatures")

	verifier := NewRSAPSSVerifier()

	attestData := []byte("test data")
	hash := sha256.Sum256(attestData)
	opts := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256}
	signature, _ := rsa.SignPSS(rand.Reader, testKeyPair, crypto.SHA256, hash[:], opts)

	// corrupt signature
	signature[len(signature)-1] ^= 0xFF

	err := verifier.VerifyQuoteSignature(attestData, signature, &testKeyPair.PublicKey)
	if err == nil {
		t.Fatal("SECURITY: Invalid PSS signature was accepted!")
	}

	t.Logf("✓ Correctly rejected corrupted PSS signature")
}

func TestSelectVerifier(t *testing.T) {
	t.Log("TEST: Verifier selection by algorithm")

	// known algorithms should succeed
	knownCases := []struct {
		sigAlg   uint16
		wantName string
	}{
		{0x0014, "RSASSA-PKCS1-v1_5"}, // TPM_ALG_RSASSA
		{0x0016, "RSASSA-PSS"},        // TPM_ALG_RSAPSS
	}

	for _, tc := range knownCases {
		t.Run(tc.wantName, func(t *testing.T) {
			v, err := SelectVerifier(tc.sigAlg)
			if err != nil {
				t.Fatalf("SelectVerifier(0x%04X) unexpected error: %v", tc.sigAlg, err)
			}
			if v.Name() != tc.wantName {
				t.Errorf("For alg 0x%04X: got %s, want %s",
					tc.sigAlg, v.Name(), tc.wantName)
			}
		})
	}

	// unknown algorithms must be rejected
	unknownAlgs := []uint16{0x0000, 0xFFFF, 0x0001, 0x0015}
	for _, alg := range unknownAlgs {
		t.Run(fmt.Sprintf("reject_0x%04X", alg), func(t *testing.T) {
			v, err := SelectVerifier(alg)
			if err == nil {
				t.Errorf("SelectVerifier(0x%04X) should fail, got verifier %q", alg, v.Name())
			}
		})
	}

	t.Log("✓ Correct verifier selection for all algorithms")
}

func TestVerifyReportSignature_ValidReport(t *testing.T) {
	t.Log("SECURITY TEST: Full report signature verification")
	t.Log("End-to-end test of signature verification pipeline")

	attestData := []byte("real TPMS_ATTEST blob would be here")
	hash := sha256.Sum256(attestData)
	signature, _ := rsa.SignPKCS1v15(rand.Reader, testKeyPair, crypto.SHA256, hash[:])

	report := &types.AttestationReport{}
	report.TPM.AttestSize = uint16(len(attestData))

	copy(report.TPM.AttestData[:], attestData)
	report.TPM.QuoteSigSize = uint16(len(signature))
	copy(report.TPM.QuoteSignature[:], signature)

	err := VerifyReportSignature(report, &testKeyPair.PublicKey)
	if err != nil {
		t.Fatalf("Report signature verification failed: %v", err)
	}

	t.Log("✓ Report signature correctly verified")
}

func TestVerifyReportSignature_NoSignature(t *testing.T) {
	t.Log("SECURITY TEST: Rejecting report without signature")

	report := &types.AttestationReport{}
	report.TPM.QuoteSigSize = 0 // no signature

	err := VerifyReportSignature(report, &testKeyPair.PublicKey)
	if err == nil {
		t.Fatal("SECURITY: Report without signature was accepted!")
	}

	t.Logf("✓ Correctly rejected unsigned report: %v", err)
}

func TestVerifyReportSignature_NoAttestData(t *testing.T) {
	t.Log("SECURITY TEST: Rejecting report without attestation data")

	report := &types.AttestationReport{}
	report.TPM.QuoteSigSize = 256
	report.TPM.AttestSize = 0 // no attest data

	err := VerifyReportSignature(report, &testKeyPair.PublicKey)
	if err == nil {
		t.Fatal("SECURITY: Report without attest data was accepted!")
	}

	t.Logf("✓ Correctly rejected report without attest data: %v", err)
}

func TestVerifyReportSignature_PSSSignature(t *testing.T) {
	t.Log("SECURITY TEST: Report signature verification with RSA-PSS")

	attestData := []byte("TPMS_ATTEST blob signed with PSS")
	hash := sha256.Sum256(attestData)
	opts := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256}
	signature, err := rsa.SignPSS(rand.Reader, testKeyPair, crypto.SHA256, hash[:], opts)
	if err != nil {
		t.Fatalf("Failed to create PSS signature: %v", err)
	}

	report := &types.AttestationReport{}
	report.TPM.AttestSize = uint16(len(attestData))
	copy(report.TPM.AttestData[:], attestData)
	report.TPM.QuoteSigSize = uint16(len(signature))
	copy(report.TPM.QuoteSignature[:], signature)

	err = VerifyReportSignature(report, &testKeyPair.PublicKey)
	if err != nil {
		t.Fatalf("PSS report signature verification failed: %v", err)
	}

	t.Log("✓ Report with PSS signature correctly verified via fallback")
}

func TestParseRSAPublicKey_RejectsSmallKey(t *testing.T) {
	t.Log("SECURITY TEST: Rejecting RSA keys smaller than 2048 bits")

	smallKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("Failed to generate small key: %v", err)
	}

	keyBytes, err := x509.MarshalPKIXPublicKey(&smallKey.PublicKey)
	if err != nil {
		t.Fatalf("Failed to marshal key: %v", err)
	}

	_, err = ParseRSAPublicKey(keyBytes)
	if err == nil {
		t.Fatal("SECURITY: 1024-bit RSA key was accepted!")
	}

	t.Logf("✓ Correctly rejected small key: %v", err)
}

func TestAIKFingerprint(t *testing.T) {
	t.Log("TEST: AIK fingerprint generation")

	fp := AIKFingerprint(&testKeyPair.PublicKey)

	// fingerprint should be 64 hex chars (256 bits = 32 bytes)
	if len(fp) != 64 {
		t.Errorf("Fingerprint length: got %d, want 64", len(fp))
	}

	// same key should produce same fingerprint
	fp2 := AIKFingerprint(&testKeyPair.PublicKey)
	if fp != fp2 {
		t.Error("Same key produced different fingerprints!")
	}

	// different key should produce different fingerprint
	otherKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	fp3 := AIKFingerprint(&otherKey.PublicKey)
	if fp == fp3 {
		t.Error("Different keys produced same fingerprint!")
	}

	t.Logf("✓ AIK fingerprint: %s", fp)
}

func BenchmarkRSASSAVerify(b *testing.B) {
	verifier := NewRSASSAVerifier()
	attestData := make([]byte, 145) // typical TPMS_ATTEST size
	rand.Read(attestData)

	hash := sha256.Sum256(attestData)
	signature, _ := rsa.SignPKCS1v15(rand.Reader, testKeyPair, crypto.SHA256, hash[:])

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		verifier.VerifyQuoteSignature(attestData, signature, &testKeyPair.PublicKey)
	}
}

func BenchmarkRSAPSSVerify(b *testing.B) {
	verifier := NewRSAPSSVerifier()
	attestData := make([]byte, 145)
	rand.Read(attestData)

	hash := sha256.Sum256(attestData)
	opts := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256}
	signature, _ := rsa.SignPSS(rand.Reader, testKeyPair, crypto.SHA256, hash[:], opts)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		verifier.VerifyQuoteSignature(attestData, signature, &testKeyPair.PublicKey)
	}
}
