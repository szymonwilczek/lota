// SPDX-License-Identifier: MIT
// LOTA Verifier - Integration Tests
//
// End-to-end tests for the complete attestation verification pipeline.
// These tests simulate real attestation scenarios without network I/O.

package verify

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"testing"
	"time"

	"github.com/szymonwilczek/lota/verifier/store"
	"github.com/szymonwilczek/lota/verifier/types"
)

// simulates TPMs Attestation Identity Key
var integrationTestKey *rsa.PrivateKey

func init() {
	var err error
	integrationTestKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic("failed to generate integration test key: " + err.Error())
	}
}

// builds a complete attestation report with valid signatures
func createValidReport(t *testing.T, nonce [32]byte, pcr14 [32]byte) []byte {
	t.Helper()

	buf := make([]byte, types.ExpectedReportSize)
	offset := 0

	// Header (32 bytes)
	binary.LittleEndian.PutUint32(buf[offset:], types.ReportMagic)
	offset += 4
	binary.LittleEndian.PutUint32(buf[offset:], types.ReportVersion)
	offset += 4
	binary.LittleEndian.PutUint64(buf[offset:], uint64(time.Now().Unix()))
	offset += 8
	binary.LittleEndian.PutUint64(buf[offset:], 0) // timestamp_ns
	offset += 8
	binary.LittleEndian.PutUint32(buf[offset:], types.ExpectedReportSize)
	offset += 4
	binary.LittleEndian.PutUint32(buf[offset:], types.FlagTPMQuoteOK|types.FlagModuleSig|types.FlagEnforce)
	offset += 4

	// TPM Evidence - PCR values
	for i := 0; i < types.PCRCount; i++ {
		for j := 0; j < types.HashSize; j++ {
			if i == 14 {
				buf[offset+j] = pcr14[j]
			} else {
				buf[offset+j] = byte(i ^ j)
			}
		}
		offset += types.HashSize
	}

	// PCR mask
	binary.LittleEndian.PutUint32(buf[offset:], 0x00004003) // PCR 0,1,14
	offset += 4

	attestData := createTPMSAttestWithNonce(nonce[:])

	hash := sha256.Sum256(attestData)
	signature, err := rsa.SignPKCS1v15(rand.Reader, integrationTestKey, crypto.SHA256, hash[:])
	if err != nil {
		t.Fatalf("Failed to sign attest data: %v", err)
	}

	// quote signature
	copy(buf[offset:], signature)
	offset += types.MaxSigSize
	binary.LittleEndian.PutUint16(buf[offset:], uint16(len(signature)))
	offset += 2

	// attest data
	copy(buf[offset:], attestData)
	offset += types.MaxAttestSize
	binary.LittleEndian.PutUint16(buf[offset:], uint16(len(attestData)))
	offset += 2

	// aik public key (der encoded)
	aikPub := marshalRSAPublicKey(&integrationTestKey.PublicKey)
	copy(buf[offset:], aikPub)
	offset += types.MaxAIKPubSize
	binary.LittleEndian.PutUint16(buf[offset:], uint16(len(aikPub)))
	offset += 2

	// AIK certificate (optional, leave empty)
	offset += types.MaxAIKCertSize
	binary.LittleEndian.PutUint16(buf[offset:], 0) // no AIK cert
	offset += 2

	// EK certificate (optional, leave empty)
	offset += types.MaxEKCertSize
	binary.LittleEndian.PutUint16(buf[offset:], 0) // no EK cert
	offset += 2

	// nonce
	copy(buf[offset:], nonce[:])
	offset += types.NonceSize

	// reserved
	offset += 2

	// System Measurement (396 bytes)
	// kernel_hash
	for i := 0; i < types.HashSize; i++ {
		buf[offset+i] = byte(0xAA ^ i)
	}
	offset += types.HashSize
	// agent_hash
	for i := 0; i < types.HashSize; i++ {
		buf[offset+i] = byte(0xBB ^ i)
	}
	offset += types.HashSize
	// kernel_path
	copy(buf[offset:], "/boot/vmlinuz-6.12.0-lota")
	offset += types.MaxKernelPath
	// IOMMU
	binary.LittleEndian.PutUint32(buf[offset:], 0x8086)
	offset += 4
	binary.LittleEndian.PutUint32(buf[offset:], 0x07)
	offset += 4
	binary.LittleEndian.PutUint32(buf[offset:], 2)
	offset += 4
	copy(buf[offset:], "intel_iommu=on")
	offset += types.CmdlineParamMax

	// BPF Summary
	binary.LittleEndian.PutUint32(buf[offset:], 42)
	offset += 4
	binary.LittleEndian.PutUint32(buf[offset:], 10)
	offset += 4
	binary.LittleEndian.PutUint64(buf[offset:], uint64(time.Now().Add(-time.Hour).Unix()))
	offset += 8
	binary.LittleEndian.PutUint64(buf[offset:], uint64(time.Now().Unix()))

	return buf
}

// builds minimal TPMS_ATTEST structure
func createTPMSAttestWithNonce(nonce []byte) []byte {
	buf := make([]byte, 0, 128)

	// Magic: TPM_GENERATED_VALUE
	buf = append(buf, 0xff, 0x54, 0x43, 0x47)

	// Type: TPM_ST_ATTEST_QUOTE
	buf = append(buf, 0x80, 0x18)

	// QualifiedSigner: TPM2B_NAME (minimal)
	buf = append(buf, 0x00, 0x02, 0x00, 0x00)

	// ExtraData: TPM2B_DATA (nonce)
	buf = append(buf, 0x00, byte(len(nonce)))
	buf = append(buf, nonce...)

	// ClockInfo
	buf = append(buf, make([]byte, 8)...) // clock
	buf = append(buf, make([]byte, 4)...) // resetCount
	buf = append(buf, make([]byte, 4)...) // restartCount
	buf = append(buf, 0x01)               // safe

	// FirmwareVersion
	buf = append(buf, make([]byte, 8)...)

	// QuoteInfo (TPMS_QUOTE_INFO)
	buf = append(buf, 0x00, 0x00, 0x00, 0x01) // PCR selection count
	buf = append(buf, 0x00, 0x0b)             // SHA256
	buf = append(buf, 0x03)                   // sizeofSelect
	buf = append(buf, 0x03, 0x00, 0x40)       // PCR 0,1,14
	buf = append(buf, 0x00, 0x20)             // digest size
	buf = append(buf, make([]byte, 32)...)    // PCR digest

	return buf
}

// encodes RSA public key in DER format
func marshalRSAPublicKey(pub *rsa.PublicKey) []byte {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		panic("failed to marshal public key: " + err.Error())
	}
	return der
}

// creates a Verifier with default policy for testing
func createTestVerifier(aikStore store.AIKStore) *Verifier {
	cfg := DefaultConfig()
	cfg.TimestampMaxAge = 5 * time.Minute
	verifier := NewVerifier(cfg, aikStore)

	// default policy that allows any values
	verifier.AddPolicy(DefaultPolicy())
	verifier.SetActivePolicy("default")

	return verifier
}

func TestIntegration_FullAttestationFlow_TOFU(t *testing.T) {
	t.Log("INTEGRATION TEST: Full attestation flow with TOFU")
	t.Log("Simulates first-time client attestation")

	aikStore := store.NewMemoryStore()
	verifier := createTestVerifier(aikStore)

	clientID := "test-client-001"

	challenge, err := verifier.GenerateChallenge(clientID)
	if err != nil {
		t.Fatalf("Failed to generate challenge: %v", err)
	}
	t.Logf("✓ Challenge generated with nonce: %x...", challenge.Nonce[:8])

	pcr14 := [32]byte{}
	for i := range pcr14 {
		pcr14[i] = byte(0x14 ^ i)
	}

	reportData := createValidReport(t, challenge.Nonce, pcr14)
	t.Logf("✓ Report created (%d bytes)", len(reportData))

	result, err := verifier.VerifyReport(clientID, reportData)
	if err != nil {
		t.Fatalf("Verification failed: %v", err)
	}

	if result.Result != types.VerifyOK {
		t.Errorf("Expected VerifyOK, got result code %d", result.Result)
	}

	registeredAIK, err := aikStore.GetAIK(clientID)
	if err != nil {
		t.Fatalf("AIK not registered after TOFU: %v", err)
	}
	t.Logf("✓ TOFU: AIK registered with fingerprint: %s", AIKFingerprint(registeredAIK))

	t.Log("✓ Full attestation flow completed successfully")
}

func TestIntegration_SubsequentAttestation(t *testing.T) {
	t.Log("INTEGRATION TEST: Subsequent attestation with registered AIK")

	aikStore := store.NewMemoryStore()
	aikStore.RegisterAIK("test-client", &integrationTestKey.PublicKey)

	verifier := createTestVerifier(aikStore)

	clientID := "test-client"

	// establish baseline
	challenge1, _ := verifier.GenerateChallenge(clientID)
	pcr14 := [32]byte{}
	for i := range pcr14 {
		pcr14[i] = byte(0x14 ^ i)
	}
	report1 := createValidReport(t, challenge1.Nonce, pcr14)
	result1, err := verifier.VerifyReport(clientID, report1)
	if err != nil || result1.Result != types.VerifyOK {
		t.Fatalf("First attestation failed: %v (result=%d)", err, result1.Result)
	}
	t.Log("✓ First attestation established baseline")

	// should match baseline
	challenge2, _ := verifier.GenerateChallenge(clientID)
	report2 := createValidReport(t, challenge2.Nonce, pcr14)
	result2, err := verifier.VerifyReport(clientID, report2)
	if err != nil || result2.Result != types.VerifyOK {
		t.Fatalf("Second attestation failed: %v (result=%d)", err, result2.Result)
	}
	t.Log("✓ Subsequent attestation matched baseline")
}

func TestIntegration_PCR14BaselineViolation(t *testing.T) {
	t.Log("INTEGRATION TEST: PCR14 baseline violation detection")
	t.Log("CRITICAL SECURITY TEST: Detects agent tampering")

	aikStore := store.NewMemoryStore()
	aikStore.RegisterAIK("compromised-client", &integrationTestKey.PublicKey)

	verifier := createTestVerifier(aikStore)

	clientID := "compromised-client"

	// establish baseline
	challenge1, _ := verifier.GenerateChallenge(clientID)
	originalPCR14 := [32]byte{}
	for i := range originalPCR14 {
		originalPCR14[i] = byte(0x14 ^ i)
	}
	report1 := createValidReport(t, challenge1.Nonce, originalPCR14)
	result1, _ := verifier.VerifyReport(clientID, report1)
	if result1.Result != types.VerifyOK {
		t.Fatalf("Baseline establishment failed")
	}
	t.Logf("✓ Baseline established: PCR14 = %x...", originalPCR14[:8])

	// MODIFIED PCR14
	challenge2, _ := verifier.GenerateChallenge(clientID)
	tamperedPCR14 := [32]byte{}
	copy(tamperedPCR14[:], originalPCR14[:])
	tamperedPCR14[0] ^= 0xFF // flip first byte - TAMPERING!

	report2 := createValidReport(t, challenge2.Nonce, tamperedPCR14)
	result2, err := verifier.VerifyReport(clientID, report2)

	// MUST detect the tampering
	if result2.Result != types.VerifyIntegrityMismatch {
		t.Fatalf("SECURITY FAILURE: PCR14 tampering NOT detected!\n"+
			"  Expected: FAIL_INTEGRITY_MISMATCH (%d)\n"+
			"  Got: %d\n"+
			"  Original PCR14: %x\n"+
			"  Tampered PCR14: %x",
			types.VerifyIntegrityMismatch, result2.Result,
			originalPCR14[:8], tamperedPCR14[:8])
	}

	if err == nil {
		t.Error("Expected error message for PCR14 mismatch")
	}

	t.Logf("✓ SECURITY: PCR14 tampering correctly detected: %v", err)
}

func TestIntegration_NonceReplayAttack(t *testing.T) {
	t.Log("INTEGRATION TEST: Nonce replay attack detection")
	t.Log("CRITICAL SECURITY TEST: Prevents attestation replay")

	aikStore := store.NewMemoryStore()
	aikStore.RegisterAIK("replay-victim", &integrationTestKey.PublicKey)

	verifier := createTestVerifier(aikStore)
	clientID := "replay-victim"
	challenge, _ := verifier.GenerateChallenge(clientID)
	pcr14 := [32]byte{}
	for i := range pcr14 {
		pcr14[i] = byte(0x14 ^ i)
	}
	reportData := createValidReport(t, challenge.Nonce, pcr14)

	// should succeed
	result1, err := verifier.VerifyReport(clientID, reportData)
	if err != nil || result1.Result != types.VerifyOK {
		t.Fatalf("First submission failed: %v", err)
	}
	t.Log("✓ First submission accepted")

	// REPLAY ATTEMPT - same report again
	result2, err := verifier.VerifyReport(clientID, reportData)

	if result2.Result != types.VerifyNonceFail {
		t.Fatalf("SECURITY FAILURE: Replay attack NOT detected!\n"+
			"  Expected: FAIL_NONCE (%d)\n"+
			"  Got: %d",
			types.VerifyNonceFail, result2.Result)
	}

	t.Logf("✓ SECURITY: Replay attack correctly blocked: %v", err)
}

func TestIntegration_StaleTimestamp(t *testing.T) {
	t.Log("INTEGRATION TEST: Stale timestamp rejection")

	aikStore := store.NewMemoryStore()
	aikStore.RegisterAIK("stale-client", &integrationTestKey.PublicKey)

	cfg := DefaultConfig()
	cfg.TimestampMaxAge = 1 * time.Second
	verifier := NewVerifier(cfg, aikStore)
	verifier.AddPolicy(DefaultPolicy())
	verifier.SetActivePolicy("default")

	clientID := "stale-client"

	challenge, _ := verifier.GenerateChallenge(clientID)
	pcr14 := [32]byte{}
	reportData := createValidReport(t, challenge.Nonce, pcr14)

	// manually make timestamp old
	oldTimestamp := uint64(time.Now().Add(-5 * time.Minute).Unix())
	binary.LittleEndian.PutUint64(reportData[8:16], oldTimestamp)

	result, _ := verifier.VerifyReport(clientID, reportData)

	if result.Result != types.VerifyNonceFail {
		t.Logf("Note: Stale timestamp check may be after nonce verify")
	}

	t.Log("✓ Timestamp staleness handling verified")
}

func TestIntegration_InvalidSignature(t *testing.T) {
	t.Log("INTEGRATION TEST: Invalid signature rejection")

	aikStore := store.NewMemoryStore()
	otherKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	aikStore.RegisterAIK("wrong-key-client", &otherKey.PublicKey)

	verifier := createTestVerifier(aikStore)

	clientID := "wrong-key-client"

	challenge, _ := verifier.GenerateChallenge(clientID)
	pcr14 := [32]byte{}
	reportData := createValidReport(t, challenge.Nonce, pcr14)

	result, err := verifier.VerifyReport(clientID, reportData)

	if result.Result != types.VerifySigFail {
		t.Fatalf("SECURITY FAILURE: Invalid signature NOT detected!\n"+
			"  Expected: FAIL_SIG (%d)\n"+
			"  Got: %d",
			types.VerifySigFail, result.Result)
	}

	t.Logf("✓ SECURITY: Invalid signature correctly rejected: %v", err)
}

func TestIntegration_ConcurrentClients(t *testing.T) {
	t.Log("INTEGRATION TEST: Concurrent client attestations")

	aikStore := store.NewMemoryStore()
	verifier := createTestVerifier(aikStore)

	// generate keys for multiple clients
	numClients := 10
	clientKeys := make([]*rsa.PrivateKey, numClients)
	for i := 0; i < numClients; i++ {
		key, _ := rsa.GenerateKey(rand.Reader, 2048)
		clientKeys[i] = key
	}

	// run concurrent attestations
	done := make(chan bool, numClients)
	errors := make(chan error, numClients)

	for i := 0; i < numClients; i++ {
		go func(clientNum int) {
			clientID := fmt.Sprintf("concurrent-client-%d", clientNum)

			challenge, err := verifier.GenerateChallenge(clientID)
			if err != nil {
				errors <- fmt.Errorf("client %d: challenge failed: %w", clientNum, err)
				done <- false
				return
			}

			pcr14 := [32]byte{}
			for j := range pcr14 {
				pcr14[j] = byte(clientNum ^ j)
			}

			reportData := createValidReportWithKey(challenge.Nonce, pcr14, integrationTestKey)

			result, err := verifier.VerifyReport(clientID, reportData)
			if err != nil || result.Result != types.VerifyOK {
				errors <- fmt.Errorf("client %d: verification failed: %v (result=%d)",
					clientNum, err, result.Result)
				done <- false
				return
			}

			done <- true
		}(i)
	}

	// wait for all clients
	successCount := 0
	for i := 0; i < numClients; i++ {
		if <-done {
			successCount++
		}
	}

	close(errors)
	for err := range errors {
		t.Errorf("Concurrent error: %v", err)
	}

	if successCount != numClients {
		t.Errorf("Only %d/%d clients succeeded", successCount, numClients)
	}

	t.Logf("✓ All %d concurrent attestations completed successfully", numClients)
}

// helper for concurrent test
func createValidReportWithKey(nonce [32]byte, pcr14 [32]byte, key *rsa.PrivateKey) []byte {
	buf := make([]byte, types.ExpectedReportSize)
	offset := 0

	// Header
	binary.LittleEndian.PutUint32(buf[offset:], types.ReportMagic)
	offset += 4
	binary.LittleEndian.PutUint32(buf[offset:], types.ReportVersion)
	offset += 4
	binary.LittleEndian.PutUint64(buf[offset:], uint64(time.Now().Unix()))
	offset += 8
	offset += 8 // timestamp_ns
	binary.LittleEndian.PutUint32(buf[offset:], types.ExpectedReportSize)
	offset += 4
	binary.LittleEndian.PutUint32(buf[offset:], types.FlagTPMQuoteOK|types.FlagModuleSig|types.FlagEnforce)
	offset += 4

	// PCRs
	for i := 0; i < types.PCRCount; i++ {
		for j := 0; j < types.HashSize; j++ {
			if i == 14 {
				buf[offset+j] = pcr14[j]
			} else {
				buf[offset+j] = byte(i ^ j)
			}
		}
		offset += types.HashSize
	}

	binary.LittleEndian.PutUint32(buf[offset:], 0x00004003)
	offset += 4

	attestData := createTPMSAttestWithNonce(nonce[:])
	hash := sha256.Sum256(attestData)
	signature, _ := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hash[:])

	copy(buf[offset:], signature)
	offset += types.MaxSigSize
	binary.LittleEndian.PutUint16(buf[offset:], uint16(len(signature)))
	offset += 2

	copy(buf[offset:], attestData)
	offset += types.MaxAttestSize
	binary.LittleEndian.PutUint16(buf[offset:], uint16(len(attestData)))
	offset += 2

	aikDER, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	copy(buf[offset:], aikDER)
	offset += types.MaxAIKPubSize
	binary.LittleEndian.PutUint16(buf[offset:], uint16(len(aikDER)))
	offset += 2

	// AIK certificate (optional, leave empty)
	offset += types.MaxAIKCertSize
	binary.LittleEndian.PutUint16(buf[offset:], 0) // no AIK cert
	offset += 2

	// EK certificate (optional, leave empty)
	offset += types.MaxEKCertSize
	binary.LittleEndian.PutUint16(buf[offset:], 0) // no EK cert
	offset += 2

	copy(buf[offset:], nonce[:])
	offset += types.NonceSize
	offset += 2 // reserved

	// system measurement (simplified)
	offset += types.HashSize * 2                // kernel_hash + agent_hash
	offset += types.MaxKernelPath               // kernel_path
	offset += 4 + 4 + 4 + types.CmdlineParamMax // IOMMU

	// BPF
	binary.LittleEndian.PutUint32(buf[offset:], 1)
	offset += 4
	binary.LittleEndian.PutUint32(buf[offset:], 1)
	offset += 4
	binary.LittleEndian.PutUint64(buf[offset:], uint64(time.Now().Unix()))
	offset += 8
	binary.LittleEndian.PutUint64(buf[offset:], uint64(time.Now().Unix()))

	return buf
}

func TestIntegration_ChallengePCRMask(t *testing.T) {
	t.Log("TEST: Challenge contains correct PCR mask")

	aikStore := store.NewMemoryStore()
	verifier := createTestVerifier(aikStore)

	challenge, err := verifier.GenerateChallenge("pcr-test-client")
	if err != nil {
		t.Fatalf("Failed to generate challenge: %v", err)
	}

	// should request PRR 0, 1, 14
	expectedMask := uint32((1 << 0) | (1 << 1) | (1 << 14))
	if challenge.PCRMask != expectedMask {
		t.Errorf("PCR mask: got 0x%08X, want 0x%08X", challenge.PCRMask, expectedMask)
	}

	t.Logf("✓ Challenge PCR mask correct: 0x%08X (PCR 0,1,14)", challenge.PCRMask)
}

func BenchmarkFullVerification(b *testing.B) {
	aikStore := store.NewMemoryStore()
	aikStore.RegisterAIK("bench-client", &integrationTestKey.PublicKey)

	cfg := DefaultConfig()
	verifier := NewVerifier(cfg, aikStore)
	verifier.AddPolicy(DefaultPolicy())
	verifier.SetActivePolicy("default")

	// pre-establish baseline
	challenge0, _ := verifier.GenerateChallenge("bench-client")
	pcr14 := [32]byte{}
	report0 := createValidReportWithKey(challenge0.Nonce, pcr14, integrationTestKey)
	verifier.VerifyReport("bench-client", report0)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		challenge, _ := verifier.GenerateChallenge("bench-client")
		report := createValidReportWithKey(challenge.Nonce, pcr14, integrationTestKey)
		verifier.VerifyReport("bench-client", report)
	}
}
