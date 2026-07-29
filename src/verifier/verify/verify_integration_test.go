// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
// LOTA Verifier - Integration Tests
//
// End-to-end tests for the complete attestation verification pipeline.
// These tests simulate real attestation scenarios without network I/O.

package verify

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
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
// productionPCRMask is the mask a current agent emits: PCR 0/1/7 (firmware,
// platform configuration, Secure Boot policy) plus PCR 14 (boot commitment).
// legacyPCRMask drops PCR 7 -- what downgraded or tampered agent would send.
const (
	productionPCRMask = uint32(0x00004083)
	legacyPCRMask     = uint32(0x00004003)
)

// productionFlags is the flag set a current agent emits:
// both PCR14 derivation bits are mandatory on the wire,
// so fixture that omits one is a report the verifier must refuse.
const productionFlags = types.FlagTPMQuoteOK | types.FlagModuleSig | types.FlagEnforce |
	types.FlagBootCommitmentV1 | types.FlagInitramfsLockV1

// uefiEventLog is the firmware log every fixture report carries:
// one EV_EFI_VARIABLE_DRIVER_CONFIG measurement of the EFI global SecureBoot
// variable on PCR 7.
// That event is the verifier's proof of UEFI boot -- legacy BIOS log has no EFI
// variable to measure.
func uefiEventLog() []byte {
	payload := encodeUEFIVariableData(efiGlobalVariableGUID, "SecureBoot", []byte{0x01})
	digest := sha256.Sum256(payload)
	return buildTestEventLog([]EventLogEntry{{
		PCRIndex:  7,
		EventType: EvEFIVariableDriverConfig,
		Digests:   map[uint16][]byte{AlgSHA256: digest[:]},
		EventData: payload,
	}})
}

// uefiPCR7 is the PCR 7 value uefiEventLog replays to.
// Fixture report must carry it so the SecureBoot measurement is quote-authenticated
func uefiPCR7() [types.HashSize]byte {
	payload := encodeUEFIVariableData(efiGlobalVariableGUID, "SecureBoot", []byte{0x01})
	digest := sha256.Sum256(payload)

	var pcr7 [types.HashSize]byte
	h := sha256.New()
	h.Write(pcr7[:])
	h.Write(digest[:])
	copy(pcr7[:], h.Sum(nil))
	return pcr7
}

// fixtureAgentHash is the agent_hash every fixture report carries.
func fixtureAgentHash() [types.HashSize]byte {
	var agentHash [types.HashSize]byte
	for i := range agentHash {
		agentHash[i] = byte(0xBB ^ i)
	}
	return agentHash
}

// fixturePCR14 is the only PCR14 a fixture report can carry and still verify:
// initramfs lock chained with the agent's boot commitment over the baseline
// the fixture event log replays to (0^32, it holds no PCR14 events)
// and the zero reset/restart counters in the fixture TPMS_ATTEST ClockInfo
func fixturePCR14() [types.HashSize]byte {
	return DeriveLockedBootCommitmentPCR14(zeroBaseline, fixtureAgentHash(), 0, 0)
}

func createValidReport(t *testing.T, clientID string, nonce [32]byte, pcr14 [32]byte) []byte {
	t.Helper()
	return createValidReportWithMask(t, clientID, nonce, pcr14, productionPCRMask)
}

func createValidReportWithMask(t *testing.T, clientID string, nonce [32]byte, pcr14 [32]byte, pcrMask uint32) []byte {
	t.Helper()
	return createValidReportWithFlags(t, clientID, nonce, pcr14, pcrMask, productionFlags)
}

func createValidReportWithFlags(t *testing.T, clientID string, nonce [32]byte, pcr14 [32]byte,
	pcrMask, flags uint32,
) []byte {
	t.Helper()
	hwID := sha256.Sum256([]byte(clientID))

	buf := make([]byte, types.MinReportSize)
	offset := 0

	// Header (32 bytes)
	binary.LittleEndian.PutUint32(buf[offset:], types.ReportMagic)
	offset += 4
	binary.LittleEndian.PutUint32(buf[offset:], types.ReportVersion)
	offset += 4

	binary.LittleEndian.PutUint32(buf[offset:], types.MinReportSize)
	offset += 4
	binary.LittleEndian.PutUint32(buf[offset:], flags)
	offset += 4

	// TPM Evidence - PCR values
	pcr7 := uefiPCR7()
	for i := 0; i < types.PCRCount; i++ {
		for j := 0; j < types.HashSize; j++ {
			switch i {
			case 14:
				buf[offset+j] = pcr14[j]
			case 7:
				buf[offset+j] = pcr7[j]
			default:
				buf[offset+j] = byte(i ^ j)
			}
		}
		offset += types.HashSize
	}

	// PCR mask
	binary.LittleEndian.PutUint32(buf[offset:], pcrMask)
	offset += 4

	// compute PCR digest from values just written
	pcrDigest := computeTestPCRDigest(buf, 16, pcrMask)

	bindingReport := &types.AttestationReport{}
	bindingReport.Header.Flags = flags
	copy(bindingReport.TPM.HardwareID[:], hwID[:])
	for i := 0; i < types.HashSize; i++ {
		bindingReport.System.KernelHash[i] = byte(0xAA ^ i)
		bindingReport.System.AgentHash[i] = byte(0xBB ^ i)
	}
	bindingReport.System.IOMMU.Vendor = 0x8086
	bindingReport.System.IOMMU.Flags = 0x07
	bindingReport.System.IOMMU.UnitCount = 2
	copy(bindingReport.System.IOMMU.CmdlineParam[:], []byte("intel_iommu=on"))

	bindingNonce := ComputeAttestationBindingNonce(nonce, bindingReport)
	attestData := createTPMSAttestWithNonce(bindingNonce[:], pcrDigest)

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

	// AIK certificate: CA-issued, subject carries the device pseudonym
	aikCertDER := issueAIKCertOrPanic(testPseudonym(clientID), &integrationTestKey.PublicKey)
	copy(buf[offset:], aikCertDER)
	offset += types.MaxAIKCertSize
	binary.LittleEndian.PutUint16(buf[offset:], uint16(len(aikCertDER)))
	offset += 2

	// EK certificate (optional, leave empty)
	offset += types.MaxEKCertSize
	binary.LittleEndian.PutUint16(buf[offset:], 0) // no EK cert
	offset += 2

	// nonce
	copy(buf[offset:], nonce[:])
	offset += types.NonceSize

	// hardware_id (32 bytes, stable per-client identity)
	copy(buf[offset:offset+types.HardwareIDSize], hwID[:])
	offset += types.HardwareIDSize

	// aik_generation
	binary.LittleEndian.PutUint64(buf[offset:], 1)
	offset += 8

	// prev_aik_public (grace period; empty in tests)
	offset += types.MaxAIKPubSize
	binary.LittleEndian.PutUint16(buf[offset:], 0)
	offset += 2

	// quote_sig_alg (was reserved)
	binary.LittleEndian.PutUint16(buf[offset:], types.TPMAlgRSASSA)
	offset += 2
	// quote_sig_hash_alg
	binary.LittleEndian.PutUint16(buf[offset:], types.TPMAlgSHA256)
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
	offset += 8

	// bpf event_count = 0 (no serialized exec events in integration fixtures)
	binary.LittleEndian.PutUint32(buf[offset:], 0)
	offset += 4

	// append the fixture firmware log
	// (Spec ID header + the PCR 7 SecureBoot variable measurement
	// the UEFI gate requires)
	eventLog := uefiEventLog()
	binary.LittleEndian.PutUint32(buf[offset:], uint32(len(eventLog)))
	buf = append(buf, eventLog...)

	// keep report_size consistent with wire payload
	binary.LittleEndian.PutUint32(buf[8:12], uint32(len(buf)))

	return buf
}

// builds minimal TPMS_ATTEST structure with correct PCR digest
func createTPMSAttestWithNonce(nonce []byte, pcrDigest []byte) []byte {
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
	buf = append(buf, pcrDigest[:32]...)      // PCR digest

	return buf
}

// computes SHA-256 digest of selected PCR values from report buffer
func computeTestPCRDigest(buf []byte, pcrOffset int, pcrMask uint32) []byte {
	h := sha256.New()
	for i := 0; i < types.PCRCount; i++ {
		if pcrMask&(1<<uint(i)) != 0 {
			start := pcrOffset + i*types.HashSize
			h.Write(buf[start : start+types.HashSize])
		}
	}
	return h.Sum(nil)
}

// encodes RSA public key in DER format
func marshalRSAPublicKey(pub *rsa.PublicKey) []byte {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		panic("failed to marshal public key: " + err.Error())
	}
	return der
}

func persistentClientID(challengeID string) string {
	hwID := sha256.Sum256([]byte(challengeID))
	return hex.EncodeToString(hwID[:])
}

// creates a Verifier with default policy for testing
func createTestVerifier(t *testing.T, aikStore store.AIKStore) *Verifier {
	t.Helper()
	cfg := DefaultConfig()
	// Fixtures carry no signed policy pinning PCR0/1/7 and
	// no pre-enrolled boot baseline, so they take the same route
	// as operator running with --allow-tofu-boot-baseline
	cfg.RequireBootEnrollment = false
	cfg.NonceLifetime = 1 * time.Second
	verifier := NewVerifier(cfg, aikStore)

	// default policy that allows any values
	if err := verifier.AddPolicy(DefaultPolicy()); err != nil {
		t.Fatalf("AddPolicy(DefaultPolicy) failed: %v", err)
	}
	if err := verifier.SetActivePolicy("default"); err != nil {
		t.Fatalf("SetActivePolicy(default) failed: %v", err)
	}

	return verifier
}

func TestIntegration_FullAttestationFlow_TOFU(t *testing.T) {
	t.Log("INTEGRATION TEST: Full attestation flow with TOFU")
	t.Log("Simulates first-time client attestation")

	aikStore := newCertStore(t)
	verifier := createTestVerifier(t, aikStore)

	clientID := "test-client-001"

	challenge, err := verifier.GenerateChallenge(clientID)
	if err != nil {
		t.Fatalf("Failed to generate challenge: %v", err)
	}
	t.Logf("✓ Challenge generated with nonce: %x...", challenge.Nonce[:8])

	pcr14 := fixturePCR14()

	reportData := createValidReport(t, clientID, challenge.Nonce, pcr14)
	t.Logf("✓ Report created (%d bytes)", len(reportData))

	result, err := verifier.VerifyReport(clientID, reportData)
	if err != nil {
		t.Fatalf("Verification failed: %v", err)
	}

	if result.Result != types.VerifyOK {
		t.Errorf("Expected VerifyOK, got result code %d", result.Result)
	}
	if bytes.Equal(result.SessionToken[:], make([]byte, len(result.SessionToken))) {
		t.Error("session token must not be all zeros")
	}

	t.Log("✓ Full attestation flow completed successfully")
}

func TestIntegration_SubsequentAttestation(t *testing.T) {
	t.Log("INTEGRATION TEST: Subsequent attestation with registered AIK")

	aikStore := newCertStore(t)

	verifier := createTestVerifier(t, aikStore)

	clientID := "test-client"

	// establish baseline
	challenge1, _ := verifier.GenerateChallenge(clientID)
	pcr14 := fixturePCR14()
	report1 := createValidReport(t, clientID, challenge1.Nonce, pcr14)
	result1, err := verifier.VerifyReport(clientID, report1)
	if err != nil || result1.Result != types.VerifyOK {
		t.Fatalf("First attestation failed: %v (result=%d)", err, result1.Result)
	}
	t.Log("✓ First attestation established baseline")

	// should match baseline
	challenge2, _ := verifier.GenerateChallenge(clientID)
	report2 := createValidReport(t, clientID, challenge2.Nonce, pcr14)
	result2, err := verifier.VerifyReport(clientID, report2)
	if err != nil || result2.Result != types.VerifyOK {
		t.Fatalf("Second attestation failed: %v (result=%d)", err, result2.Result)
	}
	if bytes.Equal(result1.SessionToken[:], result2.SessionToken[:]) {
		t.Fatal("session tokens for distinct attestations must differ")
	}
	t.Log("✓ Subsequent attestation matched baseline")
}

func TestIntegration_SessionTokenValidation(t *testing.T) {
	t.Log("INTEGRATION TEST: Session token can be validated via verifier API")

	aikStore := newCertStore(t)
	verifier := createTestVerifier(t, aikStore)

	clientID := "session-validate-client"
	challenge, err := verifier.GenerateChallenge(clientID)
	if err != nil {
		t.Fatalf("GenerateChallenge failed: %v", err)
	}

	pcr14 := fixturePCR14()

	report := createValidReport(t, clientID, challenge.Nonce, pcr14)
	res, err := verifier.VerifyReport(clientID, report)
	if err != nil {
		t.Fatalf("VerifyReport failed: %v", err)
	}
	if res.Result != types.VerifyOK {
		t.Fatalf("unexpected result code: %d", res.Result)
	}

	st := verifier.ValidateSessionToken(res.SessionToken, false)
	if !st.Exists {
		t.Fatal("session token should exist")
	}
	if st.Consumed {
		t.Fatal("session token should not be consumed by read-only validation")
	}
	if st.ResultCode != types.VerifyOK {
		t.Fatalf("unexpected token result code: %d", st.ResultCode)
	}
	if st.ClientID != testPseudonym(clientID) {
		t.Fatalf("unexpected client id binding: %s", st.ClientID)
	}
}

func TestIntegration_SessionTokenConsume(t *testing.T) {
	t.Log("INTEGRATION TEST: Session token can be consumed once")

	aikStore := newCertStore(t)
	verifier := createTestVerifier(t, aikStore)

	clientID := "session-consume-client"
	challenge, err := verifier.GenerateChallenge(clientID)
	if err != nil {
		t.Fatalf("GenerateChallenge failed: %v", err)
	}

	pcr14 := fixturePCR14()

	report := createValidReport(t, clientID, challenge.Nonce, pcr14)
	res, err := verifier.VerifyReport(clientID, report)
	if err != nil {
		t.Fatalf("VerifyReport failed: %v", err)
	}

	st1 := verifier.ValidateSessionToken(res.SessionToken, true)
	if !st1.Exists || !st1.Consumed {
		t.Fatal("consume validation should mark token as consumed")
	}

	st2 := verifier.ValidateSessionToken(res.SessionToken, false)
	if !st2.Exists || !st2.Consumed {
		t.Fatal("subsequent validation should report consumed token")
	}
}

func TestIntegration_PCR14BaselineViolation(t *testing.T) {
	t.Log("INTEGRATION TEST: PCR14 baseline violation detection")
	t.Log("CRITICAL SECURITY TEST: Detects agent tampering")

	aikStore := newCertStore(t)

	verifier := createTestVerifier(t, aikStore)

	clientID := "compromised-client"

	// establish baseline
	challenge1, _ := verifier.GenerateChallenge(clientID)
	originalPCR14 := fixturePCR14()
	report1 := createValidReport(t, clientID, challenge1.Nonce, originalPCR14)
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

	report2 := createValidReport(t, clientID, challenge2.Nonce, tamperedPCR14)
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

	aikStore := newCertStore(t)

	verifier := createTestVerifier(t, aikStore)
	clientID := "replay-victim"
	challenge, _ := verifier.GenerateChallenge(clientID)
	pcr14 := fixturePCR14()
	reportData := createValidReport(t, clientID, challenge.Nonce, pcr14)

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

func TestIntegration_InvalidSignature(t *testing.T) {
	t.Log("INTEGRATION TEST: Invalid signature rejection")

	aikStore := newCertStore(t)
	verifier := createTestVerifier(t, aikStore)

	clientID := "wrong-key-client"

	challenge, _ := verifier.GenerateChallenge(clientID)
	reportData := createValidReport(t, clientID, challenge.Nonce, fixturePCR14())

	// Corrupt the quote signature so it no longer verifies against the
	// certificate-authenticated AIK.
	sigOffset := 16 + types.PCRCount*types.HashSize + 4
	reportData[sigOffset] ^= 0xFF
	reportData[sigOffset+1] ^= 0xFF

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

	aikStore := newCertStore(t)
	verifier := createTestVerifier(t, aikStore)

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

			pcr14 := fixturePCR14()

			reportData := createValidReportWithKey(clientID, challenge.Nonce, pcr14, clientKeys[clientNum])

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

func TestIntegration_ConcurrentFirstAttestationSameClient(t *testing.T) {
	t.Log("INTEGRATION TEST: Concurrent first attestation (same hardware)")

	aikStore := newCertStore(t)
	verifier := createTestVerifier(t, aikStore)

	// both goroutines represent the same hardware identity
	hardwareLabel := "same-hardware-client"
	key, _ := rsa.GenerateKey(rand.Reader, 2048)

	num := 2
	done := make(chan bool, num)
	errs := make(chan error, num)

	for i := 0; i < num; i++ {
		go func(n int) {
			challengeID := fmt.Sprintf("conn-%d", n)
			challenge, err := verifier.GenerateChallenge(challengeID)
			if err != nil {
				errs <- fmt.Errorf("challenge failed: %w", err)
				done <- false
				return
			}

			pcr14 := fixturePCR14()

			reportData := createValidReportWithKey(hardwareLabel, challenge.Nonce, pcr14, key)
			result, err := verifier.VerifyReport(challengeID, reportData)
			if err != nil || result.Result != types.VerifyOK {
				errs <- fmt.Errorf("verify failed: %v (result=%d)", err, result.Result)
				done <- false
				return
			}
			done <- true
		}(i)
	}

	success := 0
	for i := 0; i < num; i++ {
		if <-done {
			success++
		}
	}

	close(errs)
	for err := range errs {
		t.Errorf("concurrent error: %v", err)
	}

	if success != num {
		t.Fatalf("only %d/%d succeeded", success, num)
	}
}

// helper for concurrent test
func createValidReportWithKey(clientID string, nonce [32]byte, pcr14 [32]byte, key *rsa.PrivateKey) []byte {
	hwID := sha256.Sum256([]byte(clientID))
	buf := make([]byte, types.MinReportSize)
	offset := 0

	// Header
	binary.LittleEndian.PutUint32(buf[offset:], types.ReportMagic)
	offset += 4
	binary.LittleEndian.PutUint32(buf[offset:], types.ReportVersion)
	offset += 4

	binary.LittleEndian.PutUint32(buf[offset:], types.MinReportSize)
	offset += 4
	binary.LittleEndian.PutUint32(buf[offset:], productionFlags)
	offset += 4

	// PCRs
	pcr7 := uefiPCR7()
	for i := 0; i < types.PCRCount; i++ {
		for j := 0; j < types.HashSize; j++ {
			switch i {
			case 14:
				buf[offset+j] = pcr14[j]
			case 7:
				buf[offset+j] = pcr7[j]
			default:
				buf[offset+j] = byte(i ^ j)
			}
		}
		offset += types.HashSize
	}

	binary.LittleEndian.PutUint32(buf[offset:], productionPCRMask)
	offset += 4

	// compute PCR digest from values just written
	pcrDigest := computeTestPCRDigest(buf, 16, productionPCRMask)

	bindingReport := &types.AttestationReport{}
	bindingReport.Header.Flags = productionFlags
	copy(bindingReport.TPM.HardwareID[:], hwID[:])
	for i := 0; i < types.HashSize; i++ {
		bindingReport.System.KernelHash[i] = byte(0xAA ^ i)
		bindingReport.System.AgentHash[i] = byte(0xBB ^ i)
	}
	bindingReport.System.IOMMU.Vendor = 0x8086
	bindingReport.System.IOMMU.Flags = 0x07
	bindingReport.System.IOMMU.UnitCount = 2
	copy(bindingReport.System.IOMMU.CmdlineParam[:], []byte("intel_iommu=on"))
	bindingNonce := ComputeAttestationBindingNonce(nonce, bindingReport)
	attestData := createTPMSAttestWithNonce(bindingNonce[:], pcrDigest)
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

	// AIK certificate: CA-issued, subject carries the device pseudonym
	aikCertDER := issueAIKCertOrPanic(testPseudonym(clientID), &key.PublicKey)
	copy(buf[offset:], aikCertDER)
	offset += types.MaxAIKCertSize
	binary.LittleEndian.PutUint16(buf[offset:], uint16(len(aikCertDER)))
	offset += 2

	// EK certificate (optional, leave empty)
	offset += types.MaxEKCertSize
	binary.LittleEndian.PutUint16(buf[offset:], 0) // no EK cert
	offset += 2

	copy(buf[offset:], nonce[:])
	offset += types.NonceSize
	copy(buf[offset:offset+types.HardwareIDSize], hwID[:])
	offset += types.HardwareIDSize
	// aik_generation
	binary.LittleEndian.PutUint64(buf[offset:], 1)
	offset += 8
	// prev_aik_public (empty)
	offset += types.MaxAIKPubSize
	binary.LittleEndian.PutUint16(buf[offset:], 0)
	offset += 2
	binary.LittleEndian.PutUint16(buf[offset:], types.TPMAlgRSASSA)
	offset += 2
	binary.LittleEndian.PutUint16(buf[offset:], types.TPMAlgSHA256)
	offset += 2

	// system measurement
	for i := 0; i < types.HashSize; i++ {
		buf[offset+i] = byte(0xAA ^ i)
	}
	offset += types.HashSize
	for i := 0; i < types.HashSize; i++ {
		buf[offset+i] = byte(0xBB ^ i)
	}
	offset += types.HashSize

	// kernel_path (leave empty)
	offset += types.MaxKernelPath

	// IOMMU
	binary.LittleEndian.PutUint32(buf[offset:], 0x8086)
	offset += 4
	binary.LittleEndian.PutUint32(buf[offset:], 0x07)
	offset += 4
	binary.LittleEndian.PutUint32(buf[offset:], 2)
	offset += 4
	copy(buf[offset:offset+types.CmdlineParamMax], []byte("intel_iommu=on"))
	offset += types.CmdlineParamMax

	// BPF
	binary.LittleEndian.PutUint32(buf[offset:], 1)
	offset += 4
	binary.LittleEndian.PutUint32(buf[offset:], 1)
	offset += 4
	binary.LittleEndian.PutUint64(buf[offset:], uint64(time.Now().Unix()))
	offset += 8
	binary.LittleEndian.PutUint64(buf[offset:], uint64(time.Now().Unix()))
	offset += 8

	// bpf event_count = 0
	binary.LittleEndian.PutUint32(buf[offset:], 0)
	offset += 4

	eventLog := uefiEventLog()
	binary.LittleEndian.PutUint32(buf[offset:], uint32(len(eventLog)))
	buf = append(buf, eventLog...)
	binary.LittleEndian.PutUint32(buf[8:12], uint32(len(buf)))

	return buf
}

func TestIntegration_ChallengePCRMask(t *testing.T) {
	t.Log("TEST: Challenge contains correct PCR mask")

	aikStore := newCertStore(t)
	verifier := createTestVerifier(t, aikStore)

	challenge, err := verifier.GenerateChallenge("pcr-test-client")
	if err != nil {
		t.Fatalf("Failed to generate challenge: %v", err)
	}

	// should request PCRs 0, 1, 7, 14
	expectedMask := uint32((1 << 0) | (1 << 1) | (1 << 7) | (1 << 14))
	if challenge.PCRMask != expectedMask {
		t.Errorf("PCR mask: got 0x%08X, want 0x%08X", challenge.PCRMask, expectedMask)
	}

	t.Logf("✓ Challenge PCR mask correct: 0x%08X (PCR 0,1,7,14)", challenge.PCRMask)
}

// TestVerify_RejectsMissingBootPCRs asserts that the verifier refuses any attestation
// whose pcr_mask does not include PCR 0, 1, and 7.
// Tampered or downgraded agent that strips the firmware/Secure Boot bits from its mask
// is rejected with VerifyPCRFail before the BootBaselineStorer pin is consulted.
// There is no configuration that accepts such report.
func TestVerify_RejectsMissingBootPCRs(t *testing.T) {
	aikStore := newCertStore(t)

	cfg := DefaultConfig()
	cfg.NonceLifetime = 1 * time.Second

	verifier := NewVerifier(cfg, aikStore)
	if err := verifier.AddPolicy(DefaultPolicy()); err != nil {
		t.Fatalf("AddPolicy(DefaultPolicy): %v", err)
	}
	if err := verifier.SetActivePolicy("default"); err != nil {
		t.Fatalf("SetActivePolicy(default): %v", err)
	}

	clientID := "boot-pcr-reject"
	challenge, err := verifier.GenerateChallenge(clientID)
	if err != nil {
		t.Fatalf("GenerateChallenge: %v", err)
	}

	pcr14 := fixturePCR14()
	reportData := createValidReportWithMask(t, clientID, challenge.Nonce, pcr14, legacyPCRMask)

	result, err := verifier.VerifyReport(clientID, reportData)
	if err == nil {
		t.Fatal("expected rejection: pcr_mask 0x4003 omits PCR 0/1/7")
	}
	if result.Result != types.VerifyPCRFail {
		t.Fatalf("expected VerifyPCRFail, got result=%d err=%v", result.Result, err)
	}
}

// TestVerify_RejectsMissingInitramfsLock asserts that report whose Header.Flags
// omits FlagInitramfsLockV1 is refused with VerifyPCRFail before any downstream
// baseline write.
func TestVerify_RejectsMissingInitramfsLock(t *testing.T) {
	assertFlagRejected(t, "initramfs-lock-missing",
		productionFlags&^types.FlagInitramfsLockV1, "FlagInitramfsLockV1")
}

// TestVerify_RejectsMissingBootCommitment is the companion for the other half of
// the chain: without FlagBootCommitmentV1 the report makes no claim about which
// agent binary extended PCR14.
func TestVerify_RejectsMissingBootCommitment(t *testing.T) {
	assertFlagRejected(t, "boot-commitment-missing",
		productionFlags&^(types.FlagBootCommitmentV1|types.FlagInitramfsLockV1),
		"FlagBootCommitmentV1")
}

func assertFlagRejected(t *testing.T, clientID string, flags uint32, wantMsg string) {
	t.Helper()

	verifier := createTestVerifier(t, newCertStore(t))

	challenge, err := verifier.GenerateChallenge(clientID)
	if err != nil {
		t.Fatalf("GenerateChallenge: %v", err)
	}

	reportData := createValidReportWithFlags(t, clientID, challenge.Nonce,
		fixturePCR14(), productionPCRMask, flags)

	result, err := verifier.VerifyReport(clientID, reportData)
	if err == nil {
		t.Fatalf("expected rejection: report flags 0x%08x omit %s", flags, wantMsg)
	}
	if result.Result != types.VerifyPCRFail {
		t.Fatalf("expected VerifyPCRFail, got result=%d err=%v", result.Result, err)
	}
	if !strings.Contains(err.Error(), wantMsg) {
		t.Fatalf("expected error to mention %s, got: %v", wantMsg, err)
	}
}

// TestVerify_RejectsNonUEFIBoot asserts the UEFI gate:
// report whose event log carries no EFI variable measurement never came from
// UEFI firmware (legacy BIOS/CSM has none to measure), so every firmware
// measurement below it -- the PCR 0/1/7 pin, the Secure Boot state, PCR 14
// baseline -- would be unauthenticated
func TestVerify_RejectsNonUEFIBoot(t *testing.T) {
	verifier := createTestVerifier(t, newCertStore(t))

	clientID := "bios-host"
	challenge, err := verifier.GenerateChallenge(clientID)
	if err != nil {
		t.Fatalf("GenerateChallenge: %v", err)
	}

	reportData := createValidReport(t, clientID, challenge.Nonce, fixturePCR14())
	reportData = stripEventLogEntries(t, reportData)

	result, err := verifier.VerifyReport(clientID, reportData)
	if err == nil {
		t.Fatal("expected rejection: event log carries no UEFI evidence")
	}
	if result.Result != types.VerifyPCRFail {
		t.Fatalf("expected VerifyPCRFail, got result=%d err=%v", result.Result, err)
	}
	if !strings.Contains(err.Error(), "UEFI") {
		t.Fatalf("expected the error to name UEFI, got: %v", err)
	}
}

// stripEventLogEntries rewrites the report's event log, keeping the Spec ID header
// and dropping every PCR_EVENT2 entry -- the shape legacy BIOS log has,
// with no EFI variable measurement to offer.
func stripEventLogEntries(t *testing.T, reportData []byte) []byte {
	t.Helper()

	bare := buildTestEventLog(nil)
	logOffset := len(reportData) - int(binary.LittleEndian.Uint32(
		reportData[types.MinReportSize-4:types.MinReportSize]))
	if logOffset < types.MinReportSize {
		t.Fatalf("event log offset %d precedes the fixed report", logOffset)
	}

	out := append(append([]byte{}, reportData[:logOffset]...), bare...)
	binary.LittleEndian.PutUint32(out[types.MinReportSize-4:types.MinReportSize], uint32(len(bare)))
	binary.LittleEndian.PutUint32(out[8:12], uint32(len(out)))
	return out
}

// TestVerify_BootEnrollmentGateRefusesTOFUFirstUse covers the default production
// posture: first-attestation client whose PCR0/1/7 are neither pinned by the active
// policy nor already in the store must be refused, so host booting on tampered
// firmware cannot self-pin its own baseline.
func TestVerify_BootEnrollmentGateRefusesTOFUFirstUse(t *testing.T) {
	cfg := DefaultConfig()
	cfg.NonceLifetime = 1 * time.Second

	result, err := attestUnderConfig(t, cfg, "boot-enrollment-refused")
	if err == nil {
		t.Fatal("expected rejection: boot baseline not enrolled")
	}
	if result.Result != types.VerifyIntegrityMismatch {
		t.Fatalf("expected VerifyIntegrityMismatch, got result=%d err=%v", result.Result, err)
	}
	if !strings.Contains(err.Error(), "boot baseline not enrolled") {
		t.Fatalf("expected the enrollment-gate error, got: %v", err)
	}
}

// TestVerify_BootEnrollmentGateOptOutAllowsTOFU pairs with the refusal above:
// --allow-tofu-boot-baseline (RequireBootEnrollment=false) lets the same client
// TOFU-pin its firmware PCRs on first sight.
func TestVerify_BootEnrollmentGateOptOutAllowsTOFU(t *testing.T) {
	cfg := DefaultConfig()
	cfg.NonceLifetime = 1 * time.Second
	cfg.RequireBootEnrollment = false

	result, err := attestUnderConfig(t, cfg, "boot-enrollment-tofu")
	if err != nil {
		t.Fatalf("VerifyReport: %v", err)
	}
	if result.Result != types.VerifyOK {
		t.Fatalf("expected VerifyOK, got %d", result.Result)
	}
}

func attestUnderConfig(t *testing.T, cfg VerifierConfig, clientID string) (*types.VerifyResult, error) {
	t.Helper()

	verifier := NewVerifier(cfg, newCertStore(t))
	if err := verifier.AddPolicy(DefaultPolicy()); err != nil {
		t.Fatalf("AddPolicy(DefaultPolicy): %v", err)
	}
	if err := verifier.SetActivePolicy("default"); err != nil {
		t.Fatalf("SetActivePolicy(default): %v", err)
	}

	challenge, err := verifier.GenerateChallenge(clientID)
	if err != nil {
		t.Fatalf("GenerateChallenge: %v", err)
	}

	reportData := createValidReport(t, clientID, challenge.Nonce, fixturePCR14())
	return verifier.VerifyReport(clientID, reportData)
}

// Client whose PCR14 baseline is on record must be visible through ClientInfo
// even when the nonce store holds no history for it:
// the monotonic counter starts at zero after a verifier restart with the
// in-memory nonce backend, and the Privacy CA flow records nothing in the AIK store
// (the certificate presented per attestation is the trust anchor).
// Such client is listed by ListClients but the per-client lookup reported it as not found.
func TestClientInfo_BaselineOnlyClientIsFound(t *testing.T) {
	baselines := NewBaselineStore()
	cfg := DefaultConfig()
	cfg.BaselineStore = baselines
	verifier := NewVerifier(cfg, store.NewMemoryStore())

	var pcr14 [types.HashSize]byte
	pcr14[0] = 0x42
	baselines.CheckAndUpdate("restart-survivor", pcr14)

	info, found := verifier.ClientInfo("restart-survivor")
	if !found {
		t.Fatal("client with a stored baseline reported as not found")
	}
	if info.PCR14Baseline == "" {
		t.Fatal("baseline missing from client info")
	}
}
