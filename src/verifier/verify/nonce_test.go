// SPDX-License-Identifier: MIT
// LOTA Verifier - Nonce Store Unit Tests
//
// Tests for challenge-response freshness and anti-replay protection.

package verify

import (
	"bytes"
	"testing"
	"time"

	"github.com/szymonwilczek/lota/verifier/types"
)

func TestNonceStore_GenerateAndVerify(t *testing.T) {
	t.Log("SECURITY TEST: Nonce generation and verification")
	t.Log("Verifies challenge-response protocol correctness")

	store := NewNonceStore(5 * time.Minute)

	challenge, err := store.GenerateChallenge("client1", 0x00004003)
	if err != nil {
		t.Fatalf("Failed to generate challenge: %v", err)
	}

	if len(challenge.Nonce) != 32 {
		t.Errorf("Nonce length: got %d, want 32", len(challenge.Nonce))
	}

	// verify nonce is not all zeros
	allZero := true
	for _, b := range challenge.Nonce {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("SECURITY: Nonce is all zeros - no entropy!")
	}

	t.Logf("✓ Generated nonce: %x", challenge.Nonce)

	report := &types.AttestationReport{}
	copy(report.TPM.Nonce[:], challenge.Nonce[:])

	report.TPM.AttestSize = uint16(len(createMockAttestWithNonce(challenge.Nonce[:])))
	copy(report.TPM.AttestData[:], createMockAttestWithNonce(challenge.Nonce[:]))

	err = store.VerifyNonce(report, "client1")
	if err != nil {
		t.Fatalf("Nonce verification failed for valid report: %v", err)
	}

	t.Log("✓ Nonce correctly verified on first use")
}

func TestNonceStore_OneTimeUse(t *testing.T) {
	t.Log("SECURITY TEST: Nonce one-time use (anti-replay)")
	t.Log("CRITICAL: Ensures nonces cannot be reused to replay old attestations")

	store := NewNonceStore(5 * time.Minute)

	challenge, _ := store.GenerateChallenge("client1", 0x00004003)

	report := &types.AttestationReport{}
	copy(report.TPM.Nonce[:], challenge.Nonce[:])
	report.TPM.AttestSize = uint16(len(createMockAttestWithNonce(challenge.Nonce[:])))
	copy(report.TPM.AttestData[:], createMockAttestWithNonce(challenge.Nonce[:]))

	// should succeed
	err := store.VerifyNonce(report, "client1")
	if err != nil {
		t.Fatalf("First verification failed: %v", err)
	}
	t.Log("✓ First verification succeeded")

	// MUST FAIL
	err = store.VerifyNonce(report, "client1")
	if err == nil {
		t.Fatal("SECURITY VIOLATION: Second verification succeeded - replay attack possible!")
	}

	t.Logf("✓ Correctly rejected replay attempt: %v", err)
}

func TestNonceStore_Expiration(t *testing.T) {
	t.Log("SECURITY TEST: Nonce expiration (TTL)")
	t.Log("Prevents use of stale challenges")

	store := NewNonceStore(100 * time.Millisecond)
	challenge, _ := store.GenerateChallenge("client1", 0x00004003)

	report := &types.AttestationReport{}
	copy(report.TPM.Nonce[:], challenge.Nonce[:])
	report.TPM.AttestSize = uint16(len(createMockAttestWithNonce(challenge.Nonce[:])))
	copy(report.TPM.AttestData[:], createMockAttestWithNonce(challenge.Nonce[:]))

	time.Sleep(150 * time.Millisecond)

	// should fail
	err := store.VerifyNonce(report, "client1")
	if err == nil {
		t.Fatal("SECURITY: Expired nonce was accepted!")
	}

	t.Logf("✓ Correctly rejected expired nonce: %v", err)
}

func TestNonceStore_UnknownNonce(t *testing.T) {
	t.Log("SECURITY TEST: Unknown nonce rejection")
	t.Log("Prevents forged challenges")

	store := NewNonceStore(5 * time.Minute)

	report := &types.AttestationReport{}
	for i := range report.TPM.Nonce {
		report.TPM.Nonce[i] = byte(i)
	}
	report.TPM.AttestSize = uint16(len(createMockAttestWithNonce(report.TPM.Nonce[:])))
	copy(report.TPM.AttestData[:], createMockAttestWithNonce(report.TPM.Nonce[:]))

	err := store.VerifyNonce(report, "client1")
	if err == nil {
		t.Fatal("SECURITY: Unknown nonce was accepted!")
	}

	t.Logf("✓ Correctly rejected unknown nonce: %v", err)
}

func TestNonceStore_ClientBinding(t *testing.T) {
	t.Log("SECURITY TEST: Nonce client binding")
	t.Log("Prevents using challenge from one client for another")

	store := NewNonceStore(5 * time.Minute)

	challenge, _ := store.GenerateChallenge("client1", 0x00004003)
	report := &types.AttestationReport{}

	copy(report.TPM.Nonce[:], challenge.Nonce[:])
	report.TPM.AttestSize = uint16(len(createMockAttestWithNonce(challenge.Nonce[:])))
	copy(report.TPM.AttestData[:], createMockAttestWithNonce(challenge.Nonce[:]))

	err := store.VerifyNonce(report, "client2") // wrong client
	if err == nil {
		t.Fatal("SECURITY: Nonce accepted for wrong client!")
	}

	t.Logf("✓ Correctly rejected nonce for wrong client: %v", err)
}

func TestNonceStore_UniqueNonces(t *testing.T) {
	t.Log("SECURITY TEST: Nonce uniqueness")
	t.Log("Ensures cryptographic randomness in nonce generation")

	store := NewNonceStore(5 * time.Minute)
	seen := make(map[string]bool)

	// check for collisions of nonce generation
	for i := 0; i < 100; i++ {
		challenge, err := store.GenerateChallenge("client", 0x00004003)
		if err != nil {
			t.Fatalf("Failed to generate challenge %d: %v", i, err)
		}

		key := string(challenge.Nonce[:])
		if seen[key] {
			t.Fatalf("SECURITY: Duplicate nonce generated at iteration %d!", i)
		}
		seen[key] = true
	}

	t.Log("✓ All 100 generated nonces are unique")
}

func TestNonceStore_PendingCount(t *testing.T) {
	t.Log("TEST: Pending challenge count tracking")

	store := NewNonceStore(5 * time.Minute)

	if store.PendingCount() != 0 {
		t.Errorf("Initial pending count: got %d, want 0", store.PendingCount())
	}

	for i := 0; i < 5; i++ {
		store.GenerateChallenge("client", 0x00004003)
	}

	if store.PendingCount() != 5 {
		t.Errorf("After 5 challenges: got %d, want 5", store.PendingCount())
	}

	t.Logf("✓ Pending count correctly tracks outstanding challenges")
}

func TestNonceStore_NonceMismatchInAttest(t *testing.T) {
	t.Log("SECURITY TEST: Nonce mismatch between header and TPMS_ATTEST")
	t.Log("CRITICAL: Detects tampering where header nonce is modified")

	store := NewNonceStore(5 * time.Minute)

	challenge, _ := store.GenerateChallenge("client1", 0x00004003)
	report := &types.AttestationReport{}

	copy(report.TPM.Nonce[:], challenge.Nonce[:])
	wrongNonce := make([]byte, 32)
	copy(wrongNonce, challenge.Nonce[:])
	wrongNonce[0] ^= 0xFF // corrupted first byte

	report.TPM.AttestSize = uint16(len(createMockAttestWithNonce(wrongNonce)))
	copy(report.TPM.AttestData[:], createMockAttestWithNonce(wrongNonce))

	err := store.VerifyNonce(report, "client1")
	if err == nil {
		t.Fatal("SECURITY VIOLATION: Accepted report with mismatched nonces!")
	}

	t.Logf("✓ Correctly detected nonce tampering: %v", err)
}

// Table-driven tests for edge cases
func TestNonceStore_TableDriven(t *testing.T) {
	testCases := []struct {
		name         string
		ttl          time.Duration
		clientGen    string
		clientVerify string
		sleep        time.Duration
		wantErr      bool
	}{
		{
			name:         "ValidFlow",
			ttl:          5 * time.Minute,
			clientGen:    "client1",
			clientVerify: "client1",
			sleep:        0,
			wantErr:      false,
		},
		{
			name:         "ClientMismatch",
			ttl:          5 * time.Minute,
			clientGen:    "client1",
			clientVerify: "attacker",
			sleep:        0,
			wantErr:      true,
		},
		{
			name:         "Expired",
			ttl:          50 * time.Millisecond,
			clientGen:    "client1",
			clientVerify: "client1",
			sleep:        100 * time.Millisecond,
			wantErr:      true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			store := NewNonceStore(tc.ttl)
			challenge, _ := store.GenerateChallenge(tc.clientGen, 0x00004003)

			if tc.sleep > 0 {
				time.Sleep(tc.sleep)
			}

			report := &types.AttestationReport{}
			copy(report.TPM.Nonce[:], challenge.Nonce[:])
			report.TPM.AttestSize = uint16(len(createMockAttestWithNonce(challenge.Nonce[:])))
			copy(report.TPM.AttestData[:], createMockAttestWithNonce(challenge.Nonce[:]))

			err := store.VerifyNonce(report, tc.clientVerify)

			if tc.wantErr && err == nil {
				t.Error("Expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

func createMockAttestWithNonce(nonce []byte) []byte {
	var buf bytes.Buffer

	// magic: TPM_GENERATED_VALUE
	buf.Write([]byte{0xff, 0x54, 0x43, 0x47})

	// type: TPM_ST_ATTEST_QUOTE
	buf.Write([]byte{0x80, 0x18})

	// qualifiedSigner: TPM2B_NAME
	buf.Write([]byte{0x00, 0x02}) // size = 2
	buf.Write([]byte{0x00, 0x00}) // dummy name

	// extraData: TPM2B_DATA
	buf.Write([]byte{0x00, byte(len(nonce))}) // size
	buf.Write(nonce)

	// clockInfo
	buf.Write(make([]byte, 8)) // clock
	buf.Write(make([]byte, 4)) // resetCount
	buf.Write(make([]byte, 4)) // restartCount
	buf.Write([]byte{0x01})    // safe

	// firmwareVersion
	buf.Write(make([]byte, 8))

	// QuoteInfo (TPMS_QUOTE_INFO)
	buf.Write([]byte{0x00, 0x00, 0x00, 0x01}) // PCR selection count = 1
	buf.Write([]byte{0x00, 0x0b})             // hash algorithm: SHA256
	buf.Write([]byte{0x03})                   // sizeofSelect = 3
	buf.Write([]byte{0xff, 0x00, 0x00})       // pcrSelect bitmap
	buf.Write([]byte{0x00, 0x20})             // PCR digest size = 32
	buf.Write(make([]byte, 32))               // PCR digest (zeros)

	return buf.Bytes()
}
