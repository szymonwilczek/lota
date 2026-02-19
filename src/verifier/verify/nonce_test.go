// SPDX-License-Identifier: MIT
// LOTA Verifier - Nonce Store Unit Tests
//
// Tests for challenge-response freshness and anti-replay protection.

package verify

import (
	"bytes"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/szymonwilczek/lota/verifier/types"
)

// compute binding nonce for tests from current report content
func testBindingNonce(report *types.AttestationReport, nonce [types.NonceSize]byte) []byte {
	binding := ComputeBindingNonce(nonce, report)
	out := make([]byte, len(binding))
	copy(out, binding[:])
	return out
}

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

	report.TPM.AttestSize = uint16(len(createMockAttestWithNonce(testBindingNonce(report, challenge.Nonce))))
	copy(report.TPM.AttestData[:], createMockAttestWithNonce(testBindingNonce(report, challenge.Nonce)))

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
	report.TPM.AttestSize = uint16(len(createMockAttestWithNonce(testBindingNonce(report, challenge.Nonce))))
	copy(report.TPM.AttestData[:], createMockAttestWithNonce(testBindingNonce(report, challenge.Nonce)))

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
	report.TPM.AttestSize = uint16(len(createMockAttestWithNonce(testBindingNonce(report, challenge.Nonce))))
	copy(report.TPM.AttestData[:], createMockAttestWithNonce(testBindingNonce(report, challenge.Nonce)))

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
	report.TPM.AttestSize = uint16(len(createMockAttestWithNonce(testBindingNonce(report, report.TPM.Nonce))))
	copy(report.TPM.AttestData[:], createMockAttestWithNonce(testBindingNonce(report, report.TPM.Nonce)))

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
	report.TPM.AttestSize = uint16(len(createMockAttestWithNonce(testBindingNonce(report, challenge.Nonce))))
	copy(report.TPM.AttestData[:], createMockAttestWithNonce(testBindingNonce(report, challenge.Nonce)))

	err := store.VerifyNonce(report, "client2") // wrong client
	if err == nil {
		t.Fatal("SECURITY: Nonce accepted for wrong client!")
	}

	t.Logf("✓ Correctly rejected nonce for wrong client: %v", err)
}

func TestNonceStore_UniqueNonces(t *testing.T) {
	t.Log("SECURITY TEST: Nonce uniqueness")
	t.Log("Ensures cryptographic randomness in nonce generation")

	cfg := DefaultNonceStoreConfig()
	cfg.Lifetime = 5 * time.Minute
	cfg.MaxPendingPerClient = 200
	cfg.RateLimitMax = 200
	store := NewNonceStoreFromConfig(cfg)

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

func TestNonceStore_UsedNonceHistory(t *testing.T) {
	t.Log("SECURITY TEST: Used nonce history prevents reuse")
	t.Log("CRITICAL: Even after nonce deletion, used nonce must be rejected")

	store := NewNonceStore(5 * time.Minute)

	challenge, _ := store.GenerateChallenge("client1", 0x00004003)
	report := &types.AttestationReport{}
	copy(report.TPM.Nonce[:], challenge.Nonce[:])
	report.TPM.AttestSize = uint16(len(createMockAttestWithNonce(testBindingNonce(report, challenge.Nonce))))
	copy(report.TPM.AttestData[:], createMockAttestWithNonce(testBindingNonce(report, challenge.Nonce)))

	// first use - should succeed
	err := store.VerifyNonce(report, "client1")
	if err != nil {
		t.Fatalf("First verification failed: %v", err)
	}

	// verify its tracked in used nonces
	if store.UsedCount() != 1 {
		t.Errorf("Used count: got %d, want 1", store.UsedCount())
	}

	// same report should mention "already used"
	err = store.VerifyNonce(report, "client1")
	if err == nil {
		t.Fatal("SECURITY VIOLATION: Used nonce was accepted on replay!")
	}

	t.Logf("✓ Used nonce correctly blocked on replay: %v", err)
}

func TestNonceStore_UsedNonceHistoryMax(t *testing.T) {
	t.Log("TEST: Used nonce history eviction when full")

	cfg := DefaultNonceStoreConfig()
	cfg.Lifetime = 5 * time.Minute
	cfg.UsedNonceHistory = 5
	cfg.MaxPendingPerClient = 100
	cfg.RateLimitMax = 100
	store := NewNonceStoreFromConfig(cfg)

	// generate and use 10(!) nonces
	for i := 0; i < 10; i++ {
		challenge, err := store.GenerateChallenge("client1", 0x00004003)
		if err != nil {
			t.Fatalf("Failed to generate challenge %d: %v", i, err)
		}

		report := &types.AttestationReport{}
		copy(report.TPM.Nonce[:], challenge.Nonce[:])
		report.TPM.AttestSize = uint16(len(createMockAttestWithNonce(testBindingNonce(report, challenge.Nonce))))
		copy(report.TPM.AttestData[:], createMockAttestWithNonce(testBindingNonce(report, challenge.Nonce)))

		err = store.VerifyNonce(report, "client1")
		if err != nil {
			t.Fatalf("Verification %d failed: %v", i, err)
		}
	}

	// should be capped at 5
	if store.UsedCount() > 5 {
		t.Errorf("Used count exceeds max: got %d, want <= 5", store.UsedCount())
	}

	t.Logf("✓ Used nonce history correctly bounded at max=%d (current=%d)",
		5, store.UsedCount())
}

func TestNonceStore_RateLimitPending(t *testing.T) {
	t.Log("SECURITY TEST: Per-client pending challenge limit")
	t.Log("Prevents resource exhaustion from challenge flooding")

	cfg := DefaultNonceStoreConfig()
	cfg.Lifetime = 5 * time.Minute
	cfg.MaxPendingPerClient = 3
	cfg.RateLimitMax = 100 // high to not interfere
	store := NewNonceStoreFromConfig(cfg)

	// generate up to max
	for i := 0; i < 3; i++ {
		_, err := store.GenerateChallenge("flood-client", 0x00004003)
		if err != nil {
			t.Fatalf("Challenge %d should have succeeded: %v", i, err)
		}
	}

	// should start rejecting
	_, err := store.GenerateChallenge("flood-client", 0x00004003)
	if err == nil {
		t.Fatal("SECURITY: Should have rejected challenge exceeding pending limit!")
	}

	t.Logf("✓ Correctly rejected challenge exceeding pending limit: %v", err)

	// other client should not be affected
	_, err = store.GenerateChallenge("other-client", 0x00004003)
	if err != nil {
		t.Fatalf("Other client should not be rate limited: %v", err)
	}

	t.Log("✓ Rate limiting is per-client (other clients unaffected)")
}

func TestNonceStore_RateLimitWindow(t *testing.T) {
	t.Log("SECURITY TEST: Per-client rate limit window")
	t.Log("Prevents rapid challenge-response cycling attacks")

	cfg := DefaultNonceStoreConfig()
	cfg.Lifetime = 5 * time.Minute
	cfg.MaxPendingPerClient = 100 // high to not interfere
	cfg.RateLimitMax = 3
	cfg.RateLimitWindow = 200 * time.Millisecond
	store := NewNonceStoreFromConfig(cfg)

	// exhaust rate limit (3 per window)
	for i := 0; i < 3; i++ {
		challenge, err := store.GenerateChallenge("rate-client", 0x00004003)
		if err != nil {
			t.Fatalf("Challenge %d should have succeeded: %v", i, err)
		}

		// consume to free pending slot
		report := &types.AttestationReport{}
		copy(report.TPM.Nonce[:], challenge.Nonce[:])
		report.TPM.AttestSize = uint16(len(createMockAttestWithNonce(testBindingNonce(report, challenge.Nonce))))
		copy(report.TPM.AttestData[:], createMockAttestWithNonce(testBindingNonce(report, challenge.Nonce)))
		store.VerifyNonce(report, "rate-client")
	}

	// 4th should fail
	_, err := store.GenerateChallenge("rate-client", 0x00004003)
	if err == nil {
		t.Fatal("SECURITY: Should have rejected challenge exceeding rate limit!")
	}
	t.Logf("✓ Rate limit enforced: %v", err)

	// wait for window to reset
	time.Sleep(250 * time.Millisecond)

	_, err = store.GenerateChallenge("rate-client", 0x00004003)
	if err != nil {
		t.Fatalf("Should succeed after rate limit window reset: %v", err)
	}

	t.Log("✓ Rate limit window correctly resets")
}

func TestNonceStore_MonotonicCounter(t *testing.T) {
	t.Log("TEST: Per-client monotonic attestation counter")
	t.Log("Tracks attestation sequence for audit trail")

	store := NewNonceStore(5 * time.Minute)
	clientID := "counter-client"

	if store.ClientCounter(clientID) != 0 {
		t.Errorf("Initial counter: got %d, want 0", store.ClientCounter(clientID))
	}

	for i := 1; i <= 5; i++ {
		store.GenerateChallenge(clientID, 0x00004003)
		if store.ClientCounter(clientID) != uint64(i) {
			t.Errorf("Counter after challenge %d: got %d, want %d",
				i, store.ClientCounter(clientID), i)
		}
	}

	t.Log("✓ Monotonic counter increments per challenge generation")
}

func TestNonceStore_ClientPendingTracking(t *testing.T) {
	t.Log("TEST: Per-client pending count tracking")

	store := NewNonceStore(5 * time.Minute)
	clientID := "pending-client"

	if store.ClientPendingCount(clientID) != 0 {
		t.Errorf("Initial pending: got %d, want 0", store.ClientPendingCount(clientID))
	}

	challenge, _ := store.GenerateChallenge(clientID, 0x00004003)
	store.GenerateChallenge(clientID, 0x00004003)

	if store.ClientPendingCount(clientID) != 2 {
		t.Errorf("After 2 challenges: got %d, want 2", store.ClientPendingCount(clientID))
	}

	// verify one - should decrement
	report := &types.AttestationReport{}
	copy(report.TPM.Nonce[:], challenge.Nonce[:])
	report.TPM.AttestSize = uint16(len(createMockAttestWithNonce(testBindingNonce(report, challenge.Nonce))))
	copy(report.TPM.AttestData[:], createMockAttestWithNonce(testBindingNonce(report, challenge.Nonce)))
	store.VerifyNonce(report, clientID)

	if store.ClientPendingCount(clientID) != 1 {
		t.Errorf("After verify: got %d, want 1", store.ClientPendingCount(clientID))
	}

	t.Log("✓ Per-client pending count accurately tracks state")
}

func TestNonceStore_ConcurrentSafety(t *testing.T) {
	t.Log("STRESS TEST: Concurrent nonce operations")
	t.Log("Ensures thread safety under concurrent access")

	cfg := DefaultNonceStoreConfig()
	cfg.Lifetime = 5 * time.Minute
	cfg.MaxPendingPerClient = 1000
	cfg.RateLimitMax = 1000
	store := NewNonceStoreFromConfig(cfg)

	var wg sync.WaitGroup
	errCh := make(chan error, 100)

	// 10 concurrent clients, each doing 10 challenge-verify cycles
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(clientNum int) {
			defer wg.Done()
			clientID := fmt.Sprintf("concurrent-%d", clientNum)

			for j := 0; j < 10; j++ {
				challenge, err := store.GenerateChallenge(clientID, 0x00004003)
				if err != nil {
					errCh <- fmt.Errorf("client %d, iter %d: generate failed: %w", clientNum, j, err)
					return
				}

				report := &types.AttestationReport{}
				copy(report.TPM.Nonce[:], challenge.Nonce[:])
				report.TPM.AttestSize = uint16(len(createMockAttestWithNonce(testBindingNonce(report, challenge.Nonce))))
				copy(report.TPM.AttestData[:], createMockAttestWithNonce(testBindingNonce(report, challenge.Nonce)))

				if err := store.VerifyNonce(report, clientID); err != nil {
					errCh <- fmt.Errorf("client %d, iter %d: verify failed: %w", clientNum, j, err)
					return
				}
			}
		}(i)
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Errorf("Concurrent error: %v", err)
	}

	t.Logf("✓ 100 concurrent challenge-verify cycles completed safely")
	t.Logf("  Pending: %d, Used: %d", store.PendingCount(), store.UsedCount())
}

func TestNonceStoreFromConfig(t *testing.T) {
	t.Log("TEST: NonceStore configuration")

	cfg := NonceStoreConfig{
		Lifetime:            3 * time.Minute,
		MaxPendingPerClient: 10,
		RateLimitMax:        50,
		RateLimitWindow:     30 * time.Second,
		UsedNonceHistory:    5000,
	}

	store := NewNonceStoreFromConfig(cfg)

	if store.PendingCount() != 0 {
		t.Errorf("Initial pending: got %d, want 0", store.PendingCount())
	}
	if store.UsedCount() != 0 {
		t.Errorf("Initial used: got %d, want 0", store.UsedCount())
	}

	t.Log("✓ NonceStore correctly initialized from config")
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
			report.TPM.AttestSize = uint16(len(createMockAttestWithNonce(testBindingNonce(report, challenge.Nonce))))
			copy(report.TPM.AttestData[:], createMockAttestWithNonce(testBindingNonce(report, challenge.Nonce)))

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
