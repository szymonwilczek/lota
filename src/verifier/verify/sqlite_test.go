// SPDX-License-Identifier: MIT
// LOTA Verifier - SQLite Baseline Store & Used Nonce Backend Tests
//
// Tests for persistent storage implementations.
// Covers TOFU baseline logic, nonce anti-replay persistence,
// and full integration with the Verifier through SQLite backend.

package verify

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/szymonwilczek/lota/verifier/store"
	"github.com/szymonwilczek/lota/verifier/types"
)

func TestSQLiteBaseline_FirstUse(t *testing.T) {
	t.Log("TEST: SQLite baseline TOFU first use")

	db, err := store.OpenDB(":memory:")
	if err != nil {
		t.Fatalf("OpenDB failed: %v", err)
	}
	defer db.Close()

	bs := NewSQLiteBaselineStore(db)

	pcr14 := [types.HashSize]byte{0x14, 0x14, 0x14}
	result, baseline := bs.CheckAndUpdate("first-client", pcr14)

	if result != TOFUFirstUse {
		t.Errorf("Expected TOFUFirstUse, got %d", result)
	}
	if baseline == nil {
		t.Fatal("Baseline should not be nil")
	}
	if baseline.PCR14 != pcr14 {
		t.Error("PCR14 mismatch in returned baseline")
	}
	if baseline.AttestCount != 1 {
		t.Errorf("AttestCount: got %d, want 1", baseline.AttestCount)
	}

	t.Log("✓ First use establishes baseline")
}

func TestSQLiteBaseline_MatchingPCR(t *testing.T) {
	t.Log("TEST: SQLite baseline matching PCR14")

	db, err := store.OpenDB(":memory:")
	if err != nil {
		t.Fatalf("OpenDB failed: %v", err)
	}
	defer db.Close()

	bs := NewSQLiteBaselineStore(db)

	pcr14 := [types.HashSize]byte{0xAA, 0xBB, 0xCC}
	bs.CheckAndUpdate("match-client", pcr14)

	// second attestation with same PCR
	result, baseline := bs.CheckAndUpdate("match-client", pcr14)

	if result != TOFUMatch {
		t.Errorf("Expected TOFUMatch, got %d", result)
	}
	if baseline.AttestCount != 2 {
		t.Errorf("AttestCount: got %d, want 2", baseline.AttestCount)
	}

	t.Log("✓ Matching PCR14 is accepted and count incremented")
}

func TestSQLiteBaseline_Mismatch(t *testing.T) {
	t.Log("SECURITY TEST: SQLite baseline PCR14 mismatch detection")

	db, err := store.OpenDB(":memory:")
	if err != nil {
		t.Fatalf("OpenDB failed: %v", err)
	}
	defer db.Close()

	bs := NewSQLiteBaselineStore(db)

	original := [types.HashSize]byte{0x01}
	bs.CheckAndUpdate("tamper-client", original)

	tampered := [types.HashSize]byte{0xFF}
	result, _ := bs.CheckAndUpdate("tamper-client", tampered)

	if result != TOFUMismatch {
		t.Fatalf("SECURITY FAILURE: PCR14 tampering not detected (got %d)", result)
	}

	t.Log("✓ PCR14 mismatch correctly detected")
}

func TestSQLiteBaseline_GetBaseline(t *testing.T) {
	t.Log("TEST: SQLite baseline retrieval")

	db, err := store.OpenDB(":memory:")
	if err != nil {
		t.Fatalf("OpenDB failed: %v", err)
	}
	defer db.Close()

	bs := NewSQLiteBaselineStore(db)

	// non-existent
	if bs.GetBaseline("nobody") != nil {
		t.Error("Expected nil for non-existent client")
	}

	pcr14 := [types.HashSize]byte{0xDE, 0xAD}
	bs.CheckAndUpdate("get-client", pcr14)

	baseline := bs.GetBaseline("get-client")
	if baseline == nil {
		t.Fatal("Expected non-nil baseline")
	}
	if baseline.PCR14 != pcr14 {
		t.Error("PCR14 mismatch")
	}

	t.Log("✓ Baseline retrieval works")
}

func TestSQLiteBaseline_ClearBaseline(t *testing.T) {
	t.Log("TEST: SQLite baseline clear")

	db, err := store.OpenDB(":memory:")
	if err != nil {
		t.Fatalf("OpenDB failed: %v", err)
	}
	defer db.Close()

	bs := NewSQLiteBaselineStore(db)

	pcr14 := [types.HashSize]byte{0x11}
	bs.CheckAndUpdate("clear-client", pcr14)

	bs.ClearBaseline("clear-client")

	if bs.GetBaseline("clear-client") != nil {
		t.Error("Baseline should be nil after clear")
	}

	// re-establish should be TOFUFirstUse again
	result, _ := bs.CheckAndUpdate("clear-client", pcr14)
	if result != TOFUFirstUse {
		t.Errorf("Expected TOFUFirstUse after clear, got %d", result)
	}

	t.Log("✓ Clear allows baseline re-establishment")
}

func TestSQLiteBaseline_ListClients(t *testing.T) {
	t.Log("TEST: SQLite baseline list clients")

	db, err := store.OpenDB(":memory:")
	if err != nil {
		t.Fatalf("OpenDB failed: %v", err)
	}
	defer db.Close()

	bs := NewSQLiteBaselineStore(db)

	pcr14 := [types.HashSize]byte{}
	bs.CheckAndUpdate("alpha", pcr14)
	bs.CheckAndUpdate("beta", pcr14)
	bs.CheckAndUpdate("gamma", pcr14)

	clients := bs.ListClients()
	if len(clients) != 3 {
		t.Errorf("Expected 3 clients, got %d", len(clients))
	}

	t.Log("✓ ListClients returns all baseline clients")
}

func TestSQLiteBaseline_Stats(t *testing.T) {
	t.Log("TEST: SQLite baseline statistics")

	db, err := store.OpenDB(":memory:")
	if err != nil {
		t.Fatalf("OpenDB failed: %v", err)
	}
	defer db.Close()

	bs := NewSQLiteBaselineStore(db)

	stats := bs.Stats()
	if stats.TotalClients != 0 {
		t.Errorf("Initial TotalClients: got %d, want 0", stats.TotalClients)
	}

	pcr14 := [types.HashSize]byte{}
	bs.CheckAndUpdate("stat-client-1", pcr14)
	bs.CheckAndUpdate("stat-client-2", pcr14)

	stats = bs.Stats()
	if stats.TotalClients != 2 {
		t.Errorf("TotalClients: got %d, want 2", stats.TotalClients)
	}

	t.Log("✓ Baseline stats report correct counts")
}

func TestSQLiteBaseline_Persistence(t *testing.T) {
	t.Log("CRITICAL TEST: SQLite baseline persistence across instances")

	db, err := store.OpenDB(":memory:")
	if err != nil {
		t.Fatalf("OpenDB failed: %v", err)
	}
	defer db.Close()

	pcr14 := [types.HashSize]byte{0xBE, 0xEF}

	// first instance
	bs1 := NewSQLiteBaselineStore(db)
	bs1.CheckAndUpdate("persist-client", pcr14)
	bs1.CheckAndUpdate("persist-client", pcr14) // count = 2

	// second instance (simulates restart)
	bs2 := NewSQLiteBaselineStore(db)

	baseline := bs2.GetBaseline("persist-client")
	if baseline == nil {
		t.Fatal("Baseline lost after 'restart'!")
	}
	if baseline.PCR14 != pcr14 {
		t.Error("PCR14 changed after 'restart'!")
	}
	if baseline.AttestCount != 2 {
		t.Errorf("AttestCount lost: got %d, want 2", baseline.AttestCount)
	}

	// third attestation should continue counting
	result, bl := bs2.CheckAndUpdate("persist-client", pcr14)
	if result != TOFUMatch {
		t.Errorf("Expected TOFUMatch, got %d", result)
	}
	if bl.AttestCount != 3 {
		t.Errorf("AttestCount: got %d, want 3", bl.AttestCount)
	}

	t.Log("✓ Baseline and counters persist across instances")
}

func TestSQLiteNonce_RecordAndContains(t *testing.T) {
	t.Log("TEST: SQLite used nonce record and contains")

	db, err := store.OpenDB(":memory:")
	if err != nil {
		t.Fatalf("OpenDB failed: %v", err)
	}
	defer db.Close()

	backend := NewSQLiteUsedNonceBackend(db)

	key := "test-nonce-key-12345"

	if backend.Contains(key) {
		t.Error("Should not contain unrecorded nonce")
	}

	if err := backend.Record(key, time.Now()); err != nil {
		t.Fatalf("Record failed: %v", err)
	}

	if !backend.Contains(key) {
		t.Error("Should contain recorded nonce")
	}

	t.Log("✓ Record and Contains work correctly")
}

func TestSQLiteNonce_Count(t *testing.T) {
	t.Log("TEST: SQLite used nonce count")

	db, err := store.OpenDB(":memory:")
	if err != nil {
		t.Fatalf("OpenDB failed: %v", err)
	}
	defer db.Close()

	backend := NewSQLiteUsedNonceBackend(db)

	if backend.Count() != 0 {
		t.Errorf("Initial count: got %d, want 0", backend.Count())
	}

	for i := 0; i < 10; i++ {
		backend.Record(fmt.Sprintf("nonce-%d", i), time.Now())
	}

	if backend.Count() != 10 {
		t.Errorf("Count: got %d, want 10", backend.Count())
	}

	t.Log("✓ Count tracks number of used nonces")
}

func TestSQLiteNonce_Cleanup(t *testing.T) {
	t.Log("TEST: SQLite used nonce time-based cleanup")

	db, err := store.OpenDB(":memory:")
	if err != nil {
		t.Fatalf("OpenDB failed: %v", err)
	}
	defer db.Close()

	backend := NewSQLiteUsedNonceBackend(db)

	// record nonces at different times
	oldTime := time.Now().Add(-2 * time.Hour)
	recentTime := time.Now()

	for i := 0; i < 5; i++ {
		backend.Record(fmt.Sprintf("old-nonce-%d", i), oldTime)
	}
	for i := 0; i < 3; i++ {
		backend.Record(fmt.Sprintf("new-nonce-%d", i), recentTime)
	}

	if backend.Count() != 8 {
		t.Errorf("Pre-cleanup count: got %d, want 8", backend.Count())
	}

	// cleanup entries older than 1 hour
	cutoff := time.Now().Add(-1 * time.Hour)
	backend.Cleanup(cutoff)

	if backend.Count() != 3 {
		t.Errorf("Post-cleanup count: got %d, want 3", backend.Count())
	}

	// new nonces should still be there
	if !backend.Contains("new-nonce-0") {
		t.Error("Recent nonce should survive cleanup")
	}
	if backend.Contains("old-nonce-0") {
		t.Error("Old nonce should be cleaned up")
	}

	t.Log("✓ Time-based cleanup works correctly")
}

func TestSQLiteNonce_DuplicateRecord(t *testing.T) {
	t.Log("TEST: SQLite used nonce duplicate record (idempotent)")

	db, err := store.OpenDB(":memory:")
	if err != nil {
		t.Fatalf("OpenDB failed: %v", err)
	}
	defer db.Close()

	backend := NewSQLiteUsedNonceBackend(db)

	key := "duplicate-nonce"
	backend.Record(key, time.Now())
	err = backend.Record(key, time.Now()) // INSERT OR IGNORE
	if err != nil {
		t.Errorf("Duplicate record should not error: %v", err)
	}
	if backend.Count() != 1 {
		t.Errorf("Count should be 1 after duplicate: got %d", backend.Count())
	}

	t.Log("✓ Duplicate recording is idempotent")
}

func TestSQLiteNonce_Persistence(t *testing.T) {
	t.Log("CRITICAL SECURITY TEST: Used nonce persistence across instances")
	t.Log("Prevents replay attacks after verifier restart")

	db, err := store.OpenDB(":memory:")
	if err != nil {
		t.Fatalf("OpenDB failed: %v", err)
	}
	defer db.Close()

	// first instance records a used nonce
	backend1 := NewSQLiteUsedNonceBackend(db)
	backend1.Record("replay-attempt-nonce", time.Now())

	// second instance (simulates restart)
	backend2 := NewSQLiteUsedNonceBackend(db)

	if !backend2.Contains("replay-attempt-nonce") {
		t.Fatal("SECURITY FAILURE: Used nonce lost after restart — replay attack possible!")
	}

	t.Log("✓ SECURITY: Used nonces persist across instances (anti-replay)")
}

func TestSQLiteIntegration_FullFlow(t *testing.T) {
	t.Log("INTEGRATION TEST: Full attestation flow with SQLite backend")

	db, err := store.OpenDB(":memory:")
	if err != nil {
		t.Fatalf("OpenDB failed: %v", err)
	}
	defer db.Close()

	aikStore := store.NewSQLiteAIKStore(db)
	cfg := DefaultConfig()
	cfg.TimestampMaxAge = 5 * time.Minute
	cfg.BaselineStore = NewSQLiteBaselineStore(db)
	cfg.UsedNonceBackend = NewSQLiteUsedNonceBackend(db)

	verifier := NewVerifier(cfg, aikStore)
	verifier.AddPolicy(DefaultPolicy())
	verifier.SetActivePolicy("default")

	clientID := "sqlite-client"
	pcr14 := [32]byte{0x14, 0x14}

	// first attestation (TOFU)
	challenge, err := verifier.GenerateChallenge(clientID)
	if err != nil {
		t.Fatalf("GenerateChallenge failed: %v", err)
	}

	reportData := createSQLiteTestReport(t, challenge.Nonce, pcr14)
	result, err := verifier.VerifyReport(clientID, reportData)
	if err != nil {
		t.Fatalf("VerifyReport failed: %v", err)
	}
	if result.Result != types.VerifyOK {
		t.Errorf("Expected VerifyOK, got %d", result.Result)
	}

	// second attestation (should match baseline)
	challenge2, _ := verifier.GenerateChallenge(clientID)
	report2 := createSQLiteTestReport(t, challenge2.Nonce, pcr14)
	result2, err := verifier.VerifyReport(clientID, report2)
	if err != nil || result2.Result != types.VerifyOK {
		t.Fatalf("Second attestation failed: %v (result=%d)", err, result2.Result)
	}

	// verify stats
	stats := verifier.Stats()
	if stats.TotalAttestations != 2 {
		t.Errorf("TotalAttestations: got %d, want 2", stats.TotalAttestations)
	}

	t.Log("✓ Full SQLite-backed attestation flow works")
}

func TestSQLiteIntegration_ReplayAfterRestart(t *testing.T) {
	t.Log("CRITICAL SECURITY TEST: Replay detection survives restart")
	t.Log("A verifier restart must NOT allow replaying old reports")

	db, err := store.OpenDB(":memory:")
	if err != nil {
		t.Fatalf("OpenDB failed: %v", err)
	}
	defer db.Close()

	pcr14 := [32]byte{0x14}

	// first verifier instance
	aikStore1 := store.NewSQLiteAIKStore(db)
	cfg1 := DefaultConfig()
	cfg1.TimestampMaxAge = 5 * time.Minute
	cfg1.BaselineStore = NewSQLiteBaselineStore(db)
	cfg1.UsedNonceBackend = NewSQLiteUsedNonceBackend(db)

	v1 := NewVerifier(cfg1, aikStore1)
	v1.AddPolicy(DefaultPolicy())
	v1.SetActivePolicy("default")

	// successful attestation
	challenge, _ := v1.GenerateChallenge("restart-client")
	report := createSQLiteTestReport(t, challenge.Nonce, pcr14)
	result1, err := v1.VerifyReport("restart-client", report)
	if err != nil || result1.Result != types.VerifyOK {
		t.Fatalf("First attestation failed: %v", err)
	}
	t.Log("✓ First attestation succeeded")

	// new verifier with same DB
	aikStore2 := store.NewSQLiteAIKStore(db)
	cfg2 := DefaultConfig()
	cfg2.TimestampMaxAge = 5 * time.Minute
	cfg2.BaselineStore = NewSQLiteBaselineStore(db)
	cfg2.UsedNonceBackend = NewSQLiteUsedNonceBackend(db)

	v2 := NewVerifier(cfg2, aikStore2)
	v2.AddPolicy(DefaultPolicy())
	v2.SetActivePolicy("default")

	// same report - MUST fail
	result2, err := v2.VerifyReport("restart-client", report)
	if result2.Result != types.VerifyNonceFail {
		t.Fatalf("SECURITY FAILURE: Replay attack succeeded after restart!\n"+
			"  Expected: FAIL_NONCE (%d)\n"+
			"  Got: %d",
			types.VerifyNonceFail, result2.Result)
	}

	t.Logf("✓ SECURITY: Replay correctly blocked after restart: %v", err)
}

func TestSQLiteIntegration_BaselineSurvivesRestart(t *testing.T) {
	t.Log("CRITICAL TEST: PCR14 baseline survives verifier restart")

	db, err := store.OpenDB(":memory:")
	if err != nil {
		t.Fatalf("OpenDB failed: %v", err)
	}
	defer db.Close()

	originalPCR14 := [32]byte{0x22, 0x33}
	tamperedPCR14 := [32]byte{0xFF, 0xFF}

	// establish baseline
	aikStore1 := store.NewSQLiteAIKStore(db)
	cfg1 := DefaultConfig()
	cfg1.TimestampMaxAge = 5 * time.Minute
	cfg1.BaselineStore = NewSQLiteBaselineStore(db)
	cfg1.UsedNonceBackend = NewSQLiteUsedNonceBackend(db)

	v1 := NewVerifier(cfg1, aikStore1)
	v1.AddPolicy(DefaultPolicy())
	v1.SetActivePolicy("default")

	ch1, _ := v1.GenerateChallenge("baseline-client")
	rep1 := createSQLiteTestReport(t, ch1.Nonce, originalPCR14)
	r1, err := v1.VerifyReport("baseline-client", rep1)
	if err != nil || r1.Result != types.VerifyOK {
		t.Fatalf("Baseline attestation failed: %v", err)
	}
	t.Log("✓ Baseline established")

	// new verifier with same DB
	aikStore2 := store.NewSQLiteAIKStore(db)
	cfg2 := DefaultConfig()
	cfg2.TimestampMaxAge = 5 * time.Minute
	cfg2.BaselineStore = NewSQLiteBaselineStore(db)
	cfg2.UsedNonceBackend = NewSQLiteUsedNonceBackend(db)

	v2 := NewVerifier(cfg2, aikStore2)
	v2.AddPolicy(DefaultPolicy())
	v2.SetActivePolicy("default")

	// tampered PCR14 should be detected even after restart
	ch2, _ := v2.GenerateChallenge("baseline-client")
	rep2 := createSQLiteTestReport(t, ch2.Nonce, tamperedPCR14)
	r2, err := v2.VerifyReport("baseline-client", rep2)

	if r2.Result != types.VerifyIntegrityMismatch {
		t.Fatalf("SECURITY FAILURE: PCR14 tampering not detected after restart!\n"+
			"  Expected: FAIL_INTEGRITY_MISMATCH (%d)\n"+
			"  Got: %d",
			types.VerifyIntegrityMismatch, r2.Result)
	}

	t.Logf("✓ SECURITY: Baseline persists across restart, tampering detected: %v", err)
}

func TestSQLiteIntegration_ConcurrentAttestations(t *testing.T) {
	t.Log("STRESS TEST: Concurrent attestations with SQLite backend")

	db, err := store.OpenDB(":memory:")
	if err != nil {
		t.Fatalf("OpenDB failed: %v", err)
	}
	defer db.Close()

	aikStore := store.NewSQLiteAIKStore(db)
	cfg := DefaultConfig()
	cfg.TimestampMaxAge = 5 * time.Minute
	cfg.BaselineStore = NewSQLiteBaselineStore(db)
	cfg.UsedNonceBackend = NewSQLiteUsedNonceBackend(db)

	verifier := NewVerifier(cfg, aikStore)
	verifier.AddPolicy(DefaultPolicy())
	verifier.SetActivePolicy("default")

	numClients := 10
	var wg sync.WaitGroup
	errCh := make(chan error, numClients*2)

	for i := 0; i < numClients; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			clientID := fmt.Sprintf("concurrent-sqlite-%d", n)
			pcr14 := [32]byte{byte(n)}

			// each client does 2 attestations
			for j := 0; j < 2; j++ {
				ch, err := verifier.GenerateChallenge(clientID)
				if err != nil {
					errCh <- fmt.Errorf("client %d iter %d: challenge: %w", n, j, err)
					return
				}

				rep := createSQLiteTestReport(nil, ch.Nonce, pcr14)
				result, err := verifier.VerifyReport(clientID, rep)
				if err != nil || result.Result != types.VerifyOK {
					errCh <- fmt.Errorf("client %d iter %d: verify: %v (result=%d)", n, j, err, result.Result)
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

	stats := verifier.Stats()
	expected := int64(numClients * 2)
	if stats.TotalAttestations != expected {
		t.Errorf("TotalAttestations: got %d, want %d", stats.TotalAttestations, expected)
	}

	t.Logf("✓ %d concurrent SQLite-backed attestations completed", expected)
}

func TestSQLiteIntegration_AIKPersistence(t *testing.T) {
	t.Log("TEST: AIK persists across verifier instances")

	db, err := store.OpenDB(":memory:")
	if err != nil {
		t.Fatalf("OpenDB failed: %v", err)
	}
	defer db.Close()

	pcr14 := [32]byte{0x42}

	// TOFU registers AIK
	aikStore1 := store.NewSQLiteAIKStore(db)
	cfg := DefaultConfig()
	cfg.TimestampMaxAge = 5 * time.Minute
	cfg.BaselineStore = NewSQLiteBaselineStore(db)
	cfg.UsedNonceBackend = NewSQLiteUsedNonceBackend(db)

	v1 := NewVerifier(cfg, aikStore1)
	v1.AddPolicy(DefaultPolicy())
	v1.SetActivePolicy("default")

	ch, _ := v1.GenerateChallenge("aik-persist-client")
	rep := createSQLiteTestReport(t, ch.Nonce, pcr14)
	r, err := v1.VerifyReport("aik-persist-client", rep)
	if err != nil || r.Result != types.VerifyOK {
		t.Fatalf("TOFU attestation failed: %v", err)
	}

	// second verifier: check AIK exists
	aikStore2 := store.NewSQLiteAIKStore(db)
	_, err = aikStore2.GetAIK("aik-persist-client")
	if err != nil {
		t.Fatalf("AIK not persisted after restart: %v", err)
	}

	t.Log("✓ AIK persists in SQLite across verifier instances")
}

// shared key for SQLite integration tests
var sqliteTestKey *rsa.PrivateKey

func init() {
	var err error
	sqliteTestKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic("failed to generate SQLite test key: " + err.Error())
	}
}

func createSQLiteTestReport(t testing.TB, nonce [32]byte, pcr14 [32]byte) []byte {
	if t != nil {
		t.Helper()
	}

	buf := make([]byte, types.MinReportSize)
	offset := 0

	// Header
	binary.LittleEndian.PutUint32(buf[offset:], types.ReportMagic)
	offset += 4
	binary.LittleEndian.PutUint32(buf[offset:], types.ReportVersion)
	offset += 4
	binary.LittleEndian.PutUint64(buf[offset:], uint64(time.Now().Unix()))
	offset += 8
	offset += 8 // timestamp_ns
	binary.LittleEndian.PutUint32(buf[offset:], types.MinReportSize)
	offset += 4
	binary.LittleEndian.PutUint32(buf[offset:], types.FlagTPMQuoteOK|types.FlagModuleSig|types.FlagEnforce)
	offset += 4

	// PCR values
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
	binary.LittleEndian.PutUint32(buf[offset:], 0x00004003)
	offset += 4

	// compute PCR digest from values just written
	pcrDigest := computeTestPCRDigest(buf, 32, 0x00004003)

	// TPMS_ATTEST with binding nonce = SHA-256(nonce || hardware_id)
	var zeroHWID [types.HardwareIDSize]byte
	bindingHash := sha256.New()
	bindingHash.Write(nonce[:])
	bindingHash.Write(zeroHWID[:])
	bindingNonce := bindingHash.Sum(nil)
	attestData := createTPMSAttestWithNonce(bindingNonce, pcrDigest)
	hash := sha256.Sum256(attestData)
	signature, err := rsa.SignPKCS1v15(rand.Reader, sqliteTestKey, crypto.SHA256, hash[:])
	if err != nil {
		panic("failed to sign: " + err.Error())
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

	// AIK public key
	aikDER, _ := x509.MarshalPKIXPublicKey(&sqliteTestKey.PublicKey)
	copy(buf[offset:], aikDER)
	offset += types.MaxAIKPubSize
	binary.LittleEndian.PutUint16(buf[offset:], uint16(len(aikDER)))
	offset += 2

	// AIK certificate (empty)
	offset += types.MaxAIKCertSize
	binary.LittleEndian.PutUint16(buf[offset:], 0)
	offset += 2

	// EK certificate (empty)
	offset += types.MaxEKCertSize
	binary.LittleEndian.PutUint16(buf[offset:], 0)
	offset += 2

	// nonce
	copy(buf[offset:], nonce[:])
	offset += types.NonceSize

	// reserved
	offset += 2

	// System measurement
	offset += types.HashSize * 2
	copy(buf[offset:], "/boot/vmlinuz-6.12.0-lota")
	offset += types.MaxKernelPath
	binary.LittleEndian.PutUint32(buf[offset:], 0x8086) // IOMMU vendor
	offset += 4
	binary.LittleEndian.PutUint32(buf[offset:], 0x07) // IOMMU flags
	offset += 4
	binary.LittleEndian.PutUint32(buf[offset:], 2) // unit count
	offset += 4
	copy(buf[offset:], "intel_iommu=on")
	offset += types.CmdlineParamMax

	// BPF summary
	binary.LittleEndian.PutUint32(buf[offset:], 1)
	offset += 4
	binary.LittleEndian.PutUint32(buf[offset:], 1)
	offset += 4
	binary.LittleEndian.PutUint64(buf[offset:], uint64(time.Now().Unix()))
	offset += 8
	binary.LittleEndian.PutUint64(buf[offset:], uint64(time.Now().Unix()))

	return buf
}
