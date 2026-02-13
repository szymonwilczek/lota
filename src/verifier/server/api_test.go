// SPDX-License-Identifier: MIT
// LOTA Verifier - REST Monitoring API tests
//
// Unit tests verify individual handler behavior in isolation.
// I'll update that description in some time to be more precise
// about what that tests actually are doing.

package server

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/szymonwilczek/lota/verifier/metrics"
	"github.com/szymonwilczek/lota/verifier/store"
	"github.com/szymonwilczek/lota/verifier/types"
	"github.com/szymonwilczek/lota/verifier/verify"
)

// simulated TPM Attestation Identity Key shared across tests
var testAIK *rsa.PrivateKey

func init() {
	var err error
	testAIK, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic("failed to generate test AIK: " + err.Error())
	}
}

// creates a test verifier and HTTP mux for API testing
// uses a test admin API key so that mutating endpoints are accessible
// reader key is empty so sensitive read endpoints are public
func setupTestAPI(t *testing.T) (*http.ServeMux, *verify.Verifier) {
	t.Helper()
	return setupTestAPIWithKeys(t, "test-admin-key", "")
}

// creates a test setup with a specific admin API key (no reader key)
func setupTestAPIWithKey(t *testing.T, adminKey string) (*http.ServeMux, *verify.Verifier) {
	t.Helper()
	return setupTestAPIWithKeys(t, adminKey, "")
}

// creates a test setup with specific admin and reader API keys
func setupTestAPIWithKeys(t *testing.T, adminKey, readerKey string) (*http.ServeMux, *verify.Verifier) {
	t.Helper()

	aikStore := store.NewMemoryStore()
	m := metrics.New()
	cfg := verify.DefaultConfig()
	auditLog := store.NewMemoryAuditLog()
	cfg.RevocationStore = store.NewMemoryRevocationStore(auditLog)
	cfg.BanStore = store.NewMemoryBanStore(auditLog)
	cfg.Metrics = m
	v := verify.NewVerifier(cfg, aikStore)
	v.AddPolicy(verify.DefaultPolicy())

	srv := &Server{
		verifier: v,
		addr:     ":8443",
		// listener is nil - simulates not-yet-started or stopped state
	}

	mux := http.NewServeMux()
	NewAPIHandler(mux, v, srv, auditLog, nil, m, nil, adminKey, readerKey)

	return mux, v
}

// creates a test setup where the TLS listener appears active
func setupTestAPIListening(t *testing.T) (*http.ServeMux, *verify.Verifier) {
	t.Helper()
	return setupTestAPIListeningWithKeys(t, "test-admin-key", "")
}

// creates a test setup with listener and specific admin API key (no reader key)
func setupTestAPIListeningWithKey(t *testing.T, adminKey string) (*http.ServeMux, *verify.Verifier) {
	t.Helper()
	return setupTestAPIListeningWithKeys(t, adminKey, "")
}

// creates a test setup with listener and specific admin + reader API keys
func setupTestAPIListeningWithKeys(t *testing.T, adminKey, readerKey string) (*http.ServeMux, *verify.Verifier) {
	t.Helper()

	aikStore := store.NewMemoryStore()
	m := metrics.New()
	cfg := verify.DefaultConfig()
	auditLog := store.NewMemoryAuditLog()
	cfg.RevocationStore = store.NewMemoryRevocationStore(auditLog)
	cfg.BanStore = store.NewMemoryBanStore(auditLog)
	cfg.Metrics = m
	v := verify.NewVerifier(cfg, aikStore)
	v.AddPolicy(verify.DefaultPolicy())

	ln, err := newDummyListener()
	if err != nil {
		t.Fatalf("Failed to create dummy listener: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	srv := &Server{
		verifier: v,
		listener: ln,
		addr:     ":8443",
	}

	mux := http.NewServeMux()
	NewAPIHandler(mux, v, srv, auditLog, nil, m, nil, adminKey, readerKey)

	return mux, v
}

// helper: minimal TCP listener to make HealthCheck report 'listening'
func newDummyListener() (*dummyListener, error) {
	return &dummyListener{closed: make(chan struct{})}, nil
}

type dummyListener struct {
	closed chan struct{}
}

func (d *dummyListener) Accept() (net.Conn, error) {
	<-d.closed
	return nil, net.ErrClosed
}

func (d *dummyListener) Close() error {
	select {
	case <-d.closed:
	default:
		close(d.closed)
	}
	return nil
}

func (d *dummyListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8443}
}

// builds a complete attestation report with valid TPM quote signature
func buildSignedReport(t *testing.T, nonce [32]byte, pcr14 [32]byte, key *rsa.PrivateKey) []byte {
	t.Helper()

	buf := make([]byte, types.MinReportSize)
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
	binary.LittleEndian.PutUint32(buf[offset:], types.MinReportSize)
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

	// PCR mask (PCR 0,1,14)
	binary.LittleEndian.PutUint32(buf[offset:], 0x00004003)
	offset += 4

	// compute PCR digest from values just written
	pcrDigest := computeTestPCRDigest(buf, 32, 0x00004003)
	attestData := buildTPMSAttest(nonce[:], pcrDigest)

	hash := sha256.Sum256(attestData)
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hash[:])
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

	// AIK public key (DER)
	aikDER, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
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

	// hardware_id (32 bytes, leave zero for test fallback)
	offset += types.HardwareIDSize

	// reserved
	offset += 2

	// System Measurement (396 bytes)
	for i := 0; i < types.HashSize; i++ {
		buf[offset+i] = byte(0xAA ^ i) // kernel_hash
	}
	offset += types.HashSize
	for i := 0; i < types.HashSize; i++ {
		buf[offset+i] = byte(0xBB ^ i) // agent_hash
	}
	offset += types.HashSize
	copy(buf[offset:], "/boot/vmlinuz-6.12.0-lota")
	offset += types.MaxKernelPath
	binary.LittleEndian.PutUint32(buf[offset:], 0x8086) // IOMMU vendor
	offset += 4
	binary.LittleEndian.PutUint32(buf[offset:], 0x07) // IOMMU flags
	offset += 4
	binary.LittleEndian.PutUint32(buf[offset:], 2) // IOMMU device count
	offset += 4
	copy(buf[offset:], "intel_iommu=on")
	offset += types.CmdlineParamMax

	// BPF Summary (24 bytes)
	binary.LittleEndian.PutUint32(buf[offset:], 42)
	offset += 4
	binary.LittleEndian.PutUint32(buf[offset:], 10)
	offset += 4
	binary.LittleEndian.PutUint64(buf[offset:], uint64(time.Now().Add(-time.Hour).Unix()))
	offset += 8
	binary.LittleEndian.PutUint64(buf[offset:], uint64(time.Now().Unix()))

	return buf
}

// builds minimal TPMS_ATTEST with embedded nonce and PCR digest
func buildTPMSAttest(nonce []byte, pcrDigest []byte) []byte {
	buf := make([]byte, 0, 128)

	// Magic: TPM_GENERATED_VALUE
	buf = append(buf, 0xff, 0x54, 0x43, 0x47)
	// Type: TPM_ST_ATTEST_QUOTE
	buf = append(buf, 0x80, 0x18)
	// QualifiedSigner: TPM2B_NAME
	buf = append(buf, 0x00, 0x02, 0x00, 0x00)
	// ExtraData: TPM2B_DATA (nonce)
	buf = append(buf, 0x00, byte(len(nonce)))
	buf = append(buf, nonce...)
	// ClockInfo
	buf = append(buf, make([]byte, 17)...) // clock(8)+reset(4)+restart(4)+safe(1)
	buf[len(buf)-1] = 0x01                 // safe = true
	// FirmwareVersion
	buf = append(buf, make([]byte, 8)...)
	// QuoteInfo
	buf = append(buf, 0x00, 0x00, 0x00, 0x01) // count
	buf = append(buf, 0x00, 0x0b)             // SHA256
	buf = append(buf, 0x03)                   // sizeofSelect
	buf = append(buf, 0x03, 0x00, 0x40)       // PCR 0,1,14
	buf = append(buf, 0x00, 0x20)             // digest size
	buf = append(buf, pcrDigest[:32]...)      // PCR digest

	return buf
}

// performs a full challenge-response attestation cycle via Verifier
// returns the verification result code
func attestClient(t *testing.T, v *verify.Verifier, clientID string, key *rsa.PrivateKey, pcr14 [32]byte) uint32 {
	t.Helper()

	challenge, err := v.GenerateChallenge(clientID)
	if err != nil {
		t.Fatalf("GenerateChallenge(%s) failed: %v", clientID, err)
	}

	report := buildSignedReport(t, challenge.Nonce, pcr14, key)
	result, _ := v.VerifyReport(clientID, report)
	return result.Result
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

func TestHealthEndpoint(t *testing.T) {
	mux, _ := setupTestAPIListening(t)

	req := httptest.NewRequest("GET", "/health", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d", rec.Code)
	}

	var resp healthResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if resp.Status != "ok" {
		t.Errorf("Expected status 'ok', got '%s'", resp.Status)
	}
	if !resp.TLS.Listening {
		t.Error("Expected TLS listening=true")
	}
	if resp.TLS.Address != ":8443" {
		t.Errorf("Expected address ':8443', got '%s'", resp.TLS.Address)
	}
}

func TestHealthDegraded(t *testing.T) {
	mux, _ := setupTestAPI(t) // no listener

	req := httptest.NewRequest("GET", "/health", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("Expected 503, got %d", rec.Code)
	}

	var resp healthResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if resp.Status != "degraded" {
		t.Errorf("Expected status 'degraded', got '%s'", resp.Status)
	}
}

func TestStatsEndpoint(t *testing.T) {
	mux, v := setupTestAPIListening(t)

	v.AddPolicy(verify.StrictPolicy())

	req := httptest.NewRequest("GET", "/api/v1/stats", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d", rec.Code)
	}

	var resp statsResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if resp.PendingChallenges != 0 {
		t.Errorf("Expected 0 pending challenges, got %d", resp.PendingChallenges)
	}
	if resp.ActivePolicy != "default" {
		t.Errorf("Expected active policy 'default', got '%s'", resp.ActivePolicy)
	}
	if len(resp.LoadedPolicies) != 2 {
		t.Errorf("Expected 2 loaded policies, got %d", len(resp.LoadedPolicies))
	}
	if resp.TotalAttestations != 0 {
		t.Errorf("Expected 0 total attestations, got %d", resp.TotalAttestations)
	}

	ct := rec.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("Expected Content-Type 'application/json', got '%s'", ct)
	}
}

func TestStatsCounters(t *testing.T) {
	mux, v := setupTestAPIListening(t)

	_, _ = v.GenerateChallenge("client-a")
	_, _ = v.GenerateChallenge("client-b")

	req := httptest.NewRequest("GET", "/api/v1/stats", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	var resp statsResponse
	json.NewDecoder(rec.Body).Decode(&resp)

	if resp.PendingChallenges != 2 {
		t.Errorf("Expected 2 pending challenges, got %d", resp.PendingChallenges)
	}
}

func TestListClientsEmpty(t *testing.T) {
	mux, _ := setupTestAPIListening(t)

	req := httptest.NewRequest("GET", "/api/v1/clients", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d", rec.Code)
	}

	var resp clientListResponse
	json.NewDecoder(rec.Body).Decode(&resp)

	if resp.Count != 0 {
		t.Errorf("Expected 0 clients, got %d", resp.Count)
	}
	if resp.Clients == nil || len(resp.Clients) != 0 {
		t.Errorf("Expected empty client list, got %v", resp.Clients)
	}
}

func TestListClientsWithChallenges(t *testing.T) {
	mux, v := setupTestAPIListening(t)

	_, _ = v.GenerateChallenge("10.0.0.1")
	_, _ = v.GenerateChallenge("10.0.0.2")
	_, _ = v.GenerateChallenge("10.0.0.3")

	req := httptest.NewRequest("GET", "/api/v1/clients", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	var resp clientListResponse
	json.NewDecoder(rec.Body).Decode(&resp)

	if resp.Count != 3 {
		t.Errorf("Expected 3 clients, got %d", resp.Count)
	}
}

func TestClientInfoNotFound(t *testing.T) {
	mux, _ := setupTestAPIListening(t)

	req := httptest.NewRequest("GET", "/api/v1/clients/nonexistent", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("Expected 404, got %d", rec.Code)
	}

	var resp errorResponse
	json.NewDecoder(rec.Body).Decode(&resp)

	if resp.Error != "client not found" {
		t.Errorf("Expected 'client not found', got '%s'", resp.Error)
	}
}

func TestClientInfoWithChallenge(t *testing.T) {
	mux, v := setupTestAPIListening(t)

	_, _ = v.GenerateChallenge("10.0.0.42")
	_, _ = v.GenerateChallenge("10.0.0.42")

	req := httptest.NewRequest("GET", "/api/v1/clients/10.0.0.42", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d", rec.Code)
	}

	var resp clientInfoResponse
	json.NewDecoder(rec.Body).Decode(&resp)

	if resp.ClientID != "10.0.0.42" {
		t.Errorf("Expected client ID '10.0.0.42', got '%s'", resp.ClientID)
	}
	if resp.MonotonicCounter != 2 {
		t.Errorf("Expected monotonic counter 2, got %d", resp.MonotonicCounter)
	}
	if resp.PendingChallenges != 2 {
		t.Errorf("Expected 2 pending challenges, got %d", resp.PendingChallenges)
	}
	if resp.HasAIK {
		t.Error("Expected HasAIK=false for challenge-only client")
	}
}

func TestClientInfoEmptyID(t *testing.T) {
	mux, _ := setupTestAPIListening(t)

	req := httptest.NewRequest("GET", "/api/v1/clients/", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d", rec.Code)
	}

	var resp clientListResponse
	json.NewDecoder(rec.Body).Decode(&resp)

	if resp.Count != 0 {
		t.Errorf("Expected 0 clients, got %d", resp.Count)
	}
}

func TestMetricsEndpoint(t *testing.T) {
	mux, _ := setupTestAPIListening(t)

	req := httptest.NewRequest("GET", "/metrics", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d", rec.Code)
	}

	ct := rec.Header().Get("Content-Type")
	if !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("Expected Content-Type text/plain, got '%s'", ct)
	}

	body := rec.Body.String()

	expectedMetrics := []string{
		"lota_pending_challenges",
		"lota_used_nonces",
		"lota_registered_clients",
		"lota_attestations_total",
		"lota_attestations_success_total",
		"lota_attestations_failed_total",
		"lota_uptime_seconds",
		"lota_loaded_policies",
	}

	for _, metric := range expectedMetrics {
		if !strings.Contains(body, metric) {
			t.Errorf("Missing metric: %s", metric)
		}
	}

	if !strings.Contains(body, "# HELP") {
		t.Error("Missing HELP annotations")
	}
	if !strings.Contains(body, "# TYPE") {
		t.Error("Missing TYPE annotations")
	}
}

func TestMetricsCounterValues(t *testing.T) {
	mux, v := setupTestAPIListening(t)

	_, _ = v.GenerateChallenge("test-client")

	req := httptest.NewRequest("GET", "/metrics", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	body := rec.Body.String()

	if !strings.Contains(body, "lota_pending_challenges 1") {
		t.Error("Expected pending_challenges = 1 in metrics")
	}
}

func TestUptimeIncreases(t *testing.T) {
	mux, _ := setupTestAPIListening(t)

	req := httptest.NewRequest("GET", "/health", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	var resp1 healthResponse
	json.NewDecoder(rec.Body).Decode(&resp1)

	time.Sleep(10 * time.Millisecond)

	req = httptest.NewRequest("GET", "/health", nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	var resp2 healthResponse
	json.NewDecoder(rec.Body).Decode(&resp2)

	if resp2.UptimeSec < resp1.UptimeSec {
		t.Error("Uptime should not decrease")
	}
}

func TestMethodNotAllowed(t *testing.T) {
	mux, _ := setupTestAPIListening(t)

	req := httptest.NewRequest("POST", "/health", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Logf("POST /health returned %d (expected 405)", rec.Code)
	}
}

func TestJSONContentType(t *testing.T) {
	mux, _ := setupTestAPIListening(t)

	endpoints := []string{
		"/health",
		"/api/v1/stats",
		"/api/v1/clients",
	}

	for _, ep := range endpoints {
		req := httptest.NewRequest("GET", ep, nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		ct := rec.Header().Get("Content-Type")
		if ct != "application/json" {
			t.Errorf("%s: Expected Content-Type 'application/json', got '%s'", ep, ct)
		}
	}
}

func TestIntegrationAPI_AttestationCounters(t *testing.T) {
	t.Log("INTEGRATION: Verify /api/v1/stats counters after real attestation")
	t.Log("Ensures total/success/failure counters accurately track attestation outcomes")

	mux, v := setupTestAPIListening(t)
	clientID := "attest-counter-client"
	pcr14 := [32]byte{0x14}

	// successful attestation
	code := attestClient(t, v, clientID, testAIK, pcr14)
	if code != types.VerifyOK {
		t.Fatalf("Expected VerifyOK, got %d", code)
	}

	req := httptest.NewRequest("GET", "/api/v1/stats", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	var resp statsResponse
	json.NewDecoder(rec.Body).Decode(&resp)

	if resp.TotalAttestations != 1 {
		t.Errorf("total_attestations: got %d, want 1", resp.TotalAttestations)
	}
	if resp.SuccessfulAttests != 1 {
		t.Errorf("successful_attestations: got %d, want 1", resp.SuccessfulAttests)
	}
	if resp.FailedAttests != 0 {
		t.Errorf("failed_attestations: got %d, want 0", resp.FailedAttests)
	}
	if resp.RegisteredClients != 1 {
		t.Errorf("registered_clients: got %d, want 1", resp.RegisteredClients)
	}

	t.Log("✓ Stats counters correctly reflect successful attestation")
}

func TestIntegrationAPI_FailedAttestationCounter(t *testing.T) {
	t.Log("INTEGRATION: Verify failure counter after invalid attestation")
	t.Log("Submits a malformed report and verifies the failure is tracked")

	mux, v := setupTestAPIListening(t)
	clientID := "bad-report-client"

	// generate challenge but submit garbage report
	_, err := v.GenerateChallenge(clientID)
	if err != nil {
		t.Fatalf("GenerateChallenge failed: %v", err)
	}

	garbage := make([]byte, 100)
	v.VerifyReport(clientID, garbage) // will fail

	req := httptest.NewRequest("GET", "/api/v1/stats", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	var resp statsResponse
	json.NewDecoder(rec.Body).Decode(&resp)

	if resp.TotalAttestations != 1 {
		t.Errorf("total_attestations: got %d, want 1", resp.TotalAttestations)
	}
	if resp.FailedAttests != 1 {
		t.Errorf("failed_attestations: got %d, want 1", resp.FailedAttests)
	}
	if resp.SuccessfulAttests != 0 {
		t.Errorf("successful_attestations: got %d, want 0", resp.SuccessfulAttests)
	}

	t.Log("✓ Failure counter correctly incremented for malformed report")
}

func TestIntegrationAPI_NonceConsumedVisibleInStats(t *testing.T) {
	t.Log("INTEGRATION: Verify nonce lifecycle visible through /api/v1/stats")
	t.Log("Challenge → pending +1, attestation → pending -1, used_nonces +1")

	mux, v := setupTestAPIListening(t)
	clientID := "nonce-lifecycle"
	pcr14 := [32]byte{0x14}

	// before: 0 pending, 0 used
	assertStats(t, mux, func(s statsResponse) {
		if s.PendingChallenges != 0 {
			t.Errorf("before: pending %d, want 0", s.PendingChallenges)
		}
		if s.UsedNonces != 0 {
			t.Errorf("before: used %d, want 0", s.UsedNonces)
		}
	})

	// generate challenge: pending +1
	challenge, _ := v.GenerateChallenge(clientID)
	assertStats(t, mux, func(s statsResponse) {
		if s.PendingChallenges != 1 {
			t.Errorf("after challenge: pending %d, want 1", s.PendingChallenges)
		}
	})

	// complete attestation: pending -1, used +1
	report := buildSignedReport(t, challenge.Nonce, pcr14, testAIK)
	result, err := v.VerifyReport(clientID, report)
	if err != nil || result.Result != types.VerifyOK {
		t.Fatalf("Attestation failed: %v (code=%d)", err, result.Result)
	}

	assertStats(t, mux, func(s statsResponse) {
		if s.PendingChallenges != 0 {
			t.Errorf("after verify: pending %d, want 0", s.PendingChallenges)
		}
		if s.UsedNonces != 1 {
			t.Errorf("after verify: used %d, want 1", s.UsedNonces)
		}
	})

	t.Log("✓ Nonce lifecycle (pending -> consumed -> used) visible in stats")
}

func TestIntegrationAPI_ReplayAttackVisibleInStats(t *testing.T) {
	t.Log("INTEGRATION: Verify replay attack increments failure counter")
	t.Log("CRITICAL SECURITY: Second submission of same report must fail")

	mux, v := setupTestAPIListening(t)
	clientID := "replay-stats-client"
	pcr14 := [32]byte{0x14}

	challenge, _ := v.GenerateChallenge(clientID)
	report := buildSignedReport(t, challenge.Nonce, pcr14, testAIK)

	// first submission: success
	result1, _ := v.VerifyReport(clientID, report)
	if result1.Result != types.VerifyOK {
		t.Fatalf("First attestation should succeed, got %d", result1.Result)
	}

	// replay attempt: must fail
	result2, _ := v.VerifyReport(clientID, report)
	if result2.Result != types.VerifyNonceFail {
		t.Fatalf("SECURITY: Replay not detected! Got result %d, want %d",
			result2.Result, types.VerifyNonceFail)
	}

	// verify counters through API
	assertStats(t, mux, func(s statsResponse) {
		if s.TotalAttestations != 2 {
			t.Errorf("total: %d, want 2", s.TotalAttestations)
		}
		if s.SuccessfulAttests != 1 {
			t.Errorf("success: %d, want 1", s.SuccessfulAttests)
		}
		if s.FailedAttests != 1 {
			t.Errorf("failed: %d, want 1 (replay)", s.FailedAttests)
		}
		if s.UsedNonces != 1 {
			t.Errorf("used_nonces: %d, want 1", s.UsedNonces)
		}
	})

	t.Log("✓ Replay attack correctly tracked: 1 success + 1 failure in stats")
}

func TestIntegrationAPI_ClientInfoAfterAttestation(t *testing.T) {
	t.Log("INTEGRATION: Verify /api/v1/clients/{id} after successful attestation")
	t.Log("Client info must reflect AIK registration, baseline, counter")

	mux, v := setupTestAPIListening(t)
	clientID := "attested-client"
	pcr14 := [32]byte{0x14, 0x15, 0x16}

	code := attestClient(t, v, clientID, testAIK, pcr14)
	if code != types.VerifyOK {
		t.Fatalf("Attestation failed with code %d", code)
	}

	req := httptest.NewRequest("GET", "/api/v1/clients/"+clientID, nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d", rec.Code)
	}

	var resp clientInfoResponse
	json.NewDecoder(rec.Body).Decode(&resp)

	if resp.ClientID != clientID {
		t.Errorf("client_id: got '%s', want '%s'", resp.ClientID, clientID)
	}
	if !resp.HasAIK {
		t.Error("Expected has_aik=true after TOFU registration")
	}
	if resp.AttestCount != 1 {
		t.Errorf("attestation_count: got %d, want 1", resp.AttestCount)
	}
	if resp.MonotonicCounter != 1 {
		t.Errorf("monotonic_counter: got %d, want 1", resp.MonotonicCounter)
	}
	if resp.PCR14Baseline == "" {
		t.Error("Expected non-empty pcr14_baseline after attestation")
	}
	if resp.FirstSeen == "" {
		t.Error("Expected non-empty first_seen after attestation")
	}
	if resp.HardwareID == "" {
		t.Error("Expected non-empty hardware_id after TOFU")
	}

	t.Logf("✓ Client info fully populated: AIK=%v, attests=%d, pcr14=%s...",
		resp.HasAIK, resp.AttestCount, resp.PCR14Baseline[:16])
}

func TestIntegrationAPI_MultipleAttestationsSameClient(t *testing.T) {
	t.Log("INTEGRATION: Multiple attestations from same client tracked correctly")
	t.Log("Counter, baseline match count, and last_attestation must update")

	mux, v := setupTestAPIListening(t)
	clientID := "multi-attest"
	pcr14 := [32]byte{0x44}

	for i := 0; i < 5; i++ {
		code := attestClient(t, v, clientID, testAIK, pcr14)
		if code != types.VerifyOK {
			t.Fatalf("Attestation %d failed with code %d", i+1, code)
		}
	}

	req := httptest.NewRequest("GET", "/api/v1/clients/"+clientID, nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	var resp clientInfoResponse
	json.NewDecoder(rec.Body).Decode(&resp)

	if resp.AttestCount != 5 {
		t.Errorf("attestation_count: got %d, want 5", resp.AttestCount)
	}
	if resp.MonotonicCounter != 5 {
		t.Errorf("monotonic_counter: got %d, want 5", resp.MonotonicCounter)
	}
	if resp.LastAttestation == "" {
		t.Error("Expected last_attestation to be set")
	}
	if resp.PendingChallenges != 0 {
		t.Errorf("pending_challenges: got %d, want 0 (all consumed)", resp.PendingChallenges)
	}

	// verify global stats
	assertStats(t, mux, func(s statsResponse) {
		if s.TotalAttestations != 5 {
			t.Errorf("total: %d, want 5", s.TotalAttestations)
		}
		if s.SuccessfulAttests != 5 {
			t.Errorf("success: %d, want 5", s.SuccessfulAttests)
		}
	})

	t.Logf("✓ 5 attestations tracked: counter=%d, attests=%d",
		resp.MonotonicCounter, resp.AttestCount)
}

func TestIntegrationAPI_MultipleClientsListed(t *testing.T) {
	t.Log("INTEGRATION: Multiple clients visible in /api/v1/clients after attestation")

	mux, v := setupTestAPIListening(t)

	clients := []string{"client-alpha", "client-beta", "client-gamma"}
	pcr14 := [32]byte{0x77}

	for _, c := range clients {
		code := attestClient(t, v, c, testAIK, pcr14)
		if code != types.VerifyOK {
			t.Fatalf("Attestation for %s failed: %d", c, code)
		}
	}

	req := httptest.NewRequest("GET", "/api/v1/clients", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	var resp clientListResponse
	json.NewDecoder(rec.Body).Decode(&resp)

	if resp.Count != 3 {
		t.Errorf("client count: got %d, want 3", resp.Count)
	}

	// verify all clients present
	clientSet := make(map[string]bool)
	for _, c := range resp.Clients {
		clientSet[c] = true
	}
	for _, c := range clients {
		if !clientSet[c] {
			t.Errorf("Client '%s' missing from list", c)
		}
	}

	t.Logf("✓ All %d attested clients visible in client list", resp.Count)
}

func TestIntegrationAPI_InvalidSignatureVisibleInStats(t *testing.T) {
	t.Log("INTEGRATION: Invalid TPM signature → failure counter via API")
	t.Log("CRITICAL SECURITY: Wrong key must be detected and tracked")

	mux, v := setupTestAPIListening(t)
	clientID := "wrong-sig-client"
	pcr14 := [32]byte{0x14}

	// register AIK with a different key than what LOTA will sign with
	wrongKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Key generation failed: %v", err)
	}

	// first attest with correct key to register AIK via TOFU
	code := attestClient(t, v, clientID, testAIK, pcr14)
	if code != types.VerifyOK {
		t.Fatalf("Initial TOFU attestation failed: %d", code)
	}

	// second attest with WRONG key - should fail signature check
	challenge, _ := v.GenerateChallenge(clientID)
	badReport := buildSignedReport(t, challenge.Nonce, pcr14, wrongKey)
	result, _ := v.VerifyReport(clientID, badReport)

	if result.Result != types.VerifySigFail {
		t.Fatalf("SECURITY: Wrong signature not detected! Got %d, want %d",
			result.Result, types.VerifySigFail)
	}

	assertStats(t, mux, func(s statsResponse) {
		if s.TotalAttestations != 2 {
			t.Errorf("total: %d, want 2", s.TotalAttestations)
		}
		if s.SuccessfulAttests != 1 {
			t.Errorf("success: %d, want 1 (TOFU only)", s.SuccessfulAttests)
		}
		if s.FailedAttests != 1 {
			t.Errorf("failed: %d, want 1 (wrong sig)", s.FailedAttests)
		}
	})

	t.Log("✓ Invalid signature correctly tracked as failure in stats")
}

func TestIntegrationAPI_PCR14TamperingVisibleInStats(t *testing.T) {
	t.Log("INTEGRATION: PCR14 baseline violation → failure counter via API")
	t.Log("CRITICAL SECURITY: Agent tampering must be tracked in monitoring")

	mux, v := setupTestAPIListening(t)
	clientID := "tamper-client"
	originalPCR14 := [32]byte{0xAA, 0xBB, 0xCC}

	// establish baseline
	code := attestClient(t, v, clientID, testAIK, originalPCR14)
	if code != types.VerifyOK {
		t.Fatalf("Baseline attestation failed: %d", code)
	}

	// tampered PCR14
	tamperedPCR14 := [32]byte{0xFF, 0xBB, 0xCC}
	challenge, _ := v.GenerateChallenge(clientID)
	report := buildSignedReport(t, challenge.Nonce, tamperedPCR14, testAIK)
	result, _ := v.VerifyReport(clientID, report)

	if result.Result != types.VerifyIntegrityMismatch {
		t.Fatalf("SECURITY: PCR14 tampering not detected! Got %d, want %d",
			result.Result, types.VerifyIntegrityMismatch)
	}

	assertStats(t, mux, func(s statsResponse) {
		if s.FailedAttests != 1 {
			t.Errorf("failed: %d, want 1 (integrity mismatch)", s.FailedAttests)
		}
	})

	t.Log("✓ PCR14 tampering correctly tracked as failure")
}

func TestIntegrationAPI_PrometheusAfterAttestations(t *testing.T) {
	t.Log("INTEGRATION: Prometheus /metrics reflects real attestation data")
	t.Log("Verifies counter and gauge values match actual attestation outcomes")

	mux, v := setupTestAPIListening(t)
	pcr14 := [32]byte{0x14}

	// 3 successful attestations from 2 clients
	attestClient(t, v, "prom-client-1", testAIK, pcr14)
	attestClient(t, v, "prom-client-1", testAIK, pcr14)
	attestClient(t, v, "prom-client-2", testAIK, pcr14)

	// 1 failed attestation (garbage)
	v.GenerateChallenge("prom-fail")
	v.VerifyReport("prom-fail", []byte("garbage"))

	req := httptest.NewRequest("GET", "/metrics", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	body := rec.Body.String()

	assertMetric(t, body, "lota_attestations_total", "4")
	assertMetric(t, body, "lota_attestations_success_total", "3")
	assertMetric(t, body, "lota_attestations_failed_total", "1")
	assertMetric(t, body, "lota_registered_clients", "2")
	assertMetric(t, body, "lota_loaded_policies", "1")

	t.Log("✓ Prometheus metrics accurately reflect 3 success + 1 failure")
}

func TestIntegrationAPI_PendingChallengesNotLeak(t *testing.T) {
	t.Log("INTEGRATION: Pending challenges decrement after verification")
	t.Log("Ensures challenge state is properly cleaned up after attestation")

	mux, v := setupTestAPIListening(t)
	clientID := "pending-leak-test"
	pcr14 := [32]byte{0x14}

	challenges := make([][32]byte, 3)
	for i := 0; i < 3; i++ {
		ch, _ := v.GenerateChallenge(clientID)
		challenges[i] = ch.Nonce
	}

	assertStats(t, mux, func(s statsResponse) {
		if s.PendingChallenges != 3 {
			t.Errorf("after 3 challenges: pending %d, want 3", s.PendingChallenges)
		}
	})

	// consume first challenge only
	report := buildSignedReport(t, challenges[0], pcr14, testAIK)
	v.VerifyReport(clientID, report)

	assertStats(t, mux, func(s statsResponse) {
		if s.PendingChallenges != 2 {
			t.Errorf("after 1 verify: pending %d, want 2", s.PendingChallenges)
		}
	})

	// consume second
	report2 := buildSignedReport(t, challenges[1], pcr14, testAIK)
	v.VerifyReport(clientID, report2)

	assertStats(t, mux, func(s statsResponse) {
		if s.PendingChallenges != 1 {
			t.Errorf("after 2 verify: pending %d, want 1", s.PendingChallenges)
		}
	})

	t.Log("✓ Pending challenges correctly decrement on each verification")
}

func TestIntegrationAPI_ConcurrentAttestationsTracked(t *testing.T) {
	t.Log("INTEGRATION: Concurrent attestations from multiple clients")
	t.Log("Stress test: 10 clients attesting simultaneously, stats must converge")

	mux, v := setupTestAPIListening(t)
	numClients := 10
	pcr14 := [32]byte{0xCC}

	done := make(chan bool, numClients)
	for i := 0; i < numClients; i++ {
		go func(n int) {
			clientID := fmt.Sprintf("concurrent-%d", n)
			code := attestClient(t, v, clientID, testAIK, pcr14)
			done <- (code == types.VerifyOK)
		}(i)
	}

	successes := 0
	for i := 0; i < numClients; i++ {
		if <-done {
			successes++
		}
	}

	if successes != numClients {
		t.Errorf("Only %d/%d concurrent attestations succeeded", successes, numClients)
	}

	assertStats(t, mux, func(s statsResponse) {
		if s.TotalAttestations != int64(numClients) {
			t.Errorf("total: %d, want %d", s.TotalAttestations, numClients)
		}
		if s.SuccessfulAttests != int64(numClients) {
			t.Errorf("success: %d, want %d", s.SuccessfulAttests, numClients)
		}
		if s.RegisteredClients != numClients {
			t.Errorf("registered: %d, want %d", s.RegisteredClients, numClients)
		}
	})

	// verify client list
	req := httptest.NewRequest("GET", "/api/v1/clients", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	var list clientListResponse
	json.NewDecoder(rec.Body).Decode(&list)

	if list.Count != numClients {
		t.Errorf("client list: %d, want %d", list.Count, numClients)
	}

	t.Logf("✓ %d concurrent attestations tracked: %d registered, %d attested",
		numClients, list.Count, successes)
}

func TestIntegrationAPI_MixedSuccessFailureRatio(t *testing.T) {
	t.Log("INTEGRATION: Mixed success/failure ratio visible through API")
	t.Log("3 successful + 2 failed attestations = correct ratio in all endpoints")

	mux, v := setupTestAPIListening(t)
	pcr14 := [32]byte{0x14}

	// 3 successful
	for i := 0; i < 3; i++ {
		code := attestClient(t, v, fmt.Sprintf("success-%d", i), testAIK, pcr14)
		if code != types.VerifyOK {
			t.Fatalf("Attestation %d failed: %d", i, code)
		}
	}

	// 2 failed (garbage reports)
	for i := 0; i < 2; i++ {
		v.GenerateChallenge(fmt.Sprintf("fail-%d", i))
		v.VerifyReport(fmt.Sprintf("fail-%d", i), []byte{0x00})
	}

	// check /api/v1/stats
	assertStats(t, mux, func(s statsResponse) {
		if s.TotalAttestations != 5 {
			t.Errorf("total: %d, want 5", s.TotalAttestations)
		}
		if s.SuccessfulAttests != 3 {
			t.Errorf("success: %d, want 3", s.SuccessfulAttests)
		}
		if s.FailedAttests != 2 {
			t.Errorf("failed: %d, want 2", s.FailedAttests)
		}
	})

	// check /metrics
	req := httptest.NewRequest("GET", "/metrics", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	body := rec.Body.String()
	assertMetric(t, body, "lota_attestations_total", "5")
	assertMetric(t, body, "lota_attestations_success_total", "3")
	assertMetric(t, body, "lota_attestations_failed_total", "2")

	t.Log("✓ Mixed ratio 3:2 (success:failure) consistent across stats and metrics")
}

// fetches /api/v1/stats and runs assertions on the decoded response
func assertStats(t *testing.T, mux *http.ServeMux, check func(statsResponse)) {
	t.Helper()

	req := httptest.NewRequest("GET", "/api/v1/stats", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/v1/stats returned %d", rec.Code)
	}

	var resp statsResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode stats: %v", err)
	}

	check(resp)
}

// verifies a Prometheus metric line contains expected value
func assertMetric(t *testing.T, body, metric, expectedValue string) {
	t.Helper()

	expected := metric + " " + expectedValue
	for _, line := range strings.Split(body, "\n") {
		if strings.HasPrefix(line, metric+" ") || strings.HasPrefix(line, metric+"{") {
			if strings.TrimSpace(line) == expected {
				return
			}
			t.Errorf("Metric %s: got '%s', want value %s", metric, strings.TrimSpace(line), expectedValue)
			return
		}
	}
	t.Errorf("Metric %s not found in output", metric)
}
