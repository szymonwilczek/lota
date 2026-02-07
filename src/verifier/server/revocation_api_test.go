// SPDX-License-Identifier: MIT
// LOTA Verifier - Revocation & Ban API Integration Tests
//
// Tests the REST endpoints for revocation management, hardware banning,
// and audit log query through the HTTP monitoring API.

package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/szymonwilczek/lota/verifier/types"
)

func TestAPI_RevokeClient(t *testing.T) {
	t.Log("TEST: POST /api/v1/clients/{id}/revoke")

	mux, _ := setupTestAPIListening(t)

	body := `{"reason":"cheating","actor":"admin@test","note":"caught using aimbot"}`
	req := httptest.NewRequest("POST", "/api/v1/clients/test-client/revoke",
		strings.NewReader(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("Expected 201, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp map[string]string
	json.NewDecoder(rec.Body).Decode(&resp)
	if resp["status"] != "revoked" {
		t.Errorf("Expected status 'revoked', got %q", resp["status"])
	}
	if resp["client_id"] != "test-client" {
		t.Errorf("Expected client_id 'test-client', got %q", resp["client_id"])
	}
}

func TestAPI_RevokeAlreadyRevoked(t *testing.T) {
	t.Log("TEST: Duplicate revocation returns 409 Conflict")

	mux, _ := setupTestAPIListening(t)

	body := `{"reason":"cheating","actor":"admin"}`

	// first revocation
	req := httptest.NewRequest("POST", "/api/v1/clients/dup-client/revoke",
		strings.NewReader(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("First revoke failed: %d", rec.Code)
	}

	// second revocation - should conflict
	req = httptest.NewRequest("POST", "/api/v1/clients/dup-client/revoke",
		strings.NewReader(body))
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("Expected 409 Conflict, got %d", rec.Code)
	}
}

func TestAPI_RevokeInvalidReason(t *testing.T) {
	t.Log("TEST: Invalid revocation reason returns 400")

	mux, _ := setupTestAPIListening(t)

	body := `{"reason":"hacking","actor":"admin"}`
	req := httptest.NewRequest("POST", "/api/v1/clients/bad-reason/revoke",
		strings.NewReader(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("Expected 400, got %d", rec.Code)
	}
}

func TestAPI_RevokeMissingActor(t *testing.T) {
	t.Log("TEST: Missing actor returns 400")

	mux, _ := setupTestAPIListening(t)

	body := `{"reason":"cheating"}`
	req := httptest.NewRequest("POST", "/api/v1/clients/no-actor/revoke",
		strings.NewReader(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("Expected 400, got %d", rec.Code)
	}
}

func TestAPI_UnrevokeClient(t *testing.T) {
	t.Log("TEST: DELETE /api/v1/clients/{id}/revoke")

	mux, _ := setupTestAPIListening(t)

	// first revoke
	body := `{"reason":"admin","actor":"admin"}`
	req := httptest.NewRequest("POST", "/api/v1/clients/unrevoke-target/revoke",
		strings.NewReader(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("Revoke failed: %d", rec.Code)
	}

	// then unrevoke
	req = httptest.NewRequest("DELETE", "/api/v1/clients/unrevoke-target/revoke", nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp map[string]string
	json.NewDecoder(rec.Body).Decode(&resp)
	if resp["status"] != "unrevoked" {
		t.Errorf("Expected status 'unrevoked', got %q", resp["status"])
	}
}

func TestAPI_UnrevokeNotRevoked(t *testing.T) {
	t.Log("TEST: Unrevoke of non-revoked client returns 404")

	mux, _ := setupTestAPIListening(t)

	req := httptest.NewRequest("DELETE", "/api/v1/clients/never-revoked/revoke", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("Expected 404, got %d", rec.Code)
	}
}

func TestAPI_ListRevocations(t *testing.T) {
	t.Log("TEST: GET /api/v1/revocations")

	mux, _ := setupTestAPIListening(t)

	// revoke two clients
	for _, id := range []string{"rev-1", "rev-2"} {
		body := fmt.Sprintf(`{"reason":"cheating","actor":"admin","note":"test %s"}`, id)
		req := httptest.NewRequest("POST", "/api/v1/clients/"+id+"/revoke",
			strings.NewReader(body))
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusCreated {
			t.Fatalf("Revoke %s failed: %d", id, rec.Code)
		}
	}

	// list revocations
	req := httptest.NewRequest("GET", "/api/v1/revocations", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d", rec.Code)
	}

	var resp struct {
		Revocations []revocationResponse `json:"revocations"`
		Count       int                  `json:"count"`
	}
	json.NewDecoder(rec.Body).Decode(&resp)

	if resp.Count != 2 {
		t.Errorf("Expected 2 revocations, got %d", resp.Count)
	}
}

func TestAPI_BanHardware(t *testing.T) {
	t.Log("TEST: POST /api/v1/bans")

	mux, _ := setupTestAPIListening(t)

	hwidHex := "deadbeef0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c"
	body := fmt.Sprintf(`{"hardware_id":"%s","reason":"cheating","actor":"admin","note":"banned hardware"}`, hwidHex)
	req := httptest.NewRequest("POST", "/api/v1/bans", strings.NewReader(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("Expected 201, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp map[string]string
	json.NewDecoder(rec.Body).Decode(&resp)
	if resp["status"] != "banned" {
		t.Errorf("Expected status 'banned', got %q", resp["status"])
	}
}

func TestAPI_BanAlreadyBanned(t *testing.T) {
	t.Log("TEST: Duplicate ban returns 409")

	mux, _ := setupTestAPIListening(t)

	hwidHex := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	body := fmt.Sprintf(`{"hardware_id":"%s","reason":"cheating","actor":"admin"}`, hwidHex)

	// first ban
	req := httptest.NewRequest("POST", "/api/v1/bans", strings.NewReader(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("First ban failed: %d", rec.Code)
	}

	// duplicate ban
	req = httptest.NewRequest("POST", "/api/v1/bans", strings.NewReader(body))
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("Expected 409, got %d", rec.Code)
	}
}

func TestAPI_BanInvalidHardwareID(t *testing.T) {
	t.Log("TEST: Invalid hardware_id returns 400")

	mux, _ := setupTestAPIListening(t)

	tests := []struct {
		name string
		hwid string
	}{
		{"too short", "deadbeef"},
		{"invalid hex", "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			body := fmt.Sprintf(`{"hardware_id":"%s","reason":"cheating","actor":"admin"}`, tc.hwid)
			req := httptest.NewRequest("POST", "/api/v1/bans", strings.NewReader(body))
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)

			if rec.Code != http.StatusBadRequest {
				t.Errorf("Expected 400, got %d", rec.Code)
			}
		})
	}
}

func TestAPI_UnbanHardware(t *testing.T) {
	t.Log("TEST: DELETE /api/v1/bans/{hwid}")

	mux, _ := setupTestAPIListening(t)

	hwidHex := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	body := fmt.Sprintf(`{"hardware_id":"%s","reason":"admin","actor":"admin"}`, hwidHex)

	// ban first
	req := httptest.NewRequest("POST", "/api/v1/bans", strings.NewReader(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("Ban failed: %d", rec.Code)
	}

	// unban
	req = httptest.NewRequest("DELETE", "/api/v1/bans/"+hwidHex, nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestAPI_UnbanNotBanned(t *testing.T) {
	t.Log("TEST: Unban non-banned hardware returns 404")

	mux, _ := setupTestAPIListening(t)

	hwidHex := "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	req := httptest.NewRequest("DELETE", "/api/v1/bans/"+hwidHex, nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("Expected 404, got %d", rec.Code)
	}
}

func TestAPI_ListBans(t *testing.T) {
	t.Log("TEST: GET /api/v1/bans")

	mux, _ := setupTestAPIListening(t)

	hwids := []string{
		"1111111111111111111111111111111111111111111111111111111111111111",
		"2222222222222222222222222222222222222222222222222222222222222222",
	}

	for _, hwid := range hwids {
		body := fmt.Sprintf(`{"hardware_id":"%s","reason":"cheating","actor":"admin"}`, hwid)
		req := httptest.NewRequest("POST", "/api/v1/bans", strings.NewReader(body))
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusCreated {
			t.Fatalf("Ban %s failed: %d", hwid[:8], rec.Code)
		}
	}

	req := httptest.NewRequest("GET", "/api/v1/bans", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d", rec.Code)
	}

	var resp struct {
		Bans  []banResponse `json:"bans"`
		Count int           `json:"count"`
	}
	json.NewDecoder(rec.Body).Decode(&resp)

	if resp.Count != 2 {
		t.Errorf("Expected 2 bans, got %d", resp.Count)
	}
}

func TestAPI_AuditLog(t *testing.T) {
	t.Log("TEST: GET /api/v1/audit")

	mux, _ := setupTestAPIListening(t)

	// generate some audit entries via revoke/ban actions
	body := `{"reason":"cheating","actor":"audit-test-admin","note":"audit test"}`
	req := httptest.NewRequest("POST", "/api/v1/clients/audit-client/revoke",
		strings.NewReader(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("Revoke failed: %d", rec.Code)
	}

	// query audit log
	req = httptest.NewRequest("GET", "/api/v1/audit?limit=10", nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d", rec.Code)
	}

	var resp struct {
		Entries []auditResponse `json:"entries"`
		Count   int             `json:"count"`
	}
	json.NewDecoder(rec.Body).Decode(&resp)

	if resp.Count == 0 {
		t.Fatal("Expected non-empty audit log")
	}

	// latest entry should be the revoke
	found := false
	for _, e := range resp.Entries {
		if e.Action == "revoke" && e.TargetID == "audit-client" {
			found = true
			if e.Actor != "audit-test-admin" {
				t.Errorf("Actor: got %q, want %q", e.Actor, "audit-test-admin")
			}
		}
	}
	if !found {
		t.Error("Revoke action not found in audit log")
	}
}

func TestAPI_StatsIncludeRevocationCounters(t *testing.T) {
	t.Log("TEST: /api/v1/stats includes revocation and ban counters")

	mux, _ := setupTestAPIListening(t)

	// revoke a client
	body := `{"reason":"cheating","actor":"admin"}`
	req := httptest.NewRequest("POST", "/api/v1/clients/stats-revoked/revoke",
		strings.NewReader(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	// check stats
	req = httptest.NewRequest("GET", "/api/v1/stats", nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	var resp statsResponse
	json.NewDecoder(rec.Body).Decode(&resp)

	if resp.ActiveRevocations != 1 {
		t.Errorf("active_revocations: got %d, want 1", resp.ActiveRevocations)
	}
}

func TestIntegrationAPI_RevokedClientBlockedFromAttestation(t *testing.T) {
	t.Log("CRITICAL SECURITY TEST: Revoked client is rejected during attestation")
	t.Log("Revocation check occurs BEFORE nonce consumption")

	mux, v := setupTestAPIListening(t)
	clientID := "revoke-attest-client"
	pcr14 := [32]byte{0x14}

	// successful attestation first
	code := attestClient(t, v, clientID, testAIK, pcr14)
	if code != types.VerifyOK {
		t.Fatalf("Initial attestation failed: %d", code)
	}

	// revoke via API
	body := `{"reason":"cheating","actor":"game-server"}`
	req := httptest.NewRequest("POST", "/api/v1/clients/"+clientID+"/revoke",
		strings.NewReader(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("Revoke via API failed: %d", rec.Code)
	}

	// second attestation should be rejected
	code = attestClient(t, v, clientID, testAIK, pcr14)
	if code != types.VerifyRevoked {
		t.Fatalf("SECURITY: Revoked client was NOT rejected! Got code %d, want %d",
			code, types.VerifyRevoked)
	}

	// verify rejection is counted
	assertStats(t, mux, func(s statsResponse) {
		if s.RevokedAttests != 1 {
			t.Errorf("revoked_attestations: got %d, want 1", s.RevokedAttests)
		}
	})

	// client info should show revoked
	req = httptest.NewRequest("GET", "/api/v1/clients/"+clientID, nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	var info clientInfoResponse
	json.NewDecoder(rec.Body).Decode(&info)

	if !info.Revoked {
		t.Error("Expected client info to show revoked=true")
	}
	if info.RevocationReason != "cheating" {
		t.Errorf("Expected revocation_reason 'cheating', got %q", info.RevocationReason)
	}

	t.Log("✓ Revoked client correctly rejected from attestation")
}

func TestIntegrationAPI_UnrevokedClientCanAttest(t *testing.T) {
	t.Log("TEST: Client can attest after unrevoke")

	mux, v := setupTestAPIListening(t)
	clientID := "unrevoke-attest-client"
	pcr14 := [32]byte{0x14}

	// initial attestation
	code := attestClient(t, v, clientID, testAIK, pcr14)
	if code != types.VerifyOK {
		t.Fatalf("Initial attestation failed: %d", code)
	}

	// revoke
	body := `{"reason":"admin","actor":"admin"}`
	req := httptest.NewRequest("POST", "/api/v1/clients/"+clientID+"/revoke",
		strings.NewReader(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	// verify blocked
	code = attestClient(t, v, clientID, testAIK, pcr14)
	if code != types.VerifyRevoked {
		t.Fatalf("Expected VerifyRevoked, got %d", code)
	}

	// unrevoke
	req = httptest.NewRequest("DELETE", "/api/v1/clients/"+clientID+"/revoke", nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("Unrevoke failed: %d", rec.Code)
	}

	// should now succeed
	code = attestClient(t, v, clientID, testAIK, pcr14)
	if code != types.VerifyOK {
		t.Fatalf("Expected VerifyOK after unrevoke, got %d", code)
	}

	t.Log("✓ Client can attest again after unrevoke")
}

func TestIntegrationAPI_BannedHardwareBlocksAttestation(t *testing.T) {
	t.Log("CRITICAL SECURITY TEST: Banned hardware is rejected")
	t.Log("Hardware ban defeats re-registration under new client ID")

	mux, v := setupTestAPIListening(t)
	clientID := "ban-attest-client"
	pcr14 := [32]byte{0x14}

	// successful attestation first
	code := attestClient(t, v, clientID, testAIK, pcr14)
	if code != types.VerifyOK {
		t.Fatalf("Initial attestation failed: %d", code)
	}

	// get hardware ID from client info
	req := httptest.NewRequest("GET", "/api/v1/clients/"+clientID, nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	var info clientInfoResponse
	json.NewDecoder(rec.Body).Decode(&info)

	if info.HardwareID == "" {
		t.Fatal("No hardware ID registered after attestation")
	}

	// ban that hardware ID
	body := fmt.Sprintf(`{"hardware_id":"%s","reason":"cheating","actor":"game-server"}`, info.HardwareID)
	req = httptest.NewRequest("POST", "/api/v1/bans", strings.NewReader(body))
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("Ban via API failed: %d: %s", rec.Code, rec.Body.String())
	}

	// next attestation should be banned
	code = attestClient(t, v, clientID, testAIK, pcr14)
	if code != types.VerifyBanned {
		t.Fatalf("SECURITY: Banned hardware was NOT rejected! Got code %d, want %d",
			code, types.VerifyBanned)
	}

	// verify counted in stats
	assertStats(t, mux, func(s statsResponse) {
		if s.BannedAttests != 1 {
			t.Errorf("banned_attestations: got %d, want 1", s.BannedAttests)
		}
		if s.ActiveBans != 1 {
			t.Errorf("active_bans: got %d, want 1", s.ActiveBans)
		}
	})

	t.Log("✓ Banned hardware correctly rejected from attestation")
}

func TestIntegrationAPI_PrometheusRevocationMetrics(t *testing.T) {
	t.Log("TEST: Prometheus /metrics includes revocation/ban counters")

	mux, _ := setupTestAPIListening(t)

	req := httptest.NewRequest("GET", "/metrics", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	body := rec.Body.String()

	expectedMetrics := []string{
		"lota_rejections_total",
		"lota_active_revocations",
		"lota_active_bans",
	}

	for _, metric := range expectedMetrics {
		if !strings.Contains(body, metric) {
			t.Errorf("Missing Prometheus metric: %s", metric)
		}
	}

	t.Log("✓ All revocation/ban Prometheus metrics present")
}
