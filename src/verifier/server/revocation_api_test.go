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

const testAdminKey = "test-admin-key"

// creates a POST/DELETE request with admin auth header
func adminRequest(method, path string, body string) *http.Request {
	var req *http.Request
	if body != "" {
		req = httptest.NewRequest(method, path, strings.NewReader(body))
	} else {
		req = httptest.NewRequest(method, path, nil)
	}
	req.Header.Set("Authorization", "Bearer "+testAdminKey)
	return req
}

func TestAPI_RevokeClient(t *testing.T) {
	t.Log("TEST: POST /api/v1/clients/{id}/revoke")

	mux, _ := setupTestAPIListening(t)

	body := `{"reason":"cheating","actor":"admin@test","note":"caught using aimbot"}`
	req := adminRequest("POST", "/api/v1/clients/test-client/revoke", body)
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
	req := adminRequest("POST", "/api/v1/clients/dup-client/revoke", body)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("First revoke failed: %d", rec.Code)
	}

	// second revocation - should conflict
	req = adminRequest("POST", "/api/v1/clients/dup-client/revoke", body)
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
	req := adminRequest("POST", "/api/v1/clients/bad-reason/revoke", body)
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
	req := adminRequest("POST", "/api/v1/clients/no-actor/revoke", body)
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
	req := adminRequest("POST", "/api/v1/clients/unrevoke-target/revoke", body)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("Revoke failed: %d", rec.Code)
	}

	// then unrevoke
	req = adminRequest("DELETE", "/api/v1/clients/unrevoke-target/revoke", "")
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

	req := adminRequest("DELETE", "/api/v1/clients/never-revoked/revoke", "")
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
		req := adminRequest("POST", "/api/v1/clients/"+id+"/revoke", body)
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
	req := adminRequest("POST", "/api/v1/bans", body)
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
	req := adminRequest("POST", "/api/v1/bans", body)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("First ban failed: %d", rec.Code)
	}

	// duplicate ban
	req = adminRequest("POST", "/api/v1/bans", body)
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
			req := adminRequest("POST", "/api/v1/bans", body)
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
	req := adminRequest("POST", "/api/v1/bans", body)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("Ban failed: %d", rec.Code)
	}

	// unban
	req = adminRequest("DELETE", "/api/v1/bans/"+hwidHex, "")
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
	req := adminRequest("DELETE", "/api/v1/bans/"+hwidHex, "")
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
		req := adminRequest("POST", "/api/v1/bans", body)
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
	req := adminRequest("POST", "/api/v1/clients/audit-client/revoke", body)
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
	req := adminRequest("POST", "/api/v1/clients/stats-revoked/revoke", body)
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
	persistentID := persistentClientID(clientID)
	pcr14 := [32]byte{0x14}

	// successful attestation first
	code := attestClient(t, v, clientID, testAIK, pcr14)
	if code != types.VerifyOK {
		t.Fatalf("Initial attestation failed: %d", code)
	}

	// revoke via API
	body := `{"reason":"cheating","actor":"game-server"}`
	req := adminRequest("POST", "/api/v1/clients/"+persistentID+"/revoke", body)
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
	req = httptest.NewRequest("GET", "/api/v1/clients/"+persistentID, nil)
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
	persistentID := persistentClientID(clientID)
	pcr14 := [32]byte{0x14}

	// initial attestation
	code := attestClient(t, v, clientID, testAIK, pcr14)
	if code != types.VerifyOK {
		t.Fatalf("Initial attestation failed: %d", code)
	}

	// revoke
	body := `{"reason":"admin","actor":"admin"}`
	req := adminRequest("POST", "/api/v1/clients/"+persistentID+"/revoke", body)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	// verify blocked
	code = attestClient(t, v, clientID, testAIK, pcr14)
	if code != types.VerifyRevoked {
		t.Fatalf("Expected VerifyRevoked, got %d", code)
	}

	// unrevoke
	req = adminRequest("DELETE", "/api/v1/clients/"+persistentID+"/revoke", "")
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
	persistentID := persistentClientID(clientID)
	pcr14 := [32]byte{0x14}

	// successful attestation first
	code := attestClient(t, v, clientID, testAIK, pcr14)
	if code != types.VerifyOK {
		t.Fatalf("Initial attestation failed: %d", code)
	}

	// get hardware ID from client info
	req := httptest.NewRequest("GET", "/api/v1/clients/"+persistentID, nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	var info clientInfoResponse
	json.NewDecoder(rec.Body).Decode(&info)

	if info.HardwareID == "" {
		t.Fatal("No hardware ID registered after attestation")
	}

	// ban that hardware ID
	body := fmt.Sprintf(`{"hardware_id":"%s","reason":"cheating","actor":"game-server"}`, info.HardwareID)
	req = adminRequest("POST", "/api/v1/bans", body)
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

func TestAuth_MissingTokenReturns401(t *testing.T) {
	t.Log("SECURITY TEST: Mutating endpoint without Authorization header returns 401")

	mux, _ := setupTestAPIListening(t)

	endpoints := []struct {
		method string
		path   string
		body   string
	}{
		{"POST", "/api/v1/clients/victim/revoke", `{"reason":"cheating","actor":"attacker"}`},
		{"DELETE", "/api/v1/clients/victim/revoke", ""},
		{"POST", "/api/v1/bans", `{"hardware_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","reason":"cheating","actor":"attacker"}`},
		{"DELETE", "/api/v1/bans/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ""},
	}

	for _, ep := range endpoints {
		t.Run(ep.method+" "+ep.path, func(t *testing.T) {
			var req *http.Request
			if ep.body != "" {
				req = httptest.NewRequest(ep.method, ep.path, strings.NewReader(ep.body))
			} else {
				req = httptest.NewRequest(ep.method, ep.path, nil)
			}
			// NO Authorization header
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)

			if rec.Code != http.StatusUnauthorized {
				t.Errorf("Expected 401 Unauthorized, got %d", rec.Code)
			}

			// must include WWW-Authenticate header per RFC 7235
			wwwAuth := rec.Header().Get("WWW-Authenticate")
			if wwwAuth == "" {
				t.Error("Missing WWW-Authenticate header in 401 response")
			}

			var resp errorResponse
			json.NewDecoder(rec.Body).Decode(&resp)
			if resp.Error != "missing Authorization header" {
				t.Errorf("Unexpected error message: %q", resp.Error)
			}
		})
	}

	t.Log("✓ All mutating endpoints reject requests without token")
}

func TestAuth_WrongTokenReturns403(t *testing.T) {
	t.Log("SECURITY TEST: Wrong API key returns 403 Forbidden")

	mux, _ := setupTestAPIListening(t)

	body := `{"reason":"cheating","actor":"attacker"}`
	req := httptest.NewRequest("POST", "/api/v1/clients/victim/revoke",
		strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer wrong-key-attempt")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("Expected 403, got %d", rec.Code)
	}

	var resp errorResponse
	json.NewDecoder(rec.Body).Decode(&resp)
	if resp.Error != "invalid API key" {
		t.Errorf("Unexpected error message: %q", resp.Error)
	}

	t.Log("✓ Wrong API key correctly rejected")
}

func TestAuth_NoKeyConfiguredReturns403(t *testing.T) {
	t.Log("SECURITY TEST: Admin endpoints disabled when no key is configured")

	mux, _ := setupTestAPIListeningWithKey(t, "") // no key configured

	body := `{"reason":"cheating","actor":"admin"}`
	req := httptest.NewRequest("POST", "/api/v1/clients/victim/revoke",
		strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer anything")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("Expected 403, got %d", rec.Code)
	}

	var resp errorResponse
	json.NewDecoder(rec.Body).Decode(&resp)
	if resp.Error != "admin API key not configured" {
		t.Errorf("Unexpected error message: %q", resp.Error)
	}

	t.Log("✓ Admin endpoints correctly disabled without key")
}

func TestAuth_ReadOnlyEndpointsNoAuthRequired(t *testing.T) {
	t.Log("TEST: Public endpoints work without any authentication")
	t.Log("Public endpoints: health, stats, metrics (no secrets exposed)")

	mux, _ := setupTestAPIListeningWithKey(t, "secret-key")

	publicEndpoints := []string{
		"/health",
		"/api/v1/stats",
		"/metrics",
	}

	for _, ep := range publicEndpoints {
		t.Run("GET "+ep, func(t *testing.T) {
			req := httptest.NewRequest("GET", ep, nil)
			// NO Authorization header
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)

			if rec.Code == http.StatusUnauthorized || rec.Code == http.StatusForbidden {
				t.Errorf("Public endpoint %s should not require auth, got %d", ep, rec.Code)
			}
		})
	}

	t.Log("✓ All public endpoints accessible without auth")
}

func TestAuth_ValidTokenAllowsMutation(t *testing.T) {
	t.Log("TEST: Valid Bearer token allows mutating operations")

	mux, _ := setupTestAPIListeningWithKey(t, "my-secret-admin-key")

	body := `{"reason":"admin","actor":"admin"}`
	req := httptest.NewRequest("POST", "/api/v1/clients/test-client/revoke",
		strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer my-secret-admin-key")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("Expected 201, got %d: %s", rec.Code, rec.Body.String())
	}

	t.Log("✓ Valid token grants access to admin endpoints")
}

func TestAuth_BearerPrefixCaseInsensitive(t *testing.T) {
	t.Log("TEST: Bearer prefix is case-insensitive per RFC 7235")

	mux, _ := setupTestAPIListeningWithKey(t, "case-test-key")

	prefixes := []string{"Bearer ", "bearer ", "BEARER "}
	for _, prefix := range prefixes {
		t.Run(prefix, func(t *testing.T) {
			body := `{"reason":"admin","actor":"admin"}`
			req := httptest.NewRequest("POST", "/api/v1/clients/test-client/revoke",
				strings.NewReader(body))
			req.Header.Set("Authorization", prefix+"case-test-key")
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)

			if rec.Code == http.StatusUnauthorized || rec.Code == http.StatusForbidden {
				t.Errorf("Bearer prefix %q should be accepted, got %d", prefix, rec.Code)
			}
		})
	}
}

func TestAuth_ReaderKeyRequiredForSensitiveEndpoints(t *testing.T) {
	t.Log("SECURITY TEST: Sensitive read-only endpoints require reader or admin key")

	mux, _ := setupTestAPIListeningWithKeys(t, "admin-key", "reader-key")

	sensitiveEndpoints := []string{
		"/api/v1/clients",
		"/api/v1/clients/some-id",
		"/api/v1/revocations",
		"/api/v1/bans",
		"/api/v1/audit",
		"/api/v1/attestations",
	}

	for _, ep := range sensitiveEndpoints {
		t.Run("GET "+ep+" no auth", func(t *testing.T) {
			req := httptest.NewRequest("GET", ep, nil)
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)

			if rec.Code != http.StatusUnauthorized {
				t.Errorf("Sensitive endpoint %s should return 401 without auth, got %d", ep, rec.Code)
			}
		})
	}

	t.Log("✓ All sensitive read-only endpoints reject unauthenticated requests")
}

func TestAuth_ReaderKeyGrantsReadAccess(t *testing.T) {
	t.Log("TEST: Reader API key grants access to sensitive read-only endpoints")

	mux, _ := setupTestAPIListeningWithKeys(t, "admin-key", "reader-key")

	sensitiveEndpoints := []string{
		"/api/v1/clients",
		"/api/v1/revocations",
		"/api/v1/bans",
		"/api/v1/audit",
		"/api/v1/attestations",
	}

	for _, ep := range sensitiveEndpoints {
		t.Run("GET "+ep+" reader key", func(t *testing.T) {
			req := httptest.NewRequest("GET", ep, nil)
			req.Header.Set("Authorization", "Bearer reader-key")
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)

			if rec.Code == http.StatusUnauthorized || rec.Code == http.StatusForbidden {
				t.Errorf("Reader key should grant access to %s, got %d", ep, rec.Code)
			}
		})
	}

	t.Log("✓ Reader key grants access to all sensitive read-only endpoints")
}

func TestAuth_AdminKeyGrantsReadAccess(t *testing.T) {
	t.Log("TEST: Admin API key also grants access to sensitive read-only endpoints")

	mux, _ := setupTestAPIListeningWithKeys(t, "admin-key", "reader-key")

	sensitiveEndpoints := []string{
		"/api/v1/clients",
		"/api/v1/revocations",
		"/api/v1/bans",
		"/api/v1/audit",
		"/api/v1/attestations",
	}

	for _, ep := range sensitiveEndpoints {
		t.Run("GET "+ep+" admin key", func(t *testing.T) {
			req := httptest.NewRequest("GET", ep, nil)
			req.Header.Set("Authorization", "Bearer admin-key")
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)

			if rec.Code == http.StatusUnauthorized || rec.Code == http.StatusForbidden {
				t.Errorf("Admin key should grant access to %s, got %d", ep, rec.Code)
			}
		})
	}

	t.Log("✓ Admin key grants access to all sensitive read-only endpoints")
}

func TestAuth_ReaderKeyCannotMutate(t *testing.T) {
	t.Log("SECURITY TEST: Reader API key must not allow mutating operations")

	mux, _ := setupTestAPIListeningWithKeys(t, "admin-key", "reader-key")

	endpoints := []struct {
		method string
		path   string
		body   string
	}{
		{"POST", "/api/v1/clients/victim/revoke", `{"reason":"cheating","actor":"attacker"}`},
		{"DELETE", "/api/v1/clients/victim/revoke", ""},
		{"POST", "/api/v1/bans", `{"hardware_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","reason":"cheating","actor":"attacker"}`},
		{"DELETE", "/api/v1/bans/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ""},
	}

	for _, ep := range endpoints {
		t.Run(ep.method+" "+ep.path, func(t *testing.T) {
			var req *http.Request
			if ep.body != "" {
				req = httptest.NewRequest(ep.method, ep.path, strings.NewReader(ep.body))
			} else {
				req = httptest.NewRequest(ep.method, ep.path, nil)
			}
			req.Header.Set("Authorization", "Bearer reader-key")
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)

			if rec.Code != http.StatusForbidden {
				t.Errorf("Reader key should not allow %s %s, got %d (want 403)",
					ep.method, ep.path, rec.Code)
			}
		})
	}

	t.Log("✓ Reader key correctly denied on all mutating endpoints")
}

func TestAuth_WrongReaderKeyReturns403(t *testing.T) {
	t.Log("SECURITY TEST: Wrong reader key returns 403 on sensitive read-only endpoints")

	mux, _ := setupTestAPIListeningWithKeys(t, "admin-key", "reader-key")

	req := httptest.NewRequest("GET", "/api/v1/audit", nil)
	req.Header.Set("Authorization", "Bearer wrong-reader-key")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("Expected 403, got %d", rec.Code)
	}

	var resp errorResponse
	json.NewDecoder(rec.Body).Decode(&resp)
	if resp.Error != "invalid API key" {
		t.Errorf("Unexpected error message: %q", resp.Error)
	}

	t.Log("✓ Wrong reader key correctly rejected")
}

func TestAuth_NoReaderKeyMakesEndpointsPublic(t *testing.T) {
	t.Log("TEST: When no reader key is configured, sensitive read endpoints are public")

	mux, _ := setupTestAPIListeningWithKeys(t, "", "")

	sensitiveEndpoints := []string{
		"/api/v1/clients",
		"/api/v1/revocations",
		"/api/v1/bans",
		"/api/v1/audit",
		"/api/v1/attestations",
	}

	for _, ep := range sensitiveEndpoints {
		t.Run("GET "+ep, func(t *testing.T) {
			req := httptest.NewRequest("GET", ep, nil)
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)

			if rec.Code == http.StatusUnauthorized || rec.Code == http.StatusForbidden {
				t.Errorf("Endpoint %s should be public when no keys configured, got %d", ep, rec.Code)
			}
		})
	}

	t.Log("✓ Sensitive endpoints are public when no reader key configured")
}

func TestAuth_AdminKeyOnlyDoesNotProtectReads(t *testing.T) {
	t.Log("TEST: Admin key alone does not protect sensitive read-only endpoints")
	t.Log("Reader protection is opt-in via LOTA_READER_API_KEY env var")

	mux, _ := setupTestAPIListeningWithKeys(t, "admin-key", "")

	sensitiveEndpoints := []string{
		"/api/v1/clients",
		"/api/v1/revocations",
		"/api/v1/bans",
		"/api/v1/audit",
		"/api/v1/attestations",
	}

	for _, ep := range sensitiveEndpoints {
		t.Run("GET "+ep+" no auth", func(t *testing.T) {
			req := httptest.NewRequest("GET", ep, nil)
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)

			if rec.Code == http.StatusUnauthorized || rec.Code == http.StatusForbidden {
				t.Errorf("Endpoint %s should be public when only admin key is set, got %d", ep, rec.Code)
			}
		})
	}

	t.Log("✓ Sensitive read-only endpoints are public without reader key")
}

func TestAuth_PublicEndpointsAlwaysPublic(t *testing.T) {
	t.Log("TEST: Health, stats, and metrics are always public regardless of key config")

	configs := []struct {
		name      string
		adminKey  string
		readerKey string
	}{
		{"no keys", "", ""},
		{"admin only", "admin-key", ""},
		{"reader only", "", "reader-key"},
		{"both keys", "admin-key", "reader-key"},
	}

	publicEndpoints := []string{
		"/health",
		"/api/v1/stats",
		"/metrics",
	}

	for _, cfg := range configs {
		t.Run(cfg.name, func(t *testing.T) {
			mux, _ := setupTestAPIListeningWithKeys(t, cfg.adminKey, cfg.readerKey)

			for _, ep := range publicEndpoints {
				req := httptest.NewRequest("GET", ep, nil)
				rec := httptest.NewRecorder()
				mux.ServeHTTP(rec, req)

				if rec.Code == http.StatusUnauthorized || rec.Code == http.StatusForbidden {
					t.Errorf("[%s] Public endpoint %s returned %d", cfg.name, ep, rec.Code)
				}
			}
		})
	}

	t.Log("✓ Public endpoints accessible in all key configurations")
}

func TestAuth_ReaderBearerCaseInsensitive(t *testing.T) {
	t.Log("TEST: Reader auth accepts case-insensitive Bearer prefix per RFC 7235")

	mux, _ := setupTestAPIListeningWithKeys(t, "admin-key", "reader-key")

	prefixes := []string{"Bearer ", "bearer ", "BEARER "}
	for _, prefix := range prefixes {
		t.Run(prefix, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/api/v1/audit", nil)
			req.Header.Set("Authorization", prefix+"reader-key")
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)

			if rec.Code == http.StatusUnauthorized || rec.Code == http.StatusForbidden {
				t.Errorf("Bearer prefix %q should be accepted for reader, got %d", prefix, rec.Code)
			}
		})
	}

	t.Log("✓ Reader auth accepts case-insensitive Bearer prefix")
}
