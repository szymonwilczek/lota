// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
// LOTA Fleet CLI - monitoring API client tests
//
// Fake server below implements the verifier monitoring API endpoint contract
// (paths, methods, auth, status codes, JSON envelopes) so the client is tested
// against the documented wire format without compile dependency on the verifier
// packages.

package client

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const testAPIKey = "test-admin-key"

// recorded captures the last request the fake server saw.
type recorded struct {
	method string
	path   string
	query  string
	auth   string
	body   []byte
}

// fakeVerifier serves canned responses on the monitoring API routes
// and records what the client sent.
func fakeVerifier(t *testing.T, status int, response string) (*Client, *recorded) {
	t.Helper()

	rec := &recorded{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.method = r.Method
		rec.path = r.URL.EscapedPath()
		rec.query = r.URL.RawQuery
		rec.auth = r.Header.Get("Authorization")
		rec.body, _ = io.ReadAll(r.Body)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, response)
	}))
	t.Cleanup(srv.Close)

	c, err := New(Config{ServerURL: srv.URL, APIKey: testAPIKey})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c, rec
}

func TestNewRejectsBadConfig(t *testing.T) {
	cases := []struct {
		name string
		cfg  Config
	}{
		{"bad scheme", Config{ServerURL: "ftp://host"}},
		{"no host", Config{ServerURL: "http://"}},
		{"garbage URL", Config{ServerURL: "http://bad url"}},
		{"CA over http", Config{ServerURL: "http://host", CACertPEM: []byte("x")}},
		{"unparseable CA", Config{ServerURL: "https://host", CACertPEM: []byte("not pem")}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := New(tc.cfg); err == nil {
				t.Fatalf("New(%+v) accepted invalid config", tc.cfg)
			}
		})
	}
}

func TestBearerTokenSent(t *testing.T) {
	c, rec := fakeVerifier(t, http.StatusOK, `{"status":"ok"}`)
	if _, err := c.Health(); err != nil {
		t.Fatalf("Health: %v", err)
	}
	if rec.auth != "Bearer "+testAPIKey {
		t.Fatalf("Authorization = %q, want Bearer token", rec.auth)
	}
}

func TestNoAuthHeaderWithoutKey(t *testing.T) {
	rec := &recorded{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.auth = r.Header.Get("Authorization")
		_, _ = io.WriteString(w, `{"status":"ok"}`)
	}))
	defer srv.Close()

	c, err := New(Config{ServerURL: srv.URL})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := c.Health(); err != nil {
		t.Fatalf("Health: %v", err)
	}
	if rec.auth != "" {
		t.Fatalf("Authorization = %q, want none", rec.auth)
	}
}

func TestHealthDegradedIsData(t *testing.T) {
	c, _ := fakeVerifier(t, http.StatusServiceUnavailable,
		`{"status":"degraded","uptime":"5s","uptime_sec":5,
		  "tls":{"listening":false,"address":":8443"}}`)

	h, err := c.Health()
	if err != nil {
		t.Fatalf("Health on 503: %v", err)
	}
	if h.Status != "degraded" || h.TLS.Listening {
		t.Fatalf("Health = %+v, want degraded/not-listening", h)
	}
}

func TestStats(t *testing.T) {
	c, rec := fakeVerifier(t, http.StatusOK,
		`{"registered_clients":3,"total_attestations":42,"active_policy":"prod",
		  "loaded_policies":["prod"],"uptime":"1m0s","uptime_sec":60,
		  "tenant_scoped":true,"tenants":["acme","beta"]}`)

	s, err := c.Stats()
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if rec.method != http.MethodGet || rec.path != "/api/v1/stats" {
		t.Fatalf("request = %s %s, want GET /api/v1/stats", rec.method, rec.path)
	}
	if s.RegisteredClients != 3 || s.TotalAttestations != 42 || s.ActivePolicy != "prod" {
		t.Fatalf("Stats = %+v", s)
	}
	if !s.TenantScoped || len(s.Tenants) != 2 || s.Tenants[0] != "acme" {
		t.Fatalf("tenant scoping = %+v", s)
	}
}

func TestListClientsPagination(t *testing.T) {
	c, rec := fakeVerifier(t, http.StatusOK,
		`{"clients":["a","b"],"count":2,"total":10,"limit":2,"offset":4}`)

	page, err := c.ListClients(2, 4)
	if err != nil {
		t.Fatalf("ListClients: %v", err)
	}
	if rec.path != "/api/v1/clients" || rec.query != "limit=2&offset=4" {
		t.Fatalf("request = %s?%s", rec.path, rec.query)
	}
	if page.Total != 10 || len(page.Clients) != 2 {
		t.Fatalf("page = %+v", page)
	}
}

func TestListClientsDefaultsOmitQuery(t *testing.T) {
	c, rec := fakeVerifier(t, http.StatusOK,
		`{"clients":[],"count":0,"total":0,"limit":100,"offset":0}`)

	if _, err := c.ListClients(0, 0); err != nil {
		t.Fatalf("ListClients: %v", err)
	}
	if rec.query != "" {
		t.Fatalf("query = %q, want empty (server defaults)", rec.query)
	}
}

func TestClientInfo(t *testing.T) {
	c, rec := fakeVerifier(t, http.StatusOK,
		`{"client_id":"host1","tenant":"acme","hardware_id":"ab","revoked":true,
		  "revocation_reason":"admin","attestation_count":7,
		  "pcr14_baseline":"cafe"}`)

	info, err := c.ClientInfo("host1")
	if err != nil {
		t.Fatalf("ClientInfo: %v", err)
	}
	if rec.method != http.MethodGet || rec.path != "/api/v1/clients/host1" {
		t.Fatalf("request = %s %s", rec.method, rec.path)
	}
	if !info.Revoked || info.RevocationReason != "admin" || info.AttestCount != 7 {
		t.Fatalf("info = %+v", info)
	}
	if info.Tenant != "acme" {
		t.Fatalf("tenant = %q, want acme", info.Tenant)
	}
}

func TestClientIDPathEscaped(t *testing.T) {
	c, rec := fakeVerifier(t, http.StatusOK, `{"client_id":"x"}`)

	if _, err := c.ClientInfo("a/b c"); err != nil {
		t.Fatalf("ClientInfo: %v", err)
	}
	if strings.Contains(rec.path, " ") || strings.Count(rec.path, "/") != 4 {
		t.Fatalf("path = %q, want escaped client ID", rec.path)
	}
}

func TestRevokeSendsPayload(t *testing.T) {
	c, rec := fakeVerifier(t, http.StatusCreated,
		`{"status":"revoked","client_id":"host1","reason":"cheating"}`)

	err := c.Revoke("host1", "cheating", "ops@example", "caught red-handed")
	if err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if rec.method != http.MethodPost || rec.path != "/api/v1/clients/host1/revoke" {
		t.Fatalf("request = %s %s", rec.method, rec.path)
	}

	var got map[string]string
	if err := json.Unmarshal(rec.body, &got); err != nil {
		t.Fatalf("request body: %v", err)
	}
	if got["reason"] != "cheating" || got["actor"] != "ops@example" ||
		got["note"] != "caught red-handed" {
		t.Fatalf("body = %v", got)
	}
}

func TestRevokeConflictSurfacesAPIError(t *testing.T) {
	c, _ := fakeVerifier(t, http.StatusConflict,
		`{"error":"client is already revoked"}`)

	err := c.Revoke("host1", "admin", "ops", "")
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("error = %v, want *APIError", err)
	}
	if apiErr.StatusCode != http.StatusConflict ||
		apiErr.Message != "client is already revoked" {
		t.Fatalf("APIError = %+v", apiErr)
	}
}

func TestUnrevoke(t *testing.T) {
	c, rec := fakeVerifier(t, http.StatusOK,
		`{"status":"unrevoked","client_id":"host1"}`)

	if err := c.Unrevoke("host1"); err != nil {
		t.Fatalf("Unrevoke: %v", err)
	}
	if rec.method != http.MethodDelete || rec.path != "/api/v1/clients/host1/revoke" {
		t.Fatalf("request = %s %s", rec.method, rec.path)
	}
}

func TestListRevocations(t *testing.T) {
	c, rec := fakeVerifier(t, http.StatusOK,
		`{"revocations":[{"client_id":"host1","tenant":"acme","reason":"admin",
		  "revoked_at":"2026-07-02T10:00:00Z","revoked_by":"ops","note":""}],
		  "count":1}`)

	revs, err := c.ListRevocations()
	if err != nil {
		t.Fatalf("ListRevocations: %v", err)
	}
	if rec.path != "/api/v1/revocations" {
		t.Fatalf("path = %s", rec.path)
	}
	if len(revs) != 1 || revs[0].ClientID != "host1" || revs[0].Tenant != "acme" {
		t.Fatalf("revocations = %+v", revs)
	}
}

func TestBanSendsHardwareIDAndTenant(t *testing.T) {
	hwid := strings.Repeat("ab", 32)
	c, rec := fakeVerifier(t, http.StatusCreated,
		`{"status":"banned","hardware_id":"`+hwid+`","tenant":"acme","reason":"cheating"}`)

	if err := c.Ban(hwid, "acme", "cheating", "ops", "note"); err != nil {
		t.Fatalf("Ban: %v", err)
	}
	if rec.method != http.MethodPost || rec.path != "/api/v1/bans" {
		t.Fatalf("request = %s %s", rec.method, rec.path)
	}

	var got map[string]string
	if err := json.Unmarshal(rec.body, &got); err != nil {
		t.Fatalf("request body: %v", err)
	}
	if got["hardware_id"] != hwid || got["actor"] != "ops" || got["tenant"] != "acme" {
		t.Fatalf("body = %v", got)
	}
}

func TestBanDefaultTenantOmitsField(t *testing.T) {
	hwid := strings.Repeat("ab", 32)
	c, rec := fakeVerifier(t, http.StatusCreated, `{"status":"banned"}`)

	if err := c.Ban(hwid, "", "admin", "ops", ""); err != nil {
		t.Fatalf("Ban: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(rec.body, &got); err != nil {
		t.Fatalf("request body: %v", err)
	}
	if _, present := got["tenant"]; present {
		t.Fatalf("empty tenant should be omitted from the body: %v", got)
	}
}

func TestUnbanWithTenant(t *testing.T) {
	hwid := strings.Repeat("cd", 32)
	c, rec := fakeVerifier(t, http.StatusOK,
		`{"status":"unbanned","hardware_id":"`+hwid+`","tenant":"acme"}`)

	if err := c.Unban(hwid, "acme"); err != nil {
		t.Fatalf("Unban: %v", err)
	}
	if rec.method != http.MethodDelete || rec.path != "/api/v1/bans/"+hwid {
		t.Fatalf("request = %s %s", rec.method, rec.path)
	}
	if rec.query != "tenant=acme" {
		t.Fatalf("query = %q, want tenant=acme", rec.query)
	}
}

func TestUnbanDefaultTenantOmitsQuery(t *testing.T) {
	hwid := strings.Repeat("cd", 32)
	c, rec := fakeVerifier(t, http.StatusOK, `{"status":"unbanned"}`)

	if err := c.Unban(hwid, ""); err != nil {
		t.Fatalf("Unban: %v", err)
	}
	if rec.query != "" {
		t.Fatalf("query = %q, want empty for the default tenant", rec.query)
	}
}

func TestListBansCursor(t *testing.T) {
	c, rec := fakeVerifier(t, http.StatusOK,
		`{"bans":[{"hardware_id":"ab","tenant":"acme","reason":"admin",
		  "banned_at":"2026-07-02T10:00:00Z","banned_by":"ops","note":""}],
		  "count":1,"total":5,"limit":1,"next_id":"cursor1"}`)

	page, err := c.ListBans(1, "cursor0")
	if err != nil {
		t.Fatalf("ListBans: %v", err)
	}
	if rec.query != "limit=1&next_id=cursor0" {
		t.Fatalf("query = %q", rec.query)
	}
	if page.NextID != "cursor1" || page.Total != 5 {
		t.Fatalf("page = %+v", page)
	}
	if len(page.Bans) != 1 || page.Bans[0].Tenant != "acme" {
		t.Fatalf("ban tenant = %+v", page.Bans)
	}
}

func TestReanchor(t *testing.T) {
	c, rec := fakeVerifier(t, http.StatusOK,
		`{"status":"reanchored","client_id":"host1"}`)

	if err := c.Reanchor("host1", "ops", "board swap"); err != nil {
		t.Fatalf("Reanchor: %v", err)
	}
	if rec.method != http.MethodPost || rec.path != "/api/v1/clients/host1/reanchor" {
		t.Fatalf("request = %s %s", rec.method, rec.path)
	}

	var got map[string]string
	if err := json.Unmarshal(rec.body, &got); err != nil {
		t.Fatalf("request body: %v", err)
	}
	if got["actor"] != "ops" || got["note"] != "board swap" {
		t.Fatalf("body = %v", got)
	}
}

func TestReanchorUnknownClient(t *testing.T) {
	c, _ := fakeVerifier(t, http.StatusNotFound, `{"error":"client not found"}`)

	err := c.Reanchor("ghost", "ops", "")
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusNotFound {
		t.Fatalf("error = %v, want 404 *APIError", err)
	}
}

func TestDeleteClientWithMetadata(t *testing.T) {
	c, rec := fakeVerifier(t, http.StatusOK,
		`{"status":"deleted","client_id":"host1"}`)

	if err := c.DeleteClient("host1", "ops", "decommissioned"); err != nil {
		t.Fatalf("DeleteClient: %v", err)
	}
	if rec.method != http.MethodDelete || rec.path != "/api/v1/clients/host1" {
		t.Fatalf("request = %s %s", rec.method, rec.path)
	}

	var got map[string]string
	if err := json.Unmarshal(rec.body, &got); err != nil {
		t.Fatalf("request body: %v", err)
	}
	if got["actor"] != "ops" {
		t.Fatalf("body = %v", got)
	}
}

func TestDeleteClientOmitsEmptyBody(t *testing.T) {
	c, rec := fakeVerifier(t, http.StatusOK,
		`{"status":"deleted","client_id":"host1"}`)

	if err := c.DeleteClient("host1", "", ""); err != nil {
		t.Fatalf("DeleteClient: %v", err)
	}
	if len(rec.body) != 0 {
		t.Fatalf("body = %q, want empty (DELETE without metadata)", rec.body)
	}
}

func TestReanchorReviewList(t *testing.T) {
	c, rec := fakeVerifier(t, http.StatusOK,
		`{"pending_review":["host1","host2"],"count":2}`)

	clients, err := c.ReanchorReviewList()
	if err != nil {
		t.Fatalf("ReanchorReviewList: %v", err)
	}
	if rec.path != "/api/v1/reanchor/review" {
		t.Fatalf("path = %s", rec.path)
	}
	if len(clients) != 2 || clients[0] != "host1" {
		t.Fatalf("clients = %v", clients)
	}
}

func TestReanchorReviewAck(t *testing.T) {
	c, rec := fakeVerifier(t, http.StatusOK,
		`{"status":"reviewed","client_id":"host1"}`)

	if err := c.ReanchorReviewAck("host1"); err != nil {
		t.Fatalf("ReanchorReviewAck: %v", err)
	}
	if rec.method != http.MethodPost ||
		rec.path != "/api/v1/clients/host1/reanchor-review-ack" {
		t.Fatalf("request = %s %s", rec.method, rec.path)
	}
}

func TestAuditLimit(t *testing.T) {
	c, rec := fakeVerifier(t, http.StatusOK,
		`{"entries":[{"id":1,"timestamp":"2026-07-02T10:00:00Z","tenant":"acme",
		  "action":"reanchor","target_id":"host1","actor":"ops"}],"count":1}`)

	entries, err := c.Audit(50)
	if err != nil {
		t.Fatalf("Audit: %v", err)
	}
	if rec.path != "/api/v1/audit" || rec.query != "limit=50" {
		t.Fatalf("request = %s?%s", rec.path, rec.query)
	}
	if len(entries) != 1 || entries[0].Action != "reanchor" || entries[0].Tenant != "acme" {
		t.Fatalf("entries = %+v", entries)
	}
}

func TestAttestations(t *testing.T) {
	c, rec := fakeVerifier(t, http.StatusOK,
		`{"attestations":[{"id":9,"timestamp":"2026-07-02T10:00:00Z","tenant":"acme",
		  "client_id":"host1","result":"success","duration_ms":12.5}],"count":1}`)

	entries, err := c.Attestations(10)
	if err != nil {
		t.Fatalf("Attestations: %v", err)
	}
	if rec.path != "/api/v1/attestations" || rec.query != "limit=10" {
		t.Fatalf("request = %s?%s", rec.path, rec.query)
	}
	if len(entries) != 1 || entries[0].Result != "success" || entries[0].Tenant != "acme" {
		t.Fatalf("entries = %+v", entries)
	}
}

func TestValidateSessionToken(t *testing.T) {
	token := strings.Repeat("00", 32)
	c, rec := fakeVerifier(t, http.StatusOK,
		`{"valid":true,"consumed":true,"client_id":"host1","tenant":"acme",
		  "hardware_id":"ab","result_code":1}`)

	status, err := c.ValidateSessionToken(token, true)
	if err != nil {
		t.Fatalf("ValidateSessionToken: %v", err)
	}
	if rec.method != http.MethodPost || rec.path != "/api/v1/session/validate" {
		t.Fatalf("request = %s %s", rec.method, rec.path)
	}

	var got struct {
		SessionToken string `json:"session_token"`
		Consume      bool   `json:"consume"`
	}
	if err := json.Unmarshal(rec.body, &got); err != nil {
		t.Fatalf("request body: %v", err)
	}
	if got.SessionToken != token || !got.Consume {
		t.Fatalf("body = %+v", got)
	}
	if !status.Valid || status.ClientID != "host1" || status.Tenant != "acme" {
		t.Fatalf("status = %+v", status)
	}
}

func TestAuthFailureSurfacesAPIError(t *testing.T) {
	c, _ := fakeVerifier(t, http.StatusForbidden, `{"error":"invalid API key"}`)

	_, err := c.Stats()
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("error = %v, want *APIError", err)
	}
	if apiErr.StatusCode != http.StatusForbidden || apiErr.Message != "invalid API key" {
		t.Fatalf("APIError = %+v", apiErr)
	}
}

func TestNonJSONErrorBodyStillReportsStatus(t *testing.T) {
	c, _ := fakeVerifier(t, http.StatusBadGateway, "upstream fell over")

	_, err := c.Stats()
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusBadGateway {
		t.Fatalf("error = %v, want 502 *APIError", err)
	}
	if !strings.Contains(apiErr.Error(), "502") {
		t.Fatalf("Error() = %q, want the status code visible", apiErr.Error())
	}
}
