// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
// LOTA Verifier - an instance that serves reports and changes nothing

package server

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/szymonwilczek/lota/verifier/logging"
	"github.com/szymonwilczek/lota/verifier/metrics"
	"github.com/szymonwilczek/lota/verifier/store"
	"github.com/szymonwilczek/lota/verifier/verify"
)

// reportOnlyAPI builds a report-only monitoring API;
// the admin key is set so refusals come from the mode, not the key
func reportOnlyAPI(t *testing.T) *http.ServeMux {
	t.Helper()

	m := metrics.New()
	cfg := verify.DefaultConfig()
	cfg.RequireBootEnrollment = false
	cfg.Metrics = m
	auditLog := store.NewMemoryAuditLog()
	cfg.RevocationStore = store.NewMemoryRevocationStore(auditLog)
	cfg.BanStore = store.NewMemoryBanStore(auditLog)
	v := verify.NewVerifier(cfg, store.NewMemoryStore())

	srv := &Server{verifier: v, addr: ":8443", reportOnly: true}
	mux := http.NewServeMux()
	NewAPIHandler(mux, v, srv, auditLog, logging.Nop(), m,
		store.NewMemoryAttestationLog(), "admin-key", "reader-key")
	return mux
}

// Mutating endpoints are refused in the standard envelope, naming the mode
func TestReportOnlyRefusesEveryMutatingEndpoint(t *testing.T) {
	mux := reportOnlyAPI(t)

	for _, tc := range []struct {
		name   string
		method string
		path   string
		body   string
	}{
		{"ban hardware", http.MethodPost, "/api/v1/bans", `{"hardware_id":"` + strings.Repeat("a", 64) + `","reason":"admin"}`},
		{"unban hardware", http.MethodDelete, "/api/v1/bans/" + strings.Repeat("a", 64), ""},
		{"revoke a client", http.MethodPost, "/api/v1/clients/abc/revoke", `{"reason":"admin"}`},
		{"restore a client", http.MethodDelete, "/api/v1/clients/abc/revoke", ""},
		{"force a re-anchor", http.MethodPost, "/api/v1/clients/abc/reanchor", ""},
		{"acknowledge a re-anchor", http.MethodPost, "/api/v1/clients/abc/reanchor-review-ack", ""},
	} {
		var body *strings.Reader = strings.NewReader(tc.body)
		req := httptest.NewRequest(tc.method, tc.path, body)
		req.Header.Set("Authorization", "Bearer admin-key")
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)

		if rr.Code != http.StatusServiceUnavailable {
			t.Errorf("%s: status %d, want 503 on a reporting instance (body %s)",
				tc.name, rr.Code, rr.Body.String())
			continue
		}
		var parsed errorResponse
		if err := json.Unmarshal(rr.Body.Bytes(), &parsed); err != nil {
			t.Errorf("%s: refusal is not the JSON envelope: %q", tc.name, rr.Body.String())
			continue
		}
		if !strings.Contains(parsed.Error, "read-only") {
			t.Errorf("%s: refusal does not say what is wrong: %q", tc.name, parsed.Error)
		}
	}
}

func TestReportOnlyServesTheReadEndpoints(t *testing.T) {
	mux := reportOnlyAPI(t)

	for _, path := range []string{
		"/api/v1/clients", "/api/v1/bans", "/api/v1/revocations",
		"/api/v1/stats", "/api/v1/attestations",
	} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("Authorization", "Bearer reader-key")
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Errorf("GET %s: status %d, want 200 (body %s)", path, rr.Code, rr.Body.String())
		}
	}
}

// No attestation listener is not a fault: health stays ok and names the mode
func TestReportOnlyHealthNamesTheModeInsteadOfDegrading(t *testing.T) {
	attestAddr := freeLoopbackAddr(t)
	httpAddr := freeLoopbackAddr(t)

	cfg := DefaultServerConfig()
	cfg.Address = attestAddr
	cfg.HTTPAddress = httpAddr
	cfg.Logger = logging.Nop()
	cfg.Metrics = metrics.New()
	cfg.ReportOnly = true

	vcfg := verify.DefaultConfig()
	vcfg.RequireBootEnrollment = false
	vcfg.Metrics = cfg.Metrics
	v := verify.NewVerifier(vcfg, store.NewMemoryStore())

	srv, err := NewServer(cfg, v)
	if err != nil {
		t.Fatalf("NewServer without TLS material in reporting mode: %v", err)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(srv.Stop)

	// nothing may be listening where the attestation protocol would be
	conn, err := net.DialTimeout("tcp", attestAddr, 2*time.Second)
	if err == nil {
		conn.Close()
		t.Errorf("a reporting instance bound the attestation listener at %s", attestAddr)
	}

	code, parsed := health(t, "http://"+httpAddr)
	if code != http.StatusOK {
		t.Errorf("/health status %d, want 200 on a reporting instance", code)
	}
	if parsed.Status != "ok" {
		t.Errorf("/health says %q, want ok: an instance with no attestation listener by design is not degraded", parsed.Status)
	}
	if parsed.Mode != "reporting" {
		t.Errorf("/health mode %q, want reporting", parsed.Mode)
	}
	if parsed.TLS.Listening {
		t.Error("/health reports an attestation listener a reporting instance never bound")
	}
}
