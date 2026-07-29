// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek

package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/szymonwilczek/lota/verifier/metrics"
	"github.com/szymonwilczek/lota/verifier/store"
	"github.com/szymonwilczek/lota/verifier/verify"
)

// FuzzValidateSessionTokenEndpoint drives the public session-validate API
// with arbitrary request bodies. The endpoint decodes untrusted JSON and a
// hex token; it must never panic and must always answer with a client error
// or success, never a 5xx.
func FuzzValidateSessionTokenEndpoint(f *testing.F) {
	cfg := verify.DefaultConfig()
	cfg.RequireBootEnrollment = false
	auditLog := store.NewMemoryAuditLog()
	cfg.RevocationStore = store.NewMemoryRevocationStore(auditLog)
	cfg.BanStore = store.NewMemoryBanStore(auditLog)
	cfg.Metrics = metrics.New()
	v := verify.NewVerifier(cfg, store.NewMemoryStore())
	if err := v.AddPolicy(verify.DefaultPolicy()); err != nil {
		f.Fatalf("AddPolicy: %v", err)
	}
	srv := &Server{verifier: v, addr: ":8443"}
	mux := http.NewServeMux()
	// empty keys -> endpoint is public, so the body parser is reachable
	NewAPIHandler(mux, v, srv, auditLog, nil, cfg.Metrics, nil, "", "")

	f.Add([]byte(`{"session_token":"0000000000000000000000000000000000000000000000000000000000000000","consume":true}`))
	f.Add([]byte(`{"session_token":"xyz"}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`not json`))
	f.Add([]byte(strings.Repeat(`{"a":`, 5000)))

	f.Fuzz(func(t *testing.T, body []byte) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/session/validate", strings.NewReader(string(body)))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)
		if rr.Code < 200 || rr.Code >= 500 {
			t.Fatalf("unexpected status %d for body %q", rr.Code, body)
		}
	})
}
