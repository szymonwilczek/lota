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

// FuzzAPIRequestBody drives an API endpoint that decodes an untrusted JSON
// body. The decoder is shared by every POST the API serves; it must never
// panic and must always answer with a client error or success, never a 5xx.
func FuzzAPIRequestBody(f *testing.F) {
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
	NewAPIHandler(mux, v, srv, auditLog, nil, cfg.Metrics, nil, "fuzz-admin", "")

	f.Add([]byte(`{"hardware_id":"0000000000000000000000000000000000000000000000000000000000000000","reason":"cheating","actor":"op"}`))
	f.Add([]byte(`{"hardware_id":"xyz"}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`not json`))
	f.Add([]byte(strings.Repeat(`{"a":`, 5000)))

	f.Fuzz(func(t *testing.T, body []byte) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/bans", strings.NewReader(string(body)))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer fuzz-admin")
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)
		if rr.Code < 200 || rr.Code >= 500 {
			t.Fatalf("unexpected status %d for body %q", rr.Code, body)
		}
	})
}
