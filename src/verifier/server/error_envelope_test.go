// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
// LOTA Verifier - one error envelope, including the refusals the mux writes

package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Every non-2xx answer carries the `{"error": ...}` envelope,
// including the mux's own refusals: a wrong method and an unknown path.
func TestEveryRefusalCarriesTheErrorEnvelope(t *testing.T) {
	mux, _ := setupTestAPIListening(t)

	cases := []struct {
		name   string
		method string
		path   string
		want   int
	}{
		{"wrong method on a real endpoint", "POST", "/api/v1/stats", http.StatusMethodNotAllowed},
		{"wrong method on a mutation endpoint", "GET", "/api/v1/bans/abab", http.StatusMethodNotAllowed},
		{"a path nothing serves", "GET", "/api/v1/nope", http.StatusNotFound},
		{"the root path", "GET", "/", http.StatusNotFound},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, nil)
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)

			if rec.Code != tc.want {
				t.Fatalf("%s %s answered %d, want %d", tc.method, tc.path, rec.Code, tc.want)
			}
			if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
				t.Errorf("Content-Type = %q, want application/json", ct)
			}

			var body errorResponse
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatalf("body %q is not the error envelope: %v", rec.Body.String(), err)
			}
			if body.Error == "" {
				t.Error("the envelope carries no message")
			}
		})
	}
}

// A 405 names the methods the endpoint accepts.
func TestMethodRefusalNamesTheMethodsTheEndpointTakes(t *testing.T) {
	mux, _ := setupTestAPIListening(t)

	req := httptest.NewRequest("PUT", "/api/v1/bans", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("PUT /api/v1/bans answered %d, want 405", rec.Code)
	}
	allow := rec.Header().Get("Allow")
	if !strings.Contains(allow, "GET") || !strings.Contains(allow, "POST") {
		t.Errorf("Allow = %q, want the GET and POST this path serves", allow)
	}
}
