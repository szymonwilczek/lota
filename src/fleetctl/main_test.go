// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
// LOTA Fleet CLI - command-level tests
//
// run() is exercised end to end against an httptest fake of the monitoring API:
// argument parsing, connection configuration (flags, environment, key file),
// output rendering and exit codes.

package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeAPI serves canned JSON per path and records the Authorization
// header of the last request.
type fakeAPI struct {
	srv      *httptest.Server
	lastAuth string
	requests int
}

func newFakeAPI(t *testing.T, responses map[string]string) *fakeAPI {
	t.Helper()

	f := &fakeAPI{}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.lastAuth = r.Header.Get("Authorization")
		f.requests++

		key := r.Method + " " + r.URL.Path
		body, ok := responses[key]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":"unexpected request ` + key + `"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		// API answers 201 on the revoke and ban creation endpoints
		if r.Method == http.MethodPost &&
			(strings.HasSuffix(r.URL.Path, "/revoke") || r.URL.Path == "/api/v1/bans") {
			w.WriteHeader(http.StatusCreated)
		}
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func noEnv(string) string { return "" }

// runCLI invokes run() and returns exit code, stdout and stderr.
func runCLI(t *testing.T, getenv func(string) string, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := run(args, &stdout, &stderr, getenv)
	return code, stdout.String(), stderr.String()
}

func TestStatsOutput(t *testing.T) {
	f := newFakeAPI(t, map[string]string{
		"GET /api/v1/stats": `{"registered_clients":3,"active_policy":"prod",
			"loaded_policies":["prod"],"total_attestations":42,"uptime":"1m0s"}`,
	})

	code, out, _ := runCLI(t, noEnv, "-server", f.srv.URL, "stats")
	if code != exitOK {
		t.Fatalf("exit = %d, want 0", code)
	}
	if !strings.Contains(out, "registered clients: 3") ||
		!strings.Contains(out, "active policy: prod") {
		t.Fatalf("output = %q", out)
	}
}

func TestJSONOutputIsValidJSON(t *testing.T) {
	f := newFakeAPI(t, map[string]string{
		"GET /api/v1/stats": `{"registered_clients":3}`,
	})

	code, out, _ := runCLI(t, noEnv, "-server", f.srv.URL, "-json", "stats")
	if code != exitOK {
		t.Fatalf("exit = %d, want 0", code)
	}
	var v map[string]any
	if err := json.Unmarshal([]byte(out), &v); err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, out)
	}
}

func TestServerFromEnvironment(t *testing.T) {
	f := newFakeAPI(t, map[string]string{
		"GET /health": `{"status":"ok","uptime":"1s","tls":{"listening":true,"address":":8443"}}`,
	})

	env := func(k string) string {
		if k == envServer {
			return f.srv.URL
		}
		return ""
	}
	code, _, _ := runCLI(t, env, "health")
	if code != exitOK || f.requests != 1 {
		t.Fatalf("exit = %d, requests = %d", code, f.requests)
	}
}

func TestAPIKeyFromEnvironment(t *testing.T) {
	f := newFakeAPI(t, map[string]string{
		"GET /api/v1/stats": `{}`,
	})

	env := func(k string) string {
		if k == envAPIKey {
			return "env-key"
		}
		return ""
	}
	code, _, _ := runCLI(t, env, "-server", f.srv.URL, "stats")
	if code != exitOK {
		t.Fatalf("exit = %d", code)
	}
	if f.lastAuth != "Bearer env-key" {
		t.Fatalf("Authorization = %q, want the environment key", f.lastAuth)
	}
}

func TestKeyFileOverridesEnvironment(t *testing.T) {
	f := newFakeAPI(t, map[string]string{
		"GET /api/v1/stats": `{}`,
	})

	keyPath := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(keyPath, []byte("file-key\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	env := func(k string) string {
		if k == envAPIKey {
			return "env-key"
		}
		return ""
	}
	code, _, _ := runCLI(t, env, "-server", f.srv.URL, "-key-file", keyPath, "stats")
	if code != exitOK {
		t.Fatalf("exit = %d", code)
	}
	if f.lastAuth != "Bearer file-key" {
		t.Fatalf("Authorization = %q, want the trimmed file key", f.lastAuth)
	}
}

func TestMissingKeyFileFails(t *testing.T) {
	code, _, errOut := runCLI(t, noEnv,
		"-server", "http://127.0.0.1:1", "-key-file", "/nonexistent/key", "stats")
	if code != exitError {
		t.Fatalf("exit = %d, want 1", code)
	}
	if !strings.Contains(errOut, "key file") {
		t.Fatalf("stderr = %q", errOut)
	}
}

func TestHealthDegradedExitsNonzero(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"status":"degraded","uptime":"1s",
			"tls":{"listening":false,"address":":8443"}}`))
	}))
	defer srv.Close()

	code, out, _ := runCLI(t, noEnv, "-server", srv.URL, "health")
	if code != exitError {
		t.Fatalf("exit = %d, want 1 on degraded health", code)
	}
	if !strings.Contains(out, "status: degraded") {
		t.Fatalf("output = %q", out)
	}
}

func TestDevicesListPrintsIDs(t *testing.T) {
	f := newFakeAPI(t, map[string]string{
		"GET /api/v1/clients": `{"clients":["host1","host2"],"count":2,
			"total":2,"limit":100,"offset":0}`,
	})

	code, out, errOut := runCLI(t, noEnv, "-server", f.srv.URL, "devices", "list")
	if code != exitOK {
		t.Fatalf("exit = %d", code)
	}
	if out != "host1\nhost2\n" {
		t.Fatalf("stdout = %q, want bare IDs for scripting", out)
	}
	if !strings.Contains(errOut, "2 of 2 clients") {
		t.Fatalf("stderr = %q, want the page summary", errOut)
	}
}

func TestDevicesShow(t *testing.T) {
	f := newFakeAPI(t, map[string]string{
		"GET /api/v1/clients/host1": `{"client_id":"host1","revoked":false,
			"attestation_count":7,"pcr14_baseline":"cafe"}`,
	})

	code, out, _ := runCLI(t, noEnv, "-server", f.srv.URL, "devices", "show", "host1")
	if code != exitOK {
		t.Fatalf("exit = %d", code)
	}
	if !strings.Contains(out, "client: host1") ||
		!strings.Contains(out, "attestation count: 7") ||
		!strings.Contains(out, "pcr14 baseline: cafe") {
		t.Fatalf("output = %q", out)
	}
}

func TestRevokeHappyPath(t *testing.T) {
	f := newFakeAPI(t, map[string]string{
		"POST /api/v1/clients/host1/revoke": `{"status":"revoked",
			"client_id":"host1","reason":"cheating"}`,
	})

	code, out, _ := runCLI(t, noEnv, "-server", f.srv.URL,
		"revoke", "host1", "-reason", "cheating", "-actor", "ops")
	if code != exitOK {
		t.Fatalf("exit = %d", code)
	}
	if !strings.Contains(out, "revoked host1 (cheating)") {
		t.Fatalf("output = %q", out)
	}
}

func TestRevokeRequiresReasonAndActor(t *testing.T) {
	f := newFakeAPI(t, nil)

	code, _, errOut := runCLI(t, noEnv, "-server", f.srv.URL,
		"revoke", "host1", "-actor", "ops")
	if code != exitUsage {
		t.Fatalf("exit = %d, want 2", code)
	}
	if !strings.Contains(errOut, "-reason") {
		t.Fatalf("stderr = %q", errOut)
	}
	if f.requests != 0 {
		t.Fatalf("request sent despite the usage error")
	}
}

func TestReanchorRequiresActor(t *testing.T) {
	f := newFakeAPI(t, nil)

	code, _, _ := runCLI(t, noEnv, "-server", f.srv.URL, "reanchor", "host1")
	if code != exitUsage || f.requests != 0 {
		t.Fatalf("exit = %d, requests = %d, want usage error before any request",
			code, f.requests)
	}
}

func TestDeleteWorksWithoutMetadata(t *testing.T) {
	f := newFakeAPI(t, map[string]string{
		"DELETE /api/v1/clients/host1": `{"status":"deleted","client_id":"host1"}`,
	})

	code, out, _ := runCLI(t, noEnv, "-server", f.srv.URL, "delete", "host1")
	if code != exitOK {
		t.Fatalf("exit = %d", code)
	}
	if !strings.Contains(out, "deleted host1") {
		t.Fatalf("output = %q", out)
	}
}

func TestSessionValidateInvalidExitsNonzero(t *testing.T) {
	f := newFakeAPI(t, map[string]string{
		"POST /api/v1/session/validate": `{"valid":false}`,
	})

	code, out, _ := runCLI(t, noEnv, "-server", f.srv.URL,
		"session", "validate", strings.Repeat("00", 32))
	if code != exitError {
		t.Fatalf("exit = %d, want 1 for an invalid token", code)
	}
	if !strings.Contains(out, "valid: false") {
		t.Fatalf("output = %q", out)
	}
}

func TestSessionValidateRejectsMisplacedFlags(t *testing.T) {
	f := newFakeAPI(t, nil)

	// -consume before the token would silently validate the literal string
	// "-consume" as the token
	// reject it before any request
	code, _, errOut := runCLI(t, noEnv, "-server", f.srv.URL,
		"session", "validate", "-consume", strings.Repeat("00", 32))
	if code != exitUsage {
		t.Fatalf("exit = %d, want 2 for flags before the token", code)
	}
	if !strings.Contains(errOut, "token argument") {
		t.Fatalf("stderr = %q", errOut)
	}
	if f.requests != 0 {
		t.Fatalf("request sent despite the usage error")
	}
}

func TestAPIErrorReachesStderr(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":"invalid API key"}`))
	}))
	defer srv.Close()

	code, _, errOut := runCLI(t, noEnv, "-server", srv.URL, "stats")
	if code != exitError {
		t.Fatalf("exit = %d, want 1", code)
	}
	if !strings.Contains(errOut, "invalid API key") {
		t.Fatalf("stderr = %q, want the server's error message", errOut)
	}
}

func TestUnknownCommandIsUsageError(t *testing.T) {
	code, _, errOut := runCLI(t, noEnv, "-server", "http://127.0.0.1:1", "frobnicate")
	if code != exitUsage {
		t.Fatalf("exit = %d, want 2", code)
	}
	if !strings.Contains(errOut, "frobnicate") {
		t.Fatalf("stderr = %q", errOut)
	}
}

func TestNoArgumentsPrintsUsage(t *testing.T) {
	code, _, errOut := runCLI(t, noEnv)
	if code != exitUsage {
		t.Fatalf("exit = %d, want 2", code)
	}
	if !strings.Contains(errOut, "Usage: lota-fleet") {
		t.Fatalf("stderr = %q", errOut)
	}
}

func TestReanchorReviewListAndAck(t *testing.T) {
	f := newFakeAPI(t, map[string]string{
		"GET /api/v1/reanchor/review": `{"pending_review":["host1"],"count":1}`,
		"POST /api/v1/clients/host1/reanchor-review-ack": `{"status":"reviewed",
			"client_id":"host1"}`,
	})

	code, out, _ := runCLI(t, noEnv, "-server", f.srv.URL, "reanchor-review", "list")
	if code != exitOK || out != "host1\n" {
		t.Fatalf("list: exit = %d, output = %q", code, out)
	}

	code, out, _ = runCLI(t, noEnv, "-server", f.srv.URL,
		"reanchor-review", "ack", "host1")
	if code != exitOK || !strings.Contains(out, "reviewed host1") {
		t.Fatalf("ack: exit = %d, output = %q", code, out)
	}
}

func TestUnrevoke(t *testing.T) {
	f := newFakeAPI(t, map[string]string{
		"DELETE /api/v1/clients/host1/revoke": `{"status":"unrevoked",
			"client_id":"host1"}`,
	})

	code, out, _ := runCLI(t, noEnv, "-server", f.srv.URL, "unrevoke", "host1")
	if code != exitOK || !strings.Contains(out, "unrevoked host1") {
		t.Fatalf("exit = %d, output = %q", code, out)
	}
}

func TestRevocationsTable(t *testing.T) {
	f := newFakeAPI(t, map[string]string{
		"GET /api/v1/revocations": `{"revocations":[{"client_id":"host1",
			"reason":"admin","revoked_at":"2026-07-02T10:00:00Z",
			"revoked_by":"ops","note":"n"}],"count":1}`,
	})

	code, out, _ := runCLI(t, noEnv, "-server", f.srv.URL, "revocations")
	if code != exitOK {
		t.Fatalf("exit = %d", code)
	}
	if !strings.Contains(out, "CLIENT") || !strings.Contains(out, "host1") {
		t.Fatalf("output = %q", out)
	}
}

func TestBanAndUnban(t *testing.T) {
	hwid := strings.Repeat("ab", 32)
	f := newFakeAPI(t, map[string]string{
		"POST /api/v1/bans":           `{"status":"banned","hardware_id":"` + hwid + `"}`,
		"DELETE /api/v1/bans/" + hwid: `{"status":"unbanned","hardware_id":"` + hwid + `"}`,
	})

	code, out, _ := runCLI(t, noEnv, "-server", f.srv.URL,
		"ban", hwid, "-reason", "cheating", "-actor", "ops")
	if code != exitOK || !strings.Contains(out, "banned "+hwid) {
		t.Fatalf("ban: exit = %d, output = %q", code, out)
	}

	code, out, _ = runCLI(t, noEnv, "-server", f.srv.URL, "unban", hwid)
	if code != exitOK || !strings.Contains(out, "unbanned "+hwid) {
		t.Fatalf("unban: exit = %d, output = %q", code, out)
	}
}

func TestBansTableWithCursorHint(t *testing.T) {
	f := newFakeAPI(t, map[string]string{
		"GET /api/v1/bans": `{"bans":[{"hardware_id":"ab","reason":"admin",
			"banned_at":"2026-07-02T10:00:00Z","banned_by":"ops","note":""}],
			"count":1,"total":5,"limit":1,"next_id":"cursor1"}`,
	})

	code, out, errOut := runCLI(t, noEnv, "-server", f.srv.URL,
		"bans", "-limit", "1")
	if code != exitOK {
		t.Fatalf("exit = %d", code)
	}
	if !strings.Contains(out, "HARDWARE ID") || !strings.Contains(out, "ab") {
		t.Fatalf("output = %q", out)
	}
	if !strings.Contains(errOut, "-next-id cursor1") {
		t.Fatalf("stderr = %q, want the cursor hint", errOut)
	}
}

func TestReanchorHappyPath(t *testing.T) {
	f := newFakeAPI(t, map[string]string{
		"POST /api/v1/clients/host1/reanchor": `{"status":"reanchored",
			"client_id":"host1"}`,
	})

	code, out, _ := runCLI(t, noEnv, "-server", f.srv.URL,
		"reanchor", "host1", "-actor", "ops", "-note", "board swap")
	if code != exitOK || !strings.Contains(out, "reanchored host1") {
		t.Fatalf("exit = %d, output = %q", code, out)
	}
}

func TestAttestsTable(t *testing.T) {
	f := newFakeAPI(t, map[string]string{
		"GET /api/v1/attestations": `{"attestations":[{"id":9,
			"timestamp":"2026-07-02T10:00:00Z","client_id":"host1",
			"result":"success","duration_ms":12.5}],"count":1}`,
	})

	code, out, _ := runCLI(t, noEnv, "-server", f.srv.URL, "attests")
	if code != exitOK {
		t.Fatalf("exit = %d", code)
	}
	if !strings.Contains(out, "RESULT") || !strings.Contains(out, "success") {
		t.Fatalf("output = %q", out)
	}
}

func TestSessionValidateValidToken(t *testing.T) {
	f := newFakeAPI(t, map[string]string{
		"POST /api/v1/session/validate": `{"valid":true,"consumed":true,
			"client_id":"host1","hardware_id":"ab"}`,
	})

	code, out, _ := runCLI(t, noEnv, "-server", f.srv.URL,
		"session", "validate", strings.Repeat("00", 32), "-consume")
	if code != exitOK {
		t.Fatalf("exit = %d, want 0 for a valid token", code)
	}
	if !strings.Contains(out, "valid: true") || !strings.Contains(out, "client: host1") {
		t.Fatalf("output = %q", out)
	}
}

func TestAuditTable(t *testing.T) {
	f := newFakeAPI(t, map[string]string{
		"GET /api/v1/audit": `{"entries":[{"id":1,
			"timestamp":"2026-07-02T10:00:00Z","action":"reanchor",
			"target_id":"host1","actor":"ops"}],"count":1}`,
	})

	code, out, _ := runCLI(t, noEnv, "-server", f.srv.URL, "audit", "-limit", "10")
	if code != exitOK {
		t.Fatalf("exit = %d", code)
	}
	if !strings.Contains(out, "ACTION") || !strings.Contains(out, "reanchor") {
		t.Fatalf("output = %q", out)
	}
}

// TestBanUnbanTenantForwarded checks the CLI forwards -tenant into the ban
// request body and the unban query string.
func TestBanUnbanTenantForwarded(t *testing.T) {
	hwid := strings.Repeat("ab", 32)

	var banBody []byte
	var unbanQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/bans":
			banBody, _ = io.ReadAll(r.Body)
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"status":"banned"}`))
		case r.Method == http.MethodDelete && r.URL.Path == "/api/v1/bans/"+hwid:
			unbanQuery = r.URL.RawQuery
			_, _ = w.Write([]byte(`{"status":"unbanned"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	code, out, _ := runCLI(t, noEnv, "-server", srv.URL,
		"ban", hwid, "-tenant", "acme", "-reason", "cheating", "-actor", "ops")
	if code != exitOK || !strings.Contains(out, "tenant acme") {
		t.Fatalf("ban: exit = %d, out = %q", code, out)
	}
	var body map[string]any
	if err := json.Unmarshal(banBody, &body); err != nil {
		t.Fatalf("ban body: %v", err)
	}
	if body["tenant"] != "acme" {
		t.Fatalf("ban body tenant = %v, want acme", body["tenant"])
	}

	code, out, _ = runCLI(t, noEnv, "-server", srv.URL, "unban", hwid, "-tenant", "acme")
	if code != exitOK || !strings.Contains(out, "tenant acme") {
		t.Fatalf("unban: exit = %d, out = %q", code, out)
	}
	if unbanQuery != "tenant=acme" {
		t.Fatalf("unban query = %q, want tenant=acme", unbanQuery)
	}
}

// TestBansTableTenantColumnAndFilter checks the TENANT column renders and
// the -tenant flag filters the displayed rows client-side.
func TestBansTableTenantColumnAndFilter(t *testing.T) {
	f := newFakeAPI(t, map[string]string{
		"GET /api/v1/bans": `{"bans":[
			{"hardware_id":"aa","tenant":"acme","reason":"admin",
			 "banned_at":"2026-07-02T10:00:00Z","banned_by":"ops","note":""},
			{"hardware_id":"bb","tenant":"beta","reason":"admin",
			 "banned_at":"2026-07-02T10:00:00Z","banned_by":"ops","note":""}],
			"count":2,"total":2,"limit":100}`,
	})

	code, out, _ := runCLI(t, noEnv, "-server", f.srv.URL, "bans")
	if code != exitOK || !strings.Contains(out, "TENANT") {
		t.Fatalf("bans: exit = %d, out = %q", code, out)
	}
	if !strings.Contains(out, "acme") || !strings.Contains(out, "beta") {
		t.Fatalf("unfiltered bans missing a tenant: %q", out)
	}

	code, out, _ = runCLI(t, noEnv, "-server", f.srv.URL, "bans", "-tenant", "acme")
	if code != exitOK {
		t.Fatalf("filtered bans exit = %d", code)
	}
	if !strings.Contains(out, "aa") || strings.Contains(out, "bb") {
		t.Fatalf("-tenant acme did not filter to the acme ban: %q", out)
	}
}

// TestDevicesShowTenant checks the per-client detail prints the tenant.
func TestDevicesShowTenant(t *testing.T) {
	f := newFakeAPI(t, map[string]string{
		"GET /api/v1/clients/host1": `{"client_id":"host1","tenant":"acme","revoked":false}`,
	})

	code, out, _ := runCLI(t, noEnv, "-server", f.srv.URL, "devices", "show", "host1")
	if code != exitOK || !strings.Contains(out, "tenant: acme") {
		t.Fatalf("devices show: exit = %d, out = %q", code, out)
	}
}

// TestStatsTenantScoped checks the scoped stats flag and tenant list render.
func TestStatsTenantScoped(t *testing.T) {
	f := newFakeAPI(t, map[string]string{
		"GET /api/v1/stats": `{"registered_clients":1,"active_policy":"prod",
			"loaded_policies":["prod"],"uptime":"1m0s",
			"tenant_scoped":true,"tenants":["acme"]}`,
	})

	code, out, _ := runCLI(t, noEnv, "-server", f.srv.URL, "stats")
	if code != exitOK {
		t.Fatalf("stats exit = %d", code)
	}
	if !strings.Contains(out, "tenant scoped: true") || !strings.Contains(out, "tenants: acme") {
		t.Fatalf("scoped stats output = %q", out)
	}
	if strings.Contains(out, "total attestations") ||
		strings.Contains(out, "pending challenges") {
		t.Fatalf("scoped stats leaked fleet-wide counters: %q", out)
	}
	if !strings.Contains(out, "registered clients: 1") {
		t.Fatalf("scoped stats dropped the narrowed counts: %q", out)
	}
}

// TestBanUnbanUsageErrors exercises the argument validation of the
// tenant-aware ban/unban flagsets.
func TestBanUnbanUsageErrors(t *testing.T) {
	hwid := strings.Repeat("ab", 32)
	cases := [][]string{
		{"ban"},                           // missing hardware id
		{"ban", hwid, "-actor", "ops"},    // missing reason
		{"ban", hwid, "-reason", "admin"}, // missing actor
		{"ban", hwid, "-reason", "admin", "-actor", "ops", "extra"}, // extra arg
		{"unban"},                // missing hardware id
		{"unban", hwid, "extra"}, // extra arg
	}
	for _, args := range cases {
		full := append([]string{"-server", "http://127.0.0.1:0"}, args...)
		code, _, _ := runCLI(t, noEnv, full...)
		if code != exitUsage {
			t.Fatalf("%v: exit = %d, want usage error", args, code)
		}
	}
}

// TestListTenantFilterRemovesRows checks the -tenant filter on the log and
// revocation listings drops non-matching rows.
func TestListTenantFilterRemovesRows(t *testing.T) {
	f := newFakeAPI(t, map[string]string{
		"GET /api/v1/revocations": `{"revocations":[
			{"client_id":"h1","tenant":"acme","reason":"admin",
			 "revoked_at":"2026-07-02T10:00:00Z","revoked_by":"ops","note":""},
			{"client_id":"h2","tenant":"beta","reason":"admin",
			 "revoked_at":"2026-07-02T10:00:00Z","revoked_by":"ops","note":""}],"count":2}`,
		"GET /api/v1/audit": `{"entries":[
			{"id":1,"timestamp":"t","tenant":"acme","action":"ban","target_id":"x","actor":"ops"},
			{"id":2,"timestamp":"t","tenant":"beta","action":"ban","target_id":"y","actor":"ops"}],"count":2}`,
		"GET /api/v1/attestations": `{"attestations":[
			{"id":1,"timestamp":"t","tenant":"acme","client_id":"h1","result":"success","duration_ms":1},
			{"id":2,"timestamp":"t","tenant":"beta","client_id":"h2","result":"success","duration_ms":1}],"count":2}`,
	})

	for _, tc := range []struct{ cmd, keep, drop string }{
		{"revocations", "h1", "h2"},
		{"audit", "x", "y"},
		{"attests", "h1", "h2"},
	} {
		code, out, _ := runCLI(t, noEnv, "-server", f.srv.URL, tc.cmd, "-tenant", "acme")
		if code != exitOK {
			t.Fatalf("%s: exit = %d", tc.cmd, code)
		}
		if !strings.Contains(out, tc.keep) || strings.Contains(out, tc.drop) {
			t.Fatalf("%s -tenant acme = %q, want %s kept and %s dropped", tc.cmd, out, tc.keep, tc.drop)
		}
	}
}

// TestListTenantFilterAppliesToJSON checks the -tenant filter narrows the
// -json rendering exactly like the table, including the bans page count.
func TestListTenantFilterAppliesToJSON(t *testing.T) {
	f := newFakeAPI(t, map[string]string{
		"GET /api/v1/revocations": `{"revocations":[
			{"client_id":"h1","tenant":"acme","reason":"admin",
			 "revoked_at":"2026-07-02T10:00:00Z","revoked_by":"ops","note":""},
			{"client_id":"h2","tenant":"beta","reason":"admin",
			 "revoked_at":"2026-07-02T10:00:00Z","revoked_by":"ops","note":""}],"count":2}`,
		"GET /api/v1/bans": `{"bans":[
			{"hardware_id":"ab","tenant":"acme","reason":"admin",
			 "banned_at":"2026-07-02T10:00:00Z","banned_by":"ops","note":""},
			{"hardware_id":"cd","tenant":"beta","reason":"admin",
			 "banned_at":"2026-07-02T10:00:00Z","banned_by":"ops","note":""}],
			"count":2,"total":2,"limit":100}`,
	})

	code, out, _ := runCLI(t, noEnv, "-server", f.srv.URL,
		"-json", "revocations", "-tenant", "acme")
	if code != exitOK {
		t.Fatalf("revocations exit = %d", code)
	}
	if !strings.Contains(out, "h1") || strings.Contains(out, "h2") {
		t.Fatalf("-json revocations -tenant acme = %q, want h2 filtered out", out)
	}

	code, out, _ = runCLI(t, noEnv, "-server", f.srv.URL,
		"-json", "bans", "-tenant", "acme")
	if code != exitOK {
		t.Fatalf("bans exit = %d", code)
	}
	var page struct {
		Bans  []map[string]any `json:"bans"`
		Count int              `json:"count"`
	}
	if err := json.Unmarshal([]byte(out), &page); err != nil {
		t.Fatalf("bans output is not JSON: %v\n%s", err, out)
	}
	if len(page.Bans) != 1 || page.Count != 1 || page.Bans[0]["tenant"] != "acme" {
		t.Fatalf("-json bans -tenant acme = %q, want one acme row and count 1", out)
	}
}

// TestListTenantFlagRejectsPositional checks -tenant listings still reject a
// stray positional argument.
func TestListTenantFlagRejectsPositional(t *testing.T) {
	for _, cmd := range []string{"revocations", "audit", "attests", "bans"} {
		code, _, _ := runCLI(t, noEnv, "-server", "http://127.0.0.1:0", cmd, "stray")
		if code != exitUsage {
			t.Fatalf("%s stray: exit = %d, want usage error", cmd, code)
		}
	}
}
