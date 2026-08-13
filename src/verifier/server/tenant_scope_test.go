// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
// LOTA Verifier - monitoring API tenant scoping tests

package server

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/szymonwilczek/lota/verifier/store"
	"github.com/szymonwilczek/lota/verifier/verify"
)

// scopedAPIFixture builds an API handler over a verifier seeded with
// clients in two tenants and a scoped key limited to one of them.
type scopedAPIFixture struct {
	mux      *http.ServeMux
	baseline *verify.BaselineStore
	revStore *store.MemoryRevocationStore
	banStore *store.MemoryBanStore
	auditLog *store.MemoryAuditLog
}

func newScopedAPIFixture(t *testing.T, scopedKeyHash string) *scopedAPIFixture {
	t.Helper()

	baseline := verify.NewBaselineStore()
	auditLog := store.NewMemoryAuditLog()
	revStore := store.NewMemoryRevocationStore(auditLog)
	banStore := store.NewMemoryBanStore(auditLog)

	// memory AIK store so ListClients surfaces the seeded clients
	// the same way an attested fleet would
	aikStore := store.NewMemoryStore()

	cfg := verify.DefaultConfig()
	cfg.RequireBootEnrollment = false
	cfg.BaselineStore = baseline
	cfg.RevocationStore = revStore
	cfg.BanStore = banStore
	v := verify.NewVerifier(cfg, aikStore)
	if err := v.AddPolicy(verify.DefaultPolicy()); err != nil {
		t.Fatalf("AddPolicy(DefaultPolicy): %v", err)
	}

	// two clients, one per tenant
	seed := func(clientID, tenant string) {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("seed key: %v", err)
		}
		if err := aikStore.RegisterAIK(clientID, &key.PublicKey); err != nil {
			t.Fatalf("RegisterAIK(%s): %v", clientID, err)
		}
		var pcr14 [32]byte
		pcr14[0] = byte(len(clientID))
		if res, _ := baseline.CheckAndUpdate(clientID, pcr14); res != verify.TOFUFirstUse {
			t.Fatalf("seed %s: unexpected TOFU result", clientID)
		}
		if err := baseline.SetClientTenant(clientID, tenant); err != nil {
			t.Fatalf("SetClientTenant(%s): %v", clientID, err)
		}
	}
	seed("acme-client", "acme")
	seed("beta-client", "beta")

	srv := &Server{verifier: v, addr: ":8443"}
	if scopedKeyHash != "" {
		set, err := LoadAPIKeysFile(writeKeysFile(t,
			"keys:\n  - key_sha256: "+scopedKeyHash+"\n    role: admin\n    tenants: [\"acme\"]\n"))
		if err != nil {
			t.Fatalf("LoadAPIKeysFile: %v", err)
		}
		srv.apiKeys.Store(set)
	}
	mux := http.NewServeMux()
	NewAPIHandler(mux, v, srv, auditLog, nil, nil, nil, "", "")

	return &scopedAPIFixture{mux: mux, baseline: baseline, revStore: revStore, banStore: banStore, auditLog: auditLog}
}

func (f *scopedAPIFixture) do(t *testing.T, method, target, key string) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(method, target, nil)
	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	rr := httptest.NewRecorder()
	f.mux.ServeHTTP(rr, req)

	var body map[string]any
	if rr.Body.Len() > 0 {
		_ = json.Unmarshal(rr.Body.Bytes(), &body)
	}
	return rr.Code, body
}

func TestAPITenantScoping_ClientListingFiltered(t *testing.T) {
	f := newScopedAPIFixture(t, keyHashHex("acme-key"))

	code, body := f.do(t, "GET", "/api/v1/clients", "acme-key")
	if code != http.StatusOK {
		t.Fatalf("list clients: %d, want 200", code)
	}
	clients, _ := body["clients"].([]any)
	if len(clients) != 1 || clients[0] != "acme-client" {
		t.Fatalf("scoped client list = %v, want only acme-client", clients)
	}
	if total, _ := body["total"].(float64); total != 1 {
		t.Fatalf("scoped total = %v, want 1", body["total"])
	}
}

func TestAPITenantScoping_ForeignClientInfoIs404(t *testing.T) {
	f := newScopedAPIFixture(t, keyHashHex("acme-key"))

	if code, _ := f.do(t, "GET", "/api/v1/clients/beta-client", "acme-key"); code != http.StatusNotFound {
		t.Fatalf("foreign client info: %d, want 404", code)
	}

	code, body := f.do(t, "GET", "/api/v1/clients/acme-client", "acme-key")
	if code != http.StatusOK {
		t.Fatalf("own client info: %d, want 200", code)
	}
	if body["tenant"] != "acme" {
		t.Fatalf("client info tenant = %v, want acme", body["tenant"])
	}
}

func TestAPITenantScoping_RevocationsAndStats(t *testing.T) {
	f := newScopedAPIFixture(t, keyHashHex("acme-key"))

	// seed one revocation per tenant directly in the store
	if err := f.revStore.Revoke("acme", "acme-client", store.RevocationAdmin, "op", ""); err != nil {
		t.Fatalf("Revoke acme: %v", err)
	}
	if err := f.revStore.Revoke("beta", "beta-client", store.RevocationAdmin, "op", ""); err != nil {
		t.Fatalf("Revoke beta: %v", err)
	}

	code, body := f.do(t, "GET", "/api/v1/revocations", "acme-key")
	if code != http.StatusOK {
		t.Fatalf("list revocations: %d", code)
	}
	revs, _ := body["revocations"].([]any)
	if len(revs) != 1 {
		t.Fatalf("scoped revocations = %d, want 1", len(revs))
	}
	first, _ := revs[0].(map[string]any)
	if first["tenant"] != "acme" || first["client_id"] != "acme-client" {
		t.Fatalf("scoped revocation = %v", first)
	}

	code, stats := f.do(t, "GET", "/api/v1/stats", "acme-key")
	if code != http.StatusOK {
		t.Fatalf("stats: %d", code)
	}
	if scoped, _ := stats["tenant_scoped"].(bool); !scoped {
		t.Fatal("stats not flagged tenant_scoped")
	}
	if ar, _ := stats["active_revocations"].(float64); ar != 1 {
		t.Fatalf("scoped active_revocations = %v, want 1", stats["active_revocations"])
	}
	if rc, _ := stats["registered_clients"].(float64); rc != 1 {
		t.Fatalf("scoped registered_clients = %v, want 1", stats["registered_clients"])
	}
}

// Prometheus exposition is fleet-wide with no tenant dimension,
// so tenant-scoped key must be refused:
// /api/v1/stats already withholds the same counters from scoped callers.
func TestAPITenantScoping_MetricsRefusedForScopedKey(t *testing.T) {
	f := newScopedAPIFixture(t, keyHashHex("acme-key"))

	if code, _ := f.do(t, "GET", "/metrics", "acme-key"); code != http.StatusForbidden {
		t.Fatalf("scoped key on /metrics: %d, want 403", code)
	}
}
