// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
// LOTA Verifier - the device inventory the monitoring API serves

package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/szymonwilczek/lota/verifier/store"
	"github.com/szymonwilczek/lota/verifier/types"
	"github.com/szymonwilczek/lota/verifier/verify"
)

// inventoryFixture builds an API handler whose only per-client record is
// the baseline store, as in a Privacy CA deployment: the AIK store stays
// empty and challenge history is per-process.
func inventoryFixture(t *testing.T, clients ...string) *http.ServeMux {
	t.Helper()

	baseline := verify.NewBaselineStore()
	auditLog := store.NewMemoryAuditLog()

	cfg := verify.DefaultConfig()
	cfg.RequireBootEnrollment = false
	cfg.BaselineStore = baseline
	cfg.RevocationStore = store.NewMemoryRevocationStore(auditLog)
	cfg.BanStore = store.NewMemoryBanStore(auditLog)

	v := verify.NewVerifier(cfg, store.NewMemoryStore())
	if err := v.AddPolicy(verify.DefaultPolicy()); err != nil {
		t.Fatalf("AddPolicy(DefaultPolicy): %v", err)
	}

	// a baseline row per client, as a first attestation pins one
	for i, id := range clients {
		var pcr14 [types.HashSize]byte
		pcr14[0] = byte(i + 1)
		if result, _ := baseline.CheckAndUpdate(id, pcr14); result != verify.TOFUFirstUse {
			t.Fatalf("seeding %s: expected a first-use baseline, got %v", id, result)
		}
	}

	mux := http.NewServeMux()
	NewAPIHandler(mux, v, nil, auditLog, nil, nil, store.NewMemoryAttestationLog(), "", "")
	return mux
}

func listClients(t *testing.T, mux *http.ServeMux, query string) clientListResponse {
	t.Helper()

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/clients"+query, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/v1/clients%s = %d, want 200", query, rec.Code)
	}

	var resp clientListResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return resp
}

// The inventory is read from the shared baseline store, so an instance lists
// clients it never spoke to and the answer survives a restart.
func TestListClientsServesTheDurableRecord(t *testing.T) {
	mux := inventoryFixture(t, "host-0001", "host-0002")

	resp := listClients(t, mux, "")
	if resp.Total != 2 || len(resp.Clients) != 2 {
		t.Fatalf("clients=%v count=%d total=%d; want the two clients the shared state holds",
			resp.Clients, resp.Count, resp.Total)
	}
	if resp.Clients[0] != "host-0001" || resp.Clients[1] != "host-0002" {
		t.Fatalf("clients=%v; want host-0001 and host-0002 in order", resp.Clients)
	}
}

// The page an operator asks for is a page of that same record.
func TestListClientsPagesTheDurableRecord(t *testing.T) {
	mux := inventoryFixture(t, "host-0001", "host-0002", "host-0003")

	first := listClients(t, mux, "?limit=2&offset=0")
	if first.Total != 3 || len(first.Clients) != 2 || first.Clients[0] != "host-0001" {
		t.Fatalf("first page = %+v; want two of three, starting at host-0001", first)
	}

	second := listClients(t, mux, "?limit=2&offset=2")
	if second.Total != 3 || len(second.Clients) != 1 || second.Clients[0] != "host-0003" {
		t.Fatalf("second page = %+v; want the remaining host-0003", second)
	}

	past := listClients(t, mux, "?limit=2&offset=10")
	if len(past.Clients) != 0 || past.Total != 3 {
		t.Fatalf("page past the end = %+v; want no clients and the same total", past)
	}
}

// ClientInfo reports the last attestation from the shared baseline record,
// not from this instance's session history.
func TestClientInfoReportsTheFleetsLastAttestation(t *testing.T) {
	baseline := verify.NewBaselineStore()
	auditLog := store.NewMemoryAuditLog()

	cfg := verify.DefaultConfig()
	cfg.RequireBootEnrollment = false
	cfg.BaselineStore = baseline
	cfg.RevocationStore = store.NewMemoryRevocationStore(auditLog)
	cfg.BanStore = store.NewMemoryBanStore(auditLog)

	v := verify.NewVerifier(cfg, store.NewMemoryStore())
	if err := v.AddPolicy(verify.DefaultPolicy()); err != nil {
		t.Fatalf("AddPolicy(DefaultPolicy): %v", err)
	}

	// two rounds through another instance, against the shared record
	var pcr14 [types.HashSize]byte
	pcr14[0] = 0x42
	baseline.CheckAndUpdate("host-0001", pcr14)
	baseline.CheckAndUpdate("host-0001", pcr14)

	record := baseline.GetBaseline("host-0001")
	if record == nil || record.LastSeen.IsZero() {
		t.Fatal("the shared record must carry when the client last attested")
	}

	info, found := v.ClientInfo("host-0001")
	if !found {
		t.Fatal("a client with a baseline must be known to every instance")
	}
	if !info.LastAttestation.Equal(record.LastSeen) {
		t.Fatalf("last attestation = %v; the record this deployment shares says %v",
			info.LastAttestation, record.LastSeen)
	}
	if info.AttestCount != record.AttestCount {
		t.Fatalf("attestation count = %d, record says %d", info.AttestCount, record.AttestCount)
	}
}
