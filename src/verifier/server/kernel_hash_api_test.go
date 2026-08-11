// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/szymonwilczek/lota/verifier/metrics"
	"github.com/szymonwilczek/lota/verifier/store"
	"github.com/szymonwilczek/lota/verifier/verify"
)

// The kernel hash is folded into the digest the TPM signs, so a recorded
// attestation carries attested evidence of which kernel image the agent measured.
// The runbook path -- GET /api/v1/attestations to see what a device reported
// -- keeps pcr14 and drops that, which leaves the first question anyone asks
// about a Linux host unanswerable after the fact.
func TestAttestationLogEndpoint_ReportsKernelHash(t *testing.T) {
	aikStore := newCertStore(t)
	m := metrics.New()
	cfg := verify.DefaultConfig()
	cfg.RequireBootEnrollment = false
	auditLog := store.NewMemoryAuditLog()
	attLog := store.NewMemoryAttestationLog()
	cfg.RevocationStore = store.NewMemoryRevocationStore(auditLog)
	cfg.BanStore = store.NewMemoryBanStore(auditLog)
	cfg.Metrics = m
	v := verify.NewVerifier(cfg, aikStore)
	if err := v.AddPolicy(verify.DefaultPolicy()); err != nil {
		t.Fatalf("AddPolicy(DefaultPolicy) failed: %v", err)
	}

	srv := &Server{verifier: v, addr: ":8443"}
	mux := http.NewServeMux()
	NewAPIHandler(mux, v, srv, auditLog, nil, m, attLog, "admin-key", "reader-key")

	const kernelHash = "3c3a2509e52f2ed3cbdf07780f1de96e3b44f148741ae57742c78576afe2b173"
	if err := attLog.Record(store.AttestationRecord{
		ClientID:   "c1",
		Tenant:     "alpha",
		Result:     "ok",
		PCR14:      "1bc09c6ab970b2ae",
		KernelHash: kernelHash,
	}); err != nil {
		t.Fatalf("attestation record insert failed: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/attestations", nil)
	req.Header.Set("Authorization", "Bearer reader-key")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}

	var resp struct {
		Attestations []struct {
			ClientID   string `json:"client_id"`
			PCR14      string `json:"pcr14"`
			KernelHash string `json:"kernel_hash"`
		} `json:"attestations"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if len(resp.Attestations) != 1 {
		t.Fatalf("expected one attestation entry, got %d", len(resp.Attestations))
	}
	if resp.Attestations[0].KernelHash != kernelHash {
		t.Errorf("kernel hash not served: got %q, want %q",
			resp.Attestations[0].KernelHash, kernelHash)
	}
}
