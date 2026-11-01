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
	"github.com/szymonwilczek/lota/verifier/types"
	"github.com/szymonwilczek/lota/verifier/verify"
)

// Delete drops verifier state only; the host keeps a valid AIK certificate,
// so its next attestation is a first sight and becomes the new baseline.
func TestDeleteLeavesTheDeviceAbleToReturnOnItsOwn(t *testing.T) {
	aikVerifier := newCertVerifier(t)
	bs := verify.NewBaselineStore()

	var before, after [types.HashSize]byte
	before[0] = 0x11
	after[0] = 0x22

	if res, _ := bs.CheckAndUpdate("host-0001", before); res != verify.TOFUFirstUse {
		t.Fatalf("seeding baseline: %v, want first use", res)
	}

	m := metrics.New()
	cfg := verify.DefaultConfig()
	cfg.RequireBootEnrollment = false
	cfg.BaselineStore = bs
	cfg.Metrics = m
	v := verify.NewVerifier(cfg, aikVerifier)
	srv := &Server{verifier: v, addr: ":8443"}

	db := testDB(t)

	auditLog := store.NewSQLiteAuditLog(db)
	mux := http.NewServeMux()
	NewAPIHandler(mux, v, srv, auditLog, nil, m,
		store.NewSQLiteAttestationLog(db, store.DefaultCollapseWindow), "admin-key", "reader-key")

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/clients/host-0001",
		strings.NewReader(`{"actor":"alice@ops","reason":"suspected compromise"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer admin-key")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("delete: status %d -- body %s", rr.Code, rr.Body.String())
	}

	// changed measurement is adopted without re-enrolment
	res, baseline := bs.CheckAndUpdate("host-0001", after)
	if res != verify.TOFUFirstUse {
		t.Fatalf("a deleted client came back as %v, want a first sight", res)
	}
	if baseline == nil || baseline.PCR14 != after {
		t.Fatal("the returning client's own measurement did not become the baseline")
	}
}
