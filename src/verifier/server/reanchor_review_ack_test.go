// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek

package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/szymonwilczek/lota/verifier/metrics"
	"github.com/szymonwilczek/lota/verifier/store"
	"github.com/szymonwilczek/lota/verifier/verify"
)

// A review acknowledgement records who looked at an LFA re-anchor and why,
// like forced re-anchor and delete. Unknown clients, empty queues and missing
// actor or reason are refused without an audit row.
type ackFixture struct {
	mux   *http.ServeMux
	store *verify.BaselineStore
	audit *store.MemoryAuditLog
}

// newAckFixture seeds "queued" (LFA re-anchored, pending review) and "quiet"
// (nothing pending).
func newAckFixture(t *testing.T) *ackFixture {
	t.Helper()

	aikStore := newCertStore(t)

	bs := verify.NewBaselineStore()
	var b verify.BootBaseline
	b.PCR0[0], b.PCR1[0], b.PCR7[0] = 1, 2, 7

	for _, id := range []string{"queued", "quiet"} {
		var pcr14 [32]byte
		pcr14[0] = 0xDE
		bs.CheckAndUpdate(id, pcr14)
		bs.CheckAndUpdateBootPCRs(id, b)
	}
	if err := bs.ArchiveAndReanchor("queued", b, []byte("log"), 0, false, true, "lfa", time.Now()); err != nil {
		t.Fatalf("seed LFA re-anchor: %v", err)
	}

	m := metrics.New()
	cfg := verify.DefaultConfig()
	cfg.RequireBootEnrollment = false
	cfg.BaselineStore = bs
	cfg.Metrics = m
	v := verify.NewVerifier(cfg, aikStore)
	srv := &Server{verifier: v, addr: ":8443"}

	auditLog := store.NewMemoryAuditLog()
	mux := http.NewServeMux()
	NewAPIHandler(mux, v, srv, auditLog, nil, m,
		store.NewMemoryAttestationLog(), "admin-key", "reader-key")

	return &ackFixture{mux: mux, store: bs, audit: auditLog}
}

func (f *ackFixture) ack(t *testing.T, clientID, body string) *httptest.ResponseRecorder {
	t.Helper()

	var reader *strings.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	var req *http.Request
	if reader != nil {
		req = httptest.NewRequest(http.MethodPost,
			"/api/v1/clients/"+clientID+"/reanchor-review-ack", reader)
		req.Header.Set("Content-Type", "application/json")
	} else {
		req = httptest.NewRequest(http.MethodPost,
			"/api/v1/clients/"+clientID+"/reanchor-review-ack", nil)
	}
	req.Header.Set("Authorization", "Bearer admin-key")
	rr := httptest.NewRecorder()
	f.mux.ServeHTTP(rr, req)
	return rr
}

func TestReanchorReviewAckRefusesWhatItCannotRecord(t *testing.T) {
	const attribution = `{"actor":"alice@ops","reason":"reviewed the firmware update"}`

	cases := []struct {
		name     string
		clientID string
		body     string
		status   int
		says     string
	}{
		{
			name:     "a client id that does not exist",
			clientID: "deadbeef",
			body:     attribution,
			status:   http.StatusNotFound,
			says:     "client not found",
		},
		{
			name:     "a client with nothing queued",
			clientID: "quiet",
			body:     attribution,
			status:   http.StatusConflict,
			says:     "no re-anchor review pending",
		},
		{
			name:     "an empty body",
			clientID: "queued",
			body:     "",
			status:   http.StatusBadRequest,
			says:     "actor is required",
		},
		{
			name:     "an acknowledgement with no reason",
			clientID: "queued",
			body:     `{"actor":"alice@ops"}`,
			status:   http.StatusBadRequest,
			says:     "reason is required",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newAckFixture(t)

			rr := f.ack(t, tc.clientID, tc.body)
			if rr.Code != tc.status {
				t.Fatalf("status %d, want %d -- body %s", rr.Code, tc.status, rr.Body.String())
			}
			if !strings.Contains(rr.Body.String(), tc.says) {
				t.Fatalf("body %s does not say %q", rr.Body.String(), tc.says)
			}
			if got := len(f.audit.Query(0)); got != 0 {
				t.Fatalf("a refused acknowledgement wrote %d audit row(s)", got)
			}
			if len(f.store.ListLFAReviewPending()) != 1 {
				t.Fatal("a refused acknowledgement took the client off the review queue")
			}
		})
	}
}

func TestReanchorReviewAckRecordsWhoLooked(t *testing.T) {
	f := newAckFixture(t)

	rr := f.ack(t, "queued", `{"actor":"alice@ops","reason":"reviewed the firmware update","note":"vendor advisory 41"}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d, want 200 -- body %s", rr.Code, rr.Body.String())
	}
	var resp map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp["status"] != "reviewed" || resp["client_id"] != "queued" {
		t.Fatalf("answer %v, want the reviewed client", resp)
	}
	if len(f.store.ListLFAReviewPending()) != 0 {
		t.Fatal("the client is still queued after an accepted acknowledgement")
	}

	entries := f.audit.Query(0)
	if len(entries) != 1 {
		t.Fatalf("%d audit rows, want the one naming who looked", len(entries))
	}
	e := entries[0]
	if e.Action != "reanchor_review_ack" || e.TargetID != "queued" ||
		e.Actor != "alice@ops" || e.Reason != "reviewed the firmware update" {
		t.Fatalf("audit row %+v does not name the action, the client, the actor and the reason", e)
	}

	// nothing left to review
	again := f.ack(t, "queued", `{"actor":"alice@ops","reason":"again"}`)
	if again.Code != http.StatusConflict {
		t.Fatalf("second acknowledgement: status %d, want 409", again.Code)
	}
}
