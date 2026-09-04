// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
// LOTA Verifier - what the decision log says about a refused round

package verify

import (
	"strings"
	"testing"
	"time"

	"github.com/szymonwilczek/lota/verifier/store"
	"github.com/szymonwilczek/lota/verifier/types"
)

// recordOneRound drives a single report through a verifier with a decision
// log installed and hands back the record it wrote.
func recordOneRound(t *testing.T, clientID string, report func(nonce [types.NonceSize]byte) []byte) store.AttestationRecord {
	t.Helper()

	attestLog := store.NewMemoryAttestationLog()
	cfg := DefaultConfig()
	cfg.RequireBootEnrollment = false
	cfg.NonceLifetime = 1 * time.Second
	cfg.AttestationLog = attestLog
	verifier := NewVerifier(cfg, newCertStore(t))
	if err := verifier.AddPolicy(DefaultPolicy()); err != nil {
		t.Fatalf("AddPolicy(DefaultPolicy) failed: %v", err)
	}
	if err := verifier.SetActivePolicy("default"); err != nil {
		t.Fatalf("SetActivePolicy(default) failed: %v", err)
	}

	challenge, err := verifier.GenerateChallenge(clientID)
	if err != nil {
		t.Fatalf("GenerateChallenge: %v", err)
	}
	if _, err := verifier.VerifyReport(clientID, report(challenge.Nonce)); err != nil {
		t.Logf("round refused: %v", err)
	}

	records := attestLog.QueryAttestations(1)
	if len(records) != 1 {
		t.Fatalf("attestation records = %d, want 1", len(records))
	}
	return records[0]
}

// The decision log is the surface an operator triages a refusal through.
// A record that names the verdict and not the reason sends them to the
// verifier's stdout, which is what the API exists to save them from.
func TestRefusedRoundRecordsWhyItWasRefused(t *testing.T) {
	const clientID = "detail-refused-client"

	// a report answering a nonce this verifier never issued:
	// a well-formed round the verifier refuses on its merits
	record := recordOneRound(t, clientID, func(_ [types.NonceSize]byte) []byte {
		var stale [types.NonceSize]byte
		stale[0] = 0xa5
		return createValidReport(t, clientID, stale, fixturePCR14())
	})

	if record.Result == "ok" {
		t.Fatal("the round was accepted; this test needs a refusal")
	}
	if record.Details == "" {
		t.Errorf("record for a %q round carries no reason", record.Result)
	}
}

// A round that was accepted has nothing to explain, and the record says so
// by carrying no reason.
func TestAcceptedRoundRecordsNoReason(t *testing.T) {
	const clientID = "detail-ok-client"

	record := recordOneRound(t, clientID, func(nonce [types.NonceSize]byte) []byte {
		return createValidReport(t, clientID, nonce, fixturePCR14())
	})

	if record.Result != "ok" {
		t.Fatalf("result = %q, want ok", record.Result)
	}
	if record.Details != "" {
		t.Errorf("record for an accepted round carries a reason: %q", record.Details)
	}
}

// The reason is written by the verifier, but it can quote what a report
// carried, so the record it lands in has to be bounded.
func TestRecordedReasonIsBounded(t *testing.T) {
	const clientID = "detail-bounded-client"

	record := recordOneRound(t, clientID, func(_ [types.NonceSize]byte) []byte {
		var stale [types.NonceSize]byte
		stale[0] = 0x5a
		return createValidReport(t, clientID, stale, fixturePCR14())
	})

	// the number the monitoring-API page states for this field
	const maxDetail = 2048
	if len(record.Details) > maxDetail {
		t.Errorf("recorded reason is %d bytes, want at most %d",
			len(record.Details), maxDetail)
	}
	if strings.ContainsAny(record.Details, "\r\n") {
		t.Error("recorded reason carries a line break, so one record can forge another")
	}
}
