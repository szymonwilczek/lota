// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek

package verify

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/szymonwilczek/lota/verifier/store"
)

// FuzzVerifyReport drives the verifier's top-level entrypoint with arbitrary
// report bytes. VerifyReport parses and fully checks the attestation report a
// client submits over the wire, so it must never panic and must always hand
// back a result whenever it reports no error.
func FuzzVerifyReport(f *testing.F) {
	cfg := DefaultConfig()
	cfg.RequireCert = false
	cfg.RequireBootPCRs = false
	cfg.RequireInitramfsLock = false
	cfg.NonceLifetime = time.Hour
	v := NewVerifier(cfg, store.NewMemoryStore())
	if err := v.AddPolicy(DefaultPolicy()); err != nil {
		f.Fatalf("AddPolicy: %v", err)
	}
	if err := v.SetActivePolicy("default"); err != nil {
		f.Fatalf("SetActivePolicy: %v", err)
	}

	const clientID = "fuzz-client"
	ch, err := v.GenerateChallenge(clientID)
	if err != nil {
		f.Fatalf("GenerateChallenge: %v", err)
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		f.Fatalf("AIK key: %v", err)
	}
	var pcr14 [32]byte
	validReport := createValidReportWithKey(clientID, ch.Nonce, pcr14, key)

	f.Add(validReport)
	f.Add([]byte{})
	f.Add([]byte{0x4C, 0x4F, 0x54, 0x52})

	f.Fuzz(func(t *testing.T, reportData []byte) {
		result, err := v.VerifyReport(clientID, reportData)
		if err == nil && result == nil {
			t.Fatalf("VerifyReport returned no result and no error")
		}
	})
}
