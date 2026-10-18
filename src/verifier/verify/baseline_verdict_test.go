// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek

package verify

import (
	"strings"
	"testing"
	"time"

	"github.com/szymonwilczek/lota/verifier/types"
)

// baseOnlyStore implements the base baseline contract and nothing else,
// which is the shape of a store the verifier cannot pin firmware PCRs with.
// The interface is embedded so the optional contracts are genuinely absent.
type baseOnlyStore struct{ BaselineStorer }

// A store the verifier cannot use is a verifier fault; the verdict must not
// tell a healthy host its integrity failed.
func TestBaselineStoreFailureIsNotAnIntegrityVerdict(t *testing.T) {
	cfg := DefaultConfig()
	cfg.NonceLifetime = 1 * time.Second
	cfg.RequireBootEnrollment = false
	cfg.BaselineStore = baseOnlyStore{NewBaselineStore()}

	v := NewVerifier(cfg, newCertStore(t))
	if err := v.AddPolicy(DefaultPolicy()); err != nil {
		t.Fatalf("AddPolicy: %v", err)
	}
	if err := v.SetActivePolicy("default"); err != nil {
		t.Fatalf("SetActivePolicy: %v", err)
	}

	const clientID = "store-without-boot-pinning"
	challenge, err := v.GenerateChallenge(clientID)
	if err != nil {
		t.Fatalf("GenerateChallenge: %v", err)
	}
	report := createValidReport(t, clientID, challenge.Nonce, fixturePCR14())

	result, err := v.VerifyReport(clientID, report)
	if err == nil {
		t.Fatal("a store that cannot pin boot PCRs was accepted")
	}
	if !strings.Contains(err.Error(), "store missing boot PCR support") {
		t.Fatalf("refused for another reason: %v", err)
	}
	if result.Result != types.VerifyInternalError {
		t.Fatalf("verdict %s (%d), want internal_error",
			types.VerifyResultString(result.Result), result.Result)
	}
}
