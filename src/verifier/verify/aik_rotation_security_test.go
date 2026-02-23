// SPDX-License-Identifier: MIT

package verify

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/szymonwilczek/lota/verifier/store"
	"github.com/szymonwilczek/lota/verifier/types"
)

func TestSecurity_AIKExpiry_TOFUHijackRejected(t *testing.T) {
	t.Log("SECURITY TEST: AIK expiry must not enable TOFU hijack / key swap")

	// registered
	victimKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey(victim) failed: %v", err)
	}

	// software key used to forge reports
	attackerKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey(attacker) failed: %v", err)
	}

	aikStore := store.NewMemoryStore()
	cfg := DefaultConfig()
	cfg.RequireCert = false
	cfg.NonceLifetime = 2 * time.Second
	cfg.AIKMaxAge = 1 * time.Millisecond
	verifier := NewVerifier(cfg, aikStore)
	verifier.AddPolicy(DefaultPolicy())
	if err := verifier.SetActivePolicy("default"); err != nil {
		t.Fatalf("SetActivePolicy failed: %v", err)
	}

	challengeID := "victim-client"
	pcr14 := [32]byte{}

	// perform a normal TOFU registration using the victim key
	ch1, err := verifier.GenerateChallenge(challengeID)
	if err != nil {
		t.Fatalf("GenerateChallenge failed: %v", err)
	}
	report1 := createValidReportWithKey(challengeID, ch1.Nonce, pcr14, victimKey)
	res1, err := verifier.VerifyReport(challengeID, report1)
	if err != nil || res1.Result != types.VerifyOK {
		t.Fatalf("expected initial attestation OK, got result=%d err=%v", res1.Result, err)
	}

	// wait so the registration becomes expired per AIKMaxAge
	time.Sleep(5 * time.Millisecond)

	// tries to hijack identity by submitting a report for the same
	// hardware_id/clientID, but signed with an attacker-controlled key
	ch2, err := verifier.GenerateChallenge(challengeID)
	if err != nil {
		t.Fatalf("GenerateChallenge(2) failed: %v", err)
	}
	reportAttack := createValidReportWithKey(challengeID, ch2.Nonce, pcr14, attackerKey)
	res2, err := verifier.VerifyReport(challengeID, reportAttack)
	if err == nil || res2.Result != types.VerifySigFail {
		t.Fatalf("SECURITY FAILURE: expected SIG_FAIL on TOFU hijack after expiry; got result=%d err=%v", res2.Result, err)
	}
	_ = err

	// stored AIK was NOT rotated to attacker key
	storedID := persistentClientID(challengeID)
	gotAIK, err := aikStore.GetAIK(storedID)
	if err != nil {
		t.Fatalf("GetAIK failed: %v", err)
	}
	if gotAIK.N.Cmp(attackerKey.PublicKey.N) == 0 {
		t.Fatalf("SECURITY FAILURE: AIK store rotated to attacker key")
	}
}
