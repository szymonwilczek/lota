// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek

package verify

import (
	"bytes"
	"encoding/hex"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/szymonwilczek/lota/verifier/types"
)

// A verifier that keeps every line it logs, so a test can read what an operator
// would have read.
func repinVerifierWithLog(t *testing.T, buf *bytes.Buffer,
	allowedSeeds ...byte) *Verifier {
	t.Helper()

	cfg := DefaultConfig()
	cfg.NonceLifetime = 1 * time.Second
	cfg.RequireBootEnrollment = false
	cfg.Logger = slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))

	verifier := NewVerifier(cfg, newCertStore(t))
	policy := DefaultPolicy()
	for _, seed := range allowedSeeds {
		h := fixtureAgentHashSeed(seed)
		policy.AgentHashes = append(policy.AgentHashes, hex.EncodeToString(h[:]))
	}
	if err := verifier.AddPolicy(policy); err != nil {
		t.Fatalf("AddPolicy: %v", err)
	}
	if err := verifier.SetActivePolicy("default"); err != nil {
		t.Fatalf("SetActivePolicy: %v", err)
	}
	return verifier
}

// The refusal an operator has to act on says which refusal it is.
//
// A client on a build the publisher lists, refused because it re-pinned
// less than AgentHashRepinMinInterval ago, is not the drift the pin exists
// to catch -- and the only difference visible from the outside is what
// the verifier says about it.
func TestVerify_RateLimitedRepinNamesTheInterval(t *testing.T) {
	const thirdBuild byte = 0xD3
	var logs bytes.Buffer

	v := repinVerifierWithLog(t, &logs, repinOldBuild, repinNewBuild, thirdBuild)
	const clientID = "repin-reason-rate-limited"

	if _, err := attestAsBuild(t, v, clientID, repinOldBuild); err != nil {
		t.Fatalf("first attestation: %v", err)
	}
	if _, err := attestAsBuild(t, v, clientID, repinNewBuild); err != nil {
		t.Fatalf("first update: %v", err)
	}

	logs.Reset()

	if _, err := attestAsBuild(t, v, clientID, thirdBuild); err == nil {
		t.Fatal("expected refusal: a second re-pin inside the interval")
	}

	line := logs.String()
	if !strings.Contains(line, "interval") {
		t.Fatalf("the refusal never names the interval that caused it:\n%s",
			line)
	}
	if !strings.Contains(line, "re-anchor") {
		t.Fatalf("the refusal names no way out:\n%s", line)
	}
}

// And the other refusal is not blamed on the interval.
//
// A build nobody listed is the case the pin exists for, so the interval
// must not appear in its refusal -- otherwise naming the interval would
// be a blanket sentence.
func TestVerify_UnlistedBuildIsNotBlamedOnTheInterval(t *testing.T) {
	var logs bytes.Buffer

	v := repinVerifierWithLog(t, &logs, repinOldBuild)
	const clientID = "repin-reason-unlisted"

	if _, err := attestAsBuild(t, v, clientID, repinOldBuild); err != nil {
		t.Fatalf("first attestation: %v", err)
	}

	logs.Reset()

	result, err := attestAsBuild(t, v, clientID, repinNewBuild)
	if err == nil {
		t.Fatal("expected refusal: the reported build is not listed")
	}

	// policy gate refuses an unlisted build before the pin is consulted,
	// and it already names the allow-list, so this case is not the silent one
	if result.Result != types.VerifyPCRFail {
		t.Fatalf("expected VerifyPCRFail from the policy gate, got %d",
			result.Result)
	}
	if !strings.Contains(err.Error(), "agent hash not in allowed list") {
		t.Fatalf("expected the policy-gate refusal, got: %v", err)
	}

	if strings.Contains(logs.String(), "interval") {
		t.Fatalf("an unlisted build is blamed on the interval:\n%s",
			logs.String())
	}
}
